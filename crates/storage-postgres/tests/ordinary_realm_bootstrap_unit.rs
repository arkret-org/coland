#[path = "support/accepted_pcr_account.rs"]
mod accepted_pcr_account;
#[path = "../../test-support/src/device_authorization_history.rs"]
#[allow(dead_code)]
mod device_authorization_history;
#[path = "support/human_profile.rs"]
#[allow(dead_code)]
mod human_profile;
#[path = "support/hydration.rs"]
mod hydration;
#[path = "support/ordinary_bootstrap_fault_cases.rs"]
mod ordinary_bootstrap_fault_cases;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
#[path = "../../test-support/src/pcr_genesis.rs"]
#[allow(dead_code)]
mod pcr_genesis;
#[path = "support/sql_fault_matrix.rs"]
mod sql_fault_matrix;

use arkret_models_collaboration::authority_commit::{
    OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
    SelfAuthoritySubmitRequest,
};
use coland_services::projection::ProjectionService;
use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, CurrentRealmAuthority, EventCommitRequest,
    EventCommitUnitOfWork, InviteCurrentResultStore, OrdinaryRealmBootstrapCommitOutcome,
    OrdinaryRealmBootstrapCommitUnit, SelfProducerCommitGuard,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgInviteCurrentResultStore,
    account_snapshot_material,
};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;
use hydration::BootstrapHydrationAdapter;

fn snapshot_signer_for_issuer(
    unit: &OrdinaryRealmBootstrapCommitUnit,
    issuer: &arkret_wire::DidCoreId,
) -> arkret_wire::DidUrl {
    // Retain the fixture's registered Station DID from its genesis Commit;
    // a core id alone is not a DID method-resolution record.
    let did = arkret_identity::verification_method_did(
        unit.transactions[0]
            .commit
            .signature
            .verification_method
            .as_str(),
    )
    .unwrap();
    assert_eq!(&arkret_wire::project_did_to_core_id(&did).unwrap(), issuer);
    arkret_wire::DidUrl::new(format!("{did}#notary-key")).unwrap()
}

#[tokio::test]
async fn realm_directory_entry_replays_only_its_committed_realm() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let target = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(&target, target.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let unrelated = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(
            &unrelated,
            unrelated.transactions[0].commit.committed_at,
        )
        .await
        .unwrap();
    let realm_id = &target.transactions[0].event.realm_id;
    assert_ne!(realm_id, &unrelated.transactions[0].event.realm_id);
    let persistence = coland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
        coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
    ));
    let directory = persistence.hydrate_realm_directory().await.unwrap();
    let expected = directory.get(realm_id).unwrap().clone();
    assert_eq!(expected.title, "Test Realm");
    assert!(
        expected
            .members
            .contains(target.transactions[0].event.actor_id.signing_principal_id())
    );
    assert_eq!(
        expected.source_refs,
        vec![target.transactions[0].event.event_id.to_string()]
    );
    assert_eq!(
        persistence
            .hydrate_realm_directory_entry(realm_id)
            .await
            .unwrap(),
        Some(expected.clone())
    );

    // Poison an unrelated accepted mirror. Whole-Station replay must fail,
    // while a Realm-local read must neither inspect nor rewrite that Realm.
    let mut damaged = serde_json::to_value(&unrelated.transactions[0].event).unwrap();
    damaged["payload"]["object"]["unregistered"] = serde_json::json!(true);
    damage_hydration_mirror(&pool, &unrelated.transactions[0].event.event_id, damaged).await;
    assert!(persistence.hydrate_realm_directory().await.is_err());
    assert_eq!(
        persistence
            .hydrate_realm_directory_entry(realm_id)
            .await
            .unwrap(),
        Some(expected)
    );
    let absent = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [227; 32],
    ));
    assert!(
        persistence
            .hydrate_realm_directory_entry(&absent)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn realm_directory_entry_rejects_target_commit_binding_mismatch() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let target = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(&target, target.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let persistence = coland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
        coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
    ));
    let mut damaged = serde_json::to_value(&target.transactions[1].event).unwrap();
    damaged["payload"]["title"] = serde_json::json!("forged title");
    damage_hydration_mirror(&pool, &target.transactions[1].event.event_id, damaged).await;
    let error = persistence
        .hydrate_realm_directory_entry(&target.transactions[0].event.realm_id)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("differs from its Commit binding")
    );
}

async fn damage_hydration_mirror(
    pool: &coland_storage_postgres::PgPool,
    event_id: &arkret_wire::EventId,
    damaged: serde_json::Value,
) {
    use diesel_async::AsyncConnection as _;
    let mut conn = pool.get().await.unwrap();
    // This leased test database simulates physical mirror corruption, not
    // an admitted write. Restore the immutable trigger in the same transaction.
    (&mut *conn)
        .transaction::<_, diesel::result::Error, _>(async move |conn| {
            diesel::sql_query(
                "ALTER TABLE canonical_events DISABLE TRIGGER canonical_events_immutable",
            )
            .execute(&mut *conn)
            .await?;
            let changed = diesel::sql_query(
                "UPDATE canonical_events SET envelope=$2 WHERE envelope->>'event_id'=$1",
            )
            .bind::<Text, _>(event_id.as_str())
            .bind::<diesel::sql_types::Jsonb, _>(damaged)
            .execute(&mut *conn)
            .await?;
            assert_eq!(changed, 1);
            diesel::sql_query(
                "ALTER TABLE canonical_events ENABLE TRIGGER canonical_events_immutable",
            )
            .execute(&mut *conn)
            .await?;
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn owned_agent_exact_current_is_issuer_only_even_after_membership_ends() {
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultEntry, ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
    };
    use coland_storage::SelfExactCurrentRead;
    use diesel::sql_types::Jsonb;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    human_profile::admit(&pool, &station, "bootstrap-actor").await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let realm = unit.transactions[0].event.realm_id.clone();
    let controller = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let head = &unit.transactions[6].commit;
    let agent = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:exact-agent.example").unwrap(),
        station.clone(),
    );
    let grant_id = arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [61; 32],
    ));
    let reference = serde_json::json!({"kind":"owned_agent","realm_id":realm,"controller_account_id":controller,"controller_join_event_id":unit.transactions[2].event.event_id,"agent_join_event_id":unit.transactions[2].event.event_id});
    // Storage-contract fixture for an imported current, not proof of
    // live owned-source authoring, identity verification or membership admission.
    let value = serde_json::json!({
        "id":grant_id,"schema":"ak.schema.capability.v1","realm_id":realm,
        "issuer_id":arkret_wire::ActorId::account(controller.clone()),"subject":arkret_wire::ActorId::account(agent.clone()),
        "actions":["ak.message.create"],"resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[{"constraint_kind":"authority_control","effect":"allow","max_authority_depth":0,"authority_regrant_allowed":false}],
        "issuer_authority_refs":[reference.clone()],"authority_depth":1,"authority_root_refs":[reference],
        "issued_at":arkret_canonical::format_timestamp_canonical(head.committed_at),"status":"active"
    });
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO capability_grant_current_results(realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value,updated_at) VALUES($1,$2,'active',$3,$4,$5,$6,$7,now())")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(grant_id.as_str()).bind::<Text,_>(head.event_ref.as_str()).bind::<Text,_>(head.commit_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&head.stream_ref).unwrap()).bind::<BigInt,_>(head.stream_position as i64).bind::<Jsonb,_>(value).execute(&mut *conn).await.unwrap();
    diesel::sql_query("UPDATE member_state_current_results SET membership='leave',value=jsonb_set(value,'{membership}','\"leave\"'::jsonb) WHERE realm_id=$1 AND member_id=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(arkret_wire::ActorId::account(controller.clone()).to_string()).execute(&mut *conn).await.unwrap();
    drop(conn);
    let request: ExactCurrentResultsReadRequestBody = serde_json::from_value(serde_json::json!({"realm_id":realm,"selector":{"kind":"capability_grant","grant_id":grant_id}})).unwrap();
    let SelfExactCurrentRead::Answer(ExactCurrentResultsReadOutcome::Present {
        entry: ExactCurrentResultEntry::CapabilityGrant(row),
        ..
    }) = store
        .exact_current_result_for_account(&request, &controller, &station)
        .await
        .unwrap()
    else {
        panic!("original issuer must read the ineffective revision without membership");
    };
    assert_eq!(row.revision.commit_id, head.commit_id);
    assert_eq!(
        row.value.status,
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Active
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let stale = realm_event_request_as(
        &bootstrap_tail(&unit),
        &controller,
        arkret_wire::EventKind::CapabilityRevoke,
        serde_json::json!({"grant_id":grant_id,"expected_revision":{"commit_id":head.commit_id,"stream_position":0}}),
    );
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &stale,
        coland_storage::ConflictCode::CasConflict,
    )
    .await;
    let revoke = realm_event_request_as(
        &bootstrap_tail(&unit),
        &controller,
        arkret_wire::EventKind::CapabilityRevoke,
        serde_json::json!({"grant_id":grant_id,"expected_revision":row.revision}),
    );
    uow.commit_event(revoke.clone()).await.unwrap();
    let SelfExactCurrentRead::Answer(ExactCurrentResultsReadOutcome::Present {
        entry: ExactCurrentResultEntry::CapabilityGrant(terminal),
        ..
    }) = store
        .exact_current_result_for_account(&request, &controller, &station)
        .await
        .unwrap()
    else {
        panic!("issuer must retain terminal revision access");
    };
    assert_eq!(
        terminal.value.status,
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Revoked
    );
    assert_eq!(
        terminal.revision.commit_id,
        revoke.authority_commit.commit.commit_id
    );
    for stranger in [
        agent,
        arkret_wire::AccountId::new(
            controller.principal_id,
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ),
    ] {
        assert!(matches!(
            store
                .exact_current_result_for_account(&request, &stranger, &station)
                .await
                .unwrap(),
            SelfExactCurrentRead::NotFound
        ));
    }
    let missing: ExactCurrentResultsReadRequestBody = serde_json::from_value(serde_json::json!({"realm_id":realm,"selector":{"kind":"capability_grant","grant_id":arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [62;32]))}})).unwrap();
    assert!(matches!(
        store
            .exact_current_result_for_account(
                &missing,
                row.value.issuer_id.as_account_id().unwrap(),
                &station
            )
            .await
            .unwrap(),
        SelfExactCurrentRead::NotFound
    ));
}

#[tokio::test]
async fn founder_disclosure_covers_every_accepted_cut_of_disclosed_kinds() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    // Plain-text messages need the Station in the plaintext-services facet.
    let unit = unit_with_plaintext_service(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 9);
    assert!(material.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::RealmPlaintextVisibleServices,
            ..
        }
    )));
    assert!(
        account_snapshot_material(&pool, &realm_id, &stranger)
            .await
            .is_err()
    );

    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO relation_current_results \
         (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,'injected','{}'::jsonb,'ak:relation:test','active',$2,6, \
                 '{\"id\":\"ak:relation:test\",\"state\":\"active\"}'::jsonb,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
    .execute(&mut conn).await.unwrap();
    assert!(
        account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .is_err()
    );
    diesel::sql_query("DELETE FROM relation_current_results WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    // An unrelated Circle row grants no membership or visibility. It must
    // neither disable the Realm cut nor appear in the caller snapshot.
    // This injected row is an isolation probe, not accepted Circle evidence.
    let circle_id = arkret_wire::CircleId::from_event_id(&unit.transactions[0].event.event_id);
    diesel::sql_query(
        "INSERT INTO circle_current_results \
         (realm_id,circle_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,short_name_folded,value,updated_at) \
         VALUES ($1,$2,$3,$4,0,$5,'private',$6,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(unit.transactions[0].event.event_id.as_str())
    .bind::<Text, _>(unit.transactions[0].commit.commit_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"kind":"realm","realm_id":realm_id}))
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"id":circle_id,"realm_id":realm_id}))
    .execute(&mut conn).await.unwrap();
    let isolated = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(isolated.current_state_entries.len(), 9);
    assert!(
        isolated
            .visible_stream_heads
            .iter()
            .all(|head| matches!(head.stream_ref, arkret_wire::CommitStreamRef::Realm { .. }))
    );
    diesel::sql_query("DELETE FROM circle_current_results WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    let sidecar_id = arkret_wire::SidecarId::from_event_id(&unit.transactions[0].event.event_id);
    diesel::sql_query(
        "INSERT INTO sidecar_current_results \
         (realm_id,sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,0,$6,$7,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(sidecar_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&creator).unwrap())
    .bind::<Text, _>(unit.transactions[0].event.event_id.as_str())
    .bind::<Text, _>(unit.transactions[0].commit.commit_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"kind":"realm","realm_id":realm_id}))
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"id":sidecar_id,"realm_id":realm_id,"controller_account_id":creator}))
    .execute(&mut conn).await.unwrap();
    assert!(
        account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .is_err()
    );
    diesel::sql_query("DELETE FROM sidecar_current_results WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    drop(conn);

    // Every accepted cut is disclosed, not a closed chain of fixed length:
    // a Strand without a default pointer, then the pointer, then messages.
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 11);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CalendarScheduleSource { strand_id: id },
            source_stream_ref, revision, ..
        } if id == &strand_id
            && source_stream_ref == &strand.authority_commit.commit.stream_ref
            && revision.commit_id == strand.authority_commit.commit.commit_id
            && revision.stream_position == strand.authority_commit.commit.stream_position
    )));
    assert_eq!(material.visible_stream_heads[0].stream_position, 8);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 12);
    let first = message_create_request(&default, &strand_id, "first");
    uow.commit_event(first.clone()).await.unwrap();
    let second = message_create_request(&first, &strand_id, "second");
    uow.commit_event(second.clone()).await.unwrap();
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 14);
    assert_eq!(material.visible_stream_heads[0].stream_position, 11);
    assert_eq!(
        material.retention_and_history_floor.stream_floors[0].oldest_position,
        0
    );
    for request in [&first, &second] {
        let message_id =
            arkret_wire::MessageId::from_event_id(&request.authority_commit.event.event_id);
        let commit = &request.authority_commit.commit;
        assert!(material.current_state_entries.iter().any(|entry| matches!(
            entry,
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MessageRevision { message_id: found },
                revision,
                ..
            } if found == &message_id
                && revision.commit_id == commit.commit_id
                && revision.stream_position == commit.stream_position
        )));
    }
    // The founder stays the only one who may receive the cut.
    assert!(
        account_snapshot_material(&pool, &realm_id, &stranger)
            .await
            .is_err()
    );
}

async fn issuance_count(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT count(*) AS count FROM realm_state_snapshot_issuances issued \
         JOIN realm_state_snapshots snapshot ON snapshot.snapshot_id = issued.snapshot_id \
         WHERE snapshot.realm_id = $1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<Count>(&mut conn)
    .await
    .unwrap()
    .count
}

/// Real PostgreSQL: `/head` issuance materializes, checks tenure, signs,
/// and archives in one cut; by-ref returns the exact object only while the
/// read cut still re-proves the Account's disclosure.
#[tokio::test]
async fn account_snapshot_issuance_is_same_cut_and_by_ref_rechecks_disclosure() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let other_station = arkret_wire::DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let tamper = |material: &coland_storage::RealmStateSnapshotMaterial| {
        let mut partial = material.clone();
        partial.current_state_entries.pop();
        sign(&partial)
    };

    // No tenure, no complete disclosure, or a signer that alters the proved
    // material: nothing is issued.
    assert!(matches!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &other_station, &sign)
            .await,
        Err(coland_storage::PersistenceError::SchemaViolation(_))
    ));
    assert!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &stranger, &issuer, &sign)
            .await
            .is_err()
    );
    assert!(matches!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &tamper)
            .await,
        Err(coland_storage::PersistenceError::Internal(_))
    ));
    assert_eq!(issuance_count(&pool, &realm_id).await, 0);

    let first = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.current_state_entries.len(), 9);
    assert_eq!(issuance_count(&pool, &realm_id).await, 1);
    let unsigned = arkret_canonical::unsigned_value(&first, &["signature"]).unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &first.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    let by_ref = |account: arkret_wire::AccountId,
                  realm: arkret_wire::RealmId,
                  id: arkret_wire::RealmSnapshotId,
                  station: arkret_wire::DidCoreId| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        async move {
            store
                .issued_realm_state_snapshot(&realm, &account, &id, &station)
                .await
        }
    };
    let exact = by_ref(
        creator.clone(),
        realm_id.clone(),
        first.snapshot_id.clone(),
        issuer.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&exact).unwrap(),
        arkret_canonical::canonical_json_bytes(&first).unwrap(),
    );
    assert!(
        by_ref(
            stranger.clone(),
            realm_id.clone(),
            first.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap()
        .is_none()
    );
    let other_realm = unit_with_plaintext_service(&pool).await.transactions[0]
        .event
        .realm_id
        .clone();
    assert!(
        by_ref(
            creator.clone(),
            other_realm,
            first.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            first.snapshot_id.clone(),
            other_station.clone()
        )
        .await
        .is_err()
    );

    // A later cut issues a new exact object; the earlier one stays exactly
    // readable while the Account's join revision is unchanged.
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    uow.commit_event(message_create_request(&default, &strand_id, "hello"))
        .await
        .unwrap();
    let second = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.current_state_entries.len(), 13);
    let (source_stream, source_revision, source_value) = second
        .current_state_entries
        .iter()
        .find_map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::CalendarScheduleSource { strand_id: id },
                source_stream_ref,
                revision,
                value,
            } if id == &strand_id => Some((source_stream_ref, revision, value)),
            _ => None,
        })
        .expect("every Strand writer preserves its same-cut Calendar source sibling");
    let source: arkret_wire::CalendarScheduleSourceValue =
        serde_json::from_value(source_value.clone()).unwrap();
    assert_eq!(source.strand_revision, *source_revision);
    assert_eq!(
        source.effective_scope,
        strand.authority_commit.event.scope_ref
    );
    assert!(source.source.is_none());
    assert!(source.metadata_context.is_none());
    assert_eq!(source_stream, &strand.authority_commit.commit.stream_ref);
    assert_eq!(
        source_revision.commit_id,
        strand.authority_commit.commit.commit_id
    );
    assert_eq!(second.visible_stream_heads[0].stream_position, 10);
    assert_ne!(second.snapshot_id, first.snapshot_id);
    assert_eq!(issuance_count(&pool, &realm_id).await, 2);
    // A cut carrying a message row is re-provable by reference.
    assert_eq!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            second.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap(),
        Some(second.clone()),
    );
    assert_eq!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            first.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap(),
        Some(first.clone()),
    );
    // The Realm-wide anchor ignores Account-issued disclosures.
    assert_eq!(store.latest_snapshot(&realm_id).await.unwrap(), None);

    // Read-time recheck: once the Account's membership revision changes,
    // neither exact object is disclosable, and restoring it re-admits them.
    let mut conn = pool.get().await.unwrap();
    let member = arkret_wire::ActorId::account(creator.clone()).to_string();
    diesel::sql_query(
        "UPDATE member_state_current_results SET membership='leave', \
         value='{\"membership\":\"leave\"}'::jsonb WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&member)
    .execute(&mut conn)
    .await
    .unwrap();
    for id in [&first.snapshot_id, &second.snapshot_id] {
        assert!(matches!(
            by_ref(
                creator.clone(),
                realm_id.clone(),
                id.clone(),
                issuer.clone()
            )
            .await,
            Err(coland_storage::PersistenceError::SchemaViolation(_))
        ));
    }
    diesel::sql_query(
        "UPDATE member_state_current_results SET membership='join', \
         value='{\"membership\":\"join\"}'::jsonb WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&member)
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            second.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .unwrap()
        .is_some()
    );

    // Once another Station governs the Realm, this Station can neither
    // re-prove the earlier object nor issue a new one.
    diesel::sql_query("UPDATE realm_authorities SET service_id=$2 WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(other_station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        by_ref(
            creator.clone(),
            realm_id.clone(),
            second.snapshot_id.clone(),
            issuer.clone()
        )
        .await
        .is_err()
    );
    assert!(
        store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
            .await
            .is_err()
    );
    assert_eq!(issuance_count(&pool, &realm_id).await, 2);
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn authority_root_count(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count
}

async fn bootstrap_singleton_count(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM realm_bootstrap_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count
}

async fn source_outbox_count(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT COUNT(*) AS count FROM event_federation_outbox o \
         JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count
}

fn event(
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor: &arkret_wire::DidCoreId,
    station: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        scope_ref,
        actor.clone(),
        station.clone(),
        payload,
        at,
    )
    .unwrap();
    let accepted = human_profile::fixture(station, "bootstrap-actor");
    if accepted.history.account.principal_id == *actor {
        return device_authorization_history::sign_event(
            event,
            accepted.history.device_verification_method,
            accepted.history.founding_device_signing_seed,
        );
    }
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new("did:web:bootstrap-actor.example#key")
            .unwrap(),
        event_digest: digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

fn rebind_authorization_ref(
    request: &mut EventCommitRequest,
    authorization_event_id: &arkret_wire::EventId,
) {
    let event = &mut request.authority_commit.event;
    event.authorization_ref = Some(arkret_wire::AuthorizationRef::from(
        authorization_event_id.clone(),
    ));
    let preimage =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    event.event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(&preimage),
    );
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let proof = event.producer_proof.as_mut().unwrap();
    proof.event_digest = digest.clone();
    proof.jws = arkret_wire::test_support::structural_only_detached_jws(&digest);
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("message:{}", event.event_id).as_bytes()),
    );
    request.event.event_id = event.event_id.to_string();
    request.event.envelope = serde_json::to_value(&*event).unwrap();
    request.event.canonical_bytes = preimage;
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    let material = human_profile::fixture(
        &request.authority_commit.expected_authority.service_id,
        "bootstrap-actor",
    );
    request.authority_commit.event = device_authorization_history::sign_event(
        request.authority_commit.event.clone(),
        material.history.device_verification_method,
        material.history.founding_device_signing_seed,
    );
    request.event.envelope = serde_json::to_value(&request.authority_commit.event).unwrap();
    *request = seal_request_fact(request.clone());
}

fn signature(
    station: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    let did = station.as_str().replace("ak:did_core:", "did:");
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(format!("{did}#authority")).unwrap(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at: at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

fn legacy_unit() -> OrdinaryRealmBootstrapCommitUnit {
    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let actor = human_profile::account(&station, "bootstrap-actor").principal_id;
    let genesis = event(
        arkret_wire::EventKind::RealmCreate,
        arkret_wire::ScopeRef::RealmGenesis,
        &actor,
        &station,
        serde_json::json!({"object":{
            "schema":"ak.schema.realm_genesis.v1",
            "purpose":"collaboration",
            "genesis_salt":"X-kS8-uBvWQ_iuRqO7Rsv0WGBjZG2S2wJ533Tk2SJJ4",
            "trust_domain":"ak:trust_domain:bootstrap.example",
            "security_class":"high_assurance",
            "governance_station_id":station,
            "initial_join_rule":"invite",
            "initial_history_access":"since_join",
            "initial_discoverability":"invite_only"
        }}),
        at,
    );
    let realm_id = genesis.realm_id.clone();
    let mut events = vec![genesis];
    let creator = events[0].actor_id.clone();
    for kind in [
        arkret_wire::EventKind::RealmProfile,
        arkret_wire::EventKind::RealmPolicyBundle,
        arkret_wire::EventKind::RealmJoinRule,
        arkret_wire::EventKind::RealmHistoryAccess,
        arkret_wire::EventKind::RealmDiscovery,
        arkret_wire::EventKind::MemberState,
    ]
    .into_iter()
    {
        let payload = match kind {
            arkret_wire::EventKind::RealmProfile => {
                serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Test Realm"})
            }
            arkret_wire::EventKind::RealmPolicyBundle => {
                serde_json::json!({"policy_revision":1,"federation_policy":"closed"})
            }
            arkret_wire::EventKind::RealmJoinRule => serde_json::json!({"value":"invite"}),
            arkret_wire::EventKind::RealmHistoryAccess => {
                serde_json::json!({"from":null,"to":"since_join"})
            }
            arkret_wire::EventKind::RealmDiscovery => {
                serde_json::json!({"value":{"discoverability":"invite_only"}})
            }
            arkret_wire::EventKind::MemberState => {
                serde_json::json!({"member_id":creator,"membership":"join"})
            }
            _ => unreachable!(),
        };
        events.push(event(
            kind,
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            &actor,
            &station,
            payload,
            at,
        ));
    }
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: station.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            events[0].event_id.clone(),
        ),
        last_handoff_ref: None,
    };
    let mut previous = None;
    let transactions = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let commit_id = arkret_wire::RealmCommitId::from_digest(
                arkret_canonical::sha256_bytes(format!("{}:{index}", event.event_id).as_bytes()),
            );
            let transaction = AuthorityCommitTransaction {
                expected_authority: authority.clone(),
                event: event.clone(),
                commit: arkret_wire::RealmCommit {
                    producer_signer_fact_digest: None,
                    commit_id: commit_id.clone(),
                    realm_id: realm_id.clone(),
                    stream_ref: arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                    stream_position: index as u64,
                    previous_commit_ref: previous.clone(),
                    event_ref: event.event_id.clone(),
                    governance_generation: 0,
                    authority_ref: authority.authority_ref.clone(),
                    committed_at: at,
                    signature: signature(&station, at),
                },
                producer_signer_fact: None,
                mls_state: None,
                welcomes: Vec::new(),
                recipient_queue_capacity: 0,
            };
            previous = Some(commit_id);
            transaction
        })
        .collect();
    let submission = OrdinaryRealmBootstrapUnitSubmission {
        unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
        events: events
            .into_iter()
            .map(arkret_wire::EventAdmissionSubmission::new)
            .collect(),
    };
    let exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone()),
    )
    .unwrap();
    OrdinaryRealmBootstrapCommitUnit {
        event_approvals: Vec::new(),
        submission,
        exact_request_body,
        transactions,
    }
}

fn legacy_unit_with_plaintext_service() -> OrdinaryRealmBootstrapCommitUnit {
    let mut unit = legacy_unit();
    let first = &unit.transactions[0];
    let realm_id = first.event.realm_id.clone();
    let account = first.event.actor_id.as_account_id().unwrap();
    let station = first.expected_authority.service_id.clone();
    let at = first.commit.committed_at;
    let event = event(
        arkret_wire::EventKind::RealmPlaintextVisibleServices,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &account.principal_id,
        &station,
        serde_json::json!({"services":[{
            "service_id":station,
            "service_kind":"station",
            "data_classes":["message_content"],
            "purposes":["test"],
            "visibility":"private_plaintext"
        }]}),
        at,
    );
    let mut transaction = unit.transactions[6].clone();
    transaction.event = event.clone();
    transaction.commit.event_ref = event.event_id.clone();
    transaction.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("plaintext:{}", event.event_id).as_bytes()),
    );
    transaction.commit.previous_commit_ref = Some(unit.transactions[5].commit.commit_id.clone());
    unit.transactions[6].commit.stream_position = 7;
    unit.transactions[6].commit.previous_commit_ref = Some(transaction.commit.commit_id.clone());
    unit.transactions.insert(6, transaction);
    unit.submission
        .events
        .insert(6, arkret_wire::EventAdmissionSubmission::new(event));
    unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone()),
    )
    .unwrap();
    unit
}

fn strand_create_request(unit: &OrdinaryRealmBootstrapCommitUnit) -> EventCommitRequest {
    let previous = unit.transactions.last().unwrap();
    let realm_id = previous.event.realm_id.clone();
    let actor = previous.event.actor_id.clone();
    let station = previous.expected_authority.service_id.clone();
    let principal = actor.as_account_id().unwrap().principal_id.clone();
    let at = previous.commit.committed_at;
    let event = event(
        arkret_wire::EventKind::StrandCreate,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &principal,
        &station,
        serde_json::json!({"object": {
            "schema":"ak.schema.strand.v1",
            "realm_id":realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Restart test"},
            "state":"active",
            "created_by":actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at),
        }}),
        at,
    );
    let commit = arkret_wire::RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("strand:{}", event.event_id).as_bytes(),
        )),
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        stream_position: previous.commit.stream_position + 1,
        previous_commit_ref: Some(previous.commit.commit_id.clone()),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: previous.expected_authority.authority_ref.clone(),
        committed_at: at,
        signature: signature(&station, at),
    };
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    let canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let envelope = serde_json::to_value(&event).unwrap();
    let projection = coland_storage::ProjectionEventRecord {
        event_id: event.event_id.to_string(),
        realm_id: realm_id.to_string(),
        event_kind: event.kind.as_str().to_owned(),
        operation_kind: "create".to_owned(),
        operation_id: None,
        sender: Some(event.actor_id.to_string()),
        payload: serde_json::to_value(&event.payload).unwrap(),
        created_at: event.created_at,
        received_at: at,
    };
    let record = coland_storage::CanonicalEventRecord {
        event_id: event.event_id.to_string(),
        actor_id: event.actor_id.to_string(),
        realm_id: Some(realm_id.to_string()),
        kind: event.kind.as_str().to_owned(),
        schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
        digest_suite: arkret_canonical::DigestSuite::Sha256,
        canonical_digest,
        canonical_bytes,
        envelope,
        received_at: at,
    };
    let request = EventCommitRequest {
        authority_commit: AuthorityCommitTransaction {
            expected_authority: previous.expected_authority.clone(),
            event,
            commit,
            producer_signer_fact: previous.producer_signer_fact.clone(),
            mls_state: None,
            welcomes: Vec::new(),
            recipient_queue_capacity: 0,
        },
        self_producer_guard: None,
        applet_producer_guard: None,
        widget_token_gate: None,
        agent_grant_scope_evidence: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        event: record,
        parent_membership_admission: None,
        contact_projection: None,

        device_revocation_transition: None,
        device_revocation_gate: None,
        projections: vec![projection],
        idempotency: None,
        outbox: Vec::new(),
        realm_fanout_source: None,
    };
    seal_request_fact(request)
}

fn set_default_strand_request(
    previous: &EventCommitRequest,
    strand_id: &arkret_wire::StrandId,
    expected: Option<&arkret_wire::StrandId>,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let previous_event = &previous.authority_commit.event;
    let realm_id = previous_event.realm_id.clone();
    let actor = previous_event.actor_id.as_account_id().unwrap();
    let event = event(
        arkret_wire::EventKind::RealmSetDefaultStrand,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &actor.principal_id,
        &actor.station_id,
        serde_json::json!({
            "realm_id": realm_id,
            "strand_id": strand_id,
            "expected_default_strand_id": expected,
        }),
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("default:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.event.event_id = event.event_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    seal_request_fact(request)
}

fn message_create_request(
    previous: &EventCommitRequest,
    strand_id: &arkret_wire::StrandId,
    body: &str,
) -> EventCommitRequest {
    message_create_request_with_format(previous, strand_id, body, "plain")
}

fn message_create_request_with_format(
    previous: &EventCommitRequest,
    strand_id: &arkret_wire::StrandId,
    body: &str,
    format: &str,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let previous_event = &previous.authority_commit.event;
    let realm_id = previous_event.realm_id.clone();
    let actor = previous_event.actor_id.as_account_id().unwrap();
    let event = event(
        arkret_wire::EventKind::MessageCreate,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        &actor.principal_id,
        &actor.station_id,
        serde_json::json!({
            "strand_id":strand_id,
            "track_name":"discussion",
            "content":{"kind":"ak.content.text","body":body,"format":format}
        }),
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("message:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.event.event_id = event.event_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    seal_request_fact(request)
}

#[tokio::test]
async fn ordinary_bootstrap_failure_rolls_back_every_event_then_exact_replay_returns_same_commits()
{
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    unit.validate().unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let first_event_id = unit.transactions[0].event.event_id.clone();
    let at = unit.transactions[0].commit.committed_at;

    let producer = unit.transactions[0].event.actor_id.as_account_id().unwrap();
    let first_commit = &unit.transactions[0].commit;
    let unaccepted_guard =
        SelfProducerCommitGuard::HumanDevice(coland_storage::DeviceRevocationGateSelector {
            principal_id: producer.principal_id.clone(),
            station_id: producer.station_id.clone(),
            device_id: "key".to_owned(),
            authorization_ref: arkret_wire::CommittedEventRef {
                event_id: first_event_id.clone(),
                commit_id: first_commit.commit_id.clone(),
                stream_ref: first_commit.stream_ref.clone(),
                stream_position: first_commit.stream_position,
            },
        });
    assert!(
        store
            .admit_self_ordinary_realm_bootstrap_unit(&unit, &[], at)
            .await
            .is_err()
    );
    assert!(
        store
            .admit_self_ordinary_realm_bootstrap_unit(
                &unit,
                &vec![unaccepted_guard; unit.transactions.len()],
                at,
            )
            .await
            .is_err()
    );
    assert!(store.current_authority(&realm_id).await.unwrap().is_none());
    assert_eq!(authority_root_count(&pool, &realm_id).await, 0);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 0);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);

    let mut failing = unit.clone();
    failing.transactions[1].commit.signature.verification_method =
        arkret_wire::DidUrl::new("did:web:wrong-station.example#authority").unwrap();
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&failing, at)
            .await
            .is_err()
    );
    assert!(store.current_authority(&realm_id).await.unwrap().is_none());
    assert_eq!(authority_root_count(&pool, &realm_id).await, 0);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 0);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
    assert!(
        store
            .realm_state_snapshot_material(&realm_id)
            .await
            .unwrap()
            .is_none()
    );
    for transaction in &unit.transactions {
        assert!(
            store
                .queued_event(&transaction.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .committed_event(&transaction.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    let accepted = store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let OrdinaryRealmBootstrapCommitOutcome::Committed(commits) = accepted else {
        panic!("first unit must commit");
    };
    assert_eq!(commits.len(), 7);
    for (position, commit) in commits.iter().enumerate() {
        assert_eq!(commit.stream_position, position as u64);
        assert_eq!(
            commit.previous_commit_ref.as_ref(),
            position
                .checked_sub(1)
                .map(|previous| &commits[previous].commit_id)
        );
    }
    assert_eq!(authority_root_count(&pool, &realm_id).await, 1);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 5);
    // The only member of this closed founding unit is the creator, whose
    // AccountId names the governing Station. The remote target set is empty.
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
    let snapshot = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.current_state_entries.len(), 8);
    assert_eq!(
        snapshot.retention_and_history_floor.history_access,
        arkret_wire::HistoryAccess::SinceJoin
    );
    for selector in [
        arkret_wire::CurrentSelector::RealmGenesis,
        arkret_wire::CurrentSelector::RealmAuthorityRoot,
        arkret_wire::CurrentSelector::RealmProfile,
        arkret_wire::CurrentSelector::RealmPolicyBundle,
        arkret_wire::CurrentSelector::RealmJoinRule,
        arkret_wire::CurrentSelector::RealmHistoryAccess,
        arkret_wire::CurrentSelector::RealmDiscovery,
        arkret_wire::CurrentSelector::MemberState {
            actor_id: unit.transactions[0].event.actor_id.clone(),
        },
    ] {
        assert!(snapshot.current_state_entries.iter().any(|entry| {
            matches!(entry, arkret_wire::TypedCurrentRow::Value { selector: found, .. } if found == &selector)
        }));
    }
    assert!(
        store
            .committed_event(&first_event_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits),
    );
    let mut changed = unit;
    changed.exact_request_body.push(b' ');
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&changed, at)
            .await
            .is_err()
    );
    assert_eq!(authority_root_count(&pool, &realm_id).await, 1);
    assert_eq!(bootstrap_singleton_count(&pool, &realm_id).await, 5);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
}

#[tokio::test]
async fn confirmed_bootstrap_recovers_after_postcommit_projection_install_is_lost() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0].event.actor_id.clone();
    let at = unit.transactions[0].commit.committed_at;

    // Simulate a process failure in the postcommit window: the authority
    // transaction is durable, but no process-local projection is installed.
    assert!(matches!(
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Committed(_)
    ));
    let fresh_process = ProjectionService::new("bootstrap-restart-test");
    assert!(
        fresh_process
            .snapshot()
            .realm_create_log(realm_id.as_str())
            .is_none()
    );

    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    fresh_process
        .hydrate_from_persistence(&persistence, &BootstrapHydrationAdapter, [realm_id.clone()])
        .await
        .unwrap();
    let restored = fresh_process.snapshot();
    assert_eq!(
        restored.realm_create_log(realm_id.as_str()).unwrap().len(),
        1
    );
    assert_eq!(
        restored.realm_profile_value(realm_id.as_str()),
        Some(&serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Test Realm"}))
    );
    assert_eq!(
        restored.realm_policy_bundle_value(realm_id.as_str()),
        Some(&serde_json::json!({"policy_revision":1,"federation_policy":"closed"}))
    );
    assert_eq!(
        restored.realm_default_join_rule(realm_id.as_str()),
        "invite"
    );
    assert_eq!(
        restored.realm_history_access(realm_id.as_str()).as_deref(),
        Some("since_join")
    );
    assert!(
        restored
            .member(realm_id.as_str(), &creator.to_string())
            .is_some()
    );
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);

    // Rebuilding a second process from the same Commit prefix must be exact.
    let second_process = ProjectionService::new("bootstrap-second-restart-test");
    second_process
        .hydrate_from_persistence(&persistence, &BootstrapHydrationAdapter, [realm_id.clone()])
        .await
        .unwrap();
    let second = second_process.snapshot();
    assert_eq!(
        second.realm_create_log(realm_id.as_str()),
        restored.realm_create_log(realm_id.as_str())
    );
    assert_eq!(
        second.realm_profile_value(realm_id.as_str()),
        restored.realm_profile_value(realm_id.as_str())
    );
    assert_eq!(
        second.realm_history_access(realm_id.as_str()),
        restored.realm_history_access(realm_id.as_str())
    );
}

#[tokio::test]
async fn strand_create_writes_registered_current_result_and_rejects_remote_unplanned_target() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let bootstrap_store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    bootstrap_store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let request = strand_create_request(&unit);
    let strand_id = arkret_wire::StrandId::from_event_id(&request.authority_commit.event.event_id);
    let outcome = uow.commit_event(request.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 0);
    let snapshot = bootstrap_store
        .realm_state_snapshot_material(&unit.transactions[0].event.realm_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| {
        matches!(entry, arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Strand { strand_id: found },
            source_stream_ref,
            revision,
            value,
        } if found == &strand_id
            && source_stream_ref == &request.authority_commit.commit.stream_ref
            && revision.commit_id == request.authority_commit.commit.commit_id
            && value.get("id") == Some(&serde_json::json!(strand_id))
            && value.get("state") == Some(&serde_json::json!("active")))
    }));
    assert_eq!(
        source_outbox_count(&pool, &unit.transactions[0].event.realm_id).await,
        0
    );
    let restarted = ProjectionService::new("strand-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [unit.transactions[0].event.realm_id.clone()],
        )
        .await
        .unwrap();
    assert!(
        restarted
            .snapshot()
            .strands
            .contains_key(strand_id.as_str())
    );

    // A confirmed remote joined member makes an empty source target set
    // false. Inject that current row at a valid RealmCommit basis, then prove
    // the next Strand Event/Commit/current result all roll back together.
    let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:remote.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(unit.transactions[0].event.realm_id.as_str())
    .bind::<Text, _>(serde_json::to_string(&remote).unwrap())
    .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
    .bind::<BigInt, _>(unit.transactions[6].commit.stream_position as i64)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<diesel::sql_types::Timestamptz, _>(at)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let mut denied = strand_create_request(&unit);
    // Rebuild the Event from a distinct valid create payload instead of
    // mutating a signed transcript: a new title yields a new Event-derived id.
    let mut object = serde_json::to_value(&denied.authority_commit.event.payload).unwrap();
    object["object"]["metadata"]["title"] = serde_json::json!("Denied Strand");
    denied.authority_commit.event = event(
        arkret_wire::EventKind::StrandCreate,
        arkret_wire::ScopeRef::Realm {
            realm_id: unit.transactions[0].event.realm_id.clone(),
        },
        &unit.transactions[0]
            .event
            .actor_id
            .as_account_id()
            .unwrap()
            .principal_id,
        &unit.transactions[0].expected_authority.service_id,
        object,
        at,
    );
    denied.authority_commit.commit.event_ref = denied.authority_commit.event.event_id.clone();
    denied.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(denied.authority_commit.event.event_id.as_str().as_bytes()),
    );
    denied.authority_commit.commit.previous_commit_ref =
        Some(request.authority_commit.commit.commit_id.clone());
    denied.authority_commit.commit.stream_position += 1;
    denied.event.event_id = denied.authority_commit.event.event_id.to_string();
    denied.event.envelope = serde_json::to_value(&denied.authority_commit.event).unwrap();
    denied.event.canonical_bytes = arkret_canonical::canonical_json_bytes(
        &denied.authority_commit.event.digest_payload().unwrap(),
    )
    .unwrap();
    denied.event.canonical_digest = denied
        .authority_commit
        .event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    denied.projections[0].event_id = denied.authority_commit.event.event_id.to_string();
    denied.projections[0].payload =
        serde_json::to_value(&denied.authority_commit.event.payload).unwrap();
    assert!(uow.commit_event(denied.clone()).await.is_err());
    assert!(
        bootstrap_store
            .committed_event(&denied.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let snapshot = bootstrap_store
        .realm_state_snapshot_material(&unit.transactions[0].event.realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot
            .current_state_entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::Strand { .. },
                        ..
                    }
                )
            })
            .count(),
        1
    );
}

#[tokio::test]
async fn default_strand_writes_exact_current_at_commit_and_rejects_dangling_and_stale_pointer() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let missing = arkret_wire::StrandId::from_event_id(&unit.transactions[0].event.event_id);
    let dangling = set_default_strand_request(&strand, &missing, None);
    assert!(uow.commit_event(dangling.clone()).await.is_err());
    assert!(
        store
            .committed_event(&dangling.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let request = set_default_strand_request(&strand, &strand_id, None);
    let outcome = uow.commit_event(request.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 0);
    let realm_id = &unit.transactions[0].event.realm_id;
    let snapshot = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| {
        matches!(entry, arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::RealmSetDefaultStrand,
            source_stream_ref,
            revision,
            value,
        } if source_stream_ref == &request.authority_commit.commit.stream_ref
            && revision.commit_id == request.authority_commit.commit.commit_id
            && value == &serde_json::json!({"default_strand_id": strand_id}))
    }));
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);
    let restarted = ProjectionService::new("default-strand-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap();
    assert_eq!(
        restarted
            .snapshot()
            .realm_states
            .get(realm_id.as_str())
            .and_then(|realm| realm.default_strand_id.as_deref()),
        Some(strand_id.as_str())
    );

    let stale = set_default_strand_request(&request, &strand_id, Some(&missing));
    assert!(uow.commit_event(stale.clone()).await.is_err());
    assert!(
        store
            .committed_event(&stale.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let snapshot_after = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.current_state_entries,
        snapshot_after.current_state_entries
    );
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);

    // Replica snapshots can retain unrelated typed rows before the local
    // history floor. Default-pointer hydration needs only its own source cut.
    let absent_commit = arkret_wire::RealmCommitId::from_digest([0xee; 32]);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE member_state_current_results SET current_commit_id=$2 WHERE realm_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(realm_id.as_str())
    .bind::<diesel::sql_types::Text, _>(absent_commit.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    assert!(store.realm_state_snapshot_material(realm_id).await.is_err());
    let restarted = ProjectionService::new("default-strand-isolated-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap();
    assert_eq!(
        restarted.snapshot().realm_states[realm_id.as_str()]
            .default_strand_id
            .as_deref(),
        Some(strand_id.as_str())
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_set_default_strand_current_results SET current_commit_id=$2 WHERE realm_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(realm_id.as_str())
    .bind::<diesel::sql_types::Text, _>(absent_commit.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    drop(conn);
    assert!(store.realm_default_strand_current(realm_id).await.is_err());
}

#[derive(diesel::QueryableByName, Debug, PartialEq)]
struct AccountSummaryCurrentRow {
    #[diesel(sql_type = Text)]
    actor_key: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    membership: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    default_strand_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    available: bool,
}

async fn account_summary_current(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> Vec<AccountSummaryCurrentRow> {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT actor_key,revision,membership,title,default_strand_id,available \
         FROM account_summary_current WHERE realm_id=$1 ORDER BY actor_key",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<AccountSummaryCurrentRow>(&mut *conn)
    .await
    .unwrap()
}

async fn account_summary_version_count(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM account_summary_versions WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// The creator's account summary is derived from the typed current rows in
/// the same transaction as the Commits that establish them: the bootstrap
/// unit yields membership and title, `ak.realm.set_default_strand` a new
/// revision with the default Strand, and a failed Commit leaves no summary.
#[tokio::test]
async fn account_summary_follows_bootstrap_and_default_strand_in_the_commit_transaction() {
    use coland_storage::SyncCursorStore as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cursors = coland_storage_postgres::PgSyncCursorStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0].event.actor_id.canonical_key().unwrap();
    let at = unit.transactions[0].commit.committed_at;

    let mut failing = unit.clone();
    failing.transactions[1].commit.signature.verification_method =
        arkret_wire::DidUrl::new("did:web:wrong-station.example#authority").unwrap();
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&failing, at)
            .await
            .is_err()
    );
    assert!(account_summary_current(&pool, &realm_id).await.is_empty());
    assert_eq!(account_summary_version_count(&pool, &realm_id).await, 0);

    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let bootstrapped = account_summary_current(&pool, &realm_id).await;
    assert_eq!(bootstrapped.len(), 1);
    let founding_revision = bootstrapped[0].revision;
    assert_eq!(
        bootstrapped[0],
        AccountSummaryCurrentRow {
            actor_key: creator.clone(),
            revision: founding_revision,
            membership: Some("join".to_owned()),
            title: Some("Test Realm".to_owned()),
            default_strand_id: None,
            available: true,
        }
    );
    assert_eq!(account_summary_version_count(&pool, &realm_id).await, 1);
    assert_eq!(
        cursors.account_summary_watermark().await.unwrap(),
        founding_revision
    );

    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    assert_eq!(
        account_summary_current(&pool, &realm_id).await,
        bootstrapped
    );

    let missing = arkret_wire::StrandId::from_event_id(&unit.transactions[0].event.event_id);
    let dangling = set_default_strand_request(&strand, &missing, None);
    assert!(uow.commit_event(dangling).await.is_err());
    assert_eq!(
        account_summary_current(&pool, &realm_id).await,
        bootstrapped
    );
    assert_eq!(account_summary_version_count(&pool, &realm_id).await, 1);

    uow.commit_event(set_default_strand_request(&strand, &strand_id, None))
        .await
        .unwrap();
    let pointed = account_summary_current(&pool, &realm_id).await;
    assert_eq!(pointed.len(), 1);
    assert!(pointed[0].revision > founding_revision);
    assert_eq!(pointed[0].title.as_deref(), Some("Test Realm"));
    assert_eq!(
        pointed[0].default_strand_id.as_deref(),
        Some(strand_id.as_str())
    );
    assert_eq!(account_summary_version_count(&pool, &realm_id).await, 2);

    let changes = cursors
        .account_summary_changes(&creator, founding_revision, 10)
        .await
        .unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].key.realm_id, realm_id.as_str());
    assert_eq!(changes[0].key.revision, pointed[0].revision);
    assert_eq!(changes[0].membership.as_deref(), Some("join"));
    assert_eq!(
        changes[0].default_strand_id.as_deref(),
        Some(strand_id.as_str())
    );
    assert_eq!(changes[0].current_membership.as_deref(), Some("join"));
    assert!(changes[0].current_available);
    assert!(!changes[0].invalidated);
    let page = cursors
        .account_summary_page(&creator, pointed[0].revision, None, 10)
        .await
        .unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].key.revision, pointed[0].revision);
    assert_eq!(page[1].valid_until, Some(pointed[0].revision));
}

#[tokio::test]
async fn local_markdown_text_message_writes_exact_revision_and_rejects_missing_strand() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    // PG authoring uses the internal structural TCB boundary here. A display
    // Profile is optional and supplies no producer authentication evidence.
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    unit.validate().unwrap();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();

    let missing = arkret_wire::StrandId::from_event_id(&unit.transactions[0].event.event_id);
    let denied = message_create_request(&default, &missing, "missing target");
    assert!(uow.commit_event(denied.clone()).await.is_err());
    assert!(
        store
            .committed_event(&denied.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let mut wrong_ref = message_create_request(&default, &strand_id, "wrong authorization ref");
    rebind_authorization_ref(&mut wrong_ref, &unit.transactions[6].event.event_id);
    assert!(uow.commit_event(wrong_ref.clone()).await.is_err());
    assert!(
        store
            .committed_event(&wrong_ref.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let request = message_create_request_with_format(&default, &strand_id, "hello", "markdown");
    let outcome = uow.commit_event(request.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.projections_inserted, 1);
    assert_eq!(outcome.outbox_inserted, 0);
    let message_id =
        arkret_wire::MessageId::from_event_id(&request.authority_commit.event.event_id);
    let realm_id = &unit.transactions[0].event.realm_id;
    let snapshot = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.current_state_entries.iter().any(|entry| {
        matches!(entry, arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::MessageRevision { message_id: found },
            source_stream_ref,
            revision,
            value,
        } if found == &message_id
            && source_stream_ref == &request.authority_commit.commit.stream_ref
            && revision.commit_id == request.authority_commit.commit.commit_id
            && value == &serde_json::to_value(&request.authority_commit.event.payload).unwrap())
    }));
    let restarted = ProjectionService::new("message-current-restart-test");
    restarted
        .hydrate_from_persistence(
            &coland_storage_postgres::PgPersistenceStore::new(pool.clone()),
            &BootstrapHydrationAdapter,
            [realm_id.clone()],
        )
        .await
        .unwrap();
    assert!(
        restarted
            .snapshot()
            .messages
            .contains_key(request.authority_commit.event.event_id.as_str())
    );
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);

    // A remote joined account whose Station is no private plaintext service
    // of the Realm may not hold a plaintext body: the next Message commits
    // and owes that Station nothing.
    let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:message-remote.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:message-remote-station.example").unwrap(),
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(remote.to_string())
    .bind::<Text, _>(unit.transactions.last().unwrap().commit.commit_id.as_str())
    .bind::<BigInt, _>(unit.transactions.last().unwrap().commit.stream_position as i64)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<diesel::sql_types::Timestamptz, _>(unit.transactions[0].commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let unowed = message_create_request(&request, &strand_id, "remote unowed");
    let outcome = uow.commit_event(unowed.clone()).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 0);
    assert!(
        store
            .committed_event(&unowed.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_some()
    );
    let snapshot_after = store
        .realm_state_snapshot_material(realm_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot_after
            .current_state_entries
            .iter()
            .filter(|entry| matches!(
                entry,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                    ..
                }
            ))
            .count(),
        2
    );
    assert_eq!(source_outbox_count(&pool, realm_id).await, 0);

    // A current row whose covering Commit vanished cannot silently disappear
    // from a snapshot (an INNER JOIN previously caused that data loss).
    let nonexistent = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        b"missing-message-covering-commit",
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE message_revision_current_results SET current_commit_id=$1 WHERE message_id=$2",
    )
    .bind::<Text, _>(nonexistent.as_str())
    .bind::<Text, _>(message_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(store.realm_state_snapshot_material(realm_id).await.is_err());
}

/// Real PostgreSQL: a handoff that rewrites the governing row while `/head`
/// waits on its share lock aborts the issuance cut with SQLSTATE 40001. It
/// must surface as the registered retryable `temporarily_unavailable` conflict
/// with nothing archived, never as an unclassified database fault.
#[tokio::test]
async fn snapshot_issuance_racing_a_handoff_is_retryable_unavailability() {
    use diesel_async::SimpleAsyncConnection as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;

    // The competing handoff holds the governing row before issuance starts.
    let mut handoff = pool.get().await.unwrap();
    handoff
        .batch_execute(&format!(
            "BEGIN; UPDATE realm_authorities SET service_id='ak:did_core:web:successor.example', \
             updated_at=now() WHERE realm_id='{}'",
            realm_id.as_str()
        ))
        .await
        .unwrap();

    let racing = tokio::spawn({
        let pool = pool.clone();
        let realm_id = realm_id.clone();
        let creator = creator.clone();
        let issuer = issuer.clone();
        async move {
            let store = PgAuthorityCommitStore { pool };
            let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
            let method = arkret_wire::DidUrl::new("did:web:station.example#notary-key").unwrap();
            let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
                coland_services::authority_commit::build_signed_realm_state_snapshot(
                    material,
                    method.clone(),
                    &key,
                    chrono::Utc::now(),
                )
                .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
            };
            store
                .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
                .await
        }
    });

    // Commit the handoff only once issuance is provably parked on the lock.
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type = BigInt)]
        waiting: i64,
    }
    let mut probe = pool.get().await.unwrap();
    let mut parked = false;
    for _ in 0..200 {
        let waiting = diesel::sql_query(
            "SELECT count(*) AS waiting FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock' \
               AND query LIKE '%FROM realm_authorities%FOR SHARE%'",
        )
        .get_result::<Waiting>(&mut probe)
        .await
        .unwrap()
        .waiting;
        if waiting == 1 {
            parked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(parked, "issuance never waited on the governing row lock");
    handoff.batch_execute("COMMIT").await.unwrap();

    let error = racing.await.unwrap().unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        "{error}"
    );
    assert_eq!(issuance_count(&pool, &realm_id).await, 0);
}

async fn reservation_count(pool: &coland_storage_postgres::PgPool) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM realm_state_snapshot_window_reservations")
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

/// Real PostgreSQL, decision 0101: an Account window over the Realm stream
/// names a `window_start_basis` only when an exact snapshot already issued to
/// that Account sits at its anchor and is reserved for the window's
/// consumable period; otherwise a limited stream is `preview_only`. The
/// reservation keeps the by-ref read alive through retention GC, and losing
/// the guarantee (disclosure or expiry) withdraws the basis.
#[tokio::test]
async fn account_window_basis_reserves_exact_issued_snapshot_or_is_preview_only() {
    use coland_storage::{AccountRealmWindowRequest, SyncCursorStore as _};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cursors = coland_storage_postgres::PgSyncCursorStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_ttl = 300_000;
    let request = |account: &arkret_wire::AccountId, limit: u32| AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: account.clone(),
        issuer: issuer.clone(),
        window_limit: limit,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + window_ttl,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_heads: Vec::new(),
        selected_stream_refs: None,
    };
    let positions = |window: &coland_storage::AccountRealmWindow| {
        window
            .committed_events
            .iter()
            .map(|view| match view {
                arkret_wire::CommittedEventView::Full(full) => full.commit.stream_position,
                arkret_wire::CommittedEventView::Withheld(_) => panic!("withheld window row"),
            })
            .collect::<Vec<_>>()
    };

    // Whole readable history fits: not limited, so no basis is needed.
    let full = store
        .freeze_account_realm_window(&request(&creator, 10), &sign)
        .await
        .unwrap()
        .unwrap();
    assert!(!full.window.limited && full.window.complete);
    assert_eq!(full.window.preview_only, None);
    assert!(full.window.window_start_basis.is_none());
    assert_eq!(positions(&full), (0..=6).collect::<Vec<_>>());
    assert_eq!(full.window.next_position, 7);
    assert_eq!(
        full.window.head_commit_ref,
        unit.transactions[6].commit.commit_id
    );

    // Limited, and no snapshot was ever issued at the anchor.
    let unbacked = store
        .freeze_account_realm_window(&request(&creator, 2), &sign)
        .await
        .unwrap()
        .unwrap();
    assert!(unbacked.window.limited);
    assert_eq!(unbacked.window.preview_only, Some(true));
    assert!(unbacked.window.window_start_basis.is_none());
    assert_eq!(positions(&unbacked), vec![5, 6]);

    // `/head` at position 6, then two more Commits.
    let at_six = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    uow.commit_event(set_default_strand_request(&strand, &strand_id, None))
        .await
        .unwrap();

    // Another Account can neither freeze nor be handed the creator's object.
    assert!(
        store
            .freeze_account_realm_window(&request(&stranger, 2), &sign)
            .await
            .is_err()
    );

    let backed_request = request(&creator, 2);
    let backed = store
        .freeze_account_realm_window(&backed_request, &sign)
        .await
        .unwrap()
        .unwrap();
    assert!(backed.window.limited && backed.window.complete);
    assert_eq!(backed.window.preview_only, None);
    assert_eq!(positions(&backed), vec![7, 8]);
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(basis.anchor_position, 6);
    assert_eq!(
        basis.anchor_commit_ref,
        unit.transactions[6].commit.commit_id
    );
    assert_eq!(basis.snapshot_ref, at_six.snapshot_id);
    assert_eq!(basis.governance_generation, 0);
    assert!(basis.accepted_dependency_refs.is_none());
    assert_eq!(reservation_count(&pool).await, 1);

    // The anchor must be exact: position 7 has no issued snapshot.
    let off_by_one = store
        .freeze_account_realm_window(&request(&creator, 1), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(off_by_one.window.preview_only, Some(true));
    assert!(off_by_one.window.window_start_basis.is_none());
    assert_eq!(reservation_count(&pool).await, 1);

    // The reserved basis is re-readable for the window only.
    let reread = |cursor: String, at: i64| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, stream_ref, issuer) = (
            realm_id.clone(),
            creator.clone(),
            stream_ref.clone(),
            issuer.clone(),
        );
        async move {
            store
                .account_window_basis(&realm_id, &creator, &cursor, &stream_ref, &issuer, at)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms).await,
        Some(basis.clone())
    );
    assert_eq!(
        reread(
            format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
            now_ms
        )
        .await,
        None
    );
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms + window_ttl).await,
        None
    );

    // Losing disclosure withdraws the guarantee; restoring it re-admits it.
    let mut conn = pool.get().await.unwrap();
    let member = arkret_wire::ActorId::account(creator.clone()).to_string();
    for membership in ["leave", "join"] {
        diesel::sql_query(
            "UPDATE member_state_current_results SET membership=$3, \
             value=jsonb_build_object('membership', $3::text) WHERE realm_id=$1 AND member_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&member)
        .bind::<Text, _>(membership)
        .execute(&mut conn)
        .await
        .unwrap();
        let expected = (membership == "join").then(|| basis.clone());
        assert_eq!(
            reread(backed_request.window_cursor.clone(), now_ms).await,
            expected
        );
    }

    // A private handoff anchor that was never issued to any Account.
    let handoff_anchor = {
        let mut material = store
            .realm_state_snapshot_material(&realm_id)
            .await
            .unwrap()
            .unwrap();
        material.current_state_entries.clear();
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            &material,
            method.clone(),
            &key,
            chrono::Utc::now() - chrono::Duration::hours(3),
        )
        .unwrap()
    };
    diesel::sql_query(
        "INSERT INTO realm_state_snapshots \
         (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
         VALUES ($1,$2,0,$3,$4)",
    )
    .bind::<Text, _>(handoff_anchor.snapshot_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(&handoff_anchor).unwrap())
    .bind::<diesel::sql_types::Timestamptz, _>(handoff_anchor.created_at)
    .execute(&mut conn)
    .await
    .unwrap();

    // Age the reserved issuance past the unreserved retention and add an
    // unreserved, equally old one at head 8.
    let at_eight = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    diesel::sql_query(
        "UPDATE realm_state_snapshot_issuances SET issued_at = now() - interval '2 hours'",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    // RESTRICT: nothing may delete a reserved issuance, even outside GC.
    assert!(
        diesel::sql_query("DELETE FROM realm_state_snapshot_issuances WHERE snapshot_id=$1")
            .bind::<Text, _>(at_six.snapshot_id.as_str())
            .execute(&mut conn)
            .await
            .is_err()
    );
    let by_ref = |id: arkret_wire::RealmSnapshotId| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, issuer) = (realm_id.clone(), creator.clone(), issuer.clone());
        async move {
            store
                .issued_realm_state_snapshot(&realm_id, &creator, &id, &issuer)
                .await
                .unwrap()
        }
    };

    // Sweep while the window is consumable: the reserved basis survives, the
    // old unreserved issuance goes, the never-issued anchor is untouched.
    cursors.prune_expired(now_ms).await.unwrap();
    assert_eq!(
        by_ref(at_six.snapshot_id.clone()).await,
        Some(at_six.clone())
    );
    assert_eq!(by_ref(at_eight.snapshot_id.clone()).await, None);
    assert_eq!(issuance_count(&pool, &realm_id).await, 1);
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms).await,
        Some(basis.clone())
    );

    // A fresh unreserved issuance is inside its retention and survives.
    let fresh = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    cursors.prune_expired(now_ms).await.unwrap();
    assert_eq!(by_ref(fresh.snapshot_id.clone()).await, Some(fresh.clone()));

    // After the consumable deadline the reservation and the aged object are
    // reclaimed together; the by-ref read and the basis are gone.
    cursors.prune_expired(now_ms + window_ttl).await.unwrap();
    assert_eq!(reservation_count(&pool).await, 0);
    assert_eq!(by_ref(at_six.snapshot_id.clone()).await, None);
    assert_eq!(
        reread(backed_request.window_cursor.clone(), now_ms).await,
        None
    );
    assert_eq!(by_ref(fresh.snapshot_id.clone()).await, Some(fresh.clone()));
    assert_eq!(issuance_count(&pool, &realm_id).await, 1);
    assert_eq!(
        store.latest_snapshot(&realm_id).await.unwrap(),
        Some(handoff_anchor)
    );

    // A new limited window over the reclaimed anchor is preview only.
    let reclaimed = store
        .freeze_account_realm_window(&request(&creator, 2), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.window.preview_only, Some(true));
    assert!(reclaimed.window.window_start_basis.is_none());
}

fn scan_request(
    realm_id: &arkret_wire::RealmId,
    direction: arkret_wire::StreamScanDirection,
    limit: u16,
) -> arkret_wire::StreamScanRequest {
    arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction,
        limit,
    }
}

fn scanned_page(scan: coland_storage::AccountStreamScan) -> arkret_wire::StreamScanOutcome {
    match scan {
        coland_storage::AccountStreamScan::Page(page) => page,
        other => panic!("expected a proved page, got {other:?}"),
    }
}

fn positions(page: &arkret_wire::StreamScanOutcome) -> Vec<u64> {
    page.committed_events
        .iter()
        .map(|item| item.commit().stream_position)
        .collect()
}

#[tokio::test]
async fn account_stream_scan_serves_only_the_proved_sole_founder_interval() {
    use arkret_wire::StreamScanDirection::{After, Before};
    use coland_storage::AccountStreamScan;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let genesis_commit = unit.transactions[0].commit.commit_id.clone();
    let scan = |request: arkret_wire::StreamScanRequest, account: arkret_wire::AccountId| {
        let store = store.clone();
        let station = station.clone();
        async move {
            store
                .scan_stream_for_account(&request, &account, &station)
                .await
                .unwrap()
        }
    };

    // Forward pages walk the whole founding chain, bound to the genesis floor.
    let first = scanned_page(scan(scan_request(&realm_id, After(None), 3), creator.clone()).await);
    assert_eq!(positions(&first), [0, 1, 2]);
    assert!(first.truncated);
    let floor = first
        .readable_floor
        .clone()
        .expect("the lower end carries its floor");
    assert_eq!(floor.oldest_position, 0);
    assert_eq!(floor.floor_commit_id, genesis_commit);
    assert_eq!(
        floor.floor_reason,
        arkret_wire::ReadableFloorReason::StreamStart
    );
    let second =
        scanned_page(scan(scan_request(&realm_id, After(Some(2)), 3), creator.clone()).await);
    assert_eq!(positions(&second), [3, 4, 5]);
    assert!(second.truncated);
    let last =
        scanned_page(scan(scan_request(&realm_id, After(Some(5)), 3), creator.clone()).await);
    assert_eq!(positions(&last), [6]);
    assert!(!last.truncated);
    let mut previous = None;
    for (index, item) in first
        .committed_events
        .iter()
        .chain(&second.committed_events)
        .chain(&last.committed_events)
        .enumerate()
    {
        let arkret_wire::CommittedEventView::Full(view) = item else {
            panic!("the founder's own rows are disclosed in full");
        };
        assert_eq!(view.commit, unit.transactions[index].commit);
        assert_eq!(view.event, unit.transactions[index].event);
        assert_eq!(view.commit.previous_commit_ref, previous);
        previous = Some(view.commit.commit_id.clone());
    }
    let beyond =
        scanned_page(scan(scan_request(&realm_id, After(Some(6)), 3), creator.clone()).await);
    assert!(beyond.committed_events.is_empty() && !beyond.truncated);

    // Backward backfill stops at the floor without reporting truncation.
    let newest =
        scanned_page(scan(scan_request(&realm_id, Before(None), 2), creator.clone()).await);
    assert_eq!(positions(&newest), [6, 5]);
    assert!(newest.truncated);
    let oldest =
        scanned_page(scan(scan_request(&realm_id, Before(Some(2)), 5), creator.clone()).await);
    assert_eq!(positions(&oldest), [1, 0]);
    assert!(!oldest.truncated);
    assert_eq!(oldest.readable_floor, Some(floor.clone()));

    // No readable interval: another Account, or a Realm not governed here.
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), stranger.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    let unknown = arkret_wire::RealmId::from_event_id(&unit.transactions[1].event.event_id);
    assert_eq!(
        scan(scan_request(&unknown, After(None), 3), creator.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    // Authorized in principle, but not provable here: another issuer or a
    // Circle stream.
    let other_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(matches!(
        store
            .scan_stream_for_account(
                &scan_request(&realm_id, After(None), 3),
                &creator,
                &other_station
            )
            .await
            .unwrap(),
        AccountStreamScan::Unproved(_)
    ));
    let mut circle = scan_request(&realm_id, After(None), 3);
    circle.stream_ref = arkret_wire::CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: arkret_wire::CircleId::new(
            "ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0".to_owned(),
        )
        .unwrap(),
    };
    assert!(matches!(
        scan(circle, creator.clone()).await,
        AccountStreamScan::NotAuthorized
    ));
    let stranger_actor = arkret_wire::ActorId::account(stranger.clone()).to_string();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,'knock',$3,6,'{\"membership\":\"knock\"}'::jsonb,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&stranger_actor)
    .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    // Another membership row does not move the founder's genesis floor, and a
    // knocking Account has no readable interval.
    assert_eq!(
        scanned_page(scan(scan_request(&realm_id, After(None), 3), creator.clone()).await)
            .readable_floor,
        Some(floor.clone())
    );
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), stranger.clone()).await,
        AccountStreamScan::NotAuthorized
    );
    diesel::sql_query(
        "DELETE FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&stranger_actor)
    .execute(&mut conn)
    .await
    .unwrap();
    // A founder who left no longer has a readable interval.
    diesel::sql_query(
        "UPDATE member_state_current_results \
         SET membership='leave', value='{\"membership\":\"leave\"}'::jsonb WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), creator.clone()).await,
        AccountStreamScan::NotAuthorized
    );
}

/// Real PostgreSQL: the Account Realm detail carries the frozen window, its
/// rows, and the typed current of the same proved cut. The basis reservation
/// expires exactly at the window's consumable deadline, which is the deadline
/// the Account cursor that carries the window is bounded by.
#[tokio::test]
async fn account_window_carries_same_cut_current_and_reservation_deadline() {
    use coland_storage::AccountRealmWindowRequest;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let at_six = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    let strand = strand_create_request(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    uow.commit_event(set_default_strand_request(&strand, &strand_id, None))
        .await
        .unwrap();
    let head_material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();

    let now_ms = chrono::Utc::now().timestamp_millis();
    let request = AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: creator.clone(),
        issuer: issuer.clone(),
        window_limit: 2,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + coland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_heads: Vec::new(),
        selected_stream_refs: None,
    };
    let backed = store
        .freeze_account_realm_window(&request, &sign)
        .await
        .unwrap()
        .unwrap();
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(basis.snapshot_ref, at_six.snapshot_id);
    assert_eq!(backed.window.next_position, 9);
    assert_eq!(
        backed.current_state_entries,
        head_material.current_state_entries
    );
    assert_eq!(
        backed.governance_generation,
        head_material.governance_generation
    );
    #[derive(diesel::QueryableByName)]
    struct Deadline {
        #[diesel(sql_type = BigInt)]
        expires_at_ms: i64,
    }
    let mut conn = pool.get().await.unwrap();
    let reserved = diesel::sql_query(
        "SELECT expires_at_ms FROM realm_state_snapshot_window_reservations \
         WHERE window_cursor=$1",
    )
    .bind::<Text, _>(&request.window_cursor)
    .get_result::<Deadline>(&mut conn)
    .await
    .unwrap();
    assert_eq!(reserved.expires_at_ms, request.expires_at_ms);

    #[derive(diesel::QueryableByName)]
    struct Issuances {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    const ISSUANCES: &str = "SELECT jsonb_build_object('snapshots', (SELECT jsonb_agg(to_jsonb(s) ORDER BY snapshot_id) FROM realm_state_snapshots s), 'issuances', (SELECT jsonb_agg(to_jsonb(i) ORDER BY account_id, snapshot_id) FROM realm_state_snapshot_issuances i), 'reservations', (SELECT jsonb_agg(to_jsonb(r) ORDER BY window_cursor, stream_key) FROM realm_state_snapshot_window_reservations r)) AS value";
    let before = diesel::sql_query(ISSUANCES)
        .get_result::<Issuances>(&mut conn)
        .await
        .unwrap()
        .value;
    // History alone fits. The complete current and coverage do not; the
    // attempted basis reservation must roll back along with the refusal.
    let rows_budget = arkret_canonical::canonical_json_bytes(&backed.committed_events)
        .unwrap()
        .len()
        + 16;
    let refused = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                byte_budget: rows_budget,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(refused, coland_storage::PersistenceError::SchemaViolation(ref reason)
        if reason.contains("atomic detail payload exceeds its byte budget"))
    );
    let after = diesel::sql_query(ISSUANCES)
        .get_result::<Issuances>(&mut conn)
        .await
        .unwrap()
        .value;
    assert_eq!(before, after);

    // A preview-only window still carries the same-cut current: current
    // never depends on the window start.
    let preview = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                window_limit: 1,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preview.window.preview_only, Some(true));
    assert_eq!(
        preview.current_state_entries,
        head_material.current_state_entries
    );
    // A consumable deadline beyond the cursor's lifetime is refused whole.
    assert!(
        store
            .freeze_account_realm_window(
                &AccountRealmWindowRequest {
                    expires_at_ms: now_ms + coland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS + 1,
                    window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                    ..request.clone()
                },
                &sign
            )
            .await
            .is_err()
    );
}

/// Real PostgreSQL: a founder Realm (with the plaintext-services facet that
/// plain-text messages require) grows past the product's 20-row window with a
/// message tail. The window over the last 21 Commits names the snapshot
/// issued at the default-Strand head as its basis; its
/// same-cut current and a fresh head both carry one `message_revision` row
/// per message, and that head is re-provable by reference. A window whose
/// anchor was never issued is preview only.
#[tokio::test]
async fn message_tail_window_beyond_twenty_commits_names_the_issued_anchor() {
    use coland_storage::AccountRealmWindowRequest;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let mut previous = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(previous.clone()).await.unwrap();
    let at_nine = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(at_nine.visible_stream_heads[0].stream_position, 9);
    for index in 0..21 {
        let message = message_create_request(&previous, &strand_id, &format!("message {index}"));
        uow.commit_event(message.clone()).await.unwrap();
        previous = message;
    }
    let head_material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_material.visible_stream_heads[0].stream_position, 30);
    assert_eq!(head_material.current_state_entries.len(), 33);
    let source = head_material
        .current_state_entries
        .iter()
        .find_map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::CalendarScheduleSource { strand_id: id },
                source_stream_ref,
                revision,
                value,
            } if id == &strand_id => Some((source_stream_ref, revision, value)),
            _ => None,
        })
        .expect("the tail window retains its Strand's same-cut Calendar source");
    let value: arkret_wire::CalendarScheduleSourceValue =
        serde_json::from_value(source.2.clone()).unwrap();
    assert_eq!(source.0, &strand.authority_commit.commit.stream_ref);
    assert_eq!(source.1.commit_id, strand.authority_commit.commit.commit_id);
    assert_eq!(value.strand_revision, *source.1);
    assert_eq!(
        value.effective_scope,
        strand.authority_commit.event.scope_ref
    );
    assert!(value.source.is_none());
    assert!(value.metadata_context.is_none());
    assert_eq!(
        head_material
            .current_state_entries
            .iter()
            .filter(|entry| matches!(
                entry,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                    ..
                }
            ))
            .count(),
        21
    );

    let now_ms = chrono::Utc::now().timestamp_millis();
    let request = AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: creator.clone(),
        issuer: issuer.clone(),
        window_limit: 21,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + coland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_heads: Vec::new(),
        selected_stream_refs: None,
    };
    let backed = store
        .freeze_account_realm_window(&request, &sign)
        .await
        .unwrap()
        .unwrap();
    let basis = backed.window.window_start_basis.clone().unwrap();
    assert_eq!(basis.snapshot_ref, at_nine.snapshot_id);
    assert_eq!(basis.anchor_position, 9);
    assert_eq!(backed.window.preview_only, None);
    assert_eq!(backed.window.next_position, 31);
    assert_eq!(backed.committed_events.len(), 21);
    assert_eq!(backed.committed_events[0].commit().stream_position, 10);
    assert_eq!(
        backed.current_state_entries,
        head_material.current_state_entries
    );

    let unanchored = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                window_limit: 20,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unanchored.window.preview_only, Some(true));
    assert!(unanchored.window.window_start_basis.is_none());

    let at_head = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        at_head.current_state_entries,
        head_material.current_state_entries
    );
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &at_head.snapshot_id, &issuer)
            .await
            .unwrap(),
        Some(at_head),
    );

    // Live delta: two more messages after the delivered head 30 arrive as a
    // window of exactly those two Commits, on the snapshot the earlier
    // freeze issued at its own head. The continuation's minimum head is a
    // server-held accepted binding, not an unverified caller declaration.
    let delivered = arkret_wire::CommitStreamHead {
        stream_ref: backed.window.stream_ref.clone(),
        stream_position: backed.window.next_position - 1,
        commit_id: backed.window.head_commit_ref.clone(),
    };
    for index in 0..2 {
        let message = message_create_request(&previous, &strand_id, &format!("live {index}"));
        uow.commit_event(message.clone()).await.unwrap();
        previous = message;
    }
    let delta = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                delivered_heads: vec![delivered.clone()],
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delta.window.preview_only, None);
    assert_eq!(delta.window.next_position, 33);
    assert_eq!(
        delta
            .committed_events
            .iter()
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>(),
        vec![31, 32]
    );
    let delta_basis = delta.window.window_start_basis.clone().unwrap();
    assert_eq!(delta_basis.anchor_position, 30);
    assert_eq!(delta_basis.anchor_commit_ref, delivered.commit_id);
    let delta_anchor = store
        .issued_realm_state_snapshot(&realm_id, &creator, &delta_basis.snapshot_ref, &issuer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delta_anchor.visible_stream_heads, vec![delivered.clone()]);
    // client-sync.md section 12.3.2: an unknown or conflicting minimum head
    // cannot be treated as a recoverable continuation or reset to an older cut.
    let issuances_before = issuance_count(&pool, &realm_id).await;
    let reservations_before = reservation_count(&pool).await;
    let forged = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                delivered_heads: vec![arkret_wire::CommitStreamHead {
                    commit_id: arkret_wire::RealmCommitId::from_digest([0x7f; 32]),
                    ..delivered
                }],
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        forged,
        coland_storage::PersistenceError::Internal(message)
            if message == "Account continuation minimum head is not covered at the frozen cut"
    ));
    assert_eq!(issuance_count(&pool, &realm_id).await, issuances_before);
    assert_eq!(reservation_count(&pool).await, reservations_before);
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &delta_basis.snapshot_ref, &issuer)
            .await
            .unwrap(),
        Some(delta_anchor),
        "refusing the forged continuation preserves the issued lawful anchor"
    );
}

async fn account_issuance_count(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> i64 {
    issuance_count(pool, realm_id).await
}

/// Real PostgreSQL (0441): repeated `/head` reads and window freezes at one
/// cut reuse the object already issued for it; issuances at distinct heads
/// that no window reserves are trimmed to the per-Account cap, newest kept;
/// and live reservations on one stream stop at their cap, after which a
/// limited window is preview only instead of evicting a live guarantee. A
/// retried freeze returns the same rows on the same basis, and another
/// Account can never read a window basis through the creator's cursor.
#[tokio::test]
async fn issued_snapshots_and_window_reservations_stay_within_their_caps() {
    use coland_storage::{AccountRealmWindowRequest, SyncCursorStore as _};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let cursors = coland_storage_postgres::PgSyncCursorStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let head = || {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, issuer) = (realm_id.clone(), creator.clone(), issuer.clone());
        let sign = &sign;
        async move {
            store
                .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, sign)
                .await
                .unwrap()
                .unwrap()
        }
    };
    let by_ref = |id: arkret_wire::RealmSnapshotId| {
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let (realm_id, creator, issuer) = (realm_id.clone(), creator.clone(), issuer.clone());
        async move {
            store
                .issued_realm_state_snapshot(&realm_id, &creator, &id, &issuer)
                .await
                .unwrap()
        }
    };

    // Same cut: every `/head` and every whole-history freeze reuses one object.
    let first = head().await;
    for _ in 0..4 {
        assert_eq!(head().await, first);
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_ttl = 300_000;
    let request = |limit: u32, delivered_head: Option<arkret_wire::CommitStreamHead>| {
        AccountRealmWindowRequest {
            realm_id: realm_id.clone(),
            account: creator.clone(),
            issuer: issuer.clone(),
            window_limit: limit,
            window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
            expires_at_ms: now_ms + window_ttl,
            now_ms,
            byte_budget: 7 * 1024 * 1024,
            delivered_heads: delivered_head.into_iter().collect(),
            selected_stream_refs: None,
        }
    };
    for _ in 0..4 {
        let whole = store
            .freeze_account_realm_window(&request(20, None), &sign)
            .await
            .unwrap()
            .unwrap();
        assert!(!whole.window.limited);
    }
    assert_eq!(account_issuance_count(&pool, &realm_id).await, 1);
    assert_eq!(reservation_count(&pool).await, 0);

    // Twelve distinct heads, each read once through `/head`, keep only the
    // newest eight unreserved issuances.
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let mut previous = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(previous.clone()).await.unwrap();
    let mut issued = Vec::new();
    for index in 0..12 {
        let message = message_create_request(&previous, &strand_id, &format!("head {index}"));
        uow.commit_event(message.clone()).await.unwrap();
        previous = message;
        issued.push(head().await);
    }
    let cap = coland_storage::MAX_UNRESERVED_ISSUED_SNAPSHOTS_PER_ACCOUNT_REALM;
    assert_eq!(account_issuance_count(&pool, &realm_id).await, cap);
    assert_eq!(by_ref(first.snapshot_id.clone()).await, None);
    for (index, snapshot) in issued.iter().enumerate() {
        let expected = (index >= issued.len() - cap as usize).then(|| snapshot.clone());
        assert_eq!(by_ref(snapshot.snapshot_id.clone()).await, expected);
    }

    // A live delta after the newest issued head: every retry of the same
    // request freezes the same rows on the same basis until the live
    // reservations reach their cap; then the window is preview only, and no
    // retry issues another object.
    let latest = issued.last().unwrap().clone();
    let delivered = latest.visible_stream_heads[0].clone();
    let message = message_create_request(&previous, &strand_id, "live");
    uow.commit_event(message.clone()).await.unwrap();
    let reservation_cap = coland_storage::MAX_LIVE_WINDOW_RESERVATIONS_PER_ACCOUNT_STREAM;
    let mut reference = None;
    let mut creator_cursor = None;
    for _ in 0..reservation_cap {
        let retry = request(20, Some(delivered.clone()));
        let window = store
            .freeze_account_realm_window(&retry, &sign)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(window.window.preview_only, None);
        let basis = window.window.window_start_basis.clone().unwrap();
        assert_eq!(basis.snapshot_ref, latest.snapshot_id);
        let rows = serde_json::to_value(&window.committed_events).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(*reference.get_or_insert_with(|| rows.clone()), rows);
        creator_cursor.get_or_insert(retry.window_cursor);
    }
    assert_eq!(reservation_count(&pool).await, reservation_cap);
    let over = store
        .freeze_account_realm_window(&request(20, Some(delivered.clone())), &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(over.window.preview_only, Some(true));
    assert!(over.window.window_start_basis.is_none());
    assert_eq!(
        serde_json::to_value(&over.committed_events).unwrap(),
        reference.unwrap()
    );
    assert_eq!(reservation_count(&pool).await, reservation_cap);
    // The first freeze issued the new head once; the reserved anchor is
    // outside the unreserved cap.
    assert_eq!(account_issuance_count(&pool, &realm_id).await, cap + 1);

    // The basis is bound to the Account that froze the window.
    let creator_cursor = creator_cursor.unwrap();
    for account in [&stranger, &creator] {
        let basis = store
            .account_window_basis(
                &realm_id,
                account,
                &creator_cursor,
                &stream_ref,
                &issuer,
                now_ms,
            )
            .await
            .unwrap();
        assert_eq!(basis.is_some(), account == &creator);
    }

    // Once the reservations lapse the cap frees, and the retained anchor
    // backs a live delta again.
    cursors.prune_expired(now_ms + window_ttl).await.unwrap();
    assert_eq!(reservation_count(&pool).await, 0);
    let renewed = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                expires_at_ms: now_ms + 2 * window_ttl,
                now_ms: now_ms + window_ttl,
                ..request(20, Some(delivered.clone()))
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        renewed.window.window_start_basis.unwrap().snapshot_ref,
        latest.snapshot_id
    );
}

/// Real PostgreSQL: the Account stream scan applies the committed-event
/// disclosure decision. A retention-expired Message and a redacted Message
/// keep their Commit slot as the withheld branch, so the page is still one
/// contiguous verifiable chain, while the redaction itself is disclosed in
/// full. A signed cut omits only withdrawn content, preserving state and
/// stream coordinates; old objects containing withdrawn content are unavailable.
#[tokio::test]
async fn account_scan_withholds_expired_and_redacted_messages_on_their_commits() {
    use arkret_wire::StreamScanDirection::After;
    use coland_storage::AccountRealmWindowRequest;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let safe_before = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    let expired = message_create_request(&default, &strand_id, "expired");
    uow.commit_event(expired.clone()).await.unwrap();
    let redacted = message_create_request(&expired, &strand_id, "redacted");
    uow.commit_event(redacted.clone()).await.unwrap();
    let kept = message_create_request(&redacted, &strand_id, "kept");
    uow.commit_event(kept.clone()).await.unwrap();
    let before = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();

    let redacted_message =
        arkret_wire::MessageId::new(redacted.authority_commit.event.event_id.as_str().replacen(
            "ak:event:",
            "ak:message:",
            1,
        ))
        .unwrap();
    let redaction = realm_event_request_as(
        &kept,
        &creator,
        arkret_wire::EventKind::MessageRedact,
        serde_json::json!({ "message_id": redacted_message }),
    );
    uow.commit_event(redaction.clone()).await.unwrap();
    use coland_storage::RetentionTombstoneStore as _;
    let tombstones = coland_storage_postgres::PgRetentionTombstoneStore { pool: pool.clone() };
    // Exercise the real retention store for both a content carrier and a
    // state carrier. Retention cannot discard the latter's current result.
    for request in [&expired, &strand] {
        tombstones
            .put(&coland_storage::RetentionTombstoneRecord {
                event_id: request.authority_commit.event.event_id.to_string(),
                realm_id: realm_id.to_string(),
                reason: "retention_policy.ttl".into(),
                policy_ttl_seconds: 60,
                expired_at: chrono::Utc::now(),
                tombstoned_at: chrono::Utc::now(),
                sealed: false,
            })
            .await
            .unwrap();
    }

    let page = scanned_page(
        store
            .scan_stream_for_account(
                &scan_request(&realm_id, After(None), 100),
                &creator,
                &issuer,
            )
            .await
            .unwrap(),
    );
    let last = redaction.authority_commit.commit.stream_position;
    assert_eq!(positions(&page), (0..=last).collect::<Vec<_>>());
    assert!(!page.truncated);
    for (index, item) in page.committed_events.iter().enumerate() {
        if index > 0 {
            assert_eq!(
                item.commit().previous_commit_ref.as_ref(),
                Some(&page.committed_events[index - 1].commit().commit_id)
            );
        }
        let withheld = [&expired, &redacted, &strand]
            .iter()
            .any(|request| request.authority_commit.commit.commit_id == item.commit().commit_id);
        match item {
            arkret_wire::CommittedEventView::Withheld(view) => {
                assert!(
                    withheld,
                    "unexpected withheld row {}",
                    view.commit.stream_position
                );
            }
            arkret_wire::CommittedEventView::Full(view) => {
                assert!(!withheld, "disclosed row {}", view.commit.stream_position);
                assert_eq!(view.event.event_id, view.commit.event_ref);
            }
        }
    }

    let after = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.retention_and_history_floor,
        before.retention_and_history_floor
    );
    assert_eq!(after.visible_stream_heads[0].stream_position, last);
    let messages = after
        .current_state_entries
        .iter()
        .filter_map(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MessageRevision { message_id },
                ..
            } => Some(message_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        vec![arkret_wire::MessageId::from_event_id(
            &kept.authority_commit.event.event_id
        )]
    );
    assert!(after.current_state_entries.iter().any(|row| matches!(row,
        arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::Strand { strand_id: id }, .. } if id == &strand_id)));
    assert!(after.current_state_entries.iter().any(|row| matches!(row,
        arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::ObjectRedaction { target_ref }, .. } if target_ref == redacted_message.as_str())));
    for snapshot in [&safe_before, &after] {
        assert_eq!(
            store
                .issued_realm_state_snapshot(&realm_id, &creator, &snapshot.snapshot_id, &issuer)
                .await
                .unwrap(),
            Some(snapshot.clone())
        );
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window = store
        .freeze_account_realm_window(
            &AccountRealmWindowRequest {
                realm_id: realm_id.clone(),
                account: creator.clone(),
                issuer: issuer.clone(),
                window_limit: 2,
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                expires_at_ms: now_ms + 300_000,
                now_ms,
                byte_budget: 7 * 1024 * 1024,
                delivered_heads: Vec::new(),
                selected_stream_refs: None,
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(window.committed_events.len(), 2);
    let backwards = scanned_page(
        store
            .scan_stream_for_account(
                &scan_request(
                    &realm_id,
                    arkret_wire::StreamScanDirection::Before(None),
                    100,
                ),
                &creator,
                &issuer,
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        backwards.committed_events.len(),
        page.committed_events.len()
    );
    for (actual, expected) in backwards
        .committed_events
        .iter()
        .zip(page.committed_events.iter().rev())
    {
        assert_eq!(actual.commit().commit_id, expected.commit().commit_id);
        assert_eq!(actual.reducer_input(), expected.reducer_input());
    }
    assert!(matches!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &before.snapshot_id, &issuer)
            .await,
        Err(coland_storage::PersistenceError::SchemaViolation(_))
    ));
}

#[tokio::test]
async fn peer_stream_scan_refuses_non_hosting_peers_and_serves_a_hosting_peer_its_interval() {
    use arkret_wire::StreamScanDirection::After;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let remote = arkret_wire::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let scan = |request: arkret_wire::StreamScanRequest, peer: arkret_wire::DidCoreId| {
        let store = store.clone();
        let station = station.clone();
        async move {
            store
                .scan_stream_for_peer(&request, &peer, &station)
                .await
                .unwrap()
        }
    };

    // A peer hosting no joined member has no replication right, even though
    // the founding stream is fully readable by its local founder.
    assert_eq!(
        scan(scan_request(&realm_id, After(None), 3), remote.clone()).await,
        coland_storage::PeerStreamScan::NotAuthorized
    );
    // A Realm not governed here is refused without enumerating it.
    let unknown = arkret_wire::RealmId::from_event_id(&unit.transactions[1].event.event_id);
    assert_eq!(
        scan(
            scan_request(&unknown, After(None), 3),
            creator.station_id.clone()
        )
        .await,
        coland_storage::PeerStreamScan::NotAuthorized
    );

    // A peer hosting a joined member holds its replication right from that
    // member's readable floor: a join inside the founding unit reads from
    // the genesis Commit (`federation.md` section 4.1.1).
    let remote_member = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:remote-member.example").unwrap(),
        remote.clone(),
    ))
    .to_string();
    let mut conn = pool.get().await.unwrap();
    for membership in ["knock", "join"] {
        diesel::sql_query(
            "INSERT INTO member_state_current_results \
             (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
             VALUES ($1,$2,$3,$4,6,jsonb_build_object('membership',$3::text),now()) \
             ON CONFLICT (realm_id,member_id) DO UPDATE SET membership=EXCLUDED.membership, \
             value=EXCLUDED.value",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&remote_member)
        .bind::<Text, _>(membership)
        .bind::<Text, _>(unit.transactions[6].commit.commit_id.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
        let decision = scan(scan_request(&realm_id, After(None), 3), remote.clone()).await;
        if membership == "join" {
            let coland_storage::PeerStreamScan::Page(page) = decision else {
                panic!("a hosting peer is served its interval: {decision:?}");
            };
            assert_eq!(
                page.readable_floor
                    .as_ref()
                    .map(|floor| floor.oldest_position),
                Some(0)
            );
            assert_eq!(page.committed_events.len(), 3);
            assert!(page.truncated);
            assert!(
                page.committed_events
                    .iter()
                    .all(|item| matches!(item, arkret_wire::CommittedEventView::Full(_)))
            );
        } else {
            // A knock is not a joined member and grants nothing.
            assert_eq!(decision, coland_storage::PeerStreamScan::NotAuthorized);
        }
    }
    // The same holds for a Circle stream and for a Station that lost tenure.
    let mut circle = scan_request(&realm_id, After(None), 3);
    circle.stream_ref = arkret_wire::CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: arkret_wire::CircleId::new(
            "ak:circle:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0".to_owned(),
        )
        .unwrap(),
    };
    assert!(matches!(
        scan(circle, remote.clone()).await,
        coland_storage::PeerStreamScan::NotAuthorized
    ));
    let other_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(matches!(
        store
            .scan_stream_for_peer(
                &scan_request(&realm_id, After(None), 3),
                &remote,
                &other_station
            )
            .await
            .unwrap(),
        coland_storage::PeerStreamScan::Unproved(_)
    ));
}

fn moderation_report_request(
    previous: &EventCommitRequest,
    reporter: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
) -> EventCommitRequest {
    realm_self_event_request(
        previous,
        reporter,
        arkret_wire::EventKind::SelfModerationReport,
        payload,
    )
}

fn realm_self_event_request(
    previous: &EventCommitRequest,
    reporter: &arkret_wire::DidCoreId,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let realm_id = previous.authority_commit.event.realm_id.clone();
    let station = previous
        .authority_commit
        .expected_authority
        .service_id
        .clone();
    let event = event(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        reporter,
        &station,
        payload,
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("report:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.event.event_id = event.event_id.to_string();
    request.event.actor_id = event.actor_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].sender = Some(event.actor_id.to_string());
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    seal_request_fact(request)
}

fn report_payload(
    realm_id: &arkret_wire::RealmId,
    target_ref: &str,
    reporter: &arkret_wire::DidCoreId,
) -> serde_json::Value {
    serde_json::json!({
        "realm_id": realm_id,
        "target_ref": target_ref,
        "report_reason_code": "spam",
        "reporter_id": reporter,
        "provenance": "self"
    })
}

fn franking_nonce(
    request: &EventCommitRequest,
    received_by: &arkret_wire::DidCoreId,
    replay_nonce: &str,
) -> coland_storage::EventBatchCommitRequest {
    coland_storage::EventBatchCommitRequest {
        audit_unit: None,
        events: vec![request.clone()],
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: Some(coland_storage::FrankingReplayNonceCommit {
            realm_id: request.authority_commit.event.realm_id.to_string(),
            received_by: received_by.clone(),
            replay_nonce: replay_nonce.to_owned(),
            report_event_id: request.authority_commit.event.event_id.to_string(),
            consumed_at: request.authority_commit.commit.committed_at,
        }),
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

async fn report_row_count(pool: &coland_storage_postgres::PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM moderation_report_current_results")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn franking_nonce_count(pool: &coland_storage_postgres::PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM moderation_franking_replay_nonces")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Real PostgreSQL: the reporter-signed self moderation report commits with its
/// Station-signed RealmCommit, the exact `moderation_report` current row and
/// the consumed franking nonce in one transaction; every refusal (absent
/// target, non-member reporter, facade provenance, Circle scope, reused nonce,
/// divergent bytes for an accepted Event id, unplanned remote target) leaves
/// zero Event, Commit, current, nonce and outbox writes.
#[tokio::test]
async fn self_moderation_report_commits_exact_current_and_refuses_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    unit.validate().unwrap();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let message = message_create_request(&default, &strand_id, "reported");
    uow.commit_event(message.clone()).await.unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let reporter = message
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let target = message.authority_commit.event.event_id.to_string();
    let station = message
        .authority_commit
        .expected_authority
        .service_id
        .clone();

    let assert_zero_writes = async |request: &EventCommitRequest, reports: i64, nonces: i64| {
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(report_row_count(&pool).await, reports);
        assert_eq!(franking_nonce_count(&pool).await, nonces);
        assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);
    };

    // An absent target is the single anti-oracle not_found.
    let absent = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"absent-report-target"),
    );
    let denied = moderation_report_request(
        &message,
        &reporter,
        report_payload(&realm_id, absent.as_str(), &reporter),
    );
    let error = uow.commit_event(denied.clone()).await.unwrap_err();
    assert!(
        matches!(error, coland_storage::PersistenceError::NotFound(_)),
        "{error}"
    );
    assert_zero_writes(&denied, 0, 0).await;

    // A reporter that is not a confirmed joined member cannot see the target.
    let outsider = arkret_wire::DidCoreId::new("ak:did_core:web:report-outsider.example").unwrap();
    let denied = moderation_report_request(
        &message,
        &outsider,
        report_payload(&realm_id, &target, &outsider),
    );
    assert!(matches!(
        uow.commit_event(denied.clone()).await.unwrap_err(),
        coland_storage::PersistenceError::NotFound(_)
    ));
    assert_zero_writes(&denied, 0, 0).await;

    // MIMI facade provenance has its own ingress and never enters this unit.
    let mut facade = report_payload(&realm_id, &target, &reporter);
    facade["provenance"] = serde_json::json!("mimi_facade");
    facade["source_provider_id"] = serde_json::json!("ak:did_core:web:mimi-provider.example");
    let denied = moderation_report_request(&message, &reporter, facade);
    let error = uow.commit_event(denied.clone()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("MIMI facade requires its verified Service producer guard"),
        "{error}"
    );
    assert_zero_writes(&denied, 0, 0).await;

    // A Circle effective scope does not match a Realm-scope target.
    let mut circle = report_payload(&realm_id, &target, &reporter);
    circle["effective_scope"] = serde_json::json!({
        "kind": "circle",
        "realm_id": realm_id,
        "circle_id": arkret_wire::CircleId::from_event_id(&message.authority_commit.event.event_id),
    });
    let denied = moderation_report_request(&message, &reporter, circle);
    assert!(matches!(
        uow.commit_event(denied.clone()).await.unwrap_err(),
        coland_storage::PersistenceError::NotFound(_)
    ));
    assert_zero_writes(&denied, 0, 0).await;

    // Accepted: Event, Commit, exact current row and the consumed nonce.
    let mut framed = report_payload(&realm_id, &target, &reporter);
    framed["franking_proof"] = serde_json::json!({
        "realm_id": realm_id,
        "event_id": target,
        "received_by": station,
        "verification_method": "did:web:bootstrap-station.example#notary-key",
        "received_at": message.authority_commit.commit.committed_at,
        "replay_nonce": "report-nonce-0000000001",
        "signature": "c2lnbmF0dXJl"
    });
    let report = moderation_report_request(&message, &reporter, framed);
    let outcome = uow
        .commit_event_batch(franking_nonce(&report, &station, "report-nonce-0000000001"))
        .await
        .unwrap();
    assert!(outcome.event_inserted);
    assert_eq!(outcome.outbox_inserted, 0);
    let committed = store
        .committed_event(&report.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.event, report.authority_commit.event);
    assert_eq!(committed.commit, report.authority_commit.commit);
    #[derive(diesel::QueryableByName)]
    struct ReportRow {
        #[diesel(sql_type = Text)]
        current_commit_id: String,
        #[diesel(sql_type = BigInt)]
        current_stream_position: i64,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM moderation_report_current_results WHERE report_event_id=$1 AND realm_id=$2",
    )
    .bind::<Text, _>(report.authority_commit.event.event_id.as_str())
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ReportRow>(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        row.current_commit_id,
        report.authority_commit.commit.commit_id.as_str()
    );
    assert_eq!(
        row.current_stream_position,
        report.authority_commit.commit.stream_position as i64
    );
    assert_eq!(
        row.value,
        serde_json::to_value(&report.authority_commit.event.payload).unwrap()
    );
    assert_eq!(report_row_count(&pool).await, 1);
    assert_eq!(franking_nonce_count(&pool).await, 1);
    // The Realm snapshot cut still materializes after the report Commit.
    store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();

    // The same Event id with different canonical bytes is refused and the
    // accepted Event is not rewritten.
    let mut divergent = report.clone();
    let proof = divergent
        .authority_commit
        .event
        .producer_proof
        .as_mut()
        .unwrap();
    proof.created_at = proof.created_at + chrono::Duration::seconds(1);
    divergent.event.envelope = serde_json::to_value(&divergent.authority_commit.event).unwrap();
    let error = uow.commit_event(divergent).await.unwrap_err();
    assert!(
        error.to_string().contains("event_hash_collision"),
        "{error}"
    );
    assert_eq!(
        store
            .committed_event(&report.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .event,
        report.authority_commit.event
    );
    assert_eq!(report_row_count(&pool).await, 1);

    // A second report that reuses the consumed franking nonce is refused.
    let mut reused = report_payload(&realm_id, &target, &reporter);
    reused["report_reason_code"] = serde_json::json!("harassment");
    reused["franking_proof"] = report.authority_commit.event.payload["franking_proof"].clone();
    let denied = moderation_report_request(&report, &reporter, reused);
    let error = uow
        .commit_event_batch(franking_nonce(&denied, &station, "report-nonce-0000000001"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"), "{error}");
    assert_zero_writes(&denied, 1, 1).await;

    // A Realm-target report without evidence is accepted at the next position.
    let realm_report = moderation_report_request(
        &report,
        &reporter,
        report_payload(&realm_id, realm_id.as_str(), &reporter),
    );
    uow.commit_event(realm_report.clone()).await.unwrap();
    assert_eq!(report_row_count(&pool).await, 2);

    // A remote joined account that holds no moderation capability may not
    // read a moderator-only report, so its Station is owed nothing.
    let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:report-remote.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:report-remote-station.example").unwrap(),
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(remote.to_string())
    .bind::<Text, _>(unit.transactions.last().unwrap().commit.commit_id.as_str())
    .bind::<BigInt, _>(unit.transactions.last().unwrap().commit.stream_position as i64)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<diesel::sql_types::Timestamptz, _>(unit.transactions[0].commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let mut remote_payload = report_payload(&realm_id, &target, &reporter);
    remote_payload["report_reason_code"] = serde_json::json!("illegal");
    let unowed = moderation_report_request(&realm_report, &reporter, remote_payload);
    let outcome = uow.commit_event(unowed).await.unwrap();
    assert_eq!(outcome.outbox_inserted, 0);
    assert_eq!(report_row_count(&pool).await, 3);
}

/// Real PostgreSQL: the Realm root controller sees the accepted scope report
/// with its actual covering Commit; ordinary members gain no report access.
#[tokio::test]
async fn moderation_report_row_is_disclosed_to_the_realm_root_controller() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    assert_eq!(
        account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .unwrap()
            .unwrap()
            .current_state_entries
            .len(),
        11
    );

    let report = moderation_report_request(
        &default,
        &creator.principal_id,
        report_payload(&realm_id, strand_id.as_str(), &creator.principal_id),
    );
    uow.commit_event(report.clone()).await.unwrap();
    assert_eq!(report_row_count(&pool).await, 1);
    let material = account_snapshot_material(&pool, &realm_id, &creator)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.current_state_entries.len(), 12);
    assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CalendarScheduleSource { strand_id: id },
            source_stream_ref, revision, ..
        } if id == &strand_id
            && source_stream_ref == &strand.authority_commit.commit.stream_ref
            && revision.commit_id == strand.authority_commit.commit.commit_id
            && revision.stream_position == strand.authority_commit.commit.stream_position
    )));
    assert!(material.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::ModerationReport { event_id },
            source_stream_ref, revision, value,
        } if event_id == &report.authority_commit.event.event_id
            && source_stream_ref == &report.authority_commit.commit.stream_ref
            && revision.commit_id == report.authority_commit.commit.commit_id
            && revision.stream_position == report.authority_commit.commit.stream_position
            && value == &serde_json::to_value(&report.authority_commit.event.payload).unwrap()
    )));
}

async fn event_row_count(pool: &coland_storage_postgres::PgPool, event_id: &str) -> i64 {
    let token = coland_storage::ids::parse_event_id(event_id).unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE id=$1")
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

/// Real PostgreSQL: two self reports built on the same Realm-stream head race
/// concurrently. Exactly one commits; the other loses the head CAS and answers
/// the registered retryable `temporarily_unavailable` (authority-commit-log.md
/// §4 `retryable_unavailable`) with zero Event, Commit, current and outbox
/// writes. The exact same Event then commits once rebuilt on the new head.
#[tokio::test]
async fn concurrent_self_reports_on_one_stream_head_leave_one_winner_and_a_retryable_loser() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let reporter = default
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let first = moderation_report_request(
        &default,
        &reporter,
        report_payload(&realm_id, strand_id.as_str(), &reporter),
    );
    let mut second_payload = report_payload(&realm_id, realm_id.as_str(), &reporter);
    second_payload["report_reason_code"] = serde_json::json!("harassment");
    let second = moderation_report_request(&default, &reporter, second_payload.clone());
    assert_eq!(
        first.authority_commit.commit.stream_position,
        second.authority_commit.commit.stream_position
    );

    let first_uow = PgEventCommitUnitOfWork::new(pool.clone());
    let second_uow = PgEventCommitUnitOfWork::new(pool.clone());
    let (first_result, second_result) = tokio::join!(
        first_uow.commit_event(first.clone()),
        second_uow.commit_event(second.clone())
    );
    let (winner, loser, error) = match (first_result, second_result) {
        (Ok(_), Err(error)) => (&first, &second, error),
        (Err(error), Ok(_)) => (&second, &first, error),
        (first, second) => panic!(
            "expected exactly one winner: first ok={} second ok={}",
            first.is_ok(),
            second.is_ok()
        ),
    };
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        "{error}"
    );
    assert_eq!(
        coland_services::ServiceError::from(error).conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable)
    );
    let committed = store
        .committed_event(&winner.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.commit, winner.authority_commit.commit);
    assert!(
        store
            .committed_event(&loser.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        event_row_count(&pool, loser.authority_commit.event.event_id.as_str()).await,
        0
    );
    assert_eq!(report_row_count(&pool).await, 1);
    assert_eq!(source_outbox_count(&pool, &realm_id).await, 0);

    // Exact retry: the same signed Event, ordered by the Station on the new head.
    let retried = moderation_report_request(
        winner,
        &reporter,
        serde_json::to_value(&loser.authority_commit.event.payload).unwrap(),
    );
    assert_eq!(retried.authority_commit.event, loser.authority_commit.event);
    uow.commit_event(retried.clone()).await.unwrap();
    assert_eq!(report_row_count(&pool).await, 2);
    assert_eq!(
        store
            .committed_event(&loser.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit
            .stream_position,
        winner.authority_commit.commit.stream_position + 1
    );
}

/// Real PostgreSQL: the moderation queue is a same-cut View over the
/// `moderation_report` family. The Realm root controller sees every report as
/// a closed `moderation-queue-item` with the retyped id, the exact payload and
/// the accepting Commit time; any other caller sees nothing; the full Realm
/// snapshot material carries each report under its registered selector; the
/// committed decisions fold item status from moderation_state; and a same-cut
/// moderation grant makes its subject a moderator of the queue.
#[tokio::test]
async fn moderation_queue_view_derives_from_the_report_family_at_one_cut() {
    use arkret_models_collaboration::governance::moderation_queue::ModerationQueueItem;
    use coland_storage::ModerationStore as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let queue = coland_storage_postgres::PgModerationStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let controller = default.authority_commit.event.actor_id.clone();
    let reporter = controller.signing_principal_id().clone();
    let stranger = accepted_pcr_account::accepted_pcr_account(
        &pool,
        device_authorization_history::did_web_station(
            &controller.as_account_id().unwrap().station_id,
        ),
    )
    .await;

    let items = |read: Vec<ModerationQueueItem>| read;
    assert!(items(queue.queue_view_for_actor(&controller, None).await.unwrap()).is_empty());

    let first = moderation_report_request(
        &default,
        &reporter,
        report_payload(&realm_id, strand_id.as_str(), &reporter),
    );
    uow.commit_event(first.clone()).await.unwrap();
    let mut second_payload = report_payload(&realm_id, realm_id.as_str(), &reporter);
    second_payload["report_reason_code"] = serde_json::json!("harassment");
    let second = moderation_report_request(&first, &reporter, second_payload);
    uow.commit_event(second.clone()).await.unwrap();
    assert_eq!(queue.report_count().await.unwrap(), 2);

    let view = items(queue.queue_view_for_actor(&controller, None).await.unwrap());
    assert_eq!(view.len(), 2);
    for (item, request) in view.iter().zip([&first, &second]) {
        let value = serde_json::to_value(item).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "id": request
                    .authority_commit
                    .event
                    .event_id
                    .as_str()
                    .replacen("ak:event:", "ak:moderation_queue_item:", 1),
                "report": serde_json::to_value(&request.authority_commit.event.payload).unwrap(),
                "status": "submitted",
                "visibility": "plaintext_evidence",
                "created_at": arkret_canonical::format_timestamp_canonical(
                    request.authority_commit.commit.committed_at
                ),
            })
        );
    }
    assert_eq!(
        items(
            queue
                .queue_view_for_actor(&controller, Some(&realm_id))
                .await
                .unwrap()
        )
        .len(),
        2
    );
    let other_realm = arkret_wire::RealmId::from_event_id(&strand.authority_commit.event.event_id);
    assert!(
        items(
            queue
                .queue_view_for_actor(&controller, Some(&other_realm))
                .await
                .unwrap()
        )
        .is_empty()
    );
    assert!(items(queue.queue_view_for_actor(&stranger, None).await.unwrap()).is_empty());

    let material = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    for request in [&first, &second] {
        let selector = arkret_wire::CurrentSelector::ModerationReport {
            event_id: request.authority_commit.event.event_id.clone(),
        };
        let entry = material
            .current_state_entries
            .iter()
            .find(|entry| {
                matches!(entry, arkret_wire::TypedCurrentRow::Value { selector: found, .. } if found == &selector)
            })
            .expect("snapshot material carries the report row");
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref,
            revision,
            value,
            ..
        } = entry;
        assert_eq!(
            source_stream_ref,
            &request.authority_commit.commit.stream_ref
        );
        assert_eq!(
            revision.commit_id,
            request.authority_commit.commit.commit_id
        );
        assert_eq!(
            value,
            &serde_json::to_value(&request.authority_commit.event.payload).unwrap()
        );
    }

    // A dismiss naming the first report resolves exactly that item and is
    // recorded as one assertion of the report's moderation_state.
    let dismiss = realm_self_event_request(
        &second,
        &reporter,
        arkret_wire::EventKind::ModerationDecision,
        serde_json::json!({
            "target_ref": first.authority_commit.event.event_id,
            "decision": "dismiss",
            "issuer_id": reporter,
            "request_canonical_digest": format!("sha256:{}", "00".repeat(32)),
        }),
    );
    uow.commit_event(dismiss.clone()).await.unwrap();
    let statuses = |view: Vec<ModerationQueueItem>| {
        view.iter()
            .map(|item| serde_json::to_value(&item.status).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        statuses(queue.queue_view_for_actor(&controller, None).await.unwrap()),
        [
            serde_json::json!("resolved"),
            serde_json::json!("submitted")
        ]
    );
    assert!(items(queue.queue_view_for_actor(&stranger, None).await.unwrap()).is_empty());

    // An issuer without a same-cut moderation capability writes nothing.
    let stranger_principal = stranger.signing_principal_id().clone();
    let unauthorized = realm_self_event_request(
        &dismiss,
        &stranger_principal,
        arkret_wire::EventKind::ModerationDecision,
        serde_json::json!({
            "target_ref": second.authority_commit.event.event_id,
            "decision": "dismiss",
            "issuer_id": stranger_principal,
            "request_canonical_digest": format!("sha256:{}", "01".repeat(32)),
        }),
    );
    assert!(uow.commit_event(unauthorized.clone()).await.is_err());
    assert!(
        store
            .committed_event(&unauthorized.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(moderation_state_rows(&pool).await, 1);

    // A require_review on the second report's target, committed after that
    // report, resolves it too.
    let review = realm_self_event_request(
        &dismiss,
        &reporter,
        arkret_wire::EventKind::ModerationDecision,
        serde_json::json!({
            "target_ref": realm_id,
            "decision": "require_review",
            "issuer_id": reporter,
            "request_canonical_digest": format!("sha256:{}", "02".repeat(32)),
        }),
    );
    uow.commit_event(review.clone()).await.unwrap();
    assert_eq!(
        statuses(queue.queue_view_for_actor(&controller, None).await.unwrap()),
        [serde_json::json!("resolved"), serde_json::json!("resolved")]
    );

    // A lift is compare-and-set on the durable moderation_state revision and
    // appends an assertion; it never removes the decision nor reopens items.
    let lift = |previous: &EventCommitRequest,
                stream_position: u64,
                commit_id: &arkret_wire::RealmCommitId| {
        realm_self_event_request(
            previous,
            &reporter,
            arkret_wire::EventKind::ModerationDecisionLift,
            serde_json::json!({
                "target_ref": realm_id,
                "decision_ref": review.authority_commit.event.event_id,
                "expected_revision": {
                    "commit_id": commit_id,
                    "stream_position": stream_position,
                },
            }),
        )
    };
    let stale = lift(&review, 0, &dismiss.authority_commit.commit.commit_id);
    let refusal = uow.commit_event(stale.clone()).await.unwrap_err();
    assert_eq!(
        refusal.conflict_code(),
        Some(coland_storage::ConflictCode::CasConflict),
        "{refusal:?}"
    );
    let current = lift(
        &review,
        review.authority_commit.commit.stream_position,
        &review.authority_commit.commit.commit_id,
    );
    uow.commit_event(current.clone()).await.unwrap();
    let material = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    let selector = arkret_wire::CurrentSelector::ModerationState {
        target_ref: realm_id.to_string(),
    };
    let Some(arkret_wire::TypedCurrentRow::Value {
        revision, value, ..
    }) = material.current_state_entries.iter().find(|entry| {
        matches!(entry, arkret_wire::TypedCurrentRow::Value { selector: found, .. } if found == &selector)
    })
    else {
        panic!("snapshot material carries the moderation_state row");
    };
    assert_eq!(
        revision.commit_id,
        current.authority_commit.commit.commit_id
    );
    let tags = value["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["tag_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut expected = vec![
        format!("{}:0", review.authority_commit.event.event_id),
        format!("{}:0", current.authority_commit.event.event_id),
    ];
    expected.sort();
    assert_eq!(tags, expected);
    assert_eq!(
        statuses(queue.queue_view_for_actor(&controller, None).await.unwrap()),
        [serde_json::json!("resolved"), serde_json::json!("resolved")]
    );

    // The root controller grants the decision action on this Realm: the
    // grantee is a moderator of the queue at the same cut.
    let root_event_ref = realm_root_authority_event_ref(&pool, &realm_id).await;
    let grant = realm_self_event_request(
        &current,
        &reporter,
        arkret_wire::EventKind::CapabilityGrant,
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer_id": controller,
                "subject": stranger,
                "actions": ["ak.moderation.decision"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "authority_event_ref": root_event_ref,
                    "authority_generation": 0
                }],
                "issued_at": arkret_canonical::format_timestamp_canonical(
                    current.authority_commit.commit.committed_at
                ),
            }
        }),
    );
    uow.commit_event(grant).await.unwrap();
    assert_eq!(
        items(queue.queue_view_for_actor(&stranger, None).await.unwrap()).len(),
        2
    );
}

async fn moderation_state_rows(pool: &coland_storage_postgres::PgPool) -> i64 {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COUNT(*) AS count FROM moderation_state_current_results")
        .get_result::<CountRow>(&mut *conn)
        .await
        .unwrap()
        .count
}

async fn realm_root_authority_event_ref(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> String {
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref
}

/// Real PostgreSQL: the exact self reads decide visibility, generation, head
/// and row on one governing cut. Non-members, unknown Realms and foreign
/// watchers collapse to not-found; a provable Realm-scope row is answered;
/// everything this Station cannot prove fails closed instead of being
/// inferred from absence.
#[tokio::test]
async fn self_current_reads_answer_only_the_provable_cut() {
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultEntry, ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
    };
    use arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody;
    use coland_storage::{AccountRealmStreamList, MediaServiceAnchorRead, SelfExactCurrentRead};

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    let other_station =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    let stranger = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        creator.station_id.clone(),
    );
    let unknown = arkret_wire::RealmId::from_event_id(&unit.transactions[1].event.event_id);
    let same_principal_other_station =
        arkret_wire::AccountId::new(creator.principal_id.clone(), other_station.clone());
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let head = &unit.transactions[6].commit;

    // Streams: the sole founder sees the Realm stream with its genesis floor.
    let AccountRealmStreamList::Listed(rows) = store
        .list_realm_streams_for_account(&realm_id, &creator, &station)
        .await
        .unwrap()
    else {
        panic!("the founding Realm stream is listable");
    };
    assert_eq!(
        rows,
        vec![arkret_wire::RealmStreamRow {
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            head_commit_ref: head.commit_id.clone(),
            next_position: 7,
            readable_floor: Some(arkret_wire::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: unit.transactions[0].commit.commit_id.clone(),
                floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
            }),
        }]
    );
    for (realm, account) in [
        (&realm_id, &stranger),
        (&realm_id, &same_principal_other_station),
        (&unknown, &creator),
    ] {
        assert_eq!(
            store
                .list_realm_streams_for_account(realm, account, &station)
                .await
                .unwrap(),
            AccountRealmStreamList::NotVisible
        );
    }
    assert!(matches!(
        store
            .list_realm_streams_for_account(&realm_id, &creator, &other_station)
            .await
            .unwrap(),
        AccountRealmStreamList::Unproved(_)
    ));

    // Exact Relation read: no row is never inferred as never_written.
    let domain = serde_json::json!({
        "domain_kind":"tuple",
        "relation_kind":"references",
        "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
        "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
    });
    let relation_request = |realm: &arkret_wire::RealmId| {
        serde_json::from_value::<ExactCurrentResultsReadRequestBody>(serde_json::json!({
            "realm_id": realm,
            "selector": {"kind":"relation","primary_conflict_domain": domain},
        }))
        .unwrap()
    };
    let exact = |request: ExactCurrentResultsReadRequestBody,
                 account: arkret_wire::AccountId,
                 issuer: arkret_wire::DidCoreId| {
        let store = store.clone();
        async move {
            store
                .exact_current_result_for_account(&request, &account, &issuer)
                .await
                .unwrap()
        }
    };
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            creator.clone(),
            station.clone()
        )
        .await,
        SelfExactCurrentRead::Unresolved(_)
    ));
    let relation_id = "ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
    let value = serde_json::json!({
        "schema":"ak.schema.relation.v1",
        "id":relation_id,
        "realm_id":realm_id,
        "effective_scope":{"kind":"realm","realm_id":realm_id},
        "relation_kind":"references",
        "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
        "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
        "state":"active",
        "created_by":unit.transactions[0].event.actor_id,
        "created_at":"2026-09-21T00:00:00.000Z"
    });
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO relation_current_results \
         (realm_id,domain_key,domain,relation_id,state,current_commit_id,current_stream_position,\
          value,updated_at) VALUES ($1,$2,$3,$4,'active',$5,6,$6,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(arkret_canonical::canonical_json_string(&domain).unwrap())
    .bind::<diesel::sql_types::Jsonb, _>(&domain)
    .bind::<Text, _>(relation_id)
    .bind::<Text, _>(head.commit_id.as_str())
    .bind::<diesel::sql_types::Jsonb, _>(&value)
    .execute(&mut conn)
    .await
    .unwrap();
    let SelfExactCurrentRead::Answer(ExactCurrentResultsReadOutcome::Present {
        realm_id: answered_realm,
        governance_generation,
        effective_stream_head,
        entry: ExactCurrentResultEntry::Relation(entry),
    }) = exact(
        relation_request(&realm_id),
        creator.clone(),
        station.clone(),
    )
    .await
    else {
        panic!("a Realm-scope Relation row is answered present");
    };
    assert_eq!(answered_realm, realm_id);
    assert_eq!(governance_generation, 0);
    assert_eq!(effective_stream_head.commit_id, head.commit_id);
    assert_eq!(effective_stream_head.stream_position, 6);
    assert_eq!(entry.revision.commit_id, head.commit_id);
    assert_eq!(entry.revision.stream_position, 6);
    assert_eq!(entry.source_stream_ref, effective_stream_head.stream_ref);
    // Non-members and unknown Realms cannot distinguish present from absent.
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            same_principal_other_station,
            station.clone()
        )
        .await,
        SelfExactCurrentRead::NotFound
    ));
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            stranger.clone(),
            station.clone()
        )
        .await,
        SelfExactCurrentRead::NotFound
    ));
    assert!(matches!(
        exact(relation_request(&unknown), creator.clone(), station.clone()).await,
        SelfExactCurrentRead::NotFound
    ));
    assert!(matches!(
        exact(
            relation_request(&realm_id),
            creator.clone(),
            other_station.clone()
        )
        .await,
        SelfExactCurrentRead::Unresolved(_)
    ));
    let moderation =
        serde_json::from_value::<ExactCurrentResultsReadRequestBody>(serde_json::json!({
            "realm_id": realm_id,
            "selector": {"kind":"moderation_state","target_ref": relation_id},
        }))
        .unwrap();
    // No decision ever named the target: nothing a lift could consume, and
    // never_written is Relation-only.
    assert!(matches!(
        exact(moderation, creator.clone(), station.clone()).await,
        SelfExactCurrentRead::NotFound
    ));

    // Strand watch: only the watcher itself, only a known Strand.
    let watch = |watcher: &arkret_wire::AccountId| StrandWatchCurrentRequestBody {
        realm_id: realm_id.clone(),
        strand_id: arkret_wire::StrandId::new(
            "ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4".to_owned(),
        )
        .unwrap(),
        watcher_actor_id: arkret_wire::ActorId::account(watcher.clone()),
    };
    for (request, account) in [(watch(&stranger), &creator), (watch(&creator), &creator)] {
        assert!(matches!(
            store
                .strand_watch_current_for_account(&request, account, &station)
                .await
                .unwrap(),
            SelfExactCurrentRead::NotFound
        ));
    }

    // Media service: no accepted assignment in the visible Realm.
    for account in [&creator, &stranger] {
        assert_eq!(
            store
                .media_service_anchor_for_account(&realm_id, account, &station)
                .await
                .unwrap(),
            MediaServiceAnchorRead::NotFound
        );
    }

    // A second joined member does not move the founder's genesis floor.
    let second_member = arkret_wire::ActorId::account(stranger.clone()).to_string();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,'join',$3,6,'{\"membership\":\"join\"}'::jsonb,now())",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(&second_member)
    .bind::<Text, _>(head.commit_id.as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    let AccountRealmStreamList::Listed(streams) = store
        .list_realm_streams_for_account(&realm_id, &creator, &station)
        .await
        .unwrap()
    else {
        panic!("the founder's stream list stays proved");
    };
    assert_eq!(
        streams[0]
            .readable_floor
            .as_ref()
            .map(|floor| (floor.oldest_position, floor.floor_reason)),
        Some((0, arkret_wire::ReadableFloorReason::StreamStart))
    );
}

fn realm_event_request_as(
    previous: &EventCommitRequest,
    actor: &arkret_wire::AccountId,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
) -> EventCommitRequest {
    let realm_id = previous.authority_commit.event.realm_id.clone();
    scoped_event_request_as(
        previous,
        actor,
        kind,
        payload,
        arkret_wire::ScopeRef::Realm { realm_id },
    )
}

fn scoped_event_request_as(
    previous: &EventCommitRequest,
    actor: &arkret_wire::AccountId,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
    scope: arkret_wire::ScopeRef,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let previous_commit = &previous.authority_commit.commit;
    let event = event(
        kind,
        scope.clone(),
        &actor.principal_id,
        &actor.station_id,
        payload,
        previous_commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("invite:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_position = previous_commit.stream_position + 1;
    request.authority_commit.commit.previous_commit_ref = Some(previous_commit.commit_id.clone());
    request.authority_commit.commit.stream_ref =
        arkret_wire::CommitStreamRef::from_scope(&scope, None).unwrap();
    request.event.event_id = event.event_id.to_string();
    request.event.actor_id = event.actor_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].sender = Some(event.actor_id.to_string());
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    request.realm_fanout_source = matches!(scope, arkret_wire::ScopeRef::Realm { .. })
        .then(|| arkret_wire::EventAdmissionSubmission::new(event));
    seal_request_fact(request)
}

fn invite_account(principal: &str, station: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{principal}")).unwrap(),
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{station}")).unwrap(),
    )
}

fn invite_create_payload(
    invitee: &arkret_wire::AccountId,
    digest_byte: char,
    at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "invitee_account_id": invitee,
        "introduction_evidence_digest": format!("sha256:{}", digest_byte.to_string().repeat(64)),
        "expires_at": arkret_canonical::format_timestamp_canonical(
            at + chrono::TimeDelta::days(7)
        ),
    })
}

fn creator_account(unit: &OrdinaryRealmBootstrapCommitUnit) -> arkret_wire::AccountId {
    unit.transactions[0]
        .event
        .actor_id
        .as_account_id()
        .unwrap()
        .clone()
}

fn admit_joined_human<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    uow: &'a PgEventCommitUnitOfWork,
    previous: &'a EventCommitRequest,
    unit: &'a OrdinaryRealmBootstrapCommitUnit,
    label: &'a str,
    nonce: char,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = (arkret_wire::AccountId, EventCommitRequest)> + Send + 'a>,
> {
    Box::pin(async move {
        let station = &unit.transactions[0].expected_authority.service_id;
        let account = human_profile::admit(pool, station, label).await;
        admit_joined_account(pool, uow, previous, unit, account, nonce).await
    })
}

fn admit_joined_account<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    uow: &'a PgEventCommitUnitOfWork,
    previous: &'a EventCommitRequest,
    unit: &'a OrdinaryRealmBootstrapCommitUnit,
    account: arkret_wire::AccountId,
    nonce: char,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = (arkret_wire::AccountId, EventCommitRequest)> + Send + 'a>,
> {
    Box::pin(async move {
        let invite = realm_event_request_as(
            previous,
            &creator_account(unit),
            arkret_wire::EventKind::InviteCreate,
            invite_create_payload(
                &account,
                nonce,
                previous.authority_commit.commit.committed_at,
            ),
        );
        let invite = source_if_human(pool, invite).await;
        uow.commit_event(invite.clone()).await.unwrap();
        let joined = realm_event_request_as(
            &invite,
            &account,
            arkret_wire::EventKind::InviteAccept,
            serde_json::json!({
                "invite_id": arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),
                "previous_state": "pending",
                "invitee_account_id": account,
            }),
        );
        let joined = source_if_human(pool, joined).await;
        uow.commit_event(joined.clone()).await.unwrap();
        (account, joined)
    })
}

fn bootstrap_tail(unit: &OrdinaryRealmBootstrapCommitUnit) -> EventCommitRequest {
    // A request shaped on the last bootstrap Commit: the next Event of the
    // Realm stream is sequenced right after it.
    let mut request = strand_create_request(unit);
    let last = unit.transactions.last().unwrap();
    request.authority_commit.event = last.event.clone();
    request.authority_commit.commit = last.commit.clone();
    seal_request_fact(request)
}

#[derive(Debug, PartialEq, Eq)]
struct InviteFamilies {
    events: i64,
    commits: i64,
    outbox: i64,
    lifecycle: Vec<(String, String, String)>,
    directed: Vec<(String, serde_json::Value)>,
    live_target: Vec<(String, serde_json::Value, String)>,
}

async fn invite_families(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> InviteFamilies {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        subject: String,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
        #[diesel(sql_type = Text)]
        current_commit_id: String,
    }
    let mut conn = pool.get().await.unwrap();
    let events =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .count;
    let commits =
        diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .count;
    let outbox = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM event_federation_outbox o JOIN canonical_events e ON e.pk=o.event_pk WHERE e.realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap()
    .count;
    let mut rows = Vec::new();
    for sql in [
        "SELECT invite_id AS subject, value, current_commit_id \
         FROM invite_lifecycle_current_results WHERE realm_id=$1 ORDER BY invite_id",
        "SELECT invite_id AS subject, value, current_commit_id \
         FROM invite_directed_invitee_current_results WHERE realm_id=$1 ORDER BY invite_id",
        "SELECT invitee_account_id AS subject, value, current_commit_id \
         FROM invite_live_target_current_results WHERE realm_id=$1 ORDER BY invitee_account_id",
    ] {
        rows.push(
            diesel::sql_query(sql)
                .bind::<Text, _>(realm_id.as_str())
                .load::<Row>(&mut *conn)
                .await
                .unwrap(),
        );
    }
    let live_target = rows.pop().unwrap();
    let directed = rows.pop().unwrap();
    let lifecycle = rows.pop().unwrap();
    InviteFamilies {
        events,
        commits,
        outbox,
        lifecycle: lifecycle
            .into_iter()
            .map(|row| {
                (
                    row.subject,
                    row.value.as_str().unwrap().to_owned(),
                    row.current_commit_id,
                )
            })
            .collect(),
        directed: directed
            .into_iter()
            .map(|row| (row.subject, row.value))
            .collect(),
        live_target: live_target
            .into_iter()
            .map(|row| (row.subject, row.value, row.current_commit_id))
            .collect(),
    }
}

fn live_target_key(account: &arkret_wire::AccountId) -> String {
    String::from_utf8(arkret_canonical::canonical_json_bytes(account).unwrap()).unwrap()
}

async fn inject_joined_member(
    pool: &coland_storage_postgres::PgPool,
    unit: &OrdinaryRealmBootstrapCommitUnit,
    member: &arkret_wire::AccountId,
) {
    let basis = unit.transactions.last().unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,$4,$5,$6)",
    )
    .bind::<Text, _>(basis.event.realm_id.as_str())
    .bind::<Text, _>(arkret_wire::ActorId::account(member.clone()).to_string())
    .bind::<Text, _>(basis.commit.commit_id.as_str())
    .bind::<BigInt, _>(basis.commit.stream_position as i64)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<diesel::sql_types::Timestamptz, _>(basis.commit.committed_at)
    .execute(&mut *conn)
    .await
    .unwrap();
}

fn source_if_human(
    pool: &coland_storage_postgres::PgPool,
    mut request: EventCommitRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + Send + '_>> {
    Box::pin(async move {
        // Structural fixture placeholders are signed with the key material of
        // the actual accepted Human fixture. Explicit device-proof negatives
        // remain untouched; source authority still comes only from PG below.
        if request
            .authority_commit
            .event
            .producer_proof
            .as_ref()
            .is_some_and(|proof| {
                proof.jws
                    == arkret_wire::test_support::structural_only_detached_jws(&proof.event_digest)
            })
        {
            if let Some(event) =
                human_profile::sign_fixture_event(request.authority_commit.event.clone())
            {
                request.event.event_id = event.event_id.to_string();
                request.event.actor_id = event.actor_id.to_string();
                request.event.envelope = serde_json::to_value(&event).unwrap();
                request.event.canonical_bytes =
                    arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap())
                        .unwrap();
                request.event.canonical_digest = event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap();
                for projection in &mut request.projections {
                    projection.event_id = event.event_id.to_string();
                }
                if request.realm_fanout_source.is_some() {
                    request.realm_fanout_source =
                        Some(arkret_wire::EventAdmissionSubmission::new(event.clone()));
                }
                request.authority_commit.commit.event_ref = event.event_id.clone();
                request.authority_commit.event = event;
            }
        }
        if request
            .authority_commit
            .event
            .human_device_producer()
            .unwrap()
            .is_some()
        {
            source_request(pool, request).await
        } else {
            request
        }
    })
}

fn source_request(
    pool: &coland_storage_postgres::PgPool,
    mut request: EventCommitRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + Send + '_>> {
    Box::pin(async move {
        request.authority_commit.producer_signer_fact =
            PgAuthorityCommitStore { pool: pool.clone() }
                .prepare_human_signer_fact(
                    &request.authority_commit.event,
                    request.authority_commit.commit.committed_at,
                )
                .await
                .unwrap()
                .map(Into::into);
        assert!(request.authority_commit.producer_signer_fact.is_some());
        request.authority_commit.commit.producer_signer_fact_digest = request
            .authority_commit
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        seal_suite_commit(&mut request.authority_commit.commit);
        request
    })
}

fn invite_grant_request<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    previous: &'a EventCommitRequest,
    unit: &'a OrdinaryRealmBootstrapCommitUnit,
    root_event_ref: &'a str,
    subject: &'a arkret_wire::AccountId,
    actions: &'a [&'a str],
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + Send + 'a>> {
    Box::pin(async move {
        let realm_id = unit.transactions[0].event.realm_id.clone();
        let request = realm_event_request_as(
            previous,
            &creator_account(unit),
            arkret_wire::EventKind::CapabilityGrant,
            serde_json::json!({
                "grant": {
                    "schema": "ak.schema.capability.v1",
                    "realm_id": realm_id,
                    "issuer_id": unit.transactions[0].event.actor_id,
                    "subject": arkret_wire::ActorId::account(subject.clone()),
                    "actions": actions,
                    "resources": [{"kind": "realm", "realm_id": realm_id}],
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm_id,
                        "authority_event_ref": root_event_ref,
                        "authority_generation": 0
                    }],
                    "issued_at": arkret_canonical::format_timestamp_canonical(
                        previous.authority_commit.commit.committed_at
                    ),
                }
            }),
        );
        source_request(pool, request).await
    })
}

/// Assert `request` was refused with `code` and left zero writes: no Event
/// row, no Commit and no Invite typed current change.
fn assert_refused_with_zero_writes<'a>(
    uow: &'a PgEventCommitUnitOfWork,
    store: &'a PgAuthorityCommitStore,
    pool: &'a coland_storage_postgres::PgPool,
    request: &'a EventCommitRequest,
    code: coland_storage::ConflictCode,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = coland_storage::PersistenceError> + 'a>> {
    // Long scenarios reuse this assertion without duplicating its large
    // commit future in their default-stack poll frames.
    Box::pin(async move {
        let request = source_if_human(pool, request.clone()).await;
        let realm_id = &request.authority_commit.event.realm_id;
        let before = invite_families(pool, realm_id).await;
        let error = uow.commit_event(request.clone()).await.unwrap_err();
        assert_eq!(error.conflict_code(), Some(code), "{error}");
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            event_row_count(pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(invite_families(pool, realm_id).await, before);
        error
    })
}

/// Real PostgreSQL: a directed `ak.invite.create` opens the three Invite
/// families in its Commit's transaction, and a second live directed create
/// for the same account is `invite_live_target_occupied` with zero writes.
#[tokio::test]
async fn invite_create_writes_three_families_and_rejects_occupied_live_target() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let creator = creator_account(&unit);
    let bob = invite_account("bob.example", "bob-station.example");

    let create = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::InviteCreate,
        invite_create_payload(&bob, '1', at),
    );
    let outcome = uow.commit_event(create.clone()).await.unwrap();
    assert!(outcome.event_inserted);
    let create_event_id = create.authority_commit.event.event_id.clone();
    let invite_id = arkret_wire::InviteId::from_event_id(&create_event_id);
    let commit_id = create.authority_commit.commit.commit_id.to_string();
    assert!(
        store
            .committed_event(&create_event_id)
            .await
            .unwrap()
            .is_some()
    );
    let families = invite_families(&pool, &realm_id).await;
    let current = PgInviteCurrentResultStore { pool: pool.clone() };
    let in_realm = current.invites_in_realm(Some(&realm_id)).await.unwrap();
    let all_realms = current.invites_in_realm(None).await.unwrap();
    assert_eq!(in_realm.len(), 1);
    assert_eq!(all_realms.len(), 1);
    assert_eq!(in_realm[0].invite_id, invite_id);
    assert_eq!(in_realm[0].state, arkret_wire::InviteState::Pending);
    assert_eq!(
        in_realm[0].inviter,
        arkret_wire::ActorId::account(creator.clone())
    );
    assert_eq!(in_realm[0].invitee_account_id.as_ref(), Some(&bob));
    assert!(in_realm[0].third_party_invite.is_none());
    assert!(in_realm[0].accepted_claim.is_none());
    assert_eq!(
        families.lifecycle,
        vec![(
            invite_id.to_string(),
            "pending".to_owned(),
            commit_id.clone()
        )]
    );
    assert_eq!(
        families.directed,
        vec![(
            invite_id.to_string(),
            serde_json::json!({"invitee_account_id": bob})
        )]
    );
    assert_eq!(
        families.live_target,
        vec![(
            live_target_key(&bob),
            serde_json::json!({"create_event_id": create_event_id}),
            commit_id.clone()
        )]
    );
    let material = store
        .realm_state_snapshot_material(&realm_id)
        .await
        .unwrap()
        .unwrap();
    for selector in [
        arkret_wire::CurrentSelector::InviteLifecycle {
            invite_id: invite_id.clone(),
        },
        arkret_wire::CurrentSelector::InviteDirectedInvitee {
            invite_id: invite_id.clone(),
        },
        arkret_wire::CurrentSelector::InviteLiveTarget {
            invitee_account_id: bob.clone(),
        },
    ] {
        assert!(
            material.current_state_entries.iter().any(|entry| matches!(
                entry,
                arkret_wire::TypedCurrentRow::Value { selector: found, revision, source_stream_ref, .. }
                    if found == &selector
                        && revision.commit_id == create.authority_commit.commit.commit_id
                        && source_stream_ref == &create.authority_commit.commit.stream_ref
            )),
            "{selector:?}"
        );
    }

    // A second live directed create for the same account: rejected before
    // any write, with the occupant's exact create Event id.
    let second = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::InviteCreate,
        invite_create_payload(&bob, '2', at),
    );
    let error = assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &second,
        coland_storage::ConflictCode::InviteLiveTargetOccupied,
    )
    .await;
    let coland_storage::PersistenceError::Conflict(detail) = error else {
        panic!("occupied slot is a conflict");
    };
    assert_eq!(
        detail,
        format!("invite_live_target_occupied: {create_event_id}")
    );

    // Another account's slot is independent.
    let carol = invite_account("carol.example", "carol-station.example");
    let other = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::InviteCreate,
        invite_create_payload(&carol, '3', at),
    );
    uow.commit_event(other).await.unwrap();
    assert_eq!(invite_families(&pool, &realm_id).await.live_target.len(), 2);
}

/// A 3PID create has a committed create Event and pending lifecycle at one
/// cut, but no directed invitee slot. A missing policy allowlist fails before
/// any accepted Event or derived commitment index can persist.
#[tokio::test]
async fn third_party_invite_create_reads_from_committed_event_and_lifecycle() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = creator_account(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let payload = serde_json::json!({
        "third_party_invite": {
            "oob_code_kind": "offline_token",
            "token_commitment": format!("sha256:{}", "a".repeat(64)),
            "token_salt_id": "salt-test-1410",
            "token_entropy_bits": 128,
            "max_claims": 1,
            "verification_id": "ak:did_core:web:verifier.example",
            "verification_public_key": "did:web:verifier.example#invite-1"
        },
        "expires_at": arkret_canonical::format_timestamp_canonical(at + chrono::TimeDelta::hours(12))
    });
    let refused = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        payload.clone(),
    );
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &refused,
        coland_storage::ConflictCode::CapabilityDenied,
    )
    .await;

    let policy = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({
            "policy_revision": 2,
            "federation_policy": "closed",
            "allowed_third_party_invite_verification_ids": ["ak:did_core:web:verifier.example"]
        }),
    );
    uow.commit_event(policy.clone()).await.unwrap();
    let mut long_lived_payload = payload.clone();
    long_lived_payload["expires_at"] = serde_json::json!(
        arkret_canonical::format_timestamp_canonical(at + chrono::TimeDelta::days(2))
    );
    let long_lived = realm_event_request_as(
        &policy,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        long_lived_payload,
    );
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &long_lived,
        coland_storage::ConflictCode::FailedPrecondition,
    )
    .await;
    let mut conn = pool.get().await.unwrap();
    let index_before = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM invite_third_party_create_index WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(index_before.count, 0);
    drop(conn);
    let create = realm_event_request_as(
        &policy,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        payload.clone(),
    );
    uow.commit_event(create.clone()).await.unwrap();
    let mut reused_payload = payload;
    reused_payload["third_party_invite"]["token_salt_id"] =
        serde_json::json!("salt-test-2145-reuse");
    let reused_commitment = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        reused_payload,
    );
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &reused_commitment,
        coland_storage::ConflictCode::DuplicateConflict,
    )
    .await;
    let current = PgInviteCurrentResultStore { pool: pool.clone() };
    let in_realm = current.invites_in_realm(Some(&realm_id)).await.unwrap();
    let all_realms = current.invites_in_realm(None).await.unwrap();
    assert_eq!(in_realm.len(), 1);
    assert_eq!(all_realms.len(), 1);
    let invite = &in_realm[0];
    assert_eq!(
        invite.invite_id,
        arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id)
    );
    assert_eq!(invite.state, arkret_wire::InviteState::Pending);
    assert_eq!(
        invite.inviter,
        arkret_wire::ActorId::account(creator.clone())
    );
    assert!(invite.invitee_account_id.is_none());
    assert!(invite.accepted_claim.is_none());
    assert_eq!(
        invite
            .third_party_invite
            .as_ref()
            .unwrap()
            .verification_id
            .as_str(),
        "ak:did_core:web:verifier.example"
    );
    let families = invite_families(&pool, &realm_id).await;
    assert_eq!(families.lifecycle.len(), 1);
    assert!(families.directed.is_empty());
    assert!(families.live_target.is_empty());
    let mut conn = pool.get().await.unwrap();
    let index_after = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM invite_third_party_create_index \
         WHERE realm_id=$1 AND invite_id=$2 AND create_event_id=$3 AND create_commit_id=$4",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(invite.invite_id.as_str())
    .bind::<Text, _>(create.authority_commit.event.event_id.as_str())
    .bind::<Text, _>(create.authority_commit.commit.commit_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(index_after.count, 1);
    drop(conn);

    // Portable Station evidence comes from the admitted create and the current
    // allowlist under one lock, never from the caller's material or an Event id.
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_models_collaboration::governance::third_party_invite::{
        ThirdPartyInviteAcceptanceAttestation, ThirdPartyInviteAcceptanceAttestationRequestBody,
        ThirdPartyInviteProvisioningId,
    };
    let request = ThirdPartyInviteAcceptanceAttestationRequestBody {
        realm_id: realm_id.clone(),
        invite_id: invite.invite_id.clone(),
        provisioning_id: ThirdPartyInviteProvisioningId::new(format!(
            "third_party_invite_provisioning:{}",
            "A".repeat(43)
        ))
        .unwrap(),
        verification_id: "ak:did_core:web:verifier.example".parse().unwrap(),
    };
    let method = snapshot_signer_for_issuer(&unit, &creator.station_id);
    let key = ed25519_dalek::SigningKey::from_bytes(
        &device_authorization_history::STATION_AUTHORITY_SEED,
    );
    let signed = AtomicUsize::new(0);
    let sign = |attestation: &ThirdPartyInviteAcceptanceAttestation| {
        signed.fetch_add(1, Ordering::SeqCst);
        let mut proof = attestation.signature.unsigned();
        proof.payload_digest = attestation.payload_digest().unwrap();
        proof.domain = Some(
            arkret_wire::ProofContextId::THIRD_PARTY_INVITE_ACCEPTANCE_ATTESTATION_PROOF_V1.into(),
        );
        let bytes = attestation.unsigned_proof_binding_bytes(&proof).unwrap();
        Ok(proof
            .finalize(arkret_signatures::jws::sign_jws_ed25519(&bytes, &key).unwrap())
            .unwrap())
    };
    let observed = create.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let before_attestation = invite_families(&pool, &realm_id).await;
    // The observer runs inside the held cut. Natural expiry is decided by its
    // current time rather than an earlier request-arrival timestamp.
    assert!(matches!(
        current
            .third_party_invite_acceptance_attestation(
                &request,
                &creator,
                &creator.station_id,
                &method,
                &|| invite.expires_at,
                &sign,
            )
            .await,
        Err(coland_storage::PersistenceError::NotFound(_))
    ));
    assert_eq!(AtomicUsize::load(&signed, Ordering::SeqCst), 0);
    assert_eq!(invite_families(&pool, &realm_id).await, before_attestation);

    let outcome = current
        .third_party_invite_acceptance_attestation(
            &request,
            &creator,
            &creator.station_id,
            &method,
            &|| observed,
            &sign,
        )
        .await
        .unwrap();
    outcome.validate_for_request(&request).unwrap();
    let attestation = &outcome.acceptance_attestation;
    assert_eq!(
        attestation.accepted_commit_ref.commit_id,
        create.authority_commit.commit.commit_id
    );
    assert_eq!(
        attestation.accepted_commit_ref.event_id,
        create.authority_commit.event.event_id
    );
    assert_eq!(
        attestation.third_party_invite,
        invite.third_party_invite.clone().unwrap()
    );
    assert_eq!(
        attestation.expires_at,
        observed + chrono::TimeDelta::seconds(60)
    );
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &attestation.signature,
        &attestation.proof_binding_bytes().unwrap(),
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    assert_eq!(invite_families(&pool, &realm_id).await, before_attestation);
    assert_eq!(AtomicUsize::load(&signed, Ordering::SeqCst), 1);
    let wrong_author = invite_account("outsider.example", "other-station.example");
    let mut wrong_verifier = request.clone();
    wrong_verifier.verification_id = "ak:did_core:web:other-verifier.example".parse().unwrap();
    for (request, caller) in [(&request, &wrong_author), (&wrong_verifier, &creator)] {
        assert!(matches!(
            current
                .third_party_invite_acceptance_attestation(
                    request,
                    caller,
                    &creator.station_id,
                    &method,
                    &|| observed,
                    &sign,
                )
                .await,
            Err(coland_storage::PersistenceError::NotFound(_))
        ));
    }
    let remote: arkret_wire::DidCoreId = "ak:did_core:web:replica.example".parse().unwrap();
    assert!(
        current
            .third_party_invite_acceptance_attestation(
                &request,
                &creator,
                &remote,
                &method,
                &|| observed,
                &sign,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("revision_unavailable")
    );
    assert_eq!(AtomicUsize::load(&signed, Ordering::SeqCst), 1);
    // A stale projection cannot stand in for the newest accepted checkpoint.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_policy_bundle_current_results SET current_stream_position=current_stream_position+1 WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        current
            .third_party_invite_acceptance_attestation(
                &request,
                &creator,
                &creator.station_id,
                &method,
                &|| observed,
                &sign,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("revision_unavailable")
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE realm_policy_bundle_current_results SET current_stream_position=current_stream_position-1 WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(AtomicUsize::load(&signed, Ordering::SeqCst), 1);
    assert_eq!(invite_families(&pool, &realm_id).await, before_attestation);
    let removed = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":3,"federation_policy":"closed",
            "allowed_third_party_invite_verification_ids":[]}),
    );
    uow.commit_event(removed.clone()).await.unwrap();
    assert!(matches!(
        current
            .third_party_invite_acceptance_attestation(
                &request,
                &creator,
                &creator.station_id,
                &method,
                &|| removed.authority_commit.commit.committed_at,
                &sign,
            )
            .await,
        Err(coland_storage::PersistenceError::NotFound(_))
    ));
    // Revocation stops new evidence; it does not rewrite a previously issued
    // object's explicitly signed validity window.
    attestation.validate_freshness(observed).unwrap();
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "DELETE FROM invite_lifecycle_current_results WHERE realm_id=$1 AND invite_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(request.invite_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert!(
        current
            .third_party_invite_acceptance_attestation(
                &request,
                &creator,
                &creator.station_id,
                &method,
                &|| observed,
                &sign,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("revision_unavailable")
    );
    assert_eq!(AtomicUsize::load(&signed, Ordering::SeqCst), 1);
}

/// A delegated verifier serializes actual consume/delivery with the governing
/// writer, and cancellation cannot return a locked connection to the pool.
#[tokio::test]
async fn delegated_invite_provider_holds_current_cut_until_private_completion() {
    use coland_storage::ThirdPartyInviteProviderLivenessRequest;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap();
    human_profile::admit(&pool, &station, "bootstrap-actor").await;
    let unit = unit(&pool).await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm = unit.transactions[0].event.realm_id.clone();
    let creator = creator_account(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let policy = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({
            "policy_revision":2,"federation_policy":"closed",
            "allowed_third_party_invite_verification_ids":[station]
        }),
    );
    uow.commit_event(policy.clone()).await.unwrap();
    let create = realm_event_request_as(
        &policy,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        serde_json::json!({
            "third_party_invite":{
                "oob_code_kind":"offline_token",
                "token_commitment":format!("sha256:{}", "b".repeat(64)),
                "token_salt_id":"delegated-cut-salt", "token_entropy_bits":256,
                "max_claims":1, "verification_id":station,
                "verification_public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &ed25519_dalek::SigningKey::from_bytes(&[53;32]).verifying_key().to_bytes())
            },
            "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::TimeDelta::hours(1))
        }),
    );
    uow.commit_event(create.clone()).await.unwrap();
    let current = PgInviteCurrentResultStore { pool: pool.clone() };
    let original = current
        .invites_in_realm(Some(&realm))
        .await
        .unwrap()
        .remove(0);
    let request = ThirdPartyInviteProviderLivenessRequest {
        realm_id: realm.clone(),
        invite_id: original.invite_id.clone(),
        inviter_account_id: creator.clone(),
        third_party_invite: original.third_party_invite.clone().unwrap(),
        expires_at: original.expires_at,
    };
    let observed = create.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1);
    let before = invite_families(&pool, &realm).await;
    let mut wrong = request.clone();
    wrong.third_party_invite.token_salt_id = Some("another-salt".to_owned());
    assert!(
        current
            .acquire_third_party_invite_provider_liveness(&wrong, &station, &|| observed)
            .await
            .is_err()
    );
    assert!(
        current
            .acquire_third_party_invite_provider_liveness(&request, &station, &|| request
                .expires_at)
            .await
            .is_err()
    );
    let remote = "ak:did_core:web:replica.example".parse().unwrap();
    assert!(
        current
            .acquire_third_party_invite_provider_liveness(&request, &remote, &|| observed)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("revision_unavailable")
    );
    assert_eq!(invite_families(&pool, &realm).await, before);
    let guard = current
        .acquire_third_party_invite_provider_liveness(&request, &station, &|| observed)
        .await
        .unwrap();
    assert_eq!(guard.observed_at(), observed);
    let mut probe = pool.get().await.unwrap();
    let lock = diesel::sql_query(
        "SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT",
    )
    .bind::<Text, _>(realm.as_str())
    .execute(&mut *probe)
    .await;
    assert!(lock.is_err(), "a competing governing writer must wait");
    guard.finish().await.unwrap();
    diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut *probe)
        .await
        .unwrap();
    drop(probe);
    assert_eq!(invite_families(&pool, &realm).await, before);
    let guard = current
        .acquire_third_party_invite_provider_liveness(&request, &station, &|| observed)
        .await
        .unwrap();
    drop(guard);
    // Cancellation discards the session; PostgreSQL may observe EOF after the
    // task yielding, so wait only for that concrete lock release.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let mut probe = pool.get().await.unwrap();
            if diesel::sql_query(
                "SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT",
            )
            .bind::<Text, _>(realm.as_str())
            .execute(&mut *probe)
            .await
            .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let removed = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({
            "policy_revision":3,"federation_policy":"closed",
            "allowed_third_party_invite_verification_ids":[]
        }),
    );
    uow.commit_event(removed).await.unwrap();
    let after_withdrawal = invite_families(&pool, &realm).await;
    assert!(
        current
            .acquire_third_party_invite_provider_liveness(&request, &station, &|| observed)
            .await
            .is_err(),
        "activation evidence cannot override current withdrawal"
    );
    assert_eq!(invite_families(&pool, &realm).await, after_withdrawal);
}

#[tokio::test]
async fn invite_provision_proof_uses_current_accepted_device_without_root_or_document_vm() {
    use arkret_models_collaboration::governance::third_party_invite::{
        ThirdPartyInviteDeliveryTargetUri, ThirdPartyInviteOobKind,
        ThirdPartyInviteProvisionRequestBody,
    };
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let station = "ak:did_core:web:bootstrap-station.example".parse().unwrap();
    let fixture = human_profile::fixture(&station, "provision-device");
    let account = human_profile::admit(&pool, &station, "provision-device").await;
    let at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let mut request = ThirdPartyInviteProvisionRequestBody {
        request_id: "ak:request:019b6a40-0000-7000-8000-000000000001"
            .parse()
            .unwrap(),
        realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [71; 32],
        )),
        inviter_account_id: account,
        verification_id: station.clone(),
        oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
        delivery_target_uri: ThirdPartyInviteDeliveryTargetUri::new(
            "mailto:private@example.invalid",
        )
        .unwrap(),
        expires_at: at + chrono::TimeDelta::minutes(30),
        signature: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
            verification_method: fixture.history.device_verification_method.clone(),
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: at,
            domain: Some(
                arkret_wire::ProofContextId::THIRD_PARTY_INVITE_PROVISION_REQUEST_PROOF_V1.into(),
            ),
            audience: Some(arkret_wire::Audience::Single(station.to_string())),
            proof_purpose: None,
            jws: String::new(),
        },
    };
    let mut proof = request.signature.unsigned();
    proof.payload_digest = request.payload_digest().unwrap();
    let bytes = request.unsigned_proof_binding_bytes(&proof).unwrap();
    request.signature = proof
        .finalize(
            arkret_signatures::jws::sign_jws_ed25519(
                &bytes,
                &ed25519_dalek::SigningKey::from_bytes(
                    &fixture.history.founding_device_signing_seed,
                ),
            )
            .unwrap(),
        )
        .unwrap();
    request.validate_for_service(&station).unwrap();
    let current = PgInviteCurrentResultStore { pool: pool.clone() };
    let before = current.invites_in_realm(None).await.unwrap();
    let guard = current
        .acquire_third_party_invite_provision_device(&request, &station, &|| at)
        .await
        .unwrap();
    assert_eq!(guard.observed_at(), at);
    guard.finish().await.unwrap();
    let mut changed = request.clone();
    changed.request_id = "ak:request:019b6a40-0000-7000-8000-000000000002"
        .parse()
        .unwrap();
    assert!(
        current
            .acquire_third_party_invite_provision_device(&changed, &station, &|| at)
            .await
            .is_err()
    );
    let mut wrong = request.clone();
    wrong.signature.verification_method = arkret_wire::DidUrl::new(format!(
        "{}#{}",
        fixture.history.did,
        device_authorization_history::device(9)
    ))
    .unwrap();
    assert!(
        current
            .acquire_third_party_invite_provision_device(&wrong, &station, &|| at)
            .await
            .is_err()
    );
    let mut root = request.clone();
    let root_method = fixture.history.events[0]
        .producer_proof
        .as_ref()
        .unwrap()
        .verification_method
        .clone();
    root.signature.verification_method = root_method;
    assert!(
        current
            .acquire_third_party_invite_provision_device(&root, &station, &|| at)
            .await
            .is_err()
    );
    assert!(
        current
            .acquire_third_party_invite_provision_device(&request, &station, &|| at
                + chrono::TimeDelta::seconds(301))
            .await
            .is_err()
    );
    assert_eq!(
        current.invites_in_realm(None).await.unwrap().len(),
        before.len()
    );
}

fn circle_self_member_request(
    previous: &EventCommitRequest,
    creator: &arkret_wire::AccountId,
    circle_id: &arkret_wire::CircleId,
    membership: &str,
    expected: Option<serde_json::Value>,
    parent: Option<&serde_json::Value>,
) -> EventCommitRequest {
    let mut request = previous.clone();
    let realm_id = previous.authority_commit.event.realm_id.clone();
    let mut payload = serde_json::json!({
        "circle_id": circle_id,
        "member_id": arkret_wire::ActorId::account(creator.clone()),
        "membership": membership,
    });
    if let Some(expected) = expected {
        payload["expected_membership"] = expected;
    }
    if let Some(parent) = parent {
        payload["parent_membership_revision"] = parent.clone();
    }
    let event = event(
        arkret_wire::EventKind::CircleMemberState,
        arkret_wire::ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        &creator.principal_id,
        &creator.station_id,
        payload,
        previous.authority_commit.commit.committed_at,
    );
    request.authority_commit.event = event.clone();
    request.authority_commit.commit.event_ref = event.event_id.clone();
    request.authority_commit.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(format!("circle-member:{}", event.event_id).as_bytes()),
    );
    request.authority_commit.commit.stream_ref = arkret_wire::CommitStreamRef::Circle {
        realm_id,
        circle_id: circle_id.clone(),
    };
    if matches!(&previous.authority_commit.commit.stream_ref,
        arkret_wire::CommitStreamRef::Circle { circle_id: prior, .. } if prior == circle_id)
    {
        request.authority_commit.commit.stream_position =
            previous.authority_commit.commit.stream_position + 1;
        request.authority_commit.commit.previous_commit_ref =
            Some(previous.authority_commit.commit.commit_id.clone());
    } else {
        request.authority_commit.commit.stream_position = 0;
        request.authority_commit.commit.previous_commit_ref = None;
    }
    request.event.event_id = event.event_id.to_string();
    request.event.actor_id = event.actor_id.to_string();
    request.event.kind = event.kind.as_str().to_owned();
    request.event.envelope = serde_json::to_value(&event).unwrap();
    request.event.canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
    request.event.canonical_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request.projections[0].event_id = event.event_id.to_string();
    request.projections[0].event_kind = event.kind.as_str().to_owned();
    request.projections[0].sender = Some(event.actor_id.to_string());
    request.projections[0].payload = serde_json::to_value(&event.payload).unwrap();
    seal_request_fact(request)
}

#[tokio::test]
async fn relation_snapshot_carrier_keeps_circle_and_cross_realm_reference_disclosure() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let base = relation_snapshot_base(&pool).await;
    let fixture = relation_snapshot_fixture(&pool, base).await;
    assert_circle_relation_snapshot_disclosure(&pool, &fixture).await;
    assert_cross_realm_relation_snapshot_disclosure(&pool, &fixture).await;
}

struct RelationSnapshotBase {
    unit: OrdinaryRealmBootstrapCommitUnit,
    bob: arkret_wire::AccountId,
    public: EventCommitRequest,
    circle: EventCommitRequest,
}

struct RelationSnapshotFixture {
    unit: OrdinaryRealmBootstrapCommitUnit,
    bob: arkret_wire::AccountId,
    public: EventCommitRequest,
    circle: EventCommitRequest,
    relation: EventCommitRequest,
    private_id: arkret_wire::StrandId,
}

// Keep fixture phases off the parent poll frame. Deep bootstrap/join helpers
// run in immediately awaited tasks on the same default-stack runtime.
fn relation_snapshot_base(
    pool: &coland_storage_postgres::PgPool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = RelationSnapshotBase> + '_>> {
    Box::pin(async move {
        use arkret_wire::EventKind;
        human_profile::admit(
            &pool,
            &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
            "bootstrap-actor",
        )
        .await;
        let unit = unit_with_plaintext_service(&pool).await;
        let creator = creator_account(&unit);
        let realm_id = unit.transactions[0].event.realm_id.clone();
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
            .await
            .unwrap();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let join_pool = pool.clone();
        let join_unit = unit.clone();
        let (bob, joined) = tokio::spawn(async move {
            let uow = PgEventCommitUnitOfWork::new(join_pool.clone());
            admit_joined_human(
                &join_pool,
                &uow,
                &bootstrap_tail(&join_unit),
                &join_unit,
                "relation-snapshot-bob",
                'b',
            )
            .await
        })
        .await
        .unwrap();
        let public_payload =
            serde_json::to_value(&strand_create_request(&unit).authority_commit.event.payload)
                .unwrap();
        let public = realm_event_request_as(
            &joined,
            &creator,
            EventKind::StrandCreate,
            public_payload.clone(),
        );
        let public = source_if_human(&pool, public).await;
        let public = source_request(&pool, public).await;
        Box::pin(uow.commit_event(public.clone())).await.unwrap();
        let circle = realm_event_request_as(
            &public,
            &creator,
            EventKind::CircleCreate,
            serde_json::json!({
                "object": {
                    "schema": arkret_wire::SchemaId::CIRCLE_V1, "realm_id": realm_id,
                    "title": "Private relation", "display":{"short_name":"Private-relation","color_token":"blue","symbol":{"glyph":"lock"}},
                    "directory_visibility":"members", "join_rule":"public", "history_access":"since_join",
                    "state":"active", "created_by":arkret_wire::ActorId::account(creator.clone()),
                    "created_at":arkret_canonical::format_timestamp_canonical(unit.transactions[0].commit.committed_at),
                }
            }),
        );
        let circle = source_if_human(&pool, circle).await;
        Box::pin(uow.commit_event(circle.clone())).await.unwrap();
        RelationSnapshotBase {
            unit,
            bob,
            public,
            circle,
        }
    })
}

fn relation_snapshot_fixture(
    pool: &coland_storage_postgres::PgPool,
    base: RelationSnapshotBase,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = RelationSnapshotFixture> + '_>> {
    Box::pin(async move {
        use arkret_wire::{EventKind, ScopeRef, StrandId};
        let RelationSnapshotBase {
            unit,
            bob,
            public,
            circle,
        } = base;
        let creator = creator_account(&unit);
        let realm_id = unit.transactions[0].event.realm_id.clone();
        let public_id = StrandId::from_event_id(&public.authority_commit.event.event_id);
        let public_payload = serde_json::to_value(&public.authority_commit.event.payload).unwrap();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let circle_id =
            arkret_wire::CircleId::from_event_id(&circle.authority_commit.event.event_id);
        let parent = unit
            .transactions
            .iter()
            .find(|tx| tx.event.kind == EventKind::MemberState)
            .unwrap();
        let parent = serde_json::json!({"commit_id":parent.commit.commit_id,"stream_position":parent.commit.stream_position});
        let join = circle_self_member_request(
            &circle,
            &creator,
            &circle_id,
            "join",
            Some(serde_json::Value::Null),
            Some(&parent),
        );
        Box::pin(uow.commit_event(join.clone())).await.unwrap();
        let scope = ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        let mut payload = public_payload;
        payload["object"]["scope_circle_id"] = serde_json::json!(circle_id);
        payload["object"]["metadata"]["title"] = serde_json::json!("Private discussion");
        let private = scoped_event_request_as(
            &join,
            &creator,
            EventKind::StrandCreate,
            payload,
            scope.clone(),
        );
        let private = source_if_human(&pool, private).await;
        Box::pin(uow.commit_event(private.clone())).await.unwrap();
        let private_id = StrandId::from_event_id(&private.authority_commit.event.event_id);
        let domain = serde_json::json!({"domain_kind":"from","relation_kind":"confidential_discussion_of","from_ref":private_id});
        let relation = scoped_event_request_as(
            &private,
            &creator,
            EventKind::RelationCreate,
            serde_json::json!({
                "primary_conflict_domain":domain, "expected_revision":null,
                "relation":{"relation_kind":"confidential_discussion_of","scope_circle_id":circle_id,"from_ref":private_id,"to_ref":public_id},
            }),
            scope.clone(),
        );
        let relation = source_if_human(&pool, relation).await;
        Box::pin(uow.commit_event(relation.clone())).await.unwrap();
        RelationSnapshotFixture {
            unit,
            bob,
            public,
            circle,
            relation,
            private_id,
        }
    })
}

fn relation_snapshot_rows(material: &coland_storage::RealmStateSnapshotMaterial) -> usize {
    material
        .current_state_entries
        .iter()
        .filter(|row| {
            matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::Relation { .. },
                    ..
                }
            )
        })
        .count()
}

fn assert_circle_relation_snapshot_disclosure<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a RelationSnapshotFixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        use arkret_wire::{CurrentSelector, RelationId, TypedCurrentRow};
        let RelationSnapshotFixture {
            unit,
            bob,
            circle,
            relation,
            private_id,
            ..
        } = fixture;
        let creator = creator_account(unit);
        let realm_id = &unit.transactions[0].event.realm_id;
        let circle_id =
            arkret_wire::CircleId::from_event_id(&circle.authority_commit.event.event_id);
        let domain = serde_json::json!({"domain_kind":"from","relation_kind":"confidential_discussion_of","from_ref":private_id});
        let relation_id = RelationId::from_event_id(&relation.authority_commit.event.event_id);
        let current = account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(relation_snapshot_rows(&current), 1);
        let entry = current
            .current_state_entries
            .iter()
            .find(|row| {
                matches!(
                    row,
                    TypedCurrentRow::Value {
                        selector: CurrentSelector::Relation { .. },
                        ..
                    }
                )
            })
            .unwrap();
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry;
        assert_eq!(
            serde_json::to_value(selector).unwrap(),
            serde_json::json!({"kind":"relation","primary_conflict_domain":domain})
        );
        assert_eq!(
            *source_stream_ref,
            relation.authority_commit.commit.stream_ref
        );
        assert_eq!(
            revision.commit_id,
            relation.authority_commit.commit.commit_id
        );
        assert_eq!(value["id"], serde_json::json!(relation_id));
        let hidden = account_snapshot_material(&pool, &realm_id, &bob)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(relation_snapshot_rows(&hidden), 0);
        let bytes = serde_json::to_string(&serde_json::json!({"current":hidden.current_state_entries,"heads":hidden.visible_stream_heads,"floor":hidden.retention_and_history_floor})).unwrap();
        for secret in [
            circle_id.to_string(),
            private_id.to_string(),
            relation_id.to_string(),
        ] {
            assert!(!bytes.contains(&secret));
        }
    })
}

fn assert_cross_realm_relation_snapshot_disclosure<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a RelationSnapshotFixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        use arkret_wire::{EventKind, RelationId, StrandId};
        let RelationSnapshotFixture {
            unit,
            public,
            circle,
            relation,
            ..
        } = fixture;
        let creator = creator_account(unit);
        let realm_id = &unit.transactions[0].event.realm_id;
        let relation_id = RelationId::from_event_id(&relation.authority_commit.event.event_id);
        let public_id = StrandId::from_event_id(&public.authority_commit.event.event_id);
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let foreign_pool = pool.clone();
        let foreign_station = creator.station_id.clone();
        let foreign = tokio::spawn(async move {
            ordinary_realm::open_discussion_for_station(
                &foreign_pool,
                "relation-snapshot-foreign",
                &foreign_station,
                &human_profile::station_did(&foreign_station),
            )
            .await
        })
        .await
        .unwrap();
        let cross_domain = serde_json::json!({"domain_kind":"tuple","relation_kind":"references","from_ref":public_id,"to_ref":foreign.strand_id});
        let cross = realm_event_request_as(
            &circle,
            &creator,
            EventKind::RelationCreate,
            serde_json::json!({
                "primary_conflict_domain":cross_domain,"expected_revision":null,
                "relation":{"relation_kind":"references","from_ref":public_id,"to_ref":foreign.strand_id},
            }),
        );
        let cross = source_if_human(&pool, cross).await;
        uow.commit_event(cross.clone()).await.unwrap();
        let hidden_cross = account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(relation_snapshot_rows(&hidden_cross), 1);
        assert!(
            !serde_json::to_string(&hidden_cross.current_state_entries)
                .unwrap()
                .contains(foreign.strand_id.as_str())
        );
        let actor = arkret_wire::ActorId::account(creator.clone());
        let station = unit.transactions[0].expected_authority.service_id.clone();
        assert!(matches!(
            store
                .committed_event_for_member(
                    &cross.authority_commit.event.event_id,
                    &actor,
                    &station
                )
                .await
                .unwrap(),
            coland_storage::MemberCommittedEventRead::Read(view)
                if matches!(*view, arkret_wire::CommittedEventView::Withheld(_))
        ));
        // The shared ordinary-Realm helper owns a separate fixture signing registry.
        // Reuse the actually accepted foreign founder PCR/Profile in this module's
        // registry before its new invite, without treating inherited Fact as source.
        let foreign_founder =
            human_profile::admit(&pool, &creator.station_id, "ordinary-founder").await;
        assert_eq!(foreign_founder, creator_account(&foreign.unit));
        let join_pool = pool.clone();
        let join_unit = foreign.unit.clone();
        let join_head = foreign.head.clone();
        let join_creator = creator.clone();
        let (_, foreign_join) = tokio::spawn(async move {
            let uow = PgEventCommitUnitOfWork::new(join_pool.clone());
            admit_joined_account(&join_pool, &uow, &join_head, &join_unit, join_creator, 'c').await
        })
        .await
        .unwrap();
        let visible_cross = account_snapshot_material(&pool, &realm_id, &creator)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(relation_snapshot_rows(&visible_cross), 2);
        assert!(matches!(
            store
                .committed_event_for_member(
                    &cross.authority_commit.event.event_id,
                    &actor,
                    &station
                )
                .await
                .unwrap(),
            coland_storage::MemberCommittedEventRead::Read(view)
                if matches!(*view, arkret_wire::CommittedEventView::Full(_))
        ));
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
            coland_services::authority_commit::build_signed_realm_state_snapshot(
                material,
                arkret_wire::DidUrl::new("did:web:bootstrap-station.example#snapshot").unwrap(),
                &key,
                chrono::Utc::now(),
            )
            .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
        };
        let signed = store
            .issue_realm_state_snapshot_for_account(&realm_id, &creator, &station, &sign)
            .await
            .unwrap()
            .unwrap();
        let reopened = PgAuthorityCommitStore { pool: pool.clone() };
        assert_eq!(
            reopened
                .issued_realm_state_snapshot(&realm_id, &creator, &signed.snapshot_id, &station)
                .await
                .unwrap(),
            Some(signed.clone())
        );
        let leave = realm_event_request_as(
            &foreign_join,
            &creator,
            EventKind::MemberState,
            serde_json::json!({"member_id":actor,"membership":"leave"}),
        );
        let leave = source_if_human(&pool, leave).await;
        uow.commit_event(leave).await.unwrap();
        let withdrawn = reopened
            .issued_realm_state_snapshot(&realm_id, &creator, &signed.snapshot_id, &station)
            .await
            .unwrap_err();
        assert!(
            matches!(withdrawn, coland_storage::PersistenceError::SchemaViolation(reason)
        if reason == "issued snapshot is no longer provably disclosable: a signed row is no longer disclosed")
        );
        assert_eq!(
            relation_snapshot_rows(
                &account_snapshot_material(&pool, &realm_id, &creator)
                    .await
                    .unwrap()
                    .unwrap()
            ),
            1
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("UPDATE relation_current_results SET current_stream_position=current_stream_position+1 WHERE relation_id=$1")
        .bind::<Text, _>(relation_id.as_str()).execute(&mut conn).await.unwrap();
        drop(conn);
        assert!(
            account_snapshot_material(&pool, &realm_id, &creator)
                .await
                .is_err()
        );
    })
}

#[tokio::test]
async fn circle_create_and_self_join_write_same_cut_current() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = creator_account(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let object = serde_json::json!({
        "schema": arkret_wire::SchemaId::CIRCLE_V1,
        "realm_id": realm_id,
        "title": "Project Circle",
        "display": {"short_name":"Project", "color_token":"blue", "symbol":{"glyph":"lock"}},
        "directory_visibility":"members",
        "join_rule":"public",
        "history_access":"since_join",
        "state":"active",
        "created_by":arkret_wire::ActorId::account(creator.clone()),
        "created_at":arkret_canonical::format_timestamp_canonical(at)
    });
    let create = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::CircleCreate,
        serde_json::json!({"object":object.clone()}),
    );
    uow.commit_event(create.clone()).await.unwrap();
    let circle_id = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    let mut conn = pool.get().await.unwrap();
    let created = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM circle_current_results WHERE realm_id=$1 AND circle_id=$2 \
         AND current_commit_id=$3 AND source_stream_ref->>'kind'='realm'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(create.authority_commit.commit.commit_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(created.count, 1);
    drop(conn);
    let mut duplicate_object = object.clone();
    duplicate_object["title"] = serde_json::json!("Another Project Circle");
    duplicate_object["display"]["short_name"] = serde_json::json!("PROJECT");
    let duplicate = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::CircleCreate,
        serde_json::json!({"object": duplicate_object}),
    );
    let refusal = uow.commit_event(duplicate.clone()).await.unwrap_err();
    assert_eq!(
        refusal.conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert!(
        store
            .committed_event(&duplicate.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let outsider = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:circle-outsider.example").unwrap(),
        creator.station_id.clone(),
    );
    let creator_parent = {
        let creator_join = unit
            .transactions
            .iter()
            .rev()
            .find(|transaction| transaction.event.kind == arkret_wire::EventKind::MemberState)
            .expect("the bootstrap unit admits the creator's Realm join");
        serde_json::json!({
            "commit_id": creator_join.commit.commit_id,
            "stream_position": creator_join.commit.stream_position,
        })
    };
    let outsider_join = circle_self_member_request(
        &create,
        &outsider,
        &circle_id,
        "join",
        Some(serde_json::Value::Null),
        Some(&creator_parent),
    );
    let refused = uow.commit_event(outsider_join.clone()).await.unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert!(
        store
            .committed_event(&outsider_join.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let creator_actor = arkret_wire::ActorId::account(creator.clone());
    let station = unit.transactions[0].expected_authority.service_id.clone();
    let before_join = store
        .committed_event_for_member(
            &create.authority_commit.event.event_id,
            &creator_actor,
            &station,
        )
        .await
        .unwrap();
    assert!(matches!(
        before_join,
        coland_storage::MemberCommittedEventRead::Read(view)
            if matches!(*view, arkret_wire::CommittedEventView::Withheld(_))
    ));
    let join = circle_self_member_request(
        &create,
        &creator,
        &circle_id,
        "join",
        Some(serde_json::Value::Null),
        Some(&creator_parent),
    );
    uow.commit_event(join.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let joined = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM circle_member_state_current_results \
         WHERE circle_id=$1 AND member_id=$2 AND membership='join' AND current_commit_id=$3 \
         AND current_stream_position=0 AND source_stream_ref->>'kind'='circle'",
    )
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(arkret_wire::ActorId::account(creator.clone()).to_string())
    .bind::<Text, _>(join.authority_commit.commit.commit_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(joined.count, 1);
    drop(conn);
    let after_join = store
        .committed_event_for_member(
            &create.authority_commit.event.event_id,
            &creator_actor,
            &station,
        )
        .await
        .unwrap();
    assert!(matches!(
        after_join,
        coland_storage::MemberCommittedEventRead::Read(view)
            if matches!(*view, arkret_wire::CommittedEventView::Full(_))
    ));
    // The Account detail freezes Realm and joined Circle windows at one cut.
    // The typed current and signed head keep both independent stream heads.
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &station);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    let request = coland_storage::AccountRealmWindowRequest {
        realm_id: realm_id.clone(),
        account: creator.clone(),
        issuer: station.clone(),
        window_limit: 20,
        window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
        expires_at_ms: now_ms + 300_000,
        now_ms,
        byte_budget: 7 * 1024 * 1024,
        delivered_heads: Vec::new(),
        selected_stream_refs: None,
    };
    let frozen = store
        .freeze_account_realm_window(&request, &sign)
        .await
        .unwrap()
        .unwrap();
    assert!(!frozen.streams_limited);
    assert_eq!(frozen.current_stream_heads.len(), 2);
    let windows = std::iter::once(&frozen.window)
        .chain(frozen.additional_windows.iter())
        .collect::<Vec<_>>();
    assert_eq!(windows.len(), 2);
    assert!(windows.iter().all(|window| window.complete));
    assert!(windows.iter().any(|window| matches!(
        window.stream_ref,
        arkret_wire::CommitStreamRef::Realm { .. }
    )));
    assert!(windows.iter().any(|window| matches!(
        window.stream_ref,
        arkret_wire::CommitStreamRef::Circle { .. }
    )));
    assert!(frozen.current_state_entries.iter().any(|row| matches!(
        row,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CircleMemberState { .. },
            ..
        }
    )));
    let signed = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &station, &sign)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signed.visible_stream_heads, frozen.current_stream_heads);
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &signed.snapshot_id, &station)
            .await
            .unwrap(),
        Some(signed)
    );
    let selected = store
        .freeze_account_realm_window(
            &coland_storage::AccountRealmWindowRequest {
                selected_stream_refs: Some(vec![arkret_wire::CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle_id.clone(),
                }]),
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request.clone()
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        selected.window.stream_ref,
        arkret_wire::CommitStreamRef::Circle { .. }
    ));
    assert!(selected.additional_windows.is_empty());
    assert_eq!(selected.current_stream_heads.len(), 2);
    let scan_request = arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction: arkret_wire::StreamScanDirection::After(Some(
            create.authority_commit.commit.stream_position - 1,
        )),
        limit: 1,
    };
    let coland_storage::AccountStreamScan::Page(page) = store
        .scan_stream_for_account(&scan_request, &creator, &station)
        .await
        .unwrap()
    else {
        panic!("Circle member has a proved Realm stream page");
    };
    assert!(matches!(
        page.committed_events.as_slice(),
        [arkret_wire::CommittedEventView::Full(view)]
            if view.event.event_id == create.authority_commit.event.event_id
    ));

    let stale = circle_self_member_request(
        &join,
        &creator,
        &circle_id,
        "leave",
        Some(serde_json::json!("leave")),
        None,
    );
    let refused = uow.commit_event(stale.clone()).await.unwrap_err();
    assert_eq!(
        refused.conflict_code(),
        Some(coland_storage::ConflictCode::FailedPrecondition)
    );
    assert!(
        store
            .committed_event(&stale.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    let mut conn = pool.get().await.unwrap();
    let unchanged = diesel::sql_query(
        "SELECT COUNT(*) AS count FROM circle_member_state_current_results \
         WHERE circle_id=$1 AND member_id=$2 AND membership='join' AND current_commit_id=$3",
    )
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(arkret_wire::ActorId::account(creator.clone()).to_string())
    .bind::<Text, _>(join.authority_commit.commit.commit_id.as_str())
    .get_result::<CountRow>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(unchanged.count, 1);
    drop(conn);
    let leave = circle_self_member_request(
        &join,
        &creator,
        &circle_id,
        "leave",
        Some(serde_json::json!("join")),
        None,
    );
    uow.commit_event(leave).await.unwrap();
    let after_revocation = store
        .freeze_account_realm_window(
            &coland_storage::AccountRealmWindowRequest {
                delivered_heads: frozen.current_stream_heads.clone(),
                window_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                ..request
            },
            &sign,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(after_revocation.additional_windows.is_empty());
    assert!(
        after_revocation
            .current_stream_heads
            .iter()
            .all(|head| matches!(head.stream_ref, arkret_wire::CommitStreamRef::Realm { .. }))
    );
    assert!(
        !after_revocation
            .current_state_entries
            .iter()
            .any(|row| matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::Circle { .. }
                        | arkret_wire::CurrentSelector::CircleMemberState { .. },
                    ..
                }
            ))
    );
    let after_leave = store
        .committed_event_for_member(
            &create.authority_commit.event.event_id,
            &creator_actor,
            &station,
        )
        .await
        .unwrap();
    assert!(matches!(
        after_leave,
        coland_storage::MemberCommittedEventRead::Read(view)
            if matches!(*view, arkret_wire::CommittedEventView::Withheld(_))
    ));
}

/// Real PostgreSQL: the same-cut evaluator refuses an actor without an
/// authorizing action (and a non-member) with `capability_denied` and zero
/// writes, admits a joined member once the root grants `ak.invite.create`,
/// and a grant revoked ahead of the create at the same head leaves the
/// create refused with zero writes.
#[tokio::test]
async fn invite_create_without_invite_capability_is_capability_denied_with_zero_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = invite_capability_fixture(&pool).await;
    assert_invite_initial_capability_denials(&pool, &fixture).await;
    let revoke = assert_invite_sequenced_revocation(&pool, &fixture).await;
    assert_invite_racing_revocation(&pool, &fixture, &revoke).await;
}

struct InviteCapabilityFixture {
    unit: OrdinaryRealmBootstrapCommitUnit,
    member: arkret_wire::AccountId,
    stranger: arkret_wire::AccountId,
    bob: arkret_wire::AccountId,
    tail: EventCommitRequest,
}

fn invite_capability_fixture(
    pool: &coland_storage_postgres::PgPool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = InviteCapabilityFixture> + '_>> {
    Box::pin(async move {
        human_profile::admit(
            &pool,
            &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
            "bootstrap-actor",
        )
        .await;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let unit = unit(&pool).await;
        let at = unit.transactions[0].commit.committed_at;
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap();
        let station = unit.transactions[0].expected_authority.service_id.clone();
        let member = accepted_pcr_account::accepted_pcr_account(
            &pool,
            device_authorization_history::did_web_station(&station),
        )
        .await
        .as_account_id()
        .expect("accepted PCR has an Account")
        .clone();
        let stranger = human_profile::admit(&pool, &station, "message-stranger").await;
        let bob = invite_account("bob.example", "bob-station.example");
        inject_joined_member(&pool, &unit, &member).await;
        let tail = bootstrap_tail(&unit);
        InviteCapabilityFixture {
            unit,
            member,
            stranger,
            bob,
            tail,
        }
    })
}

fn assert_invite_initial_capability_denials<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a InviteCapabilityFixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let InviteCapabilityFixture {
            unit,
            member,
            stranger,
            bob,
            tail,
        } = fixture;
        let at = unit.transactions[0].commit.committed_at;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        for actor in [&member, &stranger] {
            let denied = realm_event_request_as(
                &tail,
                actor,
                arkret_wire::EventKind::InviteCreate,
                invite_create_payload(&bob, '4', at),
            );
            let denied = source_if_human(&pool, denied).await;
            assert_refused_with_zero_writes(
                &uow,
                &store,
                &pool,
                &denied,
                coland_storage::ConflictCode::CapabilityDenied,
            )
            .await;
        }
    })
}

fn assert_invite_sequenced_revocation<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a InviteCapabilityFixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + 'a>> {
    Box::pin(async move {
        let InviteCapabilityFixture {
            unit,
            member,
            bob,
            tail,
            ..
        } = fixture;
        let at = unit.transactions[0].commit.committed_at;
        let realm_id = &unit.transactions[0].event.realm_id;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let root_event_ref = realm_root_authority_event_ref(&pool, &realm_id).await;
        let grant = invite_grant_request(
            &pool,
            &tail,
            &unit,
            &root_event_ref,
            &member,
            &["ak.invite.create"],
        )
        .await;
        uow.commit_event(grant.clone()).await.unwrap();
        let grant_id = arkret_wire::GrantId::from_event_id(&grant.authority_commit.event.event_id);

        // The member's create is prepared against the grant's head, but the
        // root's revoke of that grant commits at the same head first: the create
        // cannot commit on that head, and sequenced after the revoke it is
        // refused by the evaluator at its own cut.
        let prepared = realm_event_request_as(
            &grant,
            &member,
            arkret_wire::EventKind::InviteCreate,
            invite_create_payload(&bob, '5', at),
        );
        let prepared = source_if_human(&pool, prepared).await;
        let revoke = realm_event_request_as(
            &grant,
            &creator_account(&unit),
            arkret_wire::EventKind::CapabilityRevoke,
            serde_json::json!({
                "grant_id": grant_id,
                "expected_revision": {
                    "commit_id": grant.authority_commit.commit.commit_id,
                    "stream_position": grant.authority_commit.commit.stream_position,
                }
            }),
        );
        let revoke = source_if_human(&pool, revoke).await;
        uow.commit_event(revoke.clone()).await.unwrap();
        assert_refused_with_zero_writes(
            &uow,
            &store,
            &pool,
            &prepared,
            coland_storage::ConflictCode::TemporarilyUnavailable,
        )
        .await;
        let resequenced = realm_event_request_as(
            &revoke,
            &member,
            arkret_wire::EventKind::InviteCreate,
            invite_create_payload(&bob, '5', at),
        );
        let resequenced = source_if_human(&pool, resequenced).await;
        assert_eq!(
            resequenced.authority_commit.event,
            prepared.authority_commit.event
        );
        assert_refused_with_zero_writes(
            &uow,
            &store,
            &pool,
            &resequenced,
            coland_storage::ConflictCode::CapabilityDenied,
        )
        .await;
        revoke
    })
}

fn assert_invite_racing_revocation<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a InviteCapabilityFixture,
    revoke: &'a EventCommitRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let InviteCapabilityFixture {
            unit, member, bob, ..
        } = fixture;
        let at = unit.transactions[0].commit.committed_at;
        let realm_id = &unit.transactions[0].event.realm_id;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let root_event_ref = realm_root_authority_event_ref(&pool, realm_id).await;
        // Racing a fresh grant's revoke against a create on one head leaves one
        // winner; whichever order commits, the create never survives a revoke
        // that precedes it.
        // A distinct grant body: the first grant's exact Event is already committed.
        let regrant = invite_grant_request(
            &pool,
            &revoke,
            &unit,
            &root_event_ref,
            &member,
            &["ak.invite.create", "ak.invite.revoke"],
        )
        .await;
        uow.commit_event(regrant.clone()).await.unwrap();
        let regrant_id =
            arkret_wire::GrantId::from_event_id(&regrant.authority_commit.event.event_id);
        let racing_create = realm_event_request_as(
            &regrant,
            &member,
            arkret_wire::EventKind::InviteCreate,
            invite_create_payload(&bob, '6', at),
        );
        let racing_create = source_if_human(&pool, racing_create).await;
        let racing_revoke = realm_event_request_as(
            &regrant,
            &creator_account(&unit),
            arkret_wire::EventKind::CapabilityRevoke,
            serde_json::json!({
                "grant_id": regrant_id,
                "expected_revision": {
                    "commit_id": regrant.authority_commit.commit.commit_id,
                    "stream_position": regrant.authority_commit.commit.stream_position,
                }
            }),
        );
        let racing_revoke = source_if_human(&pool, racing_revoke).await;
        let create_uow = PgEventCommitUnitOfWork::new(pool.clone());
        let revoke_uow = PgEventCommitUnitOfWork::new(pool.clone());
        let (create_result, revoke_result) = tokio::join!(
            create_uow.commit_event(racing_create.clone()),
            revoke_uow.commit_event(racing_revoke.clone())
        );
        match (create_result, revoke_result) {
            (Ok(_), Err(error)) => {
                assert_eq!(
                    error.conflict_code(),
                    Some(coland_storage::ConflictCode::TemporarilyUnavailable)
                );
                let after = realm_event_request_as(
                    &racing_create,
                    &creator_account(&unit),
                    arkret_wire::EventKind::CapabilityRevoke,
                    serde_json::to_value(&racing_revoke.authority_commit.event.payload).unwrap(),
                );
                let after = source_if_human(&pool, after).await;
                let after = source_request(&pool, after).await;
                uow.commit_event(after).await.unwrap();
                assert_eq!(invite_families(&pool, &realm_id).await.lifecycle.len(), 1);
            }
            (Err(error), Ok(_)) => {
                assert_eq!(
                    error.conflict_code(),
                    Some(coland_storage::ConflictCode::TemporarilyUnavailable)
                );
                let after = realm_event_request_as(
                    &racing_revoke,
                    &member,
                    arkret_wire::EventKind::InviteCreate,
                    invite_create_payload(&bob, '6', at),
                );
                let after = source_if_human(&pool, after).await;
                assert_refused_with_zero_writes(
                    &uow,
                    &store,
                    &pool,
                    &after,
                    coland_storage::ConflictCode::CapabilityDenied,
                )
                .await;
                assert!(invite_families(&pool, &realm_id).await.lifecycle.is_empty());
            }
            (create, revoke) => panic!(
                "expected exactly one winner: create ok={} revoke ok={}",
                create.is_ok(),
                revoke.is_ok()
            ),
        }
    })
}

/// Real PostgreSQL: `ak.invite.revoke` and `ak.invite.cancel` move the
/// lifecycle only by exact `previous_state` CAS, release the live-target slot
/// on leaving the live set (and never on `send_failed`), and a released slot
/// accepts a fresh directed create for the same account.
#[tokio::test]
async fn invite_revoke_releases_live_target_and_stale_previous_state_fails() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let creator = creator_account(&unit);
    let bob = invite_account("bob.example", "bob-station.example");
    let slot = live_target_key(&bob);
    let slot_value = |families: &InviteFamilies| {
        families
            .live_target
            .iter()
            .find(|(key, ..)| key == &slot)
            .map(|(_, value, commit)| (value.clone(), commit.clone()))
            .unwrap()
    };
    let lifecycle_of = |families: &InviteFamilies, invite_id: &arkret_wire::InviteId| {
        families
            .lifecycle
            .iter()
            .find(|(id, ..)| id == invite_id.as_str())
            .map(|(_, state, _)| state.clone())
            .unwrap()
    };

    let create = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::InviteCreate,
        invite_create_payload(&bob, '1', at),
    );

    let create = source_if_human(&pool, create).await;
    uow.commit_event(create.clone()).await.unwrap();
    let first_event_id = create.authority_commit.event.event_id.clone();
    let first = arkret_wire::InviteId::from_event_id(&first_event_id);
    let revoke = |previous: &EventCommitRequest, payload: serde_json::Value| {
        realm_event_request_as(
            previous,
            &creator,
            arkret_wire::EventKind::InviteRevoke,
            payload,
        )
    };

    // A declared pre-state that is not the frozen register is refused.
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &revoke(
            &create,
            serde_json::json!({
                "invite_id": first, "previous_state": "claimed",
                "invitee_account_id": bob, "target_state": "revoked"
            }),
        ),
        coland_storage::ConflictCode::FailedPrecondition,
    )
    .await;

    // send_failed keeps the Invite live: the slot is not released.
    let send_failed = revoke(
        &create,
        serde_json::json!({
            "invite_id": first, "previous_state": "pending", "target_state": "send_failed",
            "reason_code": "delivery_target_unreachable"
        }),
    );
    let send_failed = source_if_human(&pool, send_failed).await;
    uow.commit_event(send_failed.clone()).await.unwrap();
    let families = invite_families(&pool, &realm_id).await;
    assert_eq!(lifecycle_of(&families, &first), "send_failed");
    assert_eq!(
        slot_value(&families),
        (
            serde_json::json!({"create_event_id": first_event_id}),
            create.authority_commit.commit.commit_id.to_string()
        )
    );

    // The register moved: the old declared pre-state is now stale.
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &revoke(
            &send_failed,
            serde_json::json!({
                "invite_id": first, "previous_state": "pending",
                "invitee_account_id": bob, "target_state": "revoked"
            }),
        ),
        coland_storage::ConflictCode::FailedPrecondition,
    )
    .await;
    // A directed Invite cannot keep its slot by omitting its invitee.
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &revoke(
            &send_failed,
            serde_json::json!({
                "invite_id": first, "previous_state": "send_failed", "target_state": "revoked"
            }),
        ),
        coland_storage::ConflictCode::InviteDirectedInviteeMismatch,
    )
    .await;

    let revoked = revoke(
        &send_failed,
        serde_json::json!({
            "invite_id": first, "previous_state": "send_failed",
            "invitee_account_id": bob, "target_state": "revoked"
        }),
    );
    let revoked = source_if_human(&pool, revoked).await;
    uow.commit_event(revoked.clone()).await.unwrap();
    let families = invite_families(&pool, &realm_id).await;
    assert_eq!(lifecycle_of(&families, &first), "revoked");
    assert_eq!(
        slot_value(&families),
        (
            serde_json::Value::Null,
            revoked.authority_commit.commit.commit_id.to_string()
        )
    );
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &revoke(
            &revoked,
            serde_json::json!({
                "invite_id": first, "previous_state": "pending",
                "invitee_account_id": bob, "target_state": "expired"
            }),
        ),
        coland_storage::ConflictCode::InviteAlreadyTerminal,
    )
    .await;

    // The released slot is a reusable register: a fresh create re-occupies it.
    let reinvite = realm_event_request_as(
        &revoked,
        &creator,
        arkret_wire::EventKind::InviteCreate,
        invite_create_payload(&bob, '2', at),
    );
    let reinvite = source_if_human(&pool, reinvite).await;
    uow.commit_event(reinvite.clone()).await.unwrap();
    let second_event_id = reinvite.authority_commit.event.event_id.clone();
    let second = arkret_wire::InviteId::from_event_id(&second_event_id);
    assert_eq!(
        slot_value(&invite_families(&pool, &realm_id).await).0,
        serde_json::json!({"create_event_id": second_event_id})
    );

    // Cancel: the invitee binding is exact, the invitee may only decline, and
    // the inviter's cancel releases the slot.
    let cancel = |previous: &EventCommitRequest,
                  actor: &arkret_wire::AccountId,
                  invitee: &arkret_wire::AccountId,
                  target: &str| {
        realm_event_request_as(
            previous,
            actor,
            arkret_wire::EventKind::InviteCancel,
            serde_json::json!({
                "invite_id": second, "previous_state": "pending",
                "invitee_account_id": invitee, "target_state": target
            }),
        )
    };
    let mallory = invite_account("mallory.example", "bob-station.example");
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &cancel(&reinvite, &creator, &mallory, "revoked"),
        coland_storage::ConflictCode::InviteDirectedInviteeMismatch,
    )
    .await;
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &cancel(&reinvite, &bob, &bob, "revoked"),
        coland_storage::ConflictCode::CapabilityDenied,
    )
    .await;
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &cancel(&reinvite, &creator, &bob, "rejected"),
        coland_storage::ConflictCode::CapabilityDenied,
    )
    .await;
    let declined = cancel(&reinvite, &bob, &bob, "rejected");
    uow.commit_event(declined.clone()).await.unwrap();
    let families = invite_families(&pool, &realm_id).await;
    assert_eq!(lifecycle_of(&families, &second), "rejected");
    assert_eq!(slot_value(&families).0, serde_json::Value::Null);
    assert_refused_with_zero_writes(
        &uow,
        &store,
        &pool,
        &cancel(&declined, &creator, &bob, "revoked"),
        coland_storage::ConflictCode::InviteAlreadyTerminal,
    )
    .await;

    let third = realm_event_request_as(
        &declined,
        &creator,
        arkret_wire::EventKind::InviteCreate,
        invite_create_payload(&bob, '3', at),
    );

    let third = source_if_human(&pool, third).await;
    uow.commit_event(third.clone()).await.unwrap();
    let third_id = arkret_wire::InviteId::from_event_id(&third.authority_commit.event.event_id);
    let cancelled = realm_event_request_as(
        &third,
        &creator,
        arkret_wire::EventKind::InviteCancel,
        serde_json::json!({
            "invite_id": third_id, "previous_state": "pending",
            "invitee_account_id": bob, "target_state": "revoked"
        }),
    );
    let cancelled = source_if_human(&pool, cancelled).await;
    uow.commit_event(cancelled).await.unwrap();
    let families = invite_families(&pool, &realm_id).await;
    assert_eq!(lifecycle_of(&families, &third_id), "revoked");
    assert_eq!(slot_value(&families).0, serde_json::Value::Null);
    assert_eq!(families.lifecycle.len(), 3);
    assert_eq!(families.directed.len(), 3);
}

#[derive(Debug, PartialEq, Eq)]
struct MessageFamilies {
    events: i64,
    revisions: Vec<(String, String, serde_json::Value)>,
    redactions: Vec<(String, String, serde_json::Value)>,
}

async fn message_families(
    pool: &coland_storage_postgres::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> MessageFamilies {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        subject: String,
        #[diesel(sql_type = Text)]
        current_commit_id: String,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let events =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<CountRow>(&mut *conn)
            .await
            .unwrap()
            .count;
    let mut families = Vec::new();
    for sql in [
        "SELECT message_id AS subject, current_commit_id, value \
         FROM message_revision_current_results WHERE realm_id=$1 ORDER BY message_id",
        "SELECT target_ref AS subject, current_commit_id, value \
         FROM object_redaction_current_results WHERE realm_id=$1 ORDER BY target_ref",
    ] {
        families.push(
            diesel::sql_query(sql)
                .bind::<Text, _>(realm_id.as_str())
                .load::<Row>(&mut *conn)
                .await
                .unwrap()
                .into_iter()
                .map(|row| (row.subject, row.current_commit_id, row.value))
                .collect::<Vec<_>>(),
        );
    }
    let redactions = families.pop().unwrap();
    let revisions = families.pop().unwrap();
    MessageFamilies {
        events,
        revisions,
        redactions,
    }
}

/// Assert `request` was refused and left zero writes: no Event row, no
/// Commit and no `message_revision` or `object_redaction` change.
fn assert_message_write_refused<'a>(
    uow: &'a PgEventCommitUnitOfWork,
    store: &'a PgAuthorityCommitStore,
    pool: &'a coland_storage_postgres::PgPool,
    request: &'a EventCommitRequest,
    code: Option<coland_storage::ConflictCode>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = coland_storage::PersistenceError> + 'a>> {
    Box::pin(async move {
        let request = source_if_human(pool, request.clone()).await;
        let realm_id = &request.authority_commit.event.realm_id;
        let before = message_families(pool, realm_id).await;
        let error = uow.commit_event(request.clone()).await.unwrap_err();
        assert_eq!(error.conflict_code(), code, "{error}");
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            event_row_count(pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(message_families(pool, realm_id).await, before);
        error
    })
}

fn plain_revision(message_id: &arkret_wire::MessageId, body: &str) -> serde_json::Value {
    serde_json::json!({
        "message_id": message_id,
        "content": {"kind": "ak.content.text", "body": body, "format": "plain"}
    })
}

/// Real PostgreSQL: `ak.message.revise` is decided at the accepting cut. A
/// joined member without an edit action, a stranger, and a member holding only
/// `ak.message.revise.own` on another author's Message are `capability_denied`,
/// and an author's own edit after its edit window closed is refused;
/// a revise built on a stale stream head, a body outside the create content
/// gate and a revise of a redacted Message are refused. Every refusal leaves
/// zero writes. The author's revise, and a member's revise under a granted
/// `ak.message.revise`, each replace the exact `message_revision` row with the
/// revise carrier at their own covering Commit.
#[tokio::test]
async fn message_revise_replaces_exact_revision_and_rejects_foreign_editor() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = message_revision_fixture(&pool).await;
    let revised = assert_message_revision_carriers(&pool, &fixture).await;
    let moderated = assert_message_revision_editor_grants(&pool, &fixture, &revised).await;
    assert_message_revision_window_and_redaction(&pool, &fixture, &moderated).await;
}

struct MessageRevisionFixture {
    unit: OrdinaryRealmBootstrapCommitUnit,
    strand_id: arkret_wire::StrandId,
    created: EventCommitRequest,
}

fn message_revision_fixture(
    pool: &coland_storage_postgres::PgPool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = MessageRevisionFixture> + '_>> {
    Box::pin(async move {
        human_profile::admit(
            &pool,
            &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
            "bootstrap-actor",
        )
        .await;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let unit = unit_with_plaintext_service(&pool).await;
        let at = unit.transactions[0].commit.committed_at;
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let strand = strand_create_request(&unit);
        uow.commit_event(strand.clone()).await.unwrap();
        let strand_id =
            arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
        let default = set_default_strand_request(&strand, &strand_id, None);
        let default = source_if_human(&pool, default).await;
        uow.commit_event(default.clone()).await.unwrap();
        let created = message_create_request(&default, &strand_id, "hello");
        let created = source_if_human(&pool, created).await;
        uow.commit_event(created.clone()).await.unwrap();
        MessageRevisionFixture {
            unit,
            strand_id,
            created,
        }
    })
}

fn assert_message_revision_carriers<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a MessageRevisionFixture,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + 'a>> {
    Box::pin(async move {
        let MessageRevisionFixture { unit, created, .. } = fixture;
        let realm_id = &unit.transactions[0].event.realm_id;
        let creator = creator_account(unit);
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let message_id =
            arkret_wire::MessageId::from_event_id(&created.authority_commit.event.event_id);

        // The author's revise replaces the create carrier at its own Commit.
        let revised = realm_event_request_as(
            &created,
            &creator,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&message_id, "hello, edited"),
        );
        let revised = source_if_human(&pool, revised).await;
        uow.commit_event(revised.clone()).await.unwrap();
        let families = message_families(&pool, &realm_id).await;
        assert_eq!(
            families.revisions,
            vec![(
                message_id.to_string(),
                revised.authority_commit.commit.commit_id.to_string(),
                plain_revision(&message_id, "hello, edited"),
            )]
        );
        let snapshot = store
            .realm_state_snapshot_material(&realm_id)
            .await
            .unwrap()
            .unwrap();
        assert!(snapshot.current_state_entries.iter().any(|entry| matches!(
            entry,
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MessageRevision { message_id: found },
                revision,
                value,
                ..
            } if found == &message_id
                && revision.commit_id == revised.authority_commit.commit.commit_id
                && value == &plain_revision(&message_id, "hello, edited")
        )));

        // A revise built on the create's head cannot commit on it once the
        // author's revise took that position.
        let stale = realm_event_request_as(
            &created,
            &creator,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&message_id, "stale edit"),
        );
        let stale = source_if_human(&pool, stale).await;
        assert_message_write_refused(
            &uow,
            &store,
            &pool,
            &stale,
            Some(coland_storage::ConflictCode::TemporarilyUnavailable),
        )
        .await;

        // Unsupported mentions and metadata remain outside the revision carrier.
        let mut mentioned = plain_revision(&message_id, "@bob");
        mentioned["content"]["mentions"] =
            serde_json::json!([{"target_id": "ak:did_core:web:bob.example"}]);
        for payload in [
            mentioned,
            serde_json::json!({
                "message_id": message_id,
                "content": {"kind": "ak.content.text", "body": "meta", "format": "plain"},
                "metadata": {"title": "x"}
            }),
        ] {
            let refused = realm_event_request_as(
                &revised,
                &creator,
                arkret_wire::EventKind::MessageRevise,
                payload,
            );
            let refused = source_if_human(&pool, refused).await;
            let before = message_families(&pool, &realm_id).await;
            assert!(uow.commit_event(refused.clone()).await.is_err());
            assert_eq!(message_families(&pool, &realm_id).await, before);
        }

        let markdown_payload = serde_json::json!({
            "message_id": message_id,
            "content": {"kind": "ak.content.text", "body": "**edited**", "format": "markdown"}
        });
        let revised = realm_event_request_as(
            &revised,
            &creator,
            arkret_wire::EventKind::MessageRevise,
            markdown_payload.clone(),
        );
        let revised = source_if_human(&pool, revised).await;
        uow.commit_event(revised.clone()).await.unwrap();
        assert_eq!(
            message_families(&pool, &realm_id).await.revisions,
            vec![(
                message_id.to_string(),
                revised.authority_commit.commit.commit_id.to_string(),
                markdown_payload
            )]
        );

        revised
    })
}

fn assert_message_revision_editor_grants<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a MessageRevisionFixture,
    revised: &'a EventCommitRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = EventCommitRequest> + 'a>> {
    Box::pin(async move {
        let unit = &fixture.unit;
        let realm_id = &unit.transactions[0].event.realm_id;
        let message_id =
            arkret_wire::MessageId::from_event_id(&fixture.created.authority_commit.event.event_id);
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let station = unit.transactions[0].expected_authority.service_id.clone();
        let (member, membership_head) =
            admit_joined_human(&pool, &uow, &revised, &unit, "message-member", 'a').await;
        let stranger = invite_account(
            "stranger.example",
            &station.as_str()["ak:did_core:web:".len()..],
        );
        for actor in [&member, &stranger] {
            let foreign = realm_event_request_as(
                &membership_head,
                actor,
                arkret_wire::EventKind::MessageRevise,
                plain_revision(&message_id, "not yours"),
            );
            let foreign = source_if_human(&pool, foreign).await;
            assert_message_write_refused(
                &uow,
                &store,
                &pool,
                &foreign,
                Some(coland_storage::ConflictCode::CapabilityDenied),
            )
            .await;
        }

        // `.own` authorizes only the author: the member's grant of it is no
        // edit right over the creator's Message.
        let root_event_ref = realm_root_authority_event_ref(&pool, &realm_id).await;
        let own = invite_grant_request(
            &pool,
            &membership_head,
            &unit,
            &root_event_ref,
            &member,
            &["ak.message.revise.own"],
        )
        .await;
        uow.commit_event(own.clone()).await.unwrap();
        let foreign = realm_event_request_as(
            &own,
            &member,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&message_id, "own is not others"),
        );
        let foreign = source_if_human(&pool, foreign).await;
        assert_message_write_refused(
            &uow,
            &store,
            &pool,
            &foreign,
            Some(coland_storage::ConflictCode::CapabilityDenied),
        )
        .await;

        // The unqualified action is an edit right over any Message.
        let broad = invite_grant_request(
            &pool,
            &own,
            &unit,
            &root_event_ref,
            &member,
            &["ak.message.revise"],
        )
        .await;
        uow.commit_event(broad.clone()).await.unwrap();
        let moderated = realm_event_request_as(
            &broad,
            &member,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&message_id, "moderated"),
        );
        let moderated = source_if_human(&pool, moderated).await;
        uow.commit_event(moderated.clone()).await.unwrap();
        assert_eq!(
            message_families(&pool, &realm_id).await.revisions,
            vec![(
                message_id.to_string(),
                moderated.authority_commit.commit.commit_id.to_string(),
                plain_revision(&message_id, "moderated"),
            )]
        );

        moderated
    })
}

fn assert_message_revision_window_and_redaction<'a>(
    pool: &'a coland_storage_postgres::PgPool,
    fixture: &'a MessageRevisionFixture,
    moderated: &'a EventCommitRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let MessageRevisionFixture {
            unit,
            strand_id,
            created,
        } = fixture;
        let realm_id = &unit.transactions[0].event.realm_id;
        let creator = creator_account(unit);
        let message_id =
            arkret_wire::MessageId::from_event_id(&created.authority_commit.event.event_id);
        let root_event_ref = realm_root_authority_event_ref(pool, realm_id).await;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        // The author path: a member holding `ak.message.create` and
        // `ak.message.revise.own` under a 15-minute edit window edits its own
        // Message inside the window and is `failed_precondition` once it closed.
        let (author, author_join_head) =
            admit_joined_human(&pool, &uow, &moderated, &unit, "message-author", 'b').await;
        let mut windowed = invite_grant_request(
            &pool,
            &author_join_head,
            &unit,
            &root_event_ref,
            &author,
            &["ak.message.create", "ak.message.revise.own"],
        )
        .await;
        let mut payload = serde_json::to_value(&windowed.authority_commit.event.payload).unwrap();
        payload["grant"]["constraints"] = serde_json::json!([{
            "constraint_kind": "temporal",
            "constraint_subkind": "edit_window",
            "applies_to_actions": ["ak.message.revise.own"],
            "effect": "allow",
            "message_edit_window": "PT15M"
        }]);
        windowed = realm_event_request_as(
            &author_join_head,
            &creator,
            arkret_wire::EventKind::CapabilityGrant,
            payload,
        );
        windowed = source_if_human(&pool, windowed).await;
        uow.commit_event(windowed.clone()).await.unwrap();
        let authored = realm_event_request_as(
            &windowed,
            &author,
            arkret_wire::EventKind::MessageCreate,
            serde_json::json!({
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "member draft", "format": "plain"}
            }),
        );
        let authored = source_if_human(&pool, authored).await;
        uow.commit_event(authored.clone()).await.unwrap();
        let authored_id =
            arkret_wire::MessageId::from_event_id(&authored.authority_commit.event.event_id);
        let own_edit = realm_event_request_as(
            &authored,
            &author,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&authored_id, "member final"),
        );
        let own_edit = source_if_human(&pool, own_edit).await;
        uow.commit_event(own_edit.clone()).await.unwrap();
        let late_edit = realm_event_request_as(
            &own_edit,
            &author,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&authored_id, "member too late"),
        );
        let mut late_edit = source_if_human(&pool, late_edit).await;
        // The window closes 15 minutes after creation plus the registered
        // temporal tolerance (`constraint-schema.md` §16.1).
        late_edit.authority_commit.commit.committed_at += chrono::TimeDelta::minutes(21);
        assert_message_write_refused(
            &uow,
            &store,
            &pool,
            &late_edit,
            Some(coland_storage::ConflictCode::FailedPrecondition),
        )
        .await;

        // A redacted Message is terminal for revise.
        let redaction = realm_event_request_as(
            &own_edit,
            &creator,
            arkret_wire::EventKind::MessageRedact,
            serde_json::json!({ "message_id": message_id }),
        );
        let redaction = source_if_human(&pool, redaction).await;
        uow.commit_event(redaction.clone()).await.unwrap();
        let after_redaction = realm_event_request_as(
            &redaction,
            &creator,
            arkret_wire::EventKind::MessageRevise,
            plain_revision(&message_id, "too late"),
        );
        let after_redaction = source_if_human(&pool, after_redaction).await;
        assert_message_write_refused(
            &uow,
            &store,
            &pool,
            &after_redaction,
            Some(coland_storage::ConflictCode::FailedPrecondition),
        )
        .await;
    })
}

/// Real PostgreSQL: `ak.message.redact` is admitted through the same-cut
/// evaluator and adds one `<event_id>:0` assertion to the Message's
/// `object_redaction` row in its Commit's transaction. Every read path then
/// derives the withheld Message from that row: the Account scan withholds the
/// create and revise Events, a fresh snapshot discloses the redaction row but
/// no longer the redacted content, and an object issued before the redaction
/// is withdrawn. A second redact, an unknown Message and a member without a
/// redact action are refused with zero writes.
#[tokio::test]
async fn message_redact_writes_object_redaction_and_withholds_on_scan() {
    use arkret_wire::StreamScanDirection::After;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let realm_id = unit.transactions[0].event.realm_id.clone();
    let creator = creator_account(&unit);
    let issuer = store
        .current_authority(&realm_id)
        .await
        .unwrap()
        .unwrap()
        .service_id;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let method = snapshot_signer_for_issuer(&unit, &issuer);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    let retracted = message_create_request(&default, &strand_id, "retracted");
    uow.commit_event(retracted.clone()).await.unwrap();
    let retracted_id =
        arkret_wire::MessageId::from_event_id(&retracted.authority_commit.event.event_id);
    let kept = message_create_request(&retracted, &strand_id, "kept");
    uow.commit_event(kept.clone()).await.unwrap();
    let kept_id = arkret_wire::MessageId::from_event_id(&kept.authority_commit.event.event_id);
    let revised = realm_event_request_as(
        &kept,
        &creator,
        arkret_wire::EventKind::MessageRevise,
        plain_revision(&retracted_id, "retracted, edited"),
    );
    uow.commit_event(revised.clone()).await.unwrap();
    let before = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();

    let unknown = arkret_wire::MessageId::from_event_id(&strand.authority_commit.event.event_id);
    let missing = realm_event_request_as(
        &revised,
        &creator,
        arkret_wire::EventKind::MessageRedact,
        serde_json::json!({ "message_id": unknown }),
    );
    let error = assert_message_write_refused(&uow, &store, &pool, &missing, None).await;
    assert!(
        matches!(error, coland_storage::PersistenceError::NotFound(_)),
        "{error}"
    );

    let redaction = realm_event_request_as(
        &revised,
        &creator,
        arkret_wire::EventKind::MessageRedact,
        serde_json::json!({ "message_id": retracted_id, "reason": "retracted by author" }),
    );
    uow.commit_event(redaction.clone()).await.unwrap();
    let families = message_families(&pool, &realm_id).await;
    assert_eq!(
        families.redactions,
        vec![(
            retracted_id.to_string(),
            redaction.authority_commit.commit.commit_id.to_string(),
            serde_json::json!({"assertions": [{
                "tag_id": format!("{}:0", redaction.authority_commit.event.event_id),
                "value": {"message_id": retracted_id, "reason": "retracted by author"},
            }]}),
        )]
    );
    // Redaction never rewrites the revision carrier.
    assert_eq!(families.revisions.len(), 2);

    let page = scanned_page(
        store
            .scan_stream_for_account(
                &scan_request(&realm_id, After(None), 100),
                &creator,
                &issuer,
            )
            .await
            .unwrap(),
    );
    let last = redaction.authority_commit.commit.stream_position;
    assert_eq!(positions(&page), (0..=last).collect::<Vec<_>>());
    for item in &page.committed_events {
        let withheld = [&retracted, &revised]
            .iter()
            .any(|request| request.authority_commit.commit.commit_id == item.commit().commit_id);
        assert_eq!(
            matches!(item, arkret_wire::CommittedEventView::Withheld(_)),
            withheld,
            "row {}",
            item.commit().stream_position
        );
    }

    // The fresh cut carries the redaction and the kept Message only.
    let after = store
        .issue_realm_state_snapshot_for_account(&realm_id, &creator, &issuer, &sign)
        .await
        .unwrap()
        .unwrap();
    let messages = after
        .current_state_entries
        .iter()
        .filter_map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::MessageRevision { message_id },
                ..
            } => Some(message_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(messages, vec![kept_id.clone()]);
    assert!(after.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::ObjectRedaction { target_ref },
            revision,
            ..
        } if target_ref == retracted_id.as_str()
            && revision.commit_id == redaction.authority_commit.commit.commit_id
    )));
    assert!(matches!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &before.snapshot_id, &issuer)
            .await,
        Err(coland_storage::PersistenceError::SchemaViolation(_))
    ));
    assert_eq!(
        store
            .issued_realm_state_snapshot(&realm_id, &creator, &after.snapshot_id, &issuer)
            .await
            .unwrap(),
        Some(after)
    );

    // A redacted Message is terminal for a second redact.
    let again = realm_event_request_as(
        &redaction,
        &creator,
        arkret_wire::EventKind::MessageRedact,
        serde_json::json!({ "message_id": retracted_id }),
    );
    assert_message_write_refused(
        &uow,
        &store,
        &pool,
        &again,
        Some(coland_storage::ConflictCode::FailedPrecondition),
    )
    .await;

    // A joined member holding no redact action cannot retract another
    // author's Message.
    let station = unit.transactions[0].expected_authority.service_id.clone();
    let member = invite_account(
        "member.example",
        &station.as_str()["ak:did_core:web:".len()..],
    );
    inject_joined_member(&pool, &unit, &member).await;
    let foreign = realm_event_request_as(
        &redaction,
        &member,
        arkret_wire::EventKind::MessageRedact,
        serde_json::json!({ "message_id": kept_id }),
    );
    assert_message_write_refused(
        &uow,
        &store,
        &pool,
        &foreign,
        Some(coland_storage::ConflictCode::CapabilityDenied),
    )
    .await;
}

async fn admitted_message_discussion(
    pool: &coland_storage_postgres::PgPool,
) -> (
    OrdinaryRealmBootstrapCommitUnit,
    EventCommitRequest,
    arkret_wire::StrandId,
) {
    let unit = unit_with_plaintext_service(&pool).await;
    let creator = creator_account(&unit);
    assert_eq!(
        human_profile::admit(pool, &creator.station_id, "bootstrap-actor").await,
        creator
    );
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let strand = strand_create_request(&unit);
    uow.commit_event(strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let default = set_default_strand_request(&strand, &strand_id, None);
    uow.commit_event(default.clone()).await.unwrap();
    (unit, default, strand_id)
}

#[tokio::test]
async fn poll_responses_keep_accepted_history_and_reject_invalid_partition_heads() {
    use arkret_models_collaboration::poll::{PollPartition, PollResponseSet, VerifiedPollResponse};
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (unit, head, strand_id) = admitted_message_discussion(&pool).await;
    let creator = creator_account(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let anchor = realm_event_request_as(
        &head,
        &creator,
        arkret_wire::EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion",
            "content":{"kind":"ak.content.text","format":"plain","body":"Poll reply anchor"}}),
    );
    uow.commit_event(anchor.clone()).await.unwrap();
    let anchor_id = arkret_wire::MessageId::from_event_id(&anchor.authority_commit.event.event_id);
    let definition = realm_event_request_as(
        &anchor,
        &creator,
        arkret_wire::EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion","reply_to_id":anchor_id,"content":{
            "kind":"ak.content.poll","body":"Choose","poll":{"kind":"disclosed","max_selections":2,
            "answers":[{"id":"a","text":{"kind":"ak.content.text","body":"A"}},
                       {"id":"b","text":{"kind":"ak.content.text","body":"B"}}]}}}),
    );
    uow.commit_event(definition.clone()).await.unwrap();
    let poll_event = definition.authority_commit.event.event_id.clone();
    let poll_id = arkret_wire::MessageId::from_event_id(&poll_event);
    let response =
        |previous: &EventCommitRequest, selections: serde_json::Value, heads: serde_json::Value| {
            let mut payload = serde_json::json!({"strand_id":strand_id,"track_name":"discussion",
            "reply_to_id":poll_id,"content":{"kind":"ak.content.poll.response","body":"vote",
            "poll_response":{"poll_ref":poll_id,"selections":selections}}});
            if heads.as_array().is_some_and(|items| !items.is_empty()) {
                payload["poll_response_heads"] = heads;
            }
            realm_event_request_as(
                previous,
                &creator,
                arkret_wire::EventKind::MessageCreate,
                payload,
            )
        };
    let first = response(
        &definition,
        serde_json::json!(["a", "b"]),
        serde_json::json!([]),
    );
    uow.commit_event(first.clone()).await.unwrap();
    let valid_head = serde_json::json!([{"poll_event_ref":poll_event,
        "response_event_ref":first.authority_commit.event.event_id}]);
    let second = response(&first, serde_json::json!(["b"]), valid_head.clone());
    uow.commit_event(second.clone()).await.unwrap();
    let material = store
        .realm_state_snapshot_material(&unit.transactions[0].event.realm_id)
        .await
        .unwrap()
        .unwrap();
    for response_event in [
        &first.authority_commit.event.event_id,
        &second.authority_commit.event.event_id,
    ] {
        let response_id = arkret_wire::MessageId::from_event_id(response_event);
        assert!(!material.current_state_entries.iter().any(|entry| matches!(entry,
            arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::MessageRevision { message_id }, .. }
                if message_id == &response_id)));
    }
    let before = message_families(&pool, &head.authority_commit.event.realm_id).await;
    uow.commit_event(second.clone()).await.unwrap();
    assert_eq!(
        message_families(&pool, &head.authority_commit.event.realm_id).await,
        before
    );
    for (selections, heads) in [
        (serde_json::json!(["unknown"]), valid_head.clone()),
        (serde_json::json!(["a", "a"]), valid_head.clone()),
        (
            serde_json::json!(["a"]),
            serde_json::json!([{"poll_event_ref":poll_event,
            "response_event_ref":head.authority_commit.event.event_id}]),
        ),
        (
            serde_json::json!(["a"]),
            serde_json::json!([{"poll_event_ref":first.authority_commit.event.event_id,
            "response_event_ref":first.authority_commit.event.event_id}]),
        ),
    ] {
        let rejected = response(&second, selections, heads);
        let saved = message_families(&pool, &head.authority_commit.event.realm_id).await;
        assert!(uow.commit_event(rejected.clone()).await.is_err());
        assert!(
            store
                .committed_event(&rejected.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            message_families(&pool, &head.authority_commit.event.realm_id).await,
            saved
        );
    }
    let page = scanned_page(
        store
            .scan_stream_for_account(
                &scan_request(
                    &head.authority_commit.event.realm_id,
                    arkret_wire::StreamScanDirection::After(None),
                    100,
                ),
                &creator,
                &creator.station_id,
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        positions(&page),
        (0..=second.authority_commit.commit.stream_position).collect::<Vec<_>>()
    );
    let partition = PollPartition {
        realm_id: head.authority_commit.event.realm_id.clone(),
        stream_ref: second.authority_commit.commit.stream_ref.clone(),
        poll_ref: poll_id,
        poll_event_ref: poll_event,
        actor_id: second.authority_commit.event.actor_id.clone(),
    };
    let accepted = |commit: &arkret_wire::RealmCommit| arkret_wire::CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let mut folded = PollResponseSet::default();
    // Reverse delivery and duplicate delivery must retain all responses and
    // choose the authority position winner, independently of Event time.
    for item in page.committed_events.iter().rev() {
        let Some(event) = item.reducer_input() else {
            continue;
        };
        if event.kind != arkret_wire::EventKind::MessageCreate {
            continue;
        }
        let Ok(payload) = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::message::MessageCreatePayload,
        >(serde_json::to_value(&event.payload).unwrap()) else {
            continue;
        };
        let Some(content) = payload.content else {
            continue;
        };
        let Ok(arkret_models_collaboration::events_payloads::poll::PollContentBlock::Response(
            content,
        )) = serde_json::from_value(serde_json::to_value(content).unwrap())
        else {
            continue;
        };
        let input = VerifiedPollResponse::new(
            partition.clone(),
            accepted(item.commit()),
            &content.poll_response.selections,
            &["a".to_owned(), "b".to_owned()].into_iter().collect(),
            2,
            payload.poll_response_heads,
            |id| {
                (id == &first.authority_commit.event.event_id)
                    .then(|| (partition.clone(), accepted(&first.authority_commit.commit)))
            },
        )
        .unwrap();
        folded.insert(input.clone()).unwrap();
        folded.insert(input).unwrap();
    }
    let projection = folded.project(true);
    assert_eq!(
        projection[&partition].winner,
        Some(accepted(&second.authority_commit.commit))
    );
    assert_eq!(
        projection[&partition].selections,
        ["b".to_owned()].into_iter().collect()
    );
    assert!(!projection[&partition].provisional);
    assert!(
        store
            .committed_event(&first.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn replies_and_direct_mentions_require_accepted_visible_full_accounts() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (unit, head, strand_id) = admitted_message_discussion(&pool).await;
    let creator = creator_account(&unit);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let target = message_create_request(&head, &strand_id, "target");
    let target = source_if_human(&pool, target).await;
    uow.commit_event(target.clone()).await.unwrap();
    let message_id = arkret_wire::MessageId::from_event_id(&target.authority_commit.event.event_id);
    let reply = realm_event_request_as(
        &target,
        &creator,
        arkret_wire::EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion","reply_to_id":message_id,
            "content":{"kind":"ak.content.text","body":"reply","mentions":[{
                "kind":"mention","subject_account_id":creator,"display_name_at_time":"untrusted audit"}]}}),
    );
    let reply = source_if_human(&pool, reply).await;
    uow.commit_event(reply.clone()).await.unwrap();
    let mut other_station = creator.clone();
    other_station.station_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    for payload in [
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion",
            "reply_to_id":arkret_wire::MessageId::from_event_id(&unit.transactions[0].event.event_id),
            "content":{"kind":"ak.content.text","body":"missing target"}}),
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion",
            "content":{"kind":"ak.content.text","body":"same principal elsewhere","mentions":[{
                "kind":"mention","subject_account_id":other_station}]}}),
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion","reply_to":message_id,
            "content":{"kind":"ak.content.text","body":"legacy alias"}}),
    ] {
        let request = realm_event_request_as(
            &reply,
            &creator,
            arkret_wire::EventKind::MessageCreate,
            payload,
        );
        let request = source_if_human(&pool, request).await;
        let before = message_families(&pool, &head.authority_commit.event.realm_id).await;
        assert!(uow.commit_event(request.clone()).await.is_err());
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            message_families(&pool, &head.authority_commit.event.realm_id).await,
            before
        );
    }
    // The exact Account joins through accepted Invite/Accept facts without
    // a display Profile. Mention admission is bound to membership and scope;
    // Profile absence or classification cannot substitute for Agent gates.
    let account_without_profile =
        human_profile::admit_without_profile(&pool, &creator.station_id, "reply-late-member").await;
    let mut conn = pool.get().await.unwrap();
    let profiles = diesel::sql_query("SELECT count(*) AS count FROM actor_profile_current_results WHERE value->>'principal_id'=$1")
        .bind::<Text, _>(account_without_profile.principal_id.as_str())
        .get_result::<CountRow>(&mut *conn).await.unwrap().count;
    assert_eq!(
        profiles, 0,
        "membership and mention do not require a display Profile"
    );
    drop(conn);
    let (late_member, joined) =
        admit_joined_account(&pool, &uow, &reply, &unit, account_without_profile, 'c').await;
    let root = realm_root_authority_event_ref(&pool, &head.authority_commit.event.realm_id).await;
    let grant = invite_grant_request(
        &pool,
        &joined,
        &unit,
        &root,
        &late_member,
        &["ak.message.create"],
    )
    .await;
    uow.commit_event(grant.clone()).await.unwrap();
    let hidden_reply = realm_event_request_as(
        &grant,
        &late_member,
        arkret_wire::EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion","reply_to_id":message_id,
            "content":{"kind":"ak.content.text","body":"before my membership floor"}}),
    );
    let hidden_reply = source_if_human(&pool, hidden_reply).await;
    assert_message_write_refused(
        &uow,
        &store,
        &pool,
        &hidden_reply,
        Some(coland_storage::ConflictCode::FailedPrecondition),
    )
    .await;
    let mention_member = realm_event_request_as(
        &grant,
        &creator,
        arkret_wire::EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion",
            "content":{"kind":"ak.content.text","body":"joined exact account","mentions":[{
                "kind":"mention","subject_account_id":late_member}]}}),
    );
    let mention_member = source_if_human(&pool, mention_member).await;
    uow.commit_event(mention_member.clone()).await.unwrap();
    let redaction = realm_event_request_as(
        &mention_member,
        &creator,
        arkret_wire::EventKind::MessageRedact,
        serde_json::json!({"message_id":message_id}),
    );
    let redaction = source_if_human(&pool, redaction).await;
    uow.commit_event(redaction.clone()).await.unwrap();
    let refused = realm_event_request_as(
        &redaction,
        &creator,
        arkret_wire::EventKind::MessageCreate,
        serde_json::json!({"strand_id":strand_id,"track_name":"discussion","reply_to_id":message_id,
            "content":{"kind":"ak.content.text","body":"reply to unavailable target"}}),
    );
    let refused = source_if_human(&pool, refused).await;
    assert_message_write_refused(
        &uow,
        &store,
        &pool,
        &refused,
        Some(coland_storage::ConflictCode::FailedPrecondition),
    )
    .await;
}

fn identity_payload(unit: &OrdinaryRealmBootstrapCommitUnit, name: &str) -> serde_json::Value {
    let actor = &unit.transactions[0].event.actor_id;
    let realm = &unit.transactions[0].event.realm_id;
    serde_json::json!({
        "realm_id": realm, "member_id":actor,"segment":"member_identity","replaces":[],
        "identity_payload":{"member_identity":{
            "schema":"ak.schema.member_identity.v1","realm_id":realm,"actor_id":actor,
            "subject_actor_id":actor,"display_profile":{"display_name":name},
            "asserted_at":arkret_canonical::format_timestamp_canonical(unit.transactions[0].commit.committed_at),
            "proof":{"verification_method":"did:web:bootstrap-actor.example#key",
                "signature_algorithm":"Ed25519","payload_digest":format!("sha256:{}","0".repeat(64)),
                "signature":"AAAA"}
        }}
    })
}

#[tokio::test]
async fn member_identity_accepted_assertions_keep_bad_proofs_edges_and_restart_exact_payloads() {
    use coland_storage::MemberIdentityStore as _;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (unit, head, _) = admitted_message_discussion(&pool).await;
    let actor = creator_account(&unit);
    let realm = unit.transactions[0].event.realm_id.clone();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut first_payload = identity_payload(&unit, "Unverified first");
    first_payload["expected_state_digest"] = serde_json::json!(
        arkret_models_identity::member_identity_effective_set_digest(&[]).unwrap()
    );
    let first = realm_event_request_as(
        &head,
        &actor,
        arkret_wire::EventKind::MemberIdentityUpdate,
        first_payload.clone(),
    );
    uow.commit_event(first.clone()).await.unwrap();
    assert!(
        !uow.commit_event(first.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let mut second_payload = identity_payload(&unit, "Unverified second");
    second_payload["replaces"] = serde_json::json!([{
        "event_id":first.authority_commit.event.event_id,"payload_digest":format!("sha256:{}","1".repeat(64))
    }]);
    second_payload["expected_state_digest"] = serde_json::json!(
        arkret_models_identity::member_identity_effective_set_digest(&[(
            &first.authority_commit.event.event_id,
            &first_payload
        )])
        .unwrap()
    );
    let second = realm_event_request_as(
        &first,
        &actor,
        arkret_wire::EventKind::MemberIdentityUpdate,
        second_payload.clone(),
    );
    uow.commit_event(second.clone()).await.unwrap();
    // A wrong edge does not remove first: the next guard names both exact payloads.
    let effective = vec![
        (&first.authority_commit.event.event_id, &first_payload),
        (&second.authority_commit.event.event_id, &second_payload),
    ];
    let mut third_payload = identity_payload(&unit, "Replacement");
    third_payload["expected_state_digest"] = serde_json::json!(
        arkret_models_identity::member_identity_effective_set_digest(&effective).unwrap()
    );
    third_payload["replaces"] = serde_json::json!([{
        "event_id":first.authority_commit.event.event_id,
        "payload_digest":arkret_canonical::canonical_sha256(&first_payload["identity_payload"]).unwrap()
    }]);
    let third = realm_event_request_as(
        &second,
        &actor,
        arkret_wire::EventKind::MemberIdentityUpdate,
        third_payload.clone(),
    );
    uow.commit_event(third.clone()).await.unwrap();
    let selector = arkret_wire::CurrentSelector::MemberIdentityUpdates {
        member_id: unit.transactions[0].event.actor_id.clone(),
        segment: arkret_wire::MemberIdentitySegment::MemberIdentity,
    };
    let material = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    let entry = material.current_state_entries.iter().find(|entry| matches!(entry,arkret_wire::TypedCurrentRow::Value{selector:found,..} if found == &selector)).unwrap();
    let arkret_wire::TypedCurrentRow::Value {
        revision, value, ..
    } = entry;
    assert_eq!(revision.commit_id, third.authority_commit.commit.commit_id);
    assert_eq!(value["assertions"].as_array().unwrap().len(), 3);
    for (request, payload) in [
        (&first, &first_payload),
        (&second, &second_payload),
        (&third, &third_payload),
    ] {
        let tag = format!("{}:0", request.authority_commit.event.event_id);
        assert_eq!(
            value["assertions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["tag_id"] == tag)
                .unwrap()["value"],
            *payload
        );
    }
    // Recreate the durable reader; hydration reads every accepted assertion,
    // including unverified display carriers, directly from Event/Commit facts.
    let restarted = coland_storage_postgres::PgMemberIdentityStore { pool: pool.clone() };
    let records = restarted
        .snapshot_events()
        .await
        .unwrap()
        .into_iter()
        .filter(|record| record.subject.realm_id == realm.as_str())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3);
    assert!(records.iter().any(|record| record.event_id
        == first.authority_commit.event.event_id.as_str()
        && record.raw_event["payload"] == first_payload));
    let mut stale = identity_payload(&unit, "stale");
    stale["expected_state_digest"] = serde_json::json!(
        arkret_models_identity::member_identity_effective_set_digest(&[]).unwrap()
    );
    let request = realm_event_request_as(
        &third,
        &actor,
        arkret_wire::EventKind::MemberIdentityUpdate,
        stale,
    );
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert!(
        error.to_string().contains("member_identity_state_mismatch"),
        "{error}"
    );
    assert_eq!(
        event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
        0
    );
    let after = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.current_state_entries, material.current_state_entries);
    let mut wrong_member = identity_payload(&unit, "wrong member");
    wrong_member["member_id"] = serde_json::json!(arkret_wire::ActorId::account(invite_account(
        "other.example",
        "bootstrap-station.example"
    )));
    let request = realm_event_request_as(
        &third,
        &actor,
        arkret_wire::EventKind::MemberIdentityUpdate,
        wrong_member,
    );
    let error = uow.commit_event(request.clone()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("self-authored exact Realm tuple"),
        "{error}"
    );
    assert_eq!(
        event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
        0
    );
    let after = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material(&realm)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.current_state_entries, material.current_state_entries);
}

#[path = "support/invite_claim_cases.rs"]
mod invite_claim_cases;

#[path = "support/realm_lifecycle_cases.rs"]
mod realm_lifecycle_cases;

async fn source_unit(
    pool: &coland_storage_postgres::PgPool,
    mut unit: OrdinaryRealmBootstrapCommitUnit,
) -> OrdinaryRealmBootstrapCommitUnit {
    let station = unit.transactions[0].expected_authority.service_id.clone();
    human_profile::admit(pool, &station, "bootstrap-actor").await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut previous = None;
    for (index, tx) in unit.transactions.iter_mut().enumerate() {
        tx.producer_signer_fact = store
            .prepare_human_signer_fact(&tx.event, tx.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        tx.commit.producer_signer_fact_digest = tx
            .producer_signer_fact
            .as_ref()
            .map(|f| f.digest().unwrap());
        tx.commit.previous_commit_ref = previous;
        seal_suite_commit(&mut tx.commit);
        previous = Some(tx.commit.commit_id.clone());
        unit.submission.events[index] =
            arkret_wire::EventAdmissionSubmission::new(tx.event.clone());
    }
    unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone()),
    )
    .unwrap();
    unit
}
async fn unit(pool: &coland_storage_postgres::PgPool) -> OrdinaryRealmBootstrapCommitUnit {
    Box::pin(source_unit(pool, legacy_unit())).await
}
async fn unit_with_plaintext_service(
    pool: &coland_storage_postgres::PgPool,
) -> OrdinaryRealmBootstrapCommitUnit {
    Box::pin(source_unit(pool, legacy_unit_with_plaintext_service())).await
}
fn seal_suite_commit(commit: &mut arkret_wire::RealmCommit) {
    let identity =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        commit.signature.verification_method.clone(),
        commit.committed_at,
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
    )
    .unwrap();
}
fn seal_request_fact(mut request: EventCommitRequest) -> EventCommitRequest {
    if let Some(fact) = request
        .authority_commit
        .producer_signer_fact
        .as_mut()
        .and_then(|fact| fact.as_human_mut())
    {
        if fact.actor == request.authority_commit.event.actor_id {
            fact.event_id = request.authority_commit.event.event_id.clone();
            request.authority_commit.commit.producer_signer_fact_digest =
                Some(fact.digest().unwrap());
        } else {
            // This deliberately foreign author has no local accepted source.
            request.authority_commit.producer_signer_fact = None;
            request.authority_commit.commit.producer_signer_fact_digest = None;
        }
    }
    seal_suite_commit(&mut request.authority_commit.commit);
    request
}
