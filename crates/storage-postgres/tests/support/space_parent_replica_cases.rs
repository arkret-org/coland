use super::*;

async fn parent_row(
    pool: &PgPool,
    realm: &arkret_wire::RealmId,
    space: &arkret_wire::SpaceId,
) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('value',value,'commit_id',current_commit_id,'stream_position',current_stream_position) AS value FROM space_parent_current_states WHERE realm_id=$1 AND space_id=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(space.as_str())
        .get_result::<Row>(&mut conn).await.unwrap().value
}

#[tokio::test]
async fn accepted_space_parent_replica_installs_exact_source_value_and_revision() {
    Box::pin(accepted_space_parent_replica_cases()).await;
}

async fn accepted_space_parent_replica_cases() {
    let governance_db = TestDatabase::lease().await;
    let member_db = TestDatabase::lease().await;
    let governance_pool = governance_db.pool();
    let member_pool = member_db.pool();
    let uow = PgEventCommitUnitOfWork::new(governance_pool.clone());
    let member = PgAuthorityCommitStore {
        pool: member_pool.clone(),
    };
    let fixture = Box::pin(historical_human::HumanFixture::new(
        &governance_pool,
        arkret_wire::Did::new("did:web:ordinary-station.example").unwrap(),
    ))
    .await;
    Box::pin(fixture.admit(&governance_pool)).await;
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.pcr.history.account,
        fixture.pcr.history.device_verification_method.clone(),
        fixture.pcr.history.founding_device_signing_seed,
    );
    let unit = fixture.unit.clone();
    let last = unit.transactions.last().unwrap();
    let realm = last.event.realm_id.clone();
    let at = last.commit.committed_at;
    let actor = arkret_wire::ActorId::account(fixture.pcr.history.account.clone());
    let principal = fixture.pcr.history.account.principal_id.clone();
    let alice = remote_member("space-parent-replica-alice");
    let join = membership_request(last, alice.clone(), &alice, "join");
    Box::pin(uow.commit_event(join.clone())).await.unwrap();
    Box::pin(member.install_committed_replica(&replica(&unit, &join, true)))
        .await
        .unwrap();
    Box::pin(anchor_at_join(
        &member,
        &join,
        vec![joined_row(&join, &alice)],
    ))
    .await;
    let mut previous = join.authority_commit.clone();
    previous.producer_signer_fact = last.producer_signer_fact.clone();
    let mut spaces = Vec::new();
    for kind in ["board", "list"] {
        let request = sourced(next_request(
            &previous,
            arkret_wire::EventKind::SpaceCreate,
            &principal,
            serde_json::json!({"object":{"schema":"ak.schema.space.v1","realm_id":realm,
                "kind":kind,"title":kind,"created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ));
        let request = Box::pin(ordinary_realm::source_request(&governance_pool, request)).await;
        Box::pin(uow.commit_event(request.clone())).await.unwrap();
        assert_eq!(
            Box::pin(member.install_committed_replica(&replica(&unit, &request, false)))
                .await
                .unwrap(),
            CommittedReplicaOutcome::Stored
        );
        spaces.push(arkret_wire::SpaceId::from_event_id(
            &request.authority_commit.event.event_id,
        ));
        previous = request.authority_commit;
    }
    let board = &spaces[0];
    let list = &spaces[1];
    let mut expected = None;
    for parent in [Some(board.clone()), None] {
        let request = sourced(next_request(
            &previous,
            arkret_wire::EventKind::SpaceParent,
            &principal,
            serde_json::json!({"space_id":list,"parent_space_id":parent,"expected_parent_space_id":expected}),
            at,
        ));
        let request = Box::pin(ordinary_realm::source_request(&governance_pool, request)).await;
        Box::pin(uow.commit_event(request.clone())).await.unwrap();
        let original = parent_row(&governance_pool, &realm, list).await;
        assert_eq!(
            original["value"],
            serde_json::json!({"parent_space_id":parent})
        );
        assert_eq!(
            original["commit_id"],
            serde_json::json!(request.authority_commit.commit.commit_id)
        );
        assert_eq!(
            original["stream_position"],
            serde_json::json!(request.authority_commit.commit.stream_position)
        );
        let delivery = replica(&unit, &request, false);
        assert_eq!(
            Box::pin(member.install_committed_replica(&delivery))
                .await
                .unwrap(),
            CommittedReplicaOutcome::Stored
        );
        assert_eq!(parent_row(&member_pool, &realm, list).await, original);
        assert_eq!(
            Box::pin(member.install_committed_replica(&delivery))
                .await
                .unwrap(),
            CommittedReplicaOutcome::Duplicate
        );
        assert_eq!(parent_row(&member_pool, &realm, list).await, original);
        let retained = member
            .committed_event(&request.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.event, request.authority_commit.event);
        assert_eq!(retained.commit, request.authority_commit.commit);
        expected = parent;
        previous = request.authority_commit;
    }
}

#[tokio::test]
async fn snapshot_only_foreign_space_parent_uses_exact_verified_current_proof() {
    Box::pin(snapshot_only_parent_cases()).await;
}

async fn snapshot_only_parent_cases() {
    let mut governor_config = coland_test_support::app_config();
    governor_config.public_base_url = "https://parent-snapshot-governor.example".into();
    governor_config.notary_signing_key_seed = Some([83; 32]);
    let (governor_state, governor_pool) = coland_test_support::app_state_with_pool(governor_config);
    let mut origin_config = coland_test_support::app_config();
    origin_config.public_base_url = "https://parent-snapshot-origin.example".into();
    origin_config.notary_signing_key_seed = Some([83; 32]);
    let (origin_state, source_pool) = coland_test_support::app_state_with_pool(origin_config);
    let caller = Box::pin(ordinary_realm::human_profile::admit_for_station_did(
        &source_pool,
        origin_state.service_did(),
        "snapshot-parent-source",
    ))
    .await;
    let source_unit = ordinary_realm::bootstrap_unit_for_account(
        "snapshot-parent-source",
        &caller,
        &origin_state.service_did(),
    );
    let source_unit = Box::pin(ordinary_realm::source_bootstrap(&source_pool, source_unit)).await;
    let source = PgAuthorityCommitStore {
        pool: source_pool.clone(),
    };
    Box::pin(source.admit_ordinary_realm_bootstrap_unit(
        &source_unit,
        source_unit.transactions[0].commit.committed_at,
    ))
    .await
    .unwrap();
    let source_uow = PgEventCommitUnitOfWork::new(source_pool.clone());
    let source_last = source_unit.transactions.last().unwrap();
    let source_realm = source_last.event.realm_id.clone();
    let child = next_request(
        source_last,
        arkret_wire::EventKind::SpaceCreate,
        &caller.principal_id,
        serde_json::json!({"object":{"schema":"ak.schema.space.v1","realm_id":source_realm,
            "kind":"list","title":"Source list","created_by":source_last.event.actor_id,
            "created_at":arkret_canonical::format_timestamp_canonical(source_last.commit.committed_at)}}),
        source_last.commit.committed_at,
    );
    let child = Box::pin(ordinary_realm::source_request(&source_pool, child)).await;
    let child_id = arkret_wire::SpaceId::from_event_id(&child.authority_commit.event.event_id);
    Box::pin(source_uow.commit_event(child.clone()))
        .await
        .unwrap();

    let governor_account = Box::pin(ordinary_realm::human_profile::admit_for_station_did(
        &governor_pool,
        governor_state.service_did(),
        "snapshot-parent-governor",
    ))
    .await;
    let unit = ordinary_realm::bootstrap_unit_for_account(
        "snapshot-parent-governor",
        &governor_account,
        &governor_state.service_did(),
    );
    let unit = Box::pin(ordinary_realm::source_bootstrap(&governor_pool, unit)).await;
    Box::pin(
        PgAuthorityCommitStore {
            pool: governor_pool.clone(),
        }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at),
    )
    .await
    .unwrap();
    let governor = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let governor_uow = PgEventCommitUnitOfWork::new(governor_pool.clone());
    let last = unit.transactions.last().unwrap();
    let foreign_realm = last.event.realm_id.clone();
    let foreign = next_request(
        last,
        arkret_wire::EventKind::SpaceCreate,
        &governor_account.principal_id,
        serde_json::json!({"object":{"schema":"ak.schema.space.v1","realm_id":foreign_realm,
            "kind":"board","title":"Foreign board","created_by":last.event.actor_id,
            "created_at":arkret_canonical::format_timestamp_canonical(last.commit.committed_at)}}),
        last.commit.committed_at,
    );
    let foreign = Box::pin(ordinary_realm::source_request(&governor_pool, foreign)).await;
    let foreign_id = arkret_wire::SpaceId::from_event_id(&foreign.authority_commit.event.event_id);
    Box::pin(governor_uow.commit_event(foreign.clone()))
        .await
        .unwrap();
    let actor = arkret_wire::ActorId::account(caller.clone());
    let join = membership_request(&foreign.authority_commit, actor.clone(), &actor, "join");
    let join = Box::pin(snapshot_forwarded_request(
        &origin_state,
        &source_pool,
        &governor_state.service_did(),
        &governor_account.station_id,
        join,
    ))
    .await;
    Box::pin(governor_uow.commit_event(join.clone()))
        .await
        .unwrap();
    let mut join_delivery = replica(&unit, &join, true);
    join_delivery.local_service_id = caller.station_id.clone();
    Box::pin(source.install_committed_replica(&join_delivery))
        .await
        .unwrap();
    let material = Box::pin(governor.member_station_bootstrap_material(
        &foreign_realm,
        &caller,
        &join.authority_commit.commit.commit_id,
    ))
    .await
    .unwrap()
    .unwrap();
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        governor_state
            .service_verification_method("notary-key")
            .unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
        chrono::Utc::now(),
    )
    .unwrap();
    Box::pin(source.install_replica_anchor(&ReplicaAnchorInstall {
        realm_id: foreign_realm.clone(),
        join_commit_id: join.authority_commit.commit.commit_id.clone(),
        governance_generation: snapshot.governance_generation,
        snapshot_head: snapshot.visible_stream_heads[0].clone(),
        visible_stream_heads: snapshot.visible_stream_heads.clone(),
        current_state_entries: snapshot.current_state_entries.clone(),
        verified_snapshot: snapshot,
    }))
    .await
    .unwrap();
    let read = Box::pin(coland_storage_postgres::account_snapshot_material(
        &source_pool,
        &foreign_realm,
        &caller,
    ))
    .await
    .unwrap()
    .unwrap();
    assert!(read.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::CurrentState::Value {selector:arkret_wire::CurrentSelector::Space {space_id},..}
            if space_id==&foreign_id)));
    let original_space = read.current_state_entries.iter().find(|entry| matches!(entry,
        arkret_wire::CurrentState::Value {selector:arkret_wire::CurrentSelector::Space {space_id},..}
            if space_id==&foreign_id)).unwrap().clone();
    let arkret_wire::CurrentState::Value {
        value: original_value,
        revision: original_revision,
        ..
    } = original_space;
    let mut conn = source_pool.get().await.unwrap();
    let old_commits = diesel::sql_query("SELECT COUNT(*)::bigint AS count FROM realm_commits WHERE realm_id=$1 AND stream_position<$2")
        .bind::<Text,_>(foreign_realm.as_str())
        .bind::<BigInt,_>(join.authority_commit.commit.stream_position as i64)
        .get_result::<CountRow>(&mut conn).await.unwrap().count;
    assert_eq!(
        old_commits, 0,
        "pre-join Space Commit must not be installed"
    );
    drop(conn);
    let reparent = next_request(
        &child.authority_commit,
        arkret_wire::EventKind::SpaceParent,
        &caller.principal_id,
        serde_json::json!({"space_id":child_id,"parent_space_id":foreign_id,"expected_parent_space_id":null}),
        child.authority_commit.commit.committed_at,
    );
    let reparent = Box::pin(ordinary_realm::source_request(&source_pool, reparent)).await;
    let before_parent = parent_row(&source_pool, &source_realm, &child_id).await;
    let before_counts = snapshot_parent_footprint(&source_pool, &source_realm).await;
    for (change, expected) in [
        ("none", ConflictCode::SpaceRealmMismatch),
        ("value", ConflictCode::SpaceParentUnreadable),
        ("revision", ConflictCode::SpaceParentUnreadable),
        ("cut", ConflictCode::SpaceParentUnreadable),
    ] {
        let mut conn = source_pool.get().await.unwrap();
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        // Corrupt only exact retained proof, never the current row or source Event.
        match change {
            "value" => {
                diesel::sql_query("UPDATE replica_authorization_rows SET value='{}' WHERE realm_id=$1 AND selector=$2")
                .bind::<Text,_>(foreign_realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CurrentSelector::Space {space_id:foreign_id.clone()}).unwrap()).execute(&mut conn).await.unwrap();
            }
            "revision" => {
                diesel::sql_query("UPDATE replica_authorization_rows SET current_stream_position=current_stream_position+1 WHERE realm_id=$1 AND selector=$2")
                .bind::<Text,_>(foreign_realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CurrentSelector::Space {space_id:foreign_id.clone()}).unwrap()).execute(&mut conn).await.unwrap();
            }
            "cut" => {
                diesel::sql_query("UPDATE replica_authorization_cuts SET head_stream_position=head_stream_position+1 WHERE realm_id=$1")
                .bind::<Text,_>(foreign_realm.as_str()).execute(&mut conn).await.unwrap();
            }
            _ => {}
        }
        diesel::sql_query("COMMIT")
            .execute(&mut conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(
            Box::pin(source_uow.commit_event(reparent.clone()))
                .await
                .unwrap_err()
                .conflict_code(),
            Some(expected),
            "{change}"
        );
        assert_eq!(
            snapshot_parent_footprint(&source_pool, &source_realm).await,
            before_counts
        );
        assert_eq!(
            parent_row(&source_pool, &source_realm, &child_id).await,
            before_parent
        );
        // Restore the exact original retained proof before the next negative probe.
        if change != "none" {
            let mut conn = source_pool.get().await.unwrap();
            diesel::sql_query("UPDATE replica_authorization_rows SET value=$3,current_commit_id=$4,current_stream_position=$5 WHERE realm_id=$1 AND selector=$2")
                .bind::<Text,_>(foreign_realm.as_str())
                .bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CurrentSelector::Space {space_id:foreign_id.clone()}).unwrap())
                .bind::<Jsonb,_>(&original_value)
                .bind::<Text,_>(original_revision.commit_id.as_str())
                .bind::<BigInt,_>(original_revision.stream_position as i64).execute(&mut conn).await.unwrap();
            diesel::sql_query(
                "UPDATE replica_authorization_cuts SET head_stream_position=$2 WHERE realm_id=$1",
            )
            .bind::<Text, _>(foreign_realm.as_str())
            .bind::<BigInt, _>(join.authority_commit.commit.stream_position as i64)
            .execute(&mut conn)
            .await
            .unwrap();
            drop(conn);
            assert_eq!(
                Box::pin(source_uow.commit_event(reparent.clone()))
                    .await
                    .unwrap_err()
                    .conflict_code(),
                Some(ConflictCode::SpaceRealmMismatch),
                "restored {change} proof"
            );
            assert_eq!(
                snapshot_parent_footprint(&source_pool, &source_realm).await,
                before_counts
            );
        }
    }
    let leave = membership_request(&join.authority_commit, actor.clone(), &actor, "leave");
    let leave = Box::pin(snapshot_forwarded_request(
        &origin_state,
        &source_pool,
        &governor_state.service_did(),
        &governor_account.station_id,
        leave,
    ))
    .await;
    Box::pin(governor_uow.commit_event(leave.clone()))
        .await
        .unwrap();
    let mut leave_delivery = replica(&unit, &leave, false);
    leave_delivery.local_service_id = caller.station_id.clone();
    Box::pin(source.install_committed_replica(&leave_delivery))
        .await
        .unwrap();
    assert!(
        Box::pin(coland_storage_postgres::account_snapshot_material(
            &source_pool,
            &foreign_realm,
            &caller,
        ))
        .await
        .is_err()
    );
    assert_eq!(
        Box::pin(source_uow.commit_event(reparent))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::SpaceParentUnreadable)
    );
    assert_eq!(
        snapshot_parent_footprint(&source_pool, &source_realm).await,
        before_counts
    );
    assert_eq!(
        parent_row(&source_pool, &source_realm, &child_id).await,
        before_parent
    );
}

async fn snapshot_parent_footprint(
    pool: &PgPool,
    realm: &arkret_wire::RealmId,
) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.pk) FROM canonical_events e WHERE e.realm_id=$1),'commits',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.stream_position,c.commit_id) FROM realm_commits c WHERE c.realm_id=$1),'event_outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.event_pk,o.outbox_id) FROM event_federation_outbox o),'federation_outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY o.id) FROM federation_outbox o),'space',(SELECT jsonb_agg(to_jsonb(s) ORDER BY space_id) FROM space_current_states s WHERE realm_id=$1),'parent',(SELECT jsonb_agg(to_jsonb(p) ORDER BY space_id) FROM space_parent_current_states p WHERE realm_id=$1),'policy',(SELECT jsonb_agg(to_jsonb(c) ORDER BY space_id) FROM space_child_scope_policy_current_states c WHERE realm_id=$1)) AS value")
        .bind::<Text,_>(realm.as_str()).get_result::<Row>(&mut conn).await.unwrap().value
}

// A remote Human stays in its origin inventory; only verified forwarded proof
// accompanies the governance request.
async fn snapshot_forwarded_request(
    origin: &coland_http::state::AppState,
    origin_pool: &PgPool,
    governing_did: &arkret_wire::Did,
    governing_station: &arkret_wire::DidCoreId,
    request: EventCommitRequest,
) -> EventCommitRequest {
    let mut request = Box::pin(ordinary_realm::source_request(origin_pool, request)).await;
    let evidence = Box::pin(coland_http::test_fresh_producer_device_evidence(
        origin,
        &request.authority_commit.event,
        governing_station,
    ))
    .await
    .unwrap()
    .unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
        &evidence,
        &request.authority_commit.event,
        &request
            .authority_commit
            .event
            .actor_id
            .as_account_id()
            .unwrap()
            .station_id,
        governing_station,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    request.authority_commit.producer_signer_fact = Some(fact.clone().into());
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.commit.committed_at = core.attested_at;
    request.self_producer_guard = None;
    request.forwarded_producer_evidence =
        Some(coland_storage::ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap());
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    historical_human::seal_commit(&mut request.authority_commit.commit, governing_did);
    request
}
