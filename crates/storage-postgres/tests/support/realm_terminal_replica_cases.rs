use super::*;

/// A terminal notification cannot extend a departed holder's canonical prefix.
/// A different joined member on the same Station preserves replication authority.
#[tokio::test]
async fn terminal_replication_respects_last_member_departure_after_restart() {
    use arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload;
    for another_member_remains in [false, true] {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let unit = bootstrap_unit_with_join_rule("terminal-departure", "public");
        let last = unit.transactions.last().unwrap();
        let alice = remote_member("terminal-departure-alice");
        let join = membership_request(last, alice.clone(), &alice, "join");
        store
            .install_committed_replica(&replica(&unit, &join, true))
            .await
            .unwrap();
        Box::pin(anchor_at_join(
            &store,
            &join,
            vec![joined_row(&join, &alice)],
        ))
        .await;
        let mut previous = join.authority_commit.clone();
        if another_member_remains {
            let bob = remote_member("terminal-departure-bob");
            let bob_join = membership_request(&previous, bob.clone(), &bob, "join");
            store
                .install_committed_replica(&replica(&unit, &bob_join, false))
                .await
                .unwrap();
            previous = bob_join.authority_commit;
        }
        let leave = membership_request(&previous, alice.clone(), &alice, "leave");
        store
            .install_committed_replica(&replica(&unit, &leave, false))
            .await
            .unwrap();
        assert_eq!(
            member_state(&pool, &last.event.realm_id, &alice)
                .await
                .as_deref(),
            Some("leave")
        );
        let before = terminal_persistent_rows(&pool).await;
        let mut source = leave.authority_commit.clone();
        source.producer_signer_fact = last.producer_signer_fact.clone();
        let terminal = sourced(next_request(
            &source,
            arkret_wire::EventKind::RealmTombstone,
            &founder(),
            RealmTombstonePayload::new(
                "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
                    .parse()
                    .unwrap(),
                "migration after membership change",
            )
            .to_value()
            .unwrap(),
            last.commit.committed_at,
        ));
        // Recreate the store so authorization must come from durable facts.
        let restarted = PgAuthorityCommitStore { pool: pool.clone() };
        // The terminal is still a candidate here. Check the recipient's durable
        // hosted-member gate; sender obligations require an accepted source Event.
        assert_eq!(
            restarted
                .replica_stream_has_hosted_member(
                    &terminal.authority_commit.commit.stream_ref,
                    &member_station(),
                )
                .await
                .unwrap(),
            Some(another_member_remains),
        );
        if another_member_remains {
            assert_eq!(
                restarted
                    .install_committed_replica(&replica(&unit, &terminal, false))
                    .await
                    .unwrap(),
                CommittedReplicaOutcome::Stored
            );
        } else {
            for _ in 0..2 {
                let error = restarted
                    .install_committed_replica(&replica(&unit, &terminal, false))
                    .await
                    .unwrap_err();
                assert_code(&error, ConflictCode::CapabilityDenied);
                assert_eq!(terminal_persistent_rows(&pool).await, before);
                assert!(
                    restarted
                        .committed_event(&terminal.authority_commit.event.event_id)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            assert!(
                restarted
                    .committed_event(&leave.authority_commit.event.event_id)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                restarted
                    .committed_event(&join.authority_commit.event.event_id)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
}

async fn terminal_persistent_rows(pool: &coland_storage_postgres::PgPool) -> serde_json::Value {
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Table {
        #[diesel(sql_type = diesel::sql_types::Text)]
        tablename: String,
    }
    #[derive(diesel::QueryableByName)]
    struct Rows {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let tables = diesel::sql_query("SELECT tablename::text AS tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_states' OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_state_heads','current_state_versions','direct_conversation_founding_slots')) ORDER BY tablename")
        .load::<Table>(&mut *conn).await.unwrap();
    let mut snapshot = serde_json::Map::new();
    for table in tables {
        assert!(
            table
                .tablename
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM public.{} r",
            table.tablename
        );
        let rows = diesel::sql_query(query)
            .get_result::<Rows>(&mut *conn)
            .await
            .unwrap();
        snapshot.insert(table.tablename, rows.value);
    }
    for table in [
        "canonical_events",
        "realm_commits",
        "realm_authorities",
        "federation_outbox",
        "event_federation_outbox",
        "realm_bootstrap_current_states",
        "replica_stream_anchors",
        "replica_authorization_rows",
        "replica_authorization_cuts",
        "account_summary_current",
        "account_summary_versions",
        "account_summary_clock",
    ] {
        assert!(
            snapshot.contains_key(table),
            "missing acceptance footprint table: {table}"
        );
    }
    serde_json::Value::Object(snapshot)
}

fn signed_audit_source(
    previous: &AuthorityCommitTransaction,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
) -> EventCommitRequest {
    let actor = arkret_wire::ActorId::service(previous.expected_authority.service_id.clone());
    if kind == arkret_wire::EventKind::AuditAccessed {
        let typed: arkret_models_collaboration::events_payloads::audit::AuditAccessedPayload =
            serde_json::from_value(payload.clone()).unwrap();
        assert_eq!(typed.writer_actor_id, actor);
        assert_eq!(typed.target_ref, previous.event.event_id.as_str());
        assert_eq!(typed.accessed_at, previous.commit.committed_at);
    } else if kind == arkret_wire::EventKind::AuditErasureReceipt {
        let typed: arkret_models_collaboration::governance::erasure::ErasureReceipt =
            serde_json::from_value(payload.clone()).unwrap();
        typed.validate_with_inline_retained_stub().unwrap();
        assert_eq!(typed.issuer_id, previous.expected_authority.service_id);
        assert_eq!(
            typed.scope.realm_id.as_ref(),
            Some(&previous.event.realm_id)
        );
        let arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger::Event {
            event_id,
        } = &typed.trigger
        else {
            panic!("terminal audit fixture must bind an Event trigger");
        };
        assert_eq!(typed.subject.subject_ref, event_id.as_str());
        assert_eq!(
            previous.event.payload.get("target_ref"),
            Some(&serde_json::json!(event_id))
        );
    }
    let at = previous.commit.committed_at;
    let mut event = ordinary_realm::event_for_actor(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: previous.event.realm_id.clone(),
        },
        actor,
        payload,
        at,
    );
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let method = "did:web:ordinary-station.example#audit-source-key";
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    };
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::new(key.clone(), method);
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    let event = authored.into_event();
    arkret_schema::validate_event_for_submit(&event).unwrap();
    arkret_signatures::verify_ed25519_detached_jws_proof(
        event.producer_proof.as_ref().unwrap(),
        &arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap(),
        &event.actor_id,
        &public,
    )
    .unwrap();
    let mut request = ordinary_realm::request_for_event(previous, event, at);
    let commit = &mut request.authority_commit.commit;
    let identity =
        arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"]).unwrap();
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&identity).unwrap(),
    ));
    let unsigned = arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap();
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        arkret_wire::DidUrl::new(method).unwrap(),
        at,
        &key,
    )
    .unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &commit.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &public,
    )
    .unwrap();
    sourced(request)
}

fn signed_terminal_receipt(terminal: &AuthorityCommitTransaction) -> serde_json::Value {
    use arkret_models_collaboration::events_payloads::event_wire::{
        ErasureTrigger, VerificationStub,
    };
    use arkret_models_collaboration::governance::erasure::{
        ErasureAttemptOutcome, ErasureReceipt, ErasureReceiptProof, ErasureScope,
        ErasureStorageBoundary, ErasureSubject, ErasureSubjectKind,
    };
    let receipt_id = format!("ak:receipt:{}", uuid::Uuid::now_v7());
    let at = terminal.commit.committed_at;
    let subject = ErasureSubject {
        kind: ErasureSubjectKind::Event,
        subject_ref: terminal.event.event_id.to_string(),
    };
    let scope = ErasureScope {
        storage_boundary: ErasureStorageBoundary::ServiceDefined,
        realm_id: Some(terminal.event.realm_id.clone()),
        target_refs: Some(vec![subject.subject_ref.clone()]),
        retention_policy_id: None,
        service_scope: Some("trusted-source terminal audit fixture".to_owned()),
    };
    let trigger = ErasureTrigger::Event {
        event_id: terminal.event.event_id.clone(),
    };
    let stub = VerificationStub {
        stub_schema: arkret_wire::SchemaId::ERASURE_VERIFICATION_STUB_V1.to_owned(),
        receipt_id: receipt_id.clone(),
        trigger: trigger.clone(),
        subject: subject.clone(),
        scope: scope.clone(),
        event_digest: None,
        retained_digests: None,
        committed_event_ref: None,
        redaction_authorization_ref: None,
        legal_hold_ref: None,
        completed_at: at,
    };
    let stub_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&stub).unwrap()).unwrap();
    let mut receipt = ErasureReceipt {
        schema: ErasureReceipt::SCHEMA.to_owned(),
        receipt_id,
        trigger: trigger.clone(),
        issuer_id: terminal.expected_authority.service_id.clone(),
        subject: subject.clone(),
        scope: scope.clone(),
        outcome: ErasureAttemptOutcome::PartiallyCompleted,
        erased_classes: Vec::new(),
        retained_stub_digest: stub_digest.clone(),
        retained_stub: Some(stub.clone()),
        legal_hold_ref: None,
        completed_at: at,
        issued_at: None,
        proofs: Vec::new(),
        fanout_status: None,
        peer_receipts: None,
    };
    let bytes = receipt.canonical_proof_input().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let signature = arkret_signatures::jws::sign_jws_ed25519(&bytes, &key).unwrap();
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    };
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&signature, &bytes, &public)
        .unwrap();
    receipt.proofs.push(ErasureReceiptProof {
        verification_method: arkret_wire::DidUrl::new(
            "did:web:ordinary-station.example#audit-source-key",
        )
        .unwrap(),
        payload_digest: receipt.canonical_payload_digest().unwrap(),
        signature,
        extra: std::collections::BTreeMap::new(),
    });
    receipt.validate_with_inline_retained_stub().unwrap();
    assert_eq!(receipt.trigger, trigger);
    assert_eq!(receipt.subject, subject);
    assert_eq!(receipt.scope, scope);
    assert_eq!(
        receipt.subject.subject_ref,
        terminal.event.event_id.as_str()
    );
    assert_eq!(
        receipt.scope.target_refs,
        Some(vec![terminal.event.event_id.to_string()])
    );
    assert_eq!(receipt.retained_stub.as_ref(), Some(&stub));
    assert_eq!(receipt.retained_stub_digest, stub_digest);
    assert_eq!(receipt.canonical_proof_input().unwrap(), bytes);
    assert_eq!(
        receipt.scope.realm_id.as_ref(),
        Some(&terminal.event.realm_id)
    );
    let payload = serde_json::to_value(&receipt).unwrap();
    let decoded: ErasureReceipt = serde_json::from_value(payload.clone()).unwrap();
    assert_eq!(decoded, receipt);
    decoded.validate_with_inline_retained_stub().unwrap();
    payload
}

async fn retained_terminal_rows(pool: &PgPool, realm: &arkret_wire::RealmId) -> serde_json::Value {
    let mut snapshot = terminal_persistent_rows(pool).await;
    for (alias, table) in [("events", "canonical_events"), ("commits", "realm_commits")] {
        let count = snapshot[table]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["realm_id"] == realm.as_str())
            .count();
        snapshot[alias] = serde_json::json!(count);
    }
    let business = snapshot
        .as_object()
        .unwrap()
        .iter()
        .filter(|(table, _)| table.ends_with("current_states"))
        .map(|(table, rows)| (table.clone(), rows.clone()))
        .collect::<serde_json::Map<_, _>>();
    snapshot["current"] = serde_json::Value::Object(business);
    snapshot["outbox"] = snapshot["event_federation_outbox"].clone();
    snapshot
}
/// Exercise the member Station's real committed-replication transaction,
/// including the held head and rollback, rather than just the lifecycle gate.
#[tokio::test]
async fn replica_terminal_admission_is_atomic_and_preserves_retained_history() {
    use arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = bootstrap_unit_with_join_rule("replica-terminal", "public");
    let realm = unit.transactions[0].event.realm_id.clone();
    let last = unit.transactions.last().unwrap();
    let alice = remote_member("replica-terminal-alice");
    let join = membership_request(last, alice.clone(), &alice, "join");
    store
        .install_committed_replica(&replica(&unit, &join, true))
        .await
        .unwrap();
    Box::pin(anchor_at_join(
        &store,
        &join,
        vec![joined_row(&join, &alice)],
    ))
    .await;
    let mut source = join.authority_commit.clone();
    source.producer_signer_fact = last.producer_signer_fact.clone();
    let before = retained_terminal_rows(&pool, &realm).await;
    let destroy = sourced(next_request(
        &source,
        arkret_wire::EventKind::RealmDestroy,
        &founder(),
        serde_json::json!({"reason":"forbidden destructive confirmation"}),
        last.commit.committed_at,
    ));
    let error = store
        .install_committed_replica(&replica(&unit, &destroy, false))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("failed_precondition"), "{error}");
    assert!(
        !error.to_string().contains("realm_terminal_state"),
        "{error}"
    );
    assert_eq!(retained_terminal_rows(&pool, &realm).await, before);
    assert!(
        store
            .committed_event(&destroy.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );

    let successor = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
        .parse()
        .unwrap();
    let terminal_payload = RealmTombstonePayload::new(successor, "migrated")
        .to_value()
        .unwrap();
    let mut missing_successor = terminal_payload.clone();
    missing_successor
        .as_object_mut()
        .unwrap()
        .remove("successor_realm_id");
    for (payload, expected_refusal) in [
        (missing_successor, "missing field `successor_realm_id`"),
        (
            RealmTombstonePayload::new(realm.clone(), "self")
                .to_value()
                .unwrap(),
            "successor must differ from the terminating Realm",
        ),
    ] {
        let request = sourced(next_request(
            &source,
            arkret_wire::EventKind::RealmTombstone,
            &founder(),
            payload,
            last.commit.committed_at,
        ));
        let error = store
            .install_committed_replica(&replica(&unit, &request, false))
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected_refusal), "{error}");
        assert!(
            !error.to_string().contains("realm_terminal_state"),
            "{error}"
        );
        assert_eq!(retained_terminal_rows(&pool, &realm).await, before);
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    let terminal = sourced(next_request(
        &source,
        arkret_wire::EventKind::RealmTombstone,
        &founder(),
        terminal_payload,
        last.commit.committed_at,
    ));
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &terminal, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Stored
    );
    let accepted = retained_terminal_rows(&pool, &realm).await;
    assert_eq!(
        accepted["events"].as_i64().unwrap(),
        before["events"].as_i64().unwrap() + 1
    );
    assert_eq!(
        accepted["commits"].as_i64().unwrap(),
        before["commits"].as_i64().unwrap() + 1
    );
    assert_eq!(accepted["outbox"], before["outbox"]);
    for (kind, payload) in [
        (
            arkret_wire::EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"forbidden"}),
        ),
        (arkret_wire::EventKind::RealmRestore, serde_json::json!({})),
        (
            arkret_wire::EventKind::RealmTombstone,
            RealmTombstonePayload::new(
                "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb"
                    .parse()
                    .unwrap(),
                "repeat",
            )
            .to_value()
            .unwrap(),
        ),
    ] {
        let request = sourced(next_request(
            &terminal.authority_commit,
            kind,
            &founder(),
            payload,
            last.commit.committed_at,
        ));
        let error = store
            .install_committed_replica(&replica(&unit, &request, false))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
        assert!(
            !error.to_string().contains("realm_terminal_state"),
            "{error}"
        );
        assert_eq!(retained_terminal_rows(&pool, &realm).await, accepted);
        assert!(
            store
                .committed_event(&request.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        store
            .install_committed_replica(&replica(&unit, &terminal, false))
            .await
            .unwrap(),
        CommittedReplicaOutcome::Duplicate
    );
    assert_eq!(retained_terminal_rows(&pool, &realm).await, accepted);
    let retained = store
        .committed_event(&join.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.event, join.authority_commit.event);
    assert_eq!(retained.commit, join.authority_commit.commit);

    // These source-trusted audit announcements have real SDK-verified producer,
    // Commit and receipt signatures. They do not exercise the source author's
    // audit-read/erasure operation or claim physical deletion by this replica.
    let access_payload =
        arkret_models_collaboration::events_payloads::audit::AuditAccessedPayload {
            access_kind:
                arkret_models_collaboration::events_payloads::audit::AuditAccessedKind::Other,
            writer_actor_id: arkret_wire::ActorId::service(
                terminal
                    .authority_commit
                    .expected_authority
                    .service_id
                    .clone(),
            ),
            target_actor_id: None,
            target_ref: terminal.authority_commit.event.event_id.to_string(),
            paired_event_id: None,
            late_recovery_original_event_id: None,
            purpose: arkret_wire::NonEmptyString::new("retained terminal history audit").unwrap(),
            accessed_at: terminal.authority_commit.commit.committed_at,
        };
    assert_eq!(
        access_payload.target_ref,
        terminal.authority_commit.event.event_id.as_str()
    );
    let access = signed_audit_source(
        &terminal.authority_commit,
        arkret_wire::EventKind::AuditAccessed,
        serde_json::to_value(access_payload).unwrap(),
    );
    let receipt = signed_audit_source(
        &access.authority_commit,
        arkret_wire::EventKind::AuditErasureReceipt,
        signed_terminal_receipt(&terminal.authority_commit),
    );
    let mut previous_rows = accepted.clone();
    for (index, audit) in [access, receipt].iter().enumerate() {
        assert_eq!(
            store
                .install_committed_replica(&replica(&unit, audit, false))
                .await
                .unwrap(),
            CommittedReplicaOutcome::Stored
        );
        let rows = retained_terminal_rows(&pool, &realm).await;
        for (table, identity, admitted_id) in [
            (
                "canonical_events",
                "id",
                audit.authority_commit.event.event_id.as_str(),
            ),
            (
                "realm_commits",
                "commit_id",
                audit.authority_commit.commit.commit_id.as_str(),
            ),
        ] {
            assert_eq!(
                rows[table].as_array().unwrap().len(),
                previous_rows[table].as_array().unwrap().len() + 1,
                "Audit must append exactly one {table} row"
            );
            let retained = rows[table]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| {
                    if table == "canonical_events" {
                        row["envelope"]["event_id"] != admitted_id
                    } else {
                        row[identity] != admitted_id
                    }
                })
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                serde_json::json!(retained),
                previous_rows[table],
                "Audit changed retained {table}"
            );
        }
        assert_eq!(rows["current"], accepted["current"]);
        assert_eq!(rows["outbox"], accepted["outbox"]);
        for table in [
            "federation_outbox",
            "realm_authorities",
            "replica_stream_anchors",
            "replica_authorization_rows",
            "account_summary_current",
            "account_summary_versions",
            "account_summary_clock",
        ] {
            assert_eq!(rows[table], accepted[table], "Audit changed {table}");
        }
        let commit = &audit.authority_commit.commit;
        let latest = rows["realm_commits"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["realm_id"] == realm.as_str())
            .max_by_key(|row| row["stream_position"].as_u64().unwrap())
            .unwrap();
        assert_eq!(latest["commit_id"], serde_json::json!(commit.commit_id));
        assert_eq!(
            latest["stream_position"],
            serde_json::json!(commit.stream_position)
        );
        let cut = rows["replica_authorization_cuts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["realm_id"] == realm.as_str()
                    && row["source_stream_ref"] == serde_json::to_value(&commit.stream_ref).unwrap()
            })
            .unwrap();
        assert_eq!(cut["head_commit_id"], serde_json::json!(commit.commit_id));
        assert_eq!(
            cut["head_stream_position"],
            serde_json::json!(commit.stream_position)
        );
        assert_eq!(
            rows["events"].as_i64().unwrap(),
            accepted["events"].as_i64().unwrap() + index as i64 + 1
        );
        assert_eq!(
            rows["commits"].as_i64().unwrap(),
            accepted["commits"].as_i64().unwrap() + index as i64 + 1
        );
        let held = store
            .committed_event(&audit.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held.event, audit.authority_commit.event);
        assert_eq!(held.commit, audit.authority_commit.commit);
        previous_rows = rows;
    }
}
