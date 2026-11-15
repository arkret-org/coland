//! Real PostgreSQL source/CAS/Snapshot boundaries; no database fallback.
use diesel::sql_types::Binary;
use diesel_async::SimpleAsyncConnection;

use super::*;

fn fixture() -> Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/call-current-fixture.json")
        .expect("pinned signed Call fixture")["capture_transcripts"]
        .clone()
}

fn row(fixture: &Value, index: usize) -> (Event, RealmCommit) {
    (
        serde_json::from_value(fixture["original_rows"][index]["event"].clone()).unwrap(),
        serde_json::from_value(fixture["original_rows"][index]["commit"].clone()).unwrap(),
    )
}

async fn seed_sources(conn: &mut AsyncPgConnection, fixture: &Value) {
    // These are already accepted, signed original inputs. This test exercises
    // the durable materializer; it does not pretend to re-run producer admission.
    for source in std::iter::once(&fixture["initiator_grant_source"])
        .chain(fixture["original_rows"].as_array().unwrap().iter())
    {
        let event: Event = serde_json::from_value(source["event"].clone()).unwrap();
        let commit: RealmCommit = serde_json::from_value(source["commit"].clone()).unwrap();
        let token = crate::ids::event_token_part_expect_internal(event.event_id.as_str(), "event");
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,received_at,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9,$9)")
            .bind::<Binary,_>(token.to_vec()).bind::<Binary,_>(token[1..].to_vec())
            .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str())
            .bind::<Jsonb,_>(json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
            .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(&event).unwrap())
            .bind::<Jsonb,_>(json!(event)).bind::<Timestamptz,_>(commit.committed_at)
            .execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,1,$7,$8 FROM canonical_events WHERE id=$9")
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(commit.realm_id.as_str())
            .bind::<Text,_>(crate::authority_commit::stream_key(&commit.stream_ref).unwrap())
            .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<BigInt,_>(commit.stream_position as i64)
            .bind::<diesel::sql_types::Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
            .bind::<Jsonb,_>(json!(commit)).bind::<Timestamptz,_>(commit.committed_at)
            .bind::<Binary,_>(token.to_vec()).execute(&mut *conn).await.unwrap();
    }
}

async fn seed_checkpoint(conn: &mut AsyncPgConnection, fixture: &Value, index: usize) {
    let (event, _) = row(fixture, 0);
    for entry in fixture["checkpoints"][index]["current_state_entries"]
        .as_array()
        .unwrap()
    {
        let commit_id: arkret_wire::RealmCommitId =
            serde_json::from_value(entry["revision"]["commit_id"].clone()).unwrap();
        let commit: RealmCommit = fixture["original_rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["commit"]["commit_id"] == json!(commit_id))
            .map(|row| serde_json::from_value(row["commit"].clone()).unwrap())
            .unwrap();
        let call: CallId = serde_json::from_value(entry["selector"]["call_id"].clone()).unwrap();
        let selector: CurrentSelector = serde_json::from_value(entry["selector"].clone()).unwrap();
        write(
            conn,
            &event,
            &commit,
            &call,
            &selector,
            entry["value"].clone(),
        )
        .await
        .unwrap();
    }
}

fn current(_payload: &CallStatePayload, commit: &RealmCommit) -> coland_storage::CallCurrentCut {
    coland_storage::CallCurrentCut {
        scope_ref: ScopeRef::Realm {
            realm_id: commit.realm_id.clone(),
        },
        head: arkret_wire::CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        generation: 1,
        lifecycle: CallLifecycleState::Active,
        focus: Some(CallFocus {
            mode: CallMode::Sfu,
            session_focus: Some(arkret_wire::NonEmptyString::new("fra-1").unwrap()),
        }),
        participants: Vec::new(),
        moderation: Vec::new(),
        roster_revision: None,
        moderation_revision: None,
        moderation_current: None,
    }
}

#[tokio::test]
async fn native_stop_and_result_cas_are_separate_and_failed_does_not_reopen_capture() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let fixture = fixture();
    seed_sources(&mut conn, &fixture).await;
    seed_checkpoint(&mut conn, &fixture, 0).await;
    let (event, commit) = row(&fixture, 2);
    let payload: CallStatePayload = serde_json::from_value(json!(event.payload)).unwrap();
    let transition = payload.recording_transition.as_ref().unwrap();
    assert!(
        result_basis(
            &mut conn,
            &event,
            &commit,
            &payload.call_id,
            &transition.recording_id,
            false,
            transition.expected_commit_id.as_ref().unwrap()
        )
        .await
        .is_err()
    );
    seed_checkpoint(&mut conn, &fixture, 1).await;
    let (_, _, stop, _) = result_basis(
        &mut conn,
        &event,
        &commit,
        &payload.call_id,
        &transition.recording_id,
        false,
        transition.expected_commit_id.as_ref().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(stop, row(&fixture, 1).0.event_id);
    transition_recording(
        &mut conn,
        &event,
        &commit,
        &payload,
        transition,
        &current(&payload, &commit),
    )
    .await
    .unwrap();
    let state = axis(
        &mut conn,
        &event.realm_id,
        &selector(
            RecordingCaptureKind::Recording,
            false,
            &payload.call_id,
            &transition.recording_id,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(state.value, json!("stopped"));
    assert_eq!(
        state.current_commit_id,
        row(&fixture, 1).1.commit_id.as_str()
    );
    assert!(
        result_basis(
            &mut conn,
            &event,
            &commit,
            &payload.call_id,
            &transition.recording_id,
            false,
            transition.expected_commit_id.as_ref().unwrap()
        )
        .await
        .is_err()
    );
    let (ready, ready_commit) = row(&fixture, 3);
    let ready_payload: CallStatePayload = serde_json::from_value(json!(ready.payload)).unwrap();
    let ready_transition = ready_payload.recording_transition.as_ref().unwrap();
    result_basis(
        &mut conn,
        &ready,
        &ready_commit,
        &ready_payload.call_id,
        &ready_transition.recording_id,
        false,
        ready_transition.expected_commit_id.as_ref().unwrap(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_stop_from_another_kind_cannot_authorize_a_recording_result() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let fixture = fixture();
    seed_sources(&mut conn, &fixture).await;
    seed_checkpoint(&mut conn, &fixture, 1).await;
    let (event, commit) = row(&fixture, 2);
    let payload: CallStatePayload = serde_json::from_value(json!(event.payload)).unwrap();
    let transition = payload.recording_transition.as_ref().unwrap();
    let mut state = axis(
        &mut conn,
        &event.realm_id,
        &selector(
            RecordingCaptureKind::Recording,
            false,
            &payload.call_id,
            &transition.recording_id,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    state.current_commit_id = row(&fixture, 5).1.commit_id.to_string();
    state.current_stream_position = row(&fixture, 5).1.stream_position as i64;
    assert!(
        stop_source(
            &mut conn,
            &event.realm_id,
            &state,
            &payload.call_id,
            &transition.recording_id,
            false,
            &commit.stream_ref
        )
        .await
        .is_err()
    );
    state.current_commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]).to_string();
    assert!(
        stop_source(
            &mut conn,
            &event.realm_id,
            &state,
            &payload.call_id,
            &transition.recording_id,
            false,
            &commit.stream_ref
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn complete_capture_snapshot_installs_both_axes_and_refuses_partial_replacement_atomically() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let fixture = fixture();
    let checkpoint = fixture["checkpoints"].as_array().unwrap().last().unwrap();
    let entries: Vec<arkret_wire::CurrentState> =
        serde_json::from_value(checkpoint["current_state_entries"].clone()).unwrap();
    let head: arkret_wire::CommitStreamHead =
        serde_json::from_value(checkpoint["source_head"].clone()).unwrap();
    for _ in 0..2 {
        crate::replica_current::install_snapshot_in_connection(
            &mut conn,
            head.stream_ref.realm_id(),
            &head,
            &entries,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    }
    let mut partial = entries.clone();
    partial.pop();
    conn.batch_execute("BEGIN").await.unwrap();
    assert!(
        crate::replica_current::install_snapshot_in_connection(
            &mut conn,
            head.stream_ref.realm_id(),
            &head,
            &partial,
            chrono::Utc::now()
        )
        .await
        .is_err()
    );
    conn.batch_execute("ROLLBACK").await.unwrap();
    for entry in entries {
        let arkret_wire::CurrentState::Value {
            selector,
            revision,
            value,
            ..
        } = entry;
        let retained = axis(&mut conn, head.stream_ref.realm_id(), &selector)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.value, value);
        assert_eq!(retained.current_commit_id, revision.commit_id.as_str());
    }
}

#[test]
fn retention_and_legal_hold_cannot_disappear_during_result_publication() {
    let now = chrono::Utc::now();
    let retention = CallRecordingRetention {
        retention_expires_at: Some(now + chrono::Duration::hours(1)),
        deletion_trigger: None,
        audit_lock: Some(true),
        consent_confirmed: Some(true),
    };
    let mut next = retention.clone();
    next.audit_lock = Some(false);
    assert!(super::retention(&retention, &next, now).is_err());
    next = retention.clone();
    next.retention_expires_at = None;
    assert!(super::retention(&retention, &next, now).is_err());
    assert!(
        retained_result(
            &json!({"status":"failed","details":{"retention":retention}}),
            None,
            now
        )
        .is_err()
    );
}

#[tokio::test]
async fn concurrent_result_writers_serialize_on_the_real_axis_and_only_one_cas_succeeds() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let fixture = fixture();
    let mut first = pool.get().await.unwrap();
    seed_sources(&mut first, &fixture).await;
    seed_checkpoint(&mut first, &fixture, 1).await;
    let (event, commit) = row(&fixture, 2);
    let payload: CallStatePayload = serde_json::from_value(json!(event.payload)).unwrap();
    let transition = payload.recording_transition.as_ref().unwrap();
    first.batch_execute("BEGIN").await.unwrap();
    result_basis(
        &mut first,
        &event,
        &commit,
        &payload.call_id,
        &transition.recording_id,
        false,
        transition.expected_commit_id.as_ref().unwrap(),
    )
    .await
    .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let other_pool = pool.clone();
    let other_fixture = fixture.clone();
    let mut waiter = tokio::spawn(async move {
        let mut conn = other_pool.get().await.unwrap();
        conn.batch_execute("BEGIN").await.unwrap();
        let (event, commit) = row(&other_fixture, 2);
        let payload: CallStatePayload = serde_json::from_value(json!(event.payload)).unwrap();
        let _ = started_tx.send(());
        let result = transition_recording(
            &mut conn,
            &event,
            &commit,
            &payload,
            payload.recording_transition.as_ref().unwrap(),
            &current(&payload, &commit),
        )
        .await;
        conn.batch_execute("ROLLBACK").await.unwrap();
        result
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut waiter)
            .await
            .is_err(),
        "competing writer must wait for the held native row lock"
    );
    transition_recording(
        &mut first,
        &event,
        &commit,
        &payload,
        transition,
        &current(&payload, &commit),
    )
    .await
    .unwrap();
    first.batch_execute("COMMIT").await.unwrap();
    let loser = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(loser.to_string().contains("revision changed"), "{loser}");
}

#[tokio::test]
async fn recording_public_metadata_checks_real_blob_and_never_substitutes_for_service_producer() {
    let database = crate::test_database::TestDatabase::lease().await;
    let pool = database.pool();
    let mut conn = pool.get().await.unwrap();
    let fixture = fixture();
    seed_sources(&mut conn, &fixture).await;
    let (start, _) = row(&fixture, 0);
    let opening: CallRecordingStartPayload = serde_json::from_value(json!(start.payload)).unwrap();
    let (ready, commit) = row(&fixture, 3);
    let payload: CallStatePayload = serde_json::from_value(json!(ready.payload)).unwrap();
    let artifact = payload
        .recording_transition
        .as_ref()
        .unwrap()
        .capture_metadata
        .as_ref()
        .unwrap()
        .artifact
        .as_ref()
        .unwrap();
    let grant = &fixture["initiator_grant_source"]["current"];
    let grant_commit: RealmCommit =
        serde_json::from_value(fixture["initiator_grant_source"]["commit"].clone()).unwrap();
    let root = &grant["authority_root_ref"];
    // Accepted authorization/media inputs of this materializer test. Their
    // independent signature/admission paths are not replaced by this seed.
    sql_query("INSERT INTO realm_authority_root_current_states(realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) VALUES($1,$2,0,1,$3,$4,19,$5)")
        .bind::<Text,_>(start.realm_id.as_str()).bind::<Jsonb,_>(json!(start.actor_id))
        .bind::<Text,_>(root["authority_event_ref"].as_str().unwrap()).bind::<Text,_>(grant_commit.commit_id.as_str())
        .bind::<Timestamptz,_>(grant_commit.committed_at).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO capability_grant_current_states(realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value,updated_at) VALUES($1,$2,'active',$3,$4,$5,19,$6,$7)")
        .bind::<Text,_>(start.realm_id.as_str()).bind::<Text,_>(artifact.recording_initiator_capability_ref.as_str())
        .bind::<Text,_>(grant_commit.event_ref.as_str()).bind::<Text,_>(grant_commit.commit_id.as_str())
        .bind::<Jsonb,_>(json!(grant_commit.stream_ref)).bind::<Jsonb,_>(grant)
        .bind::<Timestamptz,_>(grant_commit.committed_at).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO realm_media_service_current_states(realm_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,19,$4,$5)")
        .bind::<Text,_>(start.realm_id.as_str()).bind::<Jsonb,_>(json!(commit.stream_ref))
        .bind::<Text,_>(grant_commit.commit_id.as_str())
        .bind::<Jsonb,_>(json!({"service_id":"ak:did_core:web:media.example","recording_supported":true,"foci":[{"focus_id":"fra-1","focus_kind":"livekit","token_endpoint":"https://media.example/token","connect_url":"wss://media.example/connect"}]}))
        .bind::<Timestamptz,_>(grant_commit.committed_at).execute(&mut *conn).await.unwrap();
    let record = coland_storage::BlobRecord {
        sha256: artifact.blob_ref.as_str().strip_prefix("ak:blob:sha256:").unwrap().to_owned(),
        size_bytes: artifact.size_bytes as i64, storage_backend: "test-private".into(), storage_key: "ciphertext".into(),
        media_type: "application/octet-stream".into(), filename: None, realm_id: Some(start.realm_id.to_string()),
        encryption: Some(arkret_models_collaboration::objects::blob::BlobStorageEncryption { scheme: arkret_models_collaboration::objects::blob::BlobStorageEncryptionScheme::StreamV1 }),
        legal_hold: false, redacted: false,
        visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
        uploaded_by: opening.recording_agent_id.to_string(), created_at: commit.committed_at,
    };
    crate::blobs::put_blob_if_absent_in_connection(&mut conn, artifact.blob_ref.as_str(), &record)
        .await
        .unwrap();
    let cut = current(&payload, &commit);
    validate_recording_artifact(
        &mut conn,
        &commit,
        &start,
        &opening,
        &cut,
        artifact,
        &json!({"status":"pending"}),
    )
    .await
    .unwrap();
    for mutation in [
        "wrong_call",
        "wrong_start",
        "wrong_label",
        "wrong_focus",
        "wrong_size",
        "wrong_prefix_width",
    ] {
        let mut changed = artifact.clone();
        match mutation {
            "wrong_call" => changed.call_id = CallId::from_event_id(&row(&fixture, 1).0.event_id),
            "wrong_start" => changed.recording_start_event_id = row(&fixture, 1).0.event_id,
            "wrong_label" => changed.encryption.exporter_label = "ak.rtc-transcript-key/v1".into(),
            "wrong_focus" => changed.encryption.context.focus_id = "other-focus".into(),
            "wrong_size" => changed.size_bytes += 1,
            _ => {
                changed.encryption.nonce_prefix =
                    arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 18]))
                        .unwrap()
            }
        }
        assert!(
            validate_recording_artifact(
                &mut conn,
                &commit,
                &start,
                &opening,
                &cut,
                &changed,
                &json!({"status":"pending"})
            )
            .await
            .is_err(),
            "{mutation}"
        );
    }
    assert!(
        require_recording_service_producer(&mut conn, &ready, &commit, &opening, artifact)
            .await
            .is_err(),
        "public ciphertext metadata is not a real Service producer fact"
    );
}
