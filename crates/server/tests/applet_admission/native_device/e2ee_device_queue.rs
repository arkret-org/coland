//! Native queue consumers use actual accepted, encrypted recipient deliveries.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_queue_lists_and_acks_its_actual_durable_welcome_without_session() {
    for ghost in [false, true] {
        for fenced in [false, true] {
            tokio::spawn(native_phase(|| {
                exercise_consume(ghost, fenced, None, GroupCase::QueueList)
            }))
            .await
            .unwrap();
        }
    }
}

pub(super) async fn assert_initial_list(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    welcome: &arkret_wire::MlsWelcomeDelivery,
) -> arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome {
    native_phase(|| assert_list_failures(fixture, authority, key, scope)).await;
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfDeviceMessagesReadListV1,
        key,
        None,
    )
    .send(&service(fixture.state.clone()))
    .await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "the true native recipient must list its actual accepted Welcome without Session: {}",
        String::from_utf8_lossy(&bytes)
    );
    let outcome: arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(outcome.deliveries.len(), 1);
    assert!(
        matches!(&outcome.deliveries[0],arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome{mls_welcome} if mls_welcome==welcome)
    );
    assert!(outcome.ack_token.is_some());
    assert!(outcome.next_cursor.is_some());
    assert!(!outcome.has_more);
    outcome
}

pub(super) async fn assert_ack(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    token: &str,
    count: u64,
) {
    let body = arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
        ack_token: token.to_owned(),
    };
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfDeviceMessagesCommandAckV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "native exact ACK: {}",
        String::from_utf8_lossy(&bytes)
    );
    let outcome: arkret_models_collaboration::device_messages::DeviceMessagesAckOutcome =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(outcome.pruned_count, count);
}
pub(super) async fn assert_after_ack(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    after: &str,
    fenced: bool,
) {
    let path = format!("/_arkret/self/device_messages?after={after}");
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_at(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfDeviceMessagesReadListV1,
        key,
        None,
        Some(&path),
    )
    .send(&service(fixture.state.clone()))
    .await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    if fenced {
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "no future disclosure after install fence: {}",
            String::from_utf8_lossy(&bytes)
        );
        return;
    }
    assert_eq!(
        status,
        StatusCode::OK,
        "native continuation: {}",
        String::from_utf8_lossy(&bytes)
    );
    let page: arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome =
        serde_json::from_slice(&bytes).unwrap();
    assert!(page.deliveries.is_empty());
    assert!(page.ack_token.is_none());
    assert!(page.next_cursor.is_none());
    assert!(!page.has_more);
}

use coland_storage::DeviceMessageStore as _;

async fn list_response(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    path: Option<&str>,
) -> salvo::Response {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    managed_device_http_request_at(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfDeviceMessagesReadListV1,
        key,
        None,
        path,
    )
    .send(&service(fixture.state.clone()))
    .await
}

async fn release_after_cancellation(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    let started = std::time::Instant::now();
    loop {
        let mut connection = fixture.pool.get().await.unwrap();
        let available = diesel::sql_query(
            "SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT",
        )
        .bind::<diesel::sql_types::Text, _>(authority.realm_id.as_str())
        .execute(&mut *connection)
        .await
        .is_ok();
        if available {
            return;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a cancelled pending page must release its actual current cut"
        );
        drop(connection);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn cursor_writer_fault(fixture: &Fixture, enabled: bool) {
    use diesel_async::SimpleAsyncConnection as _;
    let mut connection = fixture.pool.get().await.unwrap();
    connection.batch_execute(if enabled {
        "DROP TRIGGER IF EXISTS test_native_queue_cursor_failure ON sync_cursor_handles; DROP FUNCTION IF EXISTS test_native_queue_cursor_failure(); CREATE FUNCTION test_native_queue_cursor_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'native queue cursor writer failure'; END $$; CREATE TRIGGER test_native_queue_cursor_failure BEFORE INSERT ON sync_cursor_handles FOR EACH ROW EXECUTE FUNCTION test_native_queue_cursor_failure();"
    }else{
        "DROP TRIGGER test_native_queue_cursor_failure ON sync_cursor_handles; DROP FUNCTION test_native_queue_cursor_failure();"
    }).await.unwrap();
}

async fn assert_list_failures(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
) {
    // These are fresh real RFC 9421 requests, never a manufactured Session.
    for path in [
        "/_arkret/self/device_messages?after=unknown_cursor",
        "/_arkret/self/device_messages?limit=0",
    ] {
        let before = native_phase(|| business_snapshot(fixture)).await;
        let mut response =
            native_phase(|| list_response(fixture, authority, key, scope, Some(path))).await;
        let status = response.status_code.unwrap();
        let bytes = response.take_bytes(None).await.unwrap();
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "invalid queue request {path}: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            before,
            native_phase(|| business_snapshot(fixture)).await,
            "invalid input must allocate no cursor/ACK or change business state"
        );
    }
    native_phase(|| cursor_writer_fault(fixture, true)).await;
    let before = native_phase(|| business_snapshot(fixture)).await;
    let mut response = native_phase(|| list_response(fixture, authority, key, scope, None)).await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "actual cursor writer fails after private ACK allocation: {}",
        String::from_utf8_lossy(&bytes)
    );
    native_phase(|| release_after_cancellation(fixture, authority)).await;
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "cursor writer failure rolls back its already executed ACK insertion"
    );
    native_phase(|| cursor_writer_fault(fixture, false)).await;
    let before = native_phase(|| business_snapshot(fixture)).await;
    let response = native_phase(|| list_response(fixture, authority, key, scope, None)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let mut writer = fixture.pool.get().await.unwrap();
    // Catch only SQLSTATE 55P03; server message text is locale-dependent.
    diesel::sql_query(
        "CREATE OR REPLACE FUNCTION pg_temp.assert_native_queue_writer_locked(target_realm text) \
         RETURNS void LANGUAGE plpgsql AS $$ BEGIN \
           BEGIN \
             PERFORM 1 FROM realm_authorities WHERE realm_id=target_realm FOR UPDATE NOWAIT; \
           EXCEPTION WHEN lock_not_available THEN RETURN; END; \
           RAISE EXCEPTION 'native queue authority writer was not locked'; \
         END $$",
    )
    .execute(&mut *writer)
    .await
    .unwrap();
    for realm in [&authority.realm_id, scope.realm_id()] {
        diesel::sql_query("SELECT pg_temp.assert_native_queue_writer_locked($1)")
            .bind::<diesel::sql_types::Text, _>(realm.as_str())
            .execute(&mut *writer)
            .await
            .expect("the exact PCR and business current writers must remain locked before handoff");
    }
    drop(writer);
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "prepared private allocations remain uncommitted before response handoff"
    );
    drop(response);
    native_phase(|| release_after_cancellation(fixture, authority)).await;
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "cancellation before the full response frame leaves neither ACK nor cursor"
    );
}

pub(super) async fn assert_claim_expiry(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    deadline: chrono::DateTime<chrono::Utc>,
) {
    let before = native_phase(|| business_snapshot(fixture)).await;
    let mut response = native_phase(|| list_response(fixture, authority, key, scope, None)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    assert_eq!(before, native_phase(|| business_snapshot(fixture)).await);
    let remaining = (deadline - chrono::Utc::now())
        .to_std()
        .expect("the actual claim must still be live at response preparation");
    tokio::time::sleep(remaining + std::time::Duration::from_millis(100)).await;
    use futures_util::StreamExt as _;
    let mut body = response.take_body();
    assert!(
        body.next()
            .await
            .expect("the closed handoff reports its failure")
            .is_err(),
        "physical claim expiry must prevent the first full Welcome frame"
    );
    drop(body);
    native_phase(|| release_after_cancellation(fixture, authority)).await;
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "expired handoff rolls back all private queue allocations"
    );
    let mut refused = native_phase(|| list_response(fixture, authority, key, scope, None)).await;
    let bytes = refused.take_bytes(None).await.unwrap();
    assert_eq!(
        refused.status_code,
        Some(StatusCode::NOT_FOUND),
        "expired original claim no longer supplies new Welcome material: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(before, native_phase(|| business_snapshot(fixture)).await);
}

pub(super) async fn assert_native_token_cannot_use_legacy_ack(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    token: &str,
) {
    let before = native_phase(|| business_snapshot(fixture)).await;
    let old = coland_storage_postgres::PgDeviceMessageStore {
        pool: fixture.pool.clone(),
    };
    assert_eq!(
        native_phase(|| old.ack_with_token(
            authority.actor_id.signing_principal_id().as_str(),
            authority.device_id.as_str(),
            token
        ))
        .await
        .unwrap(),
        None
    );
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "native exact scope token cannot enter legacy cumulative queue deletion"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_claim_expiry_cancels_prepared_native_queue_allocations() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(ghost, false, None, GroupCase::QueueClaimExpiry)
        }))
        .await
        .unwrap();
    }
}

pub(super) async fn accepted_sibling(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    scope: &ScopeRef,
) -> arkret_wire::MlsWelcomeDelivery {
    let mut genesis =
        native_phase(|| activate_mls_with_private_state(fixture, scope.clone())).await;
    native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let upload = fresh_upload(identity, method, key, scope);
    assert_eq!(
        native_phase(|| upload_in_scope(fixture, authority, key, &upload, scope))
            .await
            .0,
        StatusCode::OK
    );
    let human_key = SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed);
    let mut command = request(authority, key, scope, &upload.keypackages[0].keypackage_ref);
    command.requester_actor_id = None;
    command.requester_account_id = Some(fixture.pcr.history.account.clone());
    account_requester(&fixture, &mut command);
    resign(&mut command, &human_key);
    let body = serde_json::to_value(&command).unwrap();
    let (status, value) = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1.as_str(),
            &body,
            Some(command.claim_request_id.as_str()),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual independent Circle claim: {value}"
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome =
        serde_json::from_value(value).unwrap();
    let guard = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: scope.clone(),
        service_did_document: applet_service_id_document(&install.package),
    };
    let (welcome, ..) = native_phase(|| {
        accepted_add(
            fixture,
            authority,
            scope,
            &mut genesis,
            &outcome.claims[0],
            &guard,
        )
    })
    .await;
    welcome
}

pub(super) async fn assert_other_scope_refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    other: &ScopeRef,
    page: &arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome,
) {
    let before = native_phase(|| business_snapshot(fixture)).await;
    let path = format!(
        "/_arkret/self/device_messages?after={}",
        page.next_cursor.as_deref().unwrap()
    );
    let mut response =
        native_phase(|| list_response(fixture, authority, key, other, Some(&path))).await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a real Realm cursor cannot continue the real Circle queue: {}",
        String::from_utf8_lossy(&bytes)
    );
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        error["type"],
        "https://arkret.org/problems/cursor_integrity_invalid"
    );
    let body = arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
        ack_token: page.ack_token.clone().unwrap(),
    };
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = other.clone();
    let mut response = managed_device_http_request_body(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfDeviceMessagesCommandAckV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(fixture.state.clone()))
    .await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a Realm token cannot ACK Circle material: {}",
        String::from_utf8_lossy(&bytes)
    );
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["reason_code"], "invalid_ack_token");
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "cross-scope cursor and ACK allocate or delete nothing"
    );
}

pub(super) async fn assert_sibling_preserved(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    sibling: &arkret_wire::MlsWelcomeDelivery,
) {
    let rows = native_phase(|| durable_realm_welcomes(fixture, authority)).await;
    assert_eq!(
        rows.len(),
        1,
        "only the unread Circle Welcome must remain queued"
    );
    assert!(
        matches!(&rows[0].delivery,arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome{mls_welcome} if mls_welcome==sibling)
    );
    let page = native_phase(|| {
        assert_initial_list(fixture, authority, key, &sibling.effective_scope, sibling)
    })
    .await;
    assert!(
        page.ack_token.is_some(),
        "the other actual scope remains deliverable after the Realm ACK and optional Realm install fence"
    );
    assert_eq!(
        native_phase(|| durable_realm_welcomes(fixture, authority))
            .await
            .len(),
        1,
        "list and cursor do not acknowledge the unread Circle Welcome"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_realm_ack_preserves_earlier_unread_circle_welcome_and_its_current_scope() {
    for ghost in [false, true] {
        for fenced in [false, true] {
            tokio::spawn(native_phase(|| {
                exercise_consume(ghost, fenced, None, GroupCase::QueueScopes)
            }))
            .await
            .unwrap();
        }
    }
}

#[path = "e2ee_device_queue_pages.rs"]
pub(super) mod pages;

pub(super) async fn assert_cold_continuation(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    after: &str,
) {
    let reopened = native_phase(|| {
        coland_test_support::app_state_with_persistence(
            fixture.state.config().clone(),
            std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(
                fixture.pool.clone(),
            )),
        )
    })
    .await;
    native_phase(|| reopened.hydrate()).await.unwrap();
    let before = native_phase(|| business_snapshot(fixture)).await;
    let path = format!("/_arkret/self/device_messages?after={after}");
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let mut response = managed_device_http_request_at(
        &reopened,
        authority,
        &metadata,
        ServiceOperationId::SelfDeviceMessagesReadListV1,
        key,
        None,
        Some(&path),
    )
    .send(&service(reopened.clone()))
    .await;
    let status = response.status_code.unwrap();
    let bytes = response.take_bytes(None).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "a cold hydrated worker must validate the original durable native cursor without a synthetic Session: {}",
        String::from_utf8_lossy(&bytes)
    );
    let page: arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome =
        serde_json::from_slice(&bytes).unwrap();
    assert!(page.deliveries.is_empty());
    assert!(page.next_cursor.is_none());
    assert!(page.ack_token.is_none());
    assert!(!page.has_more);
    assert_eq!(
        before,
        native_phase(|| business_snapshot(fixture)).await,
        "cold empty continuation advances neither cursor nor ACK"
    );
}

pub(super) async fn assert_backend_loss(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
) {
    use futures_util::StreamExt as _;
    #[derive(diesel::QueryableByName)]
    struct Backend {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        pid: i64,
    }
    #[derive(diesel::QueryableByName)]
    struct Stopped {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        stopped: bool,
    }
    let before = native_phase(|| business_snapshot(fixture)).await;
    let mut response = native_phase(|| list_response(fixture, authority, key, scope, None)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let mut observer = fixture.pool.get().await.unwrap();
    // This fixture owns an exclusive database lease. Only the exact idle
    // pending-page transaction ends with this private cursor allocation.
    let backends=diesel::sql_query("SELECT pid::bigint AS pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='idle in transaction' AND query LIKE 'INSERT INTO sync_cursor_handles%'").load::<Backend>(&mut *observer).await.unwrap();
    assert_eq!(
        backends.len(),
        1,
        "identify only this prepared native page's actual held transaction"
    );
    let stopped = diesel::sql_query("SELECT pg_terminate_backend($1) AS stopped")
        .bind::<diesel::sql_types::Integer, _>(i32::try_from(backends[0].pid).unwrap())
        .get_result::<Stopped>(&mut *observer)
        .await
        .unwrap();
    assert!(stopped.stopped);
    drop(observer);
    native_phase(|| release_after_cancellation(fixture, authority)).await;
    native_phase(|| fixture.revoke(install)).await;
    let fenced = native_phase(|| business_snapshot(fixture)).await;
    for name in ["device_message_ack_tokens", "sync_cursor_handles"] {
        assert_eq!(
            before[name], fenced[name],
            "lost pending allocations must roll back before the real installation fence"
        );
    }
    let mut body = response.take_body();
    assert!(
        body.next()
            .await
            .expect("failed cut must fail its response stream")
            .is_err(),
        "a terminated database cut must not disclose the first full Welcome frame"
    );
    drop(body);
    assert_eq!(
        fenced,
        native_phase(|| business_snapshot(fixture)).await,
        "the refused old response has no effects after the actual current installation fence"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_prepared_queue_never_discloses_after_its_db_cut_is_lost() {
    for ghost in [false, true] {
        tokio::spawn(native_phase(|| {
            exercise_consume(ghost, false, None, GroupCase::QueueBackendDrop)
        }))
        .await
        .unwrap();
    }
}

pub(super) async fn assert_http_queue_expiry(
    fixture: &Fixture,
    prepared: &coland_storage::EventCommitRequest,
    deadline: chrono::DateTime<chrono::Utc>,
) {
    use diesel_async::SimpleAsyncConnection as _;
    let idempotency = uuid::Uuid::now_v7();
    let token = idempotency.to_string();
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: prepared.authority_commit.event.clone(),
                welcomes: prepared
                    .authority_commit
                    .welcomes
                    .iter()
                    .map(|welcome| welcome.delivery.clone())
                    .collect(),
                idempotency_key: arkret_wire::UuidV7::new(idempotency).unwrap(),
            },
        );
    let body = serde_json::to_value(&submission).unwrap();
    let mut blocker = fixture.pool.get().await.unwrap();
    blocker
        .batch_execute("BEGIN; LOCK TABLE device_messages, mls_welcome_deliveries IN SHARE MODE")
        .await
        .unwrap();
    let submit = native_phase(|| {
        fixture.admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1.as_str(),
            &body,
            Some(&token),
        )
    });
    let release = native_phase(|| async {
        let observed = native_phase(|| wait_for_welcome_queue_lock(fixture)).await;
        let delay = (deadline - chrono::Utc::now()).to_std();
        let live = observed && delay.is_ok();
        if live {
            tokio::time::sleep(delay.unwrap() + std::time::Duration::from_millis(250)).await;
        }
        blocker.batch_execute("ROLLBACK").await.unwrap();
        live
    });
    let ((status, outcome), observed_live) = tokio::join!(submit, release);
    assert!(
        observed_live,
        "the actual complete HTTP MLS writer must be observed at its queue lock while the claim is live; status={status}; outcome={outcome}"
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "physical claim expiry must reject the complete attested unit after its real queue wait: {outcome}"
    );
    assert_eq!(
        outcome["type"],
        "https://arkret.org/problems/capability_denied"
    );
}
