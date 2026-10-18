//! Native Account Device MLS admission through the actual mounted HTTP port.
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_collaboration::events_payloads::{
    MlsGenesisCreatorLeafAuthority, MlsGenesisPayload,
};
use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_wire::MlsCommitSubmission;
use coland_storage::MlsGroupCurrentStore as _;

use super::*;

#[path = "exact_current_read.rs"]
mod current_read;
#[path = "e2ee_mls_material_read.rs"]
mod material_read;
#[path = "e2ee_native_committer.rs"]
mod native_committer;

async fn public_material(fixture: &Fixture, bytes: Vec<u8>) -> arkret_wire::BlobRef {
    // Existing public objects are prerequisites here. Blob HTTP ingress is a
    // separate consumer; this test never seeds an accepted Genesis or group.
    let digest = arkret_canonical::sha256_digest(&bytes);
    let sha256 = digest.strip_prefix("sha256:").unwrap();
    let reference = arkret_wire::BlobRef::new(format!("ak:blob:{digest}")).unwrap();
    let storage_key = fixture.state.test_object_key_for_sha256(sha256);
    let record = coland_storage::BlobRecord {
        sha256: sha256.to_owned(),
        size_bytes: bytes.len() as i64,
        storage_backend: "memory".to_owned(),
        storage_key: storage_key.clone(),
        media_type: "application/octet-stream".to_owned(),
        filename: None,
        realm_id: Some(fixture.realm.to_string()),
        encryption: None,
        legal_hold: false,
        redacted: false,
        visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
        uploaded_by: fixture.pcr.history.account.principal_id.to_string(),
        created_at: chrono::Utc::now(),
    };
    fixture
        .state
        .test_put_object(&storage_key, bytes)
        .await
        .unwrap();
    fixture
        .state
        .test_persistence()
        .blobs()
        .put(reference.as_str(), &record)
        .await
        .unwrap();
    reference
}

fn original_event(
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    grant: &arkret_wire::GrantId,
    scope: &ScopeRef,
    kind: EventKind,
    payload: Value,
    at: chrono::DateTime<chrono::Utc>,
) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope.clone(),
        ActorId::account(authority.account_id.clone()),
        payload,
        at,
    )
    .unwrap();
    event.applet_id = Some(install.package.applet_id.clone());
    event.authorization_ref = Some(grant.clone().into());
    sign_managed_device_event(event, authority, key, at)
}

async fn submit_commit(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    event: &Event,
    idempotency: uuid::Uuid,
) -> (StatusCode, Value) {
    submit_commit_in_state(&fixture.state, authority, key, event, idempotency).await
}

async fn submit_commit_in_state(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    event: &Event,
    idempotency: uuid::Uuid,
) -> (StatusCode, Value) {
    let body = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(idempotency).unwrap(),
    });
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = event.scope_ref.clone();
    let token = idempotency.to_string();
    let mut response = managed_device_http_request_with_idempotency_at(
        state,
        authority,
        &metadata,
        ServiceOperationId::SelfEventsCommandSubmitV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
        None,
        &token,
    )
    .send(&service(state.clone()))
    .await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_originate_real_genesis_and_typed_self_update_commit_without_session() {
    for ghost in [false, true] {
        for circle in [false, true] {
            tokio::spawn(native_phase(|| originate(ghost, Case::Accepted, circle)))
                .await
                .unwrap();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Accepted,
    MaterialReads,
    ExactCurrentReads,
    AddWelcome,
    QualifiedRefusal,
    MissingPair,
    ClosedParent,
    ClosedInstall,
    DeniedPolicy,
    DeviceExpiry,
    SourceExpiry,
    ClosedCircle,
    SourceGlobalDeny,
    ActorGlobalDeny,
    QuotaExhausted,
    QuotaQualified,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_mls_refusal_requires_current_device_pair_service_installation_and_policy() {
    for ghost in [false, true] {
        for case in [
            Case::QualifiedRefusal,
            Case::MissingPair,
            Case::ClosedParent,
            Case::ClosedInstall,
            Case::DeniedPolicy,
            Case::ClosedCircle,
            Case::SourceGlobalDeny,
            Case::ActorGlobalDeny,
            Case::QuotaExhausted,
            Case::QuotaQualified,
        ] {
            tokio::spawn(native_phase(|| {
                originate(ghost, case, case == Case::ClosedCircle)
            }))
            .await
            .unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_mls_device_and_service_source_must_remain_live_after_the_actual_writer_wait() {
    for ghost in [false, true] {
        for case in [Case::DeviceExpiry, Case::SourceExpiry] {
            tokio::spawn(native_phase(|| {
                originate(ghost, case, case == Case::ClosedCircle)
            }))
            .await
            .unwrap();
        }
    }
}

async fn originate(ghost: bool, case: Case, circle: bool) {
    let fixture = native_phase(Fixture::new).await;
    let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
    let native = mls_service(&fixture, &namespace);
    let install =
        native_phase(|| fixture.install_package(true, native.package.clone(), &namespace)).await;
    let bundle = if ghost {
        let body = native_phase(|| fixture.ghost_body(&install, &namespace, "mls-author")).await;
        let (status, outcome) =
            native_phase(|| fixture.ghost_commit(&install, &body, "mls-author")).await;
        assert_eq!(status, StatusCode::CREATED, "{outcome}");
        body["managed_actor_bundle"].clone()
    } else {
        install.bot_body["managed_actor_bundle"].clone()
    };
    let key = SigningKey::from_bytes(&[199; 32]);
    let realm_scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let scope = if circle {
        let scope = native_phase(|| fixture.new_circle_scope()).await;
        native_phase(|| super::circle::join_founder(&fixture, &scope)).await;
        let (_, body) = native_phase(|| {
            fixture.prepare_install_service_with_constraints(
                true,
                install.package.clone(),
                scope.clone(),
                BTreeMap::new(),
            )
        })
        .await;
        let (status, outcome) = native_phase(|| {
            fixture.admin_post(
                "/_arkret/self/applets/install",
                ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &body,
                Some("native-mls-circle-install"),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "native MLS exact Circle install: {outcome}"
        );
        scope
    } else {
        realm_scope.clone()
    };
    let current_source = if case == Case::ExactCurrentReads {
        Some(native_phase(|| current_read::prepare_source(&fixture, &scope)).await)
    } else {
        None
    };
    let device_expiry = (case == Case::DeviceExpiry).then(|| {
        arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(4),
        )
    });
    let mut actions = vec!["ak.applet.join", "ak.event.read", "ak.mls.genesis"];
    if case != Case::MissingPair {
        actions.push("ak.mls.commit");
    }
    if circle {
        actions.push("ak.circle.member.add");
    }
    actions.sort_unstable();
    let mut scopes = vec![json!({"effective_scope":scope,"actions":actions})];
    if circle {
        scopes.push(
            json!({"effective_scope":realm_scope,"actions":["ak.applet.join","ak.event.read"]}),
        );
    }
    let authority = native_phase(|| {
        authorize_scopes_until(
            &fixture,
            &install,
            &bundle,
            &namespace,
            &key,
            DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
            json!(scopes),
            device_expiry,
        )
    })
    .await;
    let actor = ActorId::account(authority.account_id.clone());
    let source_expiry = (case == Case::SourceExpiry).then(|| {
        arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(4),
        )
    });
    let mut constraints = Vec::new();
    if let Some(expires_at) = source_expiry {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraintEffect, GrantConstraintKind,
        };
        let mut temporal =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
        temporal.expires_at = Some(expires_at);
        constraints.push(temporal);
    }
    let mut parent_actions = vec!["ak.mls.commit".to_owned(), "ak.mls.genesis".to_owned()];
    if circle {
        parent_actions.push("ak.circle.member.add".to_owned());
    }
    parent_actions.sort_unstable();
    if matches!(case, Case::QuotaExhausted | Case::QuotaQualified) {
        let quota: GrantConstraint = serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operations":if case == Case::QuotaExhausted {1} else {2},"period":"P1D","constraint_scope":"per_realm"})).unwrap();
        constraints.push(quota);
    }
    let parent = native_phase(|| {
        native_business_parent_in_scope(
            &fixture,
            &install,
            constraints,
            parent_actions,
            None,
            scope.clone(),
        )
    })
    .await;
    let parents = [parent.clone()];
    let child = native_phase(|| native_business_child(&fixture, &install, &actor, &parents)).await;
    let join = join_event(
        &fixture,
        &install,
        &authority,
        &key,
        &install.bot_outcome.authorization_ref,
    );
    let (status, outcome) = native_phase(|| post(&fixture, &authority, &key, &join, vec![])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native membership: {outcome}"
    );
    if circle {
        let parent_revision = native_phase(|| {
            ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &actor)
        })
        .await;
        let join = native_circle_event(
            &install,
            &authority,
            &key,
            &scope,
            &child,
            "join",
            Some(parent_revision),
            Value::Null,
        );
        let (status, outcome) =
            native_phase(|| post(&fixture, &authority, &key, &join, vec![])).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "native MLS creator's exact Circle membership: {outcome}"
        );
    }
    if let Some(source) = current_source {
        native_phase(|| {
            current_read::exercise(&fixture, &install, &authority, &key, &scope, source)
        })
        .await;
        return;
    }
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let mut group = Box::new(
        identity
            .create_group_with_governance_binding(&scope, &binding)
            .unwrap(),
    );
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let info_ref = native_phase(|| public_material(&fixture, info)).await;
    let tree_ref = native_phase(|| public_material(&fixture, tree)).await;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let payload = MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        group_info_ref: info_ref,
        ratchet_tree_ref: tree_ref,
        creator_leaf_authority: MlsGenesisCreatorLeafAuthority {
            leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(key.verifying_key().as_bytes()),
            )
            .unwrap(),
            endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: authority.device_id.clone(),
            },
            authorization_event_ref: authority.selector.authorization_ref.event_id.clone(),
        },
        governance_binding: binding,
        created_at: at,
    };
    payload.validate().unwrap();
    let genesis = original_event(
        &install,
        &authority,
        &key,
        &child,
        &scope,
        EventKind::MlsGenesis,
        serde_json::to_value(payload).unwrap(),
        at,
    );
    let (status, outcome) =
        native_phase(|| post(&fixture, &authority, &key, &genesis, vec![])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native Genesis actual HTTP: {outcome}"
    );
    assert_accepted_event(&fixture, &genesis).await;
    group
        .install_local_creator_binding(
            actor.clone(),
            Some(authority.selector.authorization_ref.event_id.clone()),
        )
        .unwrap();
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    let current = native_phase(|| groups.current(&scope))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.value.epoch, 0);
    if case == Case::AddWelcome {
        native_phase(|| {
            native_committer::exercise(
                &fixture, &install, &authority, &key, &scope, &child, &mut group,
            )
        })
        .await;
        return;
    }
    if case == Case::MaterialReads {
        native_phase(|| {
            material_read::exercise(&fixture, &install, &authority, &key, &scope, &genesis)
        })
        .await;
        return;
    }

    let next_binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(genesis.event_id.clone()),
        0,
        1,
        current.value.current_key_access_revision
            + if case == Case::ClosedCircle {
                2
            } else {
                u64::from(matches!(
                    case,
                    Case::QualifiedRefusal
                        | Case::MissingPair
                        | Case::ClosedParent
                        | Case::ClosedInstall
                        | Case::DeniedPolicy
                        | Case::ClosedCircle
                        | Case::SourceGlobalDeny
                        | Case::ActorGlobalDeny
                        | Case::QuotaExhausted
                        | Case::QuotaQualified
                ))
            },
    )
    .unwrap();
    let envelope = group
        .self_update_commit_with_governance_binding(&next_binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.value.current_mls_commit_event_ref.clone(),
        next_binding.key_access_revision(),
        &envelope,
        next_binding,
    )
    .unwrap();
    let commit = original_event(
        &install,
        &authority,
        &key,
        &child,
        &scope,
        EventKind::MlsCommit,
        serde_json::to_value(payload).unwrap(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let idempotency = uuid::Uuid::now_v7();
    if case != Case::Accepted {
        if case == Case::ClosedCircle {
            let leave = native_circle_event(
                &install,
                &authority,
                &key,
                &scope,
                &child,
                "leave",
                None,
                json!("join"),
            );
            let (status, outcome) =
                native_phase(|| post(&fixture, &authority, &key, &leave, vec![])).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "actual native Circle leave before stale Commit: {outcome}"
            );
        }
        native_phase(|| {
            exercise_refusal(
                &fixture,
                &install,
                &authority,
                &key,
                &parent,
                &commit,
                idempotency,
                case,
                device_expiry.or(source_expiry),
            )
        })
        .await;
        return;
    }
    // A real final ledger writer fault must roll back the preceding Event,
    // Commit, public epoch, signer source and every queue/outbox write.
    native_phase(|| ledger_fault(&fixture, Some(false))).await;
    let before_fault = native_phase(|| snapshot(&fixture)).await;
    let (status, error) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &commit, idempotency)).await;
    native_phase(|| ledger_fault(&fixture, None)).await;
    assert!(
        !status.is_success(),
        "actual ledger writer failure: {error}"
    );
    assert_eq!(before_fault, native_phase(|| snapshot(&fixture)).await);
    native_phase(|| ledger_fault(&fixture, Some(true))).await;
    let before_conflict = native_phase(|| snapshot(&fixture)).await;
    let (status, conflict) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &commit, idempotency)).await;
    native_phase(|| ledger_fault(&fixture, None)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "different landed hash at the real final ledger writer: {conflict}"
    );
    assert_eq!(
        conflict["type"],
        "https://arkret.org/problems/duplicate_conflict"
    );
    assert_eq!(before_conflict, native_phase(|| snapshot(&fixture)).await);
    let (status, outcome) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &commit, idempotency)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native typed Commit actual HTTP: {outcome}"
    );
    assert_accepted_event(&fixture, &commit).await;
    assert_eq!(
        native_phase(|| groups.current(&scope))
            .await
            .unwrap()
            .unwrap()
            .value
            .epoch,
        1
    );
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, replay) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &commit, idempotency)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native typed Commit retry: {replay}"
    );
    assert_eq!(
        outcome, replay,
        "exact retry retains its first complete outcome"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let (status, bare) = native_phase(|| post(&fixture, &authority, &key, &commit, vec![])).await;
    assert!(
        !status.is_success(),
        "accepted Event cannot bypass the complete MLS branch: {bare}"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
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
    let (status, cold) =
        native_phase(|| submit_commit_in_state(&reopened, &authority, &key, &commit, idempotency))
            .await;
    assert_eq!(status, StatusCode::OK, "cold native MLS retry: {cold}");
    assert_eq!(outcome, cold);
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let persistence = fixture.state.test_persistence();
    for event in [&genesis, &commit] {
        let accepted = native_phase(|| {
            persistence
                .authority_commits()
                .committed_event(&event.event_id)
        })
        .await
        .unwrap()
        .unwrap();
        let fact = native_phase(|| {
            persistence
                .authority_commits()
                .account_device_signer_fact(event, &accepted.commit)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fact.actor, actor);
        assert_eq!(
            fact.key.authorization_ref,
            authority.selector.authorization_ref
        );
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(event, &fact, fixture.realm.digest_suite_code().digest_suite()).unwrap();
    }
    let accepted = native_phase(|| {
        persistence
            .authority_commits()
            .committed_event(&commit.event_id)
    })
    .await
    .unwrap()
    .unwrap();
    group
        .install_accepted_commit(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event,
                commit: accepted.commit,
            },
            &current.value,
        )
        .unwrap();
    let next = native_phase(|| groups.current(&scope))
        .await
        .unwrap()
        .unwrap();
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(commit.event_id.clone()),
        1,
        2,
        next.value.current_key_access_revision,
    )
    .unwrap();
    let envelope = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        next.value.current_mls_commit_event_ref,
        next.value.current_key_access_revision,
        &envelope,
        binding,
    )
    .unwrap();
    let second = original_event(
        &install,
        &authority,
        &key,
        &child,
        &scope,
        EventKind::MlsCommit,
        json!(payload),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, conflict) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &second, idempotency)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "same key with a real different Commit: {conflict}"
    );
    assert_eq!(
        conflict["type"],
        "https://arkret.org/problems/duplicate_conflict"
    );
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    native_phase(|| fixture.revoke(&install)).await;
    let before = native_phase(|| snapshot(&fixture)).await;
    let (status, replay) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &commit, idempotency)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "accepted result survives business fence: {replay}"
    );
    assert_eq!(outcome, replay);
    assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    let (status, next_outcome) =
        native_phase(|| submit_commit(&fixture, &authority, &key, &second, uuid::Uuid::now_v7()))
            .await;
    if circle {
        assert_eq!(
            status,
            StatusCode::OK,
            "Realm installation fence preserves exact Circle MLS business: {next_outcome}"
        );
        assert_eq!(
            native_phase(|| groups.current(&scope))
                .await
                .unwrap()
                .unwrap()
                .value
                .epoch,
            2
        );
    } else {
        assert!(
            !status.is_success(),
            "fenced exact Realm cannot accept another MLS epoch: {next_outcome}"
        );
        assert_eq!(before, native_phase(|| snapshot(&fixture)).await);
    }
}

async fn snapshot(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut before = business(fixture).await;
    let mut conn = fixture.pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT jsonb_build_object('groups',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM mls_group_current_results r),'queue',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM device_messages r)) AS value")
        .get_result::<Row>(&mut *conn).await.unwrap();
    before
        .as_object_mut()
        .unwrap()
        .insert("mls".into(), row.value);
    before
}

async fn ledger_fault(fixture: &Fixture, conflict: Option<bool>) {
    use diesel_async::SimpleAsyncConnection as _;
    let mut conn = fixture.pool.get().await.unwrap();
    conn.batch_execute("DROP TRIGGER IF EXISTS test_native_mls_ledger_failure ON idempotency_keys; DROP FUNCTION IF EXISTS test_native_mls_ledger_failure();").await.unwrap();
    let Some(conflict) = conflict else {
        return;
    };
    // Inject the competing row at the real INSERT, after all MLS writers.
    // This proves the landed-hash comparison and whole-transaction rollback;
    // it is deliberately not presented as a concurrent transport scenario.
    let body = if conflict {
        "IF NEW.request_hash <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000' THEN INSERT INTO idempotency_keys(actor_key,authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at) VALUES(NEW.actor_key,NEW.authenticated_actor,NEW.operation_id,NEW.idempotency_key,'sha256:0000000000000000000000000000000000000000000000000000000000000000',NEW.response_status,NEW.response_body,NEW.created_at,NEW.expires_at); END IF; RETURN NEW;"
    } else {
        "RAISE EXCEPTION 'native MLS ledger writer failure';"
    };
    conn.batch_execute(&format!("CREATE FUNCTION test_native_mls_ledger_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {body} END $$; CREATE TRIGGER test_native_mls_ledger_failure BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION test_native_mls_ledger_failure();")).await.unwrap();
}

async fn exercise_refusal(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    parent: &arkret_wire::GrantId,
    event: &Event,
    idempotency: uuid::Uuid,
    case: Case,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) {
    match case {
        Case::ClosedParent => native_phase(|| native_current_revoke(fixture, parent)).await,
        Case::ClosedInstall => {
            native_phase(|| fixture.revoke(install)).await;
        }
        Case::DeniedPolicy => {
            native_phase(|| install_policy(fixture, &install.package.applet_id, "execute")).await
        }
        _ => (),
    }
    if matches!(case, Case::SourceGlobalDeny | Case::ActorGlobalDeny) {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraintEffect, GrantConstraintKind,
        };
        let mut deny =
            GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Deny);
        deny.not_before = Some(arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() - chrono::Duration::seconds(1),
        ));
        deny.applies_to_actions = vec![
            arkret_wire::CapabilityActionId::MlsCommit
                .as_str()
                .to_owned(),
        ];
        if case == Case::SourceGlobalDeny {
            native_phase(|| {
                native_business_parent(
                    fixture,
                    install,
                    vec![deny],
                    vec!["ak.mls.commit".to_owned()],
                    None,
                )
            })
            .await;
        } else {
            native_phase(|| {
                native_business_child_with_constraints(
                    fixture,
                    install,
                    &event.actor_id,
                    std::slice::from_ref(parent),
                    vec![deny],
                )
            })
            .await;
        }
    }
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, outcome) = if let Some(expiry) = expires_at {
        native_phase(|| submit_after_wait(fixture, authority, key, event, idempotency, expiry))
            .await
    } else {
        native_phase(|| submit_commit(fixture, authority, key, event, idempotency)).await
    };
    if matches!(case, Case::QualifiedRefusal | Case::QuotaQualified) {
        assert_eq!(
            status,
            StatusCode::OK,
            "qualified exclusive native refusal: {outcome}"
        );
        assert_eq!(outcome["status"], "rejected", "{outcome}");
        assert_eq!(outcome["reason_code"], "governance_binding_mismatch");
        let refused = native_phase(|| snapshot(fixture)).await;
        for table in ["quota_counters", "quota_buckets", "quota_consumptions"] {
            assert_eq!(
                before[table], refused[table],
                "exclusive refusal cannot spend logical business quota"
            );
        }
        let (status, replay) =
            native_phase(|| submit_commit(fixture, authority, key, event, idempotency)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(outcome, replay);
        assert_eq!(refused, native_phase(|| snapshot(fixture)).await);
    } else {
        assert!(
            !status.is_success(),
            "{case:?} cannot mint a terminal native refusal: {outcome}"
        );
        assert_eq!(
            before,
            native_phase(|| snapshot(fixture)).await,
            "{case:?} leaves zero business writes"
        );
    }
}

async fn submit_after_wait(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    event: &Event,
    idempotency: uuid::Uuid,
    expiry: chrono::DateTime<chrono::Utc>,
) -> (StatusCode, Value) {
    use diesel_async::SimpleAsyncConnection as _;
    let mut blocker = fixture.pool.get().await.unwrap();
    blocker.batch_execute("BEGIN").await.unwrap();
    diesel::sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<diesel::sql_types::Text, _>(fixture.realm.as_str())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let submit = native_phase(|| submit_commit(fixture, authority, key, event, idempotency));
    let release = native_phase(|| async {
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            waiting: bool,
        }
        let mut observer = fixture.pool.get().await.unwrap();
        let limit = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let row = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query ILIKE '%realm_authorities%') AS waiting").get_result::<Row>(&mut *observer).await.unwrap();
            if row.waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "actual native MLS writer must wait on its authority cut"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let delay = (expiry - chrono::Utc::now())
            .to_std()
            .expect("real signed source must still be live at observed writer wait");
        tokio::time::sleep(delay + std::time::Duration::from_millis(100)).await;
        blocker.batch_execute("ROLLBACK").await.unwrap();
    });
    let (outcome, ()) = tokio::join!(submit, release);
    outcome
}
