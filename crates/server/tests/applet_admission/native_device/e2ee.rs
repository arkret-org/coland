//! Independent consent uses real accepted installation and MLS Genesis sources.
#[path = "e2ee_circle.rs"]
mod circle;
#[path = "e2ee_keypackage.rs"]
mod keypackage;
#[path = "e2ee_read.rs"]
mod read;
use coland_storage::EventCommitUnitOfWork as _;

use super::*;

async fn install_policy(fixture: &Fixture, applet: &AppletId, operation: &str) {
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let target = if operation == "install" {
        json!({"kind":"requester","actor_id":admin})
    } else {
        json!({"kind":"installation","applet_id":applet,"effective_scope":scope})
    };
    let event = fixture.admin_event(
        EventKind::PolicySet,
        scope.clone(),
        json!({
            "policy_id":id,"expected_revision":null,"value":{
                "schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,
                "policy_kind":"applet","default_effect":"allow","created_by":admin,
                "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
                "rules":[{"rule_id":"current_applet_gate","kind":"applet","effect":"deny",
                    "applet_target":target,
                    "applet_operations":[operation]}]
            }
        }),
    );
    Box::pin(accepted_admin_domain_event(fixture, event)).await;
}

fn mls_service(fixture: &Fixture, namespace: &str) -> NativeAppletService {
    let mut native = NativeAppletService::new(
        &format!("ak:applet:{}", uuid::Uuid::now_v7()),
        namespace,
        &fixture.state.service_core_id(),
    );
    native.package.e2ee_policy.enabled = true;
    native.package.e2ee_policy.mls_join_requested = Some(true);
    native
        .package
        .claimed_profiles
        .push(arkret_wire::ProfileId::APPLET_E2EE_JOIN_V1.to_owned());
    resign_native_applet_package(&mut native.package);
    native
}

struct MlsGenesisRuntime {
    group: arkret_mls::ArkretMlsGroup,
    accepted: arkret_wire::CommittedEventFullView,
}

async fn activate_mls(fixture: &Fixture, scope: ScopeRef) {
    let _ = native_phase(|| activate_mls_with_private_state(fixture, scope)).await;
}

async fn activate_mls_with_private_state(
    fixture: &Fixture,
    scope: ScopeRef,
) -> Box<MlsGenesisRuntime> {
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        fixture.pcr.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(
            &fixture.pcr.history.founding_device_signing_seed,
        )),
    )
    .unwrap();
    let binding =
        arkret_models_crypto::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)
            .unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let group_id = scope.canonical_mls_group_id().unwrap();
    let tracker =
        arkret_mls::MlsPublicGroupTracker::from_external(&info, &tree, group_id.as_str(), 0)
            .unwrap();
    let event = fixture.admin_event(EventKind::MlsGenesis, scope.clone(), json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref":format!("ak:blob:{}", arkret_canonical::sha256_digest(&info)),
        "ratchet_tree_ref":format!("ak:blob:{}", arkret_canonical::sha256_digest(&tree)),
        "creator_leaf_authority":{
            "leaf_signature_key_b64u":arkret_canonical::base64url_encode(SigningKey::from_bytes(&fixture.pcr.history.founding_device_signing_seed).verifying_key().as_bytes()),
            "endpoint":{"kind":"device","device_id":fixture.pcr.history.founding_device_id},
            "authorization_event_ref":fixture.pcr.history.events[1].event_id
        },
        "governance_binding":binding,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }));
    let mut request = Box::pin(admin_domain_request(fixture, event.clone())).await;
    request.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
        effective_scope: scope,
        base: None,
        epoch: 0,
        public_state: tracker.export_state().unwrap(),
        member_principals: [actor.clone()].into_iter().collect(),
        consumed_proposals: vec![],
        public_blobs: vec![],
    });
    coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
        .commit_event(request)
        .await
        .unwrap();
    assert_accepted_event(fixture, &event).await;
    group
        .install_local_creator_binding(actor, Some(fixture.pcr.history.events[1].event_id.clone()))
        .unwrap();
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let accepted = native_phase(|| store.committed_event(&event.event_id))
        .await
        .unwrap()
        .unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: accepted.event,
        commit: accepted.commit,
    };
    Box::new(MlsGenesisRuntime { group, accepted })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mls_install_consent_requires_profile_and_both_explicit_admin_choices() {
    tokio::spawn(Box::pin(async {
        let fixture = Box::pin(Fixture::new()).await;
        for missing in ["profile", "approval", "policy", "enabled"] {
            let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
            let native = mls_service(&fixture, &namespace);
            let mut package = native.package.clone();
            if missing == "profile" {
                package
                    .claimed_profiles
                    .retain(|p| p != arkret_wire::ProfileId::APPLET_E2EE_JOIN_V1);
                resign_native_applet_package(&mut package);
            }
            if missing == "enabled" {
                package.e2ee_policy.enabled = false;
                resign_native_applet_package(&mut package);
            }
            let (_, mut body) = Box::pin(fixture.prepare_install_service_with_constraints(
                true,
                package,
                ScopeRef::Realm {
                    realm_id: fixture.realm.clone(),
                },
                BTreeMap::new(),
            ))
            .await;
            if missing == "approval" {
                body["authoring_request_basis"]["approval_request"]["e2ee_join_allowed"] =
                    json!(false);
            }
            if missing == "policy" {
                body["authoring_request_basis"]["e2ee_policy"] = json!({});
            }
            let before = business(&fixture).await;
            let (status, error) = fixture
                .admin_post(
                    "/_arkret/self/applets/install",
                    ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                    &body,
                    Some(&format!("missing-{missing}")),
                )
                .await;
            assert!(!status.is_success(), "missing {missing}: {error}");
            assert_eq!(
                error["type"], "https://arkret.org/problems/applet_e2ee_join_unauthorized",
                "{error}"
            );
            assert_eq!(before, business(&fixture).await);
        }
    }))
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installation_rechecks_current_policy_before_writing_consent_or_business() {
    tokio::spawn(Box::pin(async {
        let fixture = Box::pin(Fixture::new()).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let package = native.package.clone();
        let (_, body) = Box::pin(fixture.prepare_install_service_with_constraints(
            true,
            package.clone(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            BTreeMap::new(),
        ))
        .await;
        Box::pin(install_policy(&fixture, &package.applet_id, "install")).await;
        let before = business(&fixture).await;
        let (status, error) = fixture
            .admin_post(
                "/_arkret/self/applets/install",
                ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &body,
                Some("policy-changed-after-preview"),
            )
            .await;
        assert!(!status.is_success(), "{error}");
        assert_eq!(
            error["type"], "https://arkret.org/problems/capability_denied",
            "{error}"
        );
        assert_eq!(before, business(&fixture).await);
    }))
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_join_rechecks_current_policy_after_explicit_consent() {
    tokio::spawn(Box::pin(async {
        let fixture = Box::pin(Fixture::new()).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let package = native.package.clone();
        let install = Box::pin(fixture.install_package(false, package, &namespace)).await;
        Box::pin(activate_mls(
            &fixture,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
        ))
        .await;
        let key = SigningKey::from_bytes(&[158; 32]);
        let authority = Box::pin(authorize(
            &fixture,
            &install,
            &install.bot_body["managed_actor_bundle"],
            &namespace,
            &key,
            DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
            true,
        ))
        .await;
        Box::pin(install_policy(&fixture, &install.package.applet_id, "join")).await;
        let event = join_event(
            &fixture,
            &install,
            &authority,
            &key,
            &install.bot_outcome.authorization_ref,
        );
        let before = business(&fixture).await;
        let (status, error) = Box::pin(post(&fixture, &authority, &key, &event, vec![])).await;
        assert!(!status.is_success(), "current join policy: {error}");
        assert_eq!(
            error["type"], "https://arkret.org/problems/capability_denied",
            "{error}"
        );
        assert_eq!(before, business(&fixture).await);
    }))
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_encrypted_join_reconstruct_exact_accepted_consent() {
    tokio::spawn(Box::pin(async {
        let fixture = Box::pin(Fixture::new()).await;
        let scope = ScopeRef::Realm { realm_id: fixture.realm.clone() };
        Box::pin(activate_mls(&fixture, scope)).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let package = native.package.clone();
        let install = Box::pin(fixture.install_package(true, package, &namespace)).await;
        let body: AppletInstallRequestBody = serde_json::from_value(install.body.clone()).unwrap();
        assert_eq!(install.outcome.e2ee_authorization_refs, body.e2ee_join_authorization_refs().unwrap());
        assert_eq!(install.outcome.e2ee_authorization_refs.len(), 4);
        let ghost = Box::pin(fixture.ghost_body(&install, &namespace, "encrypted-join")).await;
        assert_eq!(fixture.ghost_commit(&install, &ghost, "encrypted-ghost").await.0, StatusCode::CREATED);
        for bundle in [install.bot_body["managed_actor_bundle"].clone(), ghost["managed_actor_bundle"].clone()] {
            let key = SigningKey::from_bytes(&[156; 32]);
            let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
            let authority = Box::pin(authorize(&fixture, &install, &bundle, &namespace, &key, device, true)).await;
            let event = join_event(&fixture, &install, &authority, &key, &install.bot_outcome.authorization_ref);
            // A retained install mirror must not bypass the immutable request.
            // Corrupt only this fixture's private audit row, then restore it.
            let digest = arkret_canonical::canonical_sha256(&install.body).unwrap();
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("UPDATE applet_authoring_units SET request_body=jsonb_set(request_body,'{authoring_request_basis,e2ee_policy,mls_join_allowed}','false'::jsonb) WHERE canonical_request_hash=$1")
                .bind::<diesel::sql_types::Text,_>(&digest).execute(&mut conn).await.unwrap();
            drop(conn);
            let before = business(&fixture).await;
            let (status, error) = Box::pin(post(&fixture, &authority, &key, &event, vec![])).await;
            let after = business(&fixture).await;
            let mut conn = fixture.pool.get().await.unwrap();
            diesel::sql_query("UPDATE applet_authoring_units SET request_body=$2 WHERE canonical_request_hash=$1")
                .bind::<diesel::sql_types::Text,_>(&digest).bind::<diesel::sql_types::Jsonb,_>(&install.body)
                .execute(&mut conn).await.unwrap();
            drop(conn);
            assert!(!status.is_success(), "corrupt consent original: {error}");
            assert_eq!(error["type"], "https://arkret.org/problems/applet_e2ee_join_unauthorized", "{error}");
            assert_eq!(before, after);
            let (status, accepted) = Box::pin(post(&fixture, &authority, &key, &event, vec![])).await;
            assert_eq!(status, StatusCode::OK, "encrypted native join: {accepted}");
            assert_accepted_event(&fixture, &event).await;
            let before = business(&fixture).await;
            let (status, replay) = Box::pin(post(&fixture, &authority, &key, &event, vec![])).await;
            assert_eq!(status, StatusCode::OK, "{replay}");
            assert_eq!(before, business(&fixture).await);
        }
        let ordinary_namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = NativeAppletService::new(&format!("ak:applet:{}", uuid::Uuid::now_v7()), &ordinary_namespace, &fixture.state.service_core_id());
        let ordinary = Box::pin(fixture.install_package(false, native.package.clone(), &ordinary_namespace)).await;
        let key = SigningKey::from_bytes(&[157; 32]);
        let authority = Box::pin(authorize(&fixture, &ordinary, &ordinary.bot_body["managed_actor_bundle"], &ordinary_namespace, &key, DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(), true)).await;
        let event = join_event(&fixture, &ordinary, &authority, &key, &ordinary.bot_outcome.authorization_ref);
        let before = business(&fixture).await;
        let (status, error) = Box::pin(post(&fixture, &authority, &key, &event, vec![])).await;
        assert!(!status.is_success(), "no consent: {error}");
        assert_eq!(error["type"], "https://arkret.org/problems/applet_e2ee_join_unauthorized", "{error}");
        assert_eq!(before, business(&fixture).await);
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_creation_grants_keeps_existing_accounts_independent_e2ee_join_consent() {
    tokio::spawn(Box::pin(async {
        let fixture = Box::pin(Fixture::new()).await;
        let scope = ScopeRef::Realm { realm_id: fixture.realm.clone() };
        Box::pin(activate_mls(&fixture, scope.clone())).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let install = Box::pin(fixture.install_package(true, native.package.clone(), &namespace)).await;
        let ghost = Box::pin(fixture.ghost_body(&install, &namespace, "existing-after-create-close")).await;
        assert_eq!(fixture.ghost_commit(&install, &ghost, "existing-before-create-close").await.0, StatusCode::CREATED);
        let remaining = Box::pin(fixture.ghost_body(&install, &namespace, "existing-before-all-close")).await;
        assert_eq!(fixture.ghost_commit(&install, &remaining, "remaining-before-create-close").await.0, StatusCode::CREATED);
        let mut devices = Vec::new();
        for bundle in [install.bot_body["managed_actor_bundle"].clone(), ghost["managed_actor_bundle"].clone(), remaining["managed_actor_bundle"].clone()] {
            let key = SigningKey::from_bytes(&[159;32]);
            let authority = Box::pin(authorize(&fixture, &install, &bundle, &namespace, &key, DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(), true)).await;
            devices.push((authority,key));
        }
        let body: AppletInstallRequestBody = serde_json::from_value(install.body.clone()).unwrap();
        let mut binding = None;
        for original in &body.authoring_request_basis.capability_grant_events {
            let payload: CapabilityGrantPayload = serde_json::from_value(json!(original.payload)).unwrap();
            let id = arkret_wire::GrantId::from_event_id(&original.event_id);
            if payload.grant.actions == ["ak.message.create"] {
                binding = Some(id);
                continue;
            }
            assert!(payload.grant.actions.iter().all(|a| matches!(a.as_str(), "ak.applet.bot.provision" | "ak.applet.ghost.provision")));
            let rows = fixture.state.test_persistence().capability_grant_current_results().snapshot_for_realm(&fixture.realm).await.unwrap();
            let current = rows.iter().find(|r| r.grant_id == id).unwrap();
            let revoke = fixture.admin_event(EventKind::CapabilityRevoke, scope.clone(), json!({"grant_id":id,"expected_revision":current.revision,"reason":"stop new identity creation only"}));
            Box::pin(accepted_admin_domain_event(&fixture,revoke)).await;
        }
        let binding = binding.unwrap();
        let rows = fixture.state.test_persistence().capability_grant_current_results().snapshot_for_realm(&fixture.realm).await.unwrap();
        assert_eq!(rows.iter().find(|r| r.grant_id == binding).unwrap().value.status, arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Active);
        let (remaining_authority,remaining_key) = devices.pop().unwrap();
        for (authority,key) in devices {
            assert!(fixture.state.test_persistence().device_revocations().applet_managed_device_authority(&authority.account_id,&authority.device_id,chrono::Utc::now()).await.unwrap().is_some());
            let event = join_event(&fixture,&install,&authority,&key,&binding);
            let before = business(&fixture).await;
            let (status,outcome) = Box::pin(post(&fixture,&authority,&key,&event,vec![])).await;
            if !status.is_success() { assert_eq!(before,business(&fixture).await,"failed join must have no business effects"); }
            assert_eq!(status,StatusCode::OK,"existing Account with explicit MLS consent and a live installation binding: {outcome}");
            assert_accepted_event(&fixture,&event).await;
        }

        // Missing current is not a known withdrawal. Restore only this
        // fixture's derived row before any assertion, leaving its originals.
        #[derive(diesel::QueryableByName)]
        struct OriginalCurrent { #[diesel(sql_type=diesel::sql_types::Jsonb)] value:Value }
        let mut conn = fixture.pool.get().await.unwrap();
        let original = diesel::sql_query("SELECT to_jsonb(g) AS value FROM capability_grant_current_results g WHERE realm_id=$1 AND grant_id=$2")
            .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(binding.as_str())
            .get_result::<OriginalCurrent>(&mut conn).await.unwrap();
        assert_eq!(diesel::sql_query("DELETE FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2")
            .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(binding.as_str())
            .execute(&mut conn).await.unwrap(),1);
        drop(conn);
        let event = join_event(&fixture,&install,&remaining_authority,&remaining_key,&binding);
        let before = business(&fixture).await;
        let (status,error) = Box::pin(post(&fixture,&remaining_authority,&remaining_key,&event,vec![])).await;
        let after = business(&fixture).await;
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO capability_grant_current_results SELECT (jsonb_populate_record(NULL::capability_grant_current_results,$1)).*")
            .bind::<diesel::sql_types::Jsonb,_>(&original.value).execute(&mut conn).await.unwrap();
        drop(conn);
        assert_eq!(status,StatusCode::SERVICE_UNAVAILABLE,"unknown consent binding current: {error}");
        assert_eq!(before,after);

        let rows = fixture.state.test_persistence().capability_grant_current_results().snapshot_for_realm(&fixture.realm).await.unwrap();
        let current = rows.iter().find(|r| r.grant_id == binding).unwrap();
        let revoke = fixture.admin_event(EventKind::CapabilityRevoke,scope,json!({"grant_id":binding,"expected_revision":current.revision,"reason":"close last installation binding"}));
        Box::pin(accepted_admin_domain_event(&fixture,revoke)).await;
        let event = join_event(&fixture,&install,&remaining_authority,&remaining_key,&binding);
        let before = business(&fixture).await;
        let (status,error) = Box::pin(post(&fixture,&remaining_authority,&remaining_key,&event,vec![])).await;
        assert_eq!(status,StatusCode::FORBIDDEN,"all original bindings withdrawn: {error}");
        assert_eq!(error["type"],"https://arkret.org/problems/applet_e2ee_join_unauthorized","{error}");
        assert_eq!(before,business(&fixture).await);
    })).await.unwrap();
}
