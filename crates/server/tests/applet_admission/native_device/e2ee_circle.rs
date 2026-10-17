//! Exact encrypted Circle admission through real native Account Devices.
use super::*;

pub(super) async fn join_founder(fixture: &Fixture, scope: &ScopeRef) -> Value {
    let actor = ActorId::account(fixture.pcr.history.account.clone());
    let parent =
        ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &actor).await;
    let event = fixture.admin_event(
        EventKind::CircleMemberState,
        scope.clone(),
        json!({
            "circle_id":scope.circle_id().unwrap(),"member_id":actor,
            "membership":"join","expected_membership":null,
            "parent_membership_revision":parent
        }),
    );
    native_phase(|| accepted_admin_domain_event(fixture, event)).await;
    parent
}

pub(super) async fn deny_policy(
    fixture: &Fixture,
    install: &Installed,
    scope: &ScopeRef,
    policy_scope: ScopeRef,
    operation: &str,
) -> Event {
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let event = fixture.admin_event(EventKind::PolicySet, policy_scope, json!({
        "policy_id":id,"expected_revision":null,"value":{
            "schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,
            "policy_kind":"applet","default_effect":"allow","created_by":admin,
            "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            "rules":[{"rule_id":"exact_circle_join","kind":"applet","effect":"deny",
                "applet_target":{"kind":"installation","applet_id":install.package.applet_id,"effective_scope":scope},
                "applet_operations":[operation]}]
        }
    }));
    native_phase(|| accepted_admin_domain_event(fixture, event.clone())).await;
    event
}

pub(super) async fn allow_policy(fixture: &Fixture, previous: &Event) {
    #[derive(diesel::QueryableByName)]
    struct Current {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut payload = json!(&previous.payload);
    let mut conn = fixture.pool.get().await.unwrap();
    let current = diesel::sql_query("SELECT jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position) AS value FROM policy_current_results WHERE policy_id=$1")
        .bind::<diesel::sql_types::Text,_>(payload["policy_id"].as_str().unwrap())
        .get_result::<Current>(&mut conn).await.unwrap();
    drop(conn);
    payload["expected_revision"] = current.value;
    payload["value"]["rules"][0]["effect"] = json!("allow");
    let event = fixture.admin_event(EventKind::PolicySet, previous.scope_ref.clone(), payload);
    native_phase(|| accepted_admin_domain_event(fixture, event)).await;
}

async fn assert_refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    event: &Event,
    label: &str,
    code: Option<&str>,
) {
    let before = native_circle_snapshot(fixture).await;
    let (status, error) = native_phase(|| post(fixture, authority, key, event, vec![])).await;
    assert!(status.is_client_error(), "{label}: {error}");
    if let Some(code) = code {
        assert_eq!(
            error["type"],
            format!("https://arkret.org/problems/{code}"),
            "{label}: {error}"
        );
    }
    assert_eq!(
        before,
        native_circle_snapshot(fixture).await,
        "{label} must have no business effects"
    );
}

async fn circle_actor(
    fixture: &Fixture,
    install: &Installed,
    namespace: &str,
    bundle: &Value,
    scope: &ScopeRef,
    founder_parent: &Value,
    circle_body: &Value,
    policy_scope: ScopeRef,
) {
    let key = SigningKey::from_bytes(&[161; 32]);
    let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
    let realm = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let full_pairs = json!([
        {"effective_scope":scope,"actions":["ak.applet.join","ak.circle.member.add","ak.event.read"]},
        {"effective_scope":realm,"actions":["ak.applet.join","ak.event.read"]}
    ]);
    let authority = native_phase(|| {
        authorize_scopes(
            fixture,
            install,
            bundle,
            namespace,
            &key,
            device.clone(),
            full_pairs.clone(),
        )
    })
    .await;
    let actor = ActorId::account(authority.account_id.clone());
    let parent = native_business_parent_in_scope(
        fixture,
        install,
        vec![],
        vec!["ak.circle.member.add".into()],
        None,
        scope.clone(),
    )
    .await;
    let child = native_phase(|| {
        native_business_child(fixture, install, &actor, std::slice::from_ref(&parent))
    })
    .await;
    let event = native_circle_event(
        install,
        &authority,
        &key,
        scope,
        &child,
        "join",
        Some(founder_parent.clone()),
        Value::Null,
    );
    native_phase(|| {
        assert_refused(
            fixture,
            &authority,
            &key,
            &event,
            "no actual parent Realm membership",
            None,
        )
    })
    .await;

    let realm_join = join_event(
        fixture,
        install,
        &authority,
        &key,
        &install.bot_outcome.authorization_ref,
    );
    let (status, outcome) =
        native_phase(|| post(fixture, &authority, &key, &realm_join, vec![])).await;
    assert_eq!(status, StatusCode::OK, "real parent Realm join: {outcome}");
    assert_accepted_event(fixture, &realm_join).await;
    let parent_revision =
        ordinary_realm::parent_membership_revision(&fixture.pool, &fixture.realm, &actor).await;

    let realm_only = native_phase(|| authorize_scopes(fixture, install, bundle, namespace, &key, device.clone(), json!([
        {"effective_scope":realm,"actions":["ak.applet.join","ak.circle.member.add","ak.event.read"]}
    ]))).await;
    let event = native_circle_event(
        install,
        &realm_only,
        &key,
        scope,
        &child,
        "join",
        Some(parent_revision.clone()),
        Value::Null,
    );
    native_phase(|| {
        assert_refused(
            fixture,
            &realm_only,
            &key,
            &event,
            "Realm pair cannot cover Circle",
            Some("unauthenticated"),
        )
    })
    .await;

    let narrow = native_phase(|| {
        authorize_scopes(
            fixture,
            install,
            bundle,
            namespace,
            &key,
            device.clone(),
            json!([
                {"effective_scope":scope,"actions":["ak.applet.join","ak.event.read"]}
            ]),
        )
    })
    .await;
    let event = native_circle_event(
        install,
        &narrow,
        &key,
        scope,
        &child,
        "join",
        Some(parent_revision.clone()),
        Value::Null,
    );
    native_phase(|| {
        assert_refused(
            fixture,
            &narrow,
            &key,
            &event,
            "Circle pair lacks domain action",
            Some("capability_denied"),
        )
    })
    .await;
    let authority = native_phase(|| {
        authorize_scopes(
            fixture, install, bundle, namespace, &key, device, full_pairs,
        )
    })
    .await;
    let stale_parent = native_circle_event(
        install,
        &authority,
        &key,
        scope,
        &child,
        "join",
        Some(founder_parent.clone()),
        Value::Null,
    );
    native_phase(|| {
        assert_refused(
            fixture,
            &authority,
            &key,
            &stale_parent,
            "another Account parent revision",
            None,
        )
    })
    .await;
    let event = native_circle_event(
        install,
        &authority,
        &key,
        scope,
        &child,
        "join",
        Some(parent_revision),
        Value::Null,
    );

    // The intact Realm installation cannot substitute for a Circle's original
    // consent. Restore the private Circle audit row before any assertions.
    let digest = arkret_canonical::canonical_sha256(circle_body).unwrap();
    let mut conn = fixture.pool.get().await.unwrap();
    assert_eq!(diesel::sql_query("UPDATE applet_authoring_units SET request_body=jsonb_set(request_body,'{authoring_request_basis,e2ee_policy,mls_join_allowed}','false'::jsonb) WHERE canonical_request_hash=$1")
        .bind::<diesel::sql_types::Text,_>(&digest).execute(&mut conn).await.unwrap(),1);
    drop(conn);
    let before = native_circle_snapshot(fixture).await;
    let (status, error) = native_phase(|| post(fixture, &authority, &key, &event, vec![])).await;
    let after = native_circle_snapshot(fixture).await;
    let mut conn = fixture.pool.get().await.unwrap();
    assert_eq!(
        diesel::sql_query(
            "UPDATE applet_authoring_units SET request_body=$2 WHERE canonical_request_hash=$1"
        )
        .bind::<diesel::sql_types::Text, _>(&digest)
        .bind::<diesel::sql_types::Jsonb, _>(circle_body)
        .execute(&mut conn)
        .await
        .unwrap(),
        1
    );
    drop(conn);
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "missing exact Circle consent: {error}"
    );
    assert_eq!(
        error["type"], "https://arkret.org/problems/applet_e2ee_join_unauthorized",
        "{error}"
    );
    assert_eq!(before, after);

    let policy = native_phase(|| deny_policy(fixture, install, scope, policy_scope, "join")).await;
    native_phase(|| {
        assert_refused(
            fixture,
            &authority,
            &key,
            &event,
            "current parent or Circle Policy",
            Some("capability_denied"),
        )
    })
    .await;
    native_phase(|| allow_policy(fixture, &policy)).await;
    let (status, accepted) = native_phase(|| post(fixture, &authority, &key, &event, vec![])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact encrypted Circle join: {accepted}"
    );
    assert_accepted_event(fixture, &event).await;
    let before = native_circle_snapshot(fixture).await;
    let (status, replay) = native_phase(|| post(fixture, &authority, &key, &event, vec![])).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(before, native_circle_snapshot(fixture).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_encrypted_circle_require_exact_consent_pairs_parent_and_policies() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let install =
            native_phase(|| fixture.install_package(true, native.package.clone(), &namespace))
                .await;
        let ghost =
            native_phase(|| fixture.ghost_body(&install, &namespace, "encrypted-circle")).await;
        assert_eq!(
            fixture
                .ghost_commit(&install, &ghost, "encrypted-circle-ghost")
                .await
                .0,
            StatusCode::CREATED
        );
        let scope = native_phase(|| fixture.new_circle_scope()).await;
        let founder_parent = native_phase(|| join_founder(&fixture, &scope)).await;
        native_phase(|| activate_mls(&fixture, scope.clone())).await;
        let (_, circle_body) = native_phase(|| {
            fixture.prepare_install_service_with_constraints(
                true,
                install.package.clone(),
                scope.clone(),
                BTreeMap::new(),
            )
        })
        .await;
        let (status, outcome) = fixture
            .admin_post(
                "/_arkret/self/applets/install",
                ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &circle_body,
                Some("encrypted-circle-install"),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "exact Circle installation: {outcome}"
        );
        for (bundle, policy_scope) in [
            (
                &install.bot_body["managed_actor_bundle"],
                ScopeRef::Realm {
                    realm_id: fixture.realm.clone(),
                },
            ),
            (&ghost["managed_actor_bundle"], scope.clone()),
        ] {
            native_phase(|| {
                circle_actor(
                    &fixture,
                    &install,
                    &namespace,
                    bundle,
                    &scope,
                    &founder_parent,
                    &circle_body,
                    policy_scope,
                )
            })
            .await;
        }
    }))
    .await
    .unwrap();
}
