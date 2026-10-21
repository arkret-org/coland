//! Original signed targets bind real scope before and after MLS activation.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_publication_before_genesis_accepts_real_signed_targets() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let realm_scope = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let native = mls_service(&fixture, &namespace);
        let install =
            native_phase(|| fixture.install_package(true, native.package.clone(), &namespace))
                .await;
        let ghost =
            native_phase(|| fixture.ghost_body(&install, &namespace, "target-publication")).await;
        assert_eq!(
            fixture
                .ghost_commit(&install, &ghost, "target-publication")
                .await
                .0,
            StatusCode::CREATED
        );
        for bundle in [
            &install.bot_body["managed_actor_bundle"],
            &ghost["managed_actor_bundle"],
        ] {
            let key = SigningKey::from_bytes(&[171; 32]);
            let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
            let authority = native_phase(|| {
                authorize(
                    &fixture,
                    &install,
                    bundle,
                    &namespace,
                    &key,
                    device.clone(),
                    true,
                )
            })
            .await;
            let join = join_event(
                &fixture,
                &install,
                &authority,
                &key,
                &install.bot_outcome.authorization_ref,
            );
            let (status, outcome) =
                native_phase(|| post(&fixture, &authority, &key, &join, vec![])).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "actual membership before publication: {outcome}"
            );
            let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
                ActorId::account(authority.account_id.clone()),
                device,
                arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
            )
            .unwrap();
            let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                key.verifying_key().as_bytes(),
            );
            let method = format!("did:key:{fingerprint}#{fingerprint}");
            native_phase(|| {
                scope_targets(
                    &fixture,
                    &install,
                    &authority,
                    &key,
                    &identity,
                    &method,
                    &realm_scope,
                )
            })
            .await;
            let authority = native_phase(|| {
                circle_membership(
                    &fixture, &install, &namespace, bundle, &authority, &key, false,
                )
            })
            .await;
            let circle = authority
                .scopes
                .entries()
                .iter()
                .find(|entry| matches!(entry.effective_scope, ScopeRef::Circle { .. }))
                .unwrap()
                .effective_scope
                .clone();
            native_phase(|| {
                scope_targets(
                    &fixture, &install, &authority, &key, &identity, &method, &circle,
                )
            })
            .await;
        }
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            value: i64,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let count = diesel::sql_query(
            "SELECT COUNT(*) AS value FROM mls_group_current_results WHERE realm_id=$1",
        )
        .bind::<diesel::sql_types::Text, _>(fixture.realm.as_str())
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .value;
        assert_eq!(count, 0, "all tested targets exist without MLSGenesis");
    }))
    .await
    .unwrap();
}

async fn strand(fixture: &Fixture, scope: &ScopeRef) -> arkret_wire::StrandId {
    let mut object = json!({"schema":"ak.schema.strand.v1","realm_id":fixture.realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Original publication target"},"state":"active",
        "created_by":ActorId::account(fixture.pcr.history.account.clone()),
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
    if let ScopeRef::Circle { circle_id, .. } = scope {
        object["scope_circle_id"] = json!(circle_id);
    }
    let event = fixture.admin_event(
        EventKind::StrandCreate,
        scope.clone(),
        json!({"object":object}),
    );
    let id = arkret_wire::StrandId::from_event_id(&event.event_id);
    native_phase(|| accepted_admin_domain_event(fixture, event)).await;
    id
}

fn target_body(
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    key: &SigningKey,
    scope: &ScopeRef,
    strand: Option<&arkret_wire::StrandId>,
    group: bool,
) -> arkret_models_crypto::KeyPackagesUploadRequestBody {
    let mut body = fresh_upload(identity, method, key, scope).unsigned();
    body.strand_id = strand.cloned();
    if !group {
        body.mls_group_id = None;
    }
    sign_upload(body, method, key)
}

async fn published(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
) {
    let (status, outcome) =
        native_phase(|| upload_in_scope(fixture, authority, key, body, scope)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "original publication target: {outcome}"
    );
    assert_eq!(outcome["accepted"], 1, "{outcome}");
    let record = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_by_ref(&body.keypackages[0].keypackage_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.owner_actor_id, authority.account_id);
    assert_eq!(record.effective_scope.as_ref(), Some(scope));
    assert_eq!(
        record.device_authorize_event_id.as_deref(),
        Some(authority.selector.authorization_ref.event_id.as_str())
    );
}

async fn refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
) {
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) =
        native_phase(|| upload_in_scope(fixture, authority, key, body, scope)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "target must be bound to real current scope: {error}"
    );
    assert_eq!(before, native_phase(|| snapshot(fixture)).await);
}

async fn scope_targets(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    scope: &ScopeRef,
) {
    let target = native_phase(|| strand(fixture, scope)).await;
    for (bound, group) in [(None, true), (Some(&target), false), (Some(&target), true)] {
        let body = target_body(identity, method, key, scope, bound, group);
        native_phase(|| published(fixture, authority, key, scope, &body)).await;
    }
    let absent = arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [195; 32],
    ));
    for (bound, group) in [(None, false), (Some(&absent), false), (Some(&absent), true)] {
        let body = target_body(identity, method, key, scope, bound, group);
        native_phase(|| refused(fixture, authority, key, scope, &body)).await;
    }
    let other_scope = native_phase(|| fixture.new_circle_scope()).await;
    native_phase(|| super::super::circle::join_founder(fixture, &other_scope)).await;
    let foreign = native_phase(|| strand(fixture, &other_scope)).await;
    for group in [false, true] {
        let body = target_body(identity, method, key, scope, Some(&foreign), group);
        native_phase(|| refused(fixture, authority, key, scope, &body)).await;
    }
    let mut expired = target_body(identity, method, key, scope, Some(&target), true).unsigned();
    expired.expires_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() - chrono::Duration::seconds(1),
    ));
    let expired = sign_upload(expired, method, key);
    native_phase(|| refused(fixture, authority, key, scope, &expired)).await;

    let policy = deny_target(fixture, install, scope, &target).await;
    let body = target_body(identity, method, key, scope, Some(&target), false);
    native_phase(|| refused(fixture, authority, key, scope, &body)).await;
    let unrelated = target_body(identity, method, key, scope, None, true);
    native_phase(|| published(fixture, authority, key, scope, &unrelated)).await;
    native_phase(|| super::super::circle::allow_policy(fixture, &policy)).await;
    native_phase(|| published(fixture, authority, key, scope, &body)).await;

    let spare = native_phase(|| strand(fixture, scope)).await;
    native_phase(|| {
        wrong_current_writer(
            fixture, authority, key, identity, method, scope, &target, &spare,
        )
    })
    .await;
    if matches!(scope, ScopeRef::Circle { .. }) {
        let wrong = fixture.admin_event(
            EventKind::StrandArchive,
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            json!({"target_ref":target}),
        );
        let request = native_phase(|| admin_domain_request(fixture, wrong)).await;
        let before = native_phase(|| snapshot(fixture)).await;
        let result = native_phase(|| async {
            coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
                .commit_event(request)
                .await
        })
        .await;
        assert!(
            result.is_err(),
            "a Realm carrier cannot mutate a Circle Strand"
        );
        assert_eq!(before, native_phase(|| snapshot(fixture)).await);
    }
    let archive = fixture.admin_event(
        EventKind::StrandArchive,
        scope.clone(),
        json!({"target_ref":target}),
    );
    native_phase(|| accepted_admin_domain_event(fixture, archive)).await;
    let body = target_body(identity, method, key, scope, Some(&target), true);
    native_phase(|| refused(fixture, authority, key, scope, &body)).await;
    let restore = fixture.admin_event(
        EventKind::StrandRestore,
        scope.clone(),
        json!({"target_ref":target}),
    );
    native_phase(|| accepted_admin_domain_event(fixture, restore)).await;
    native_phase(|| published(fixture, authority, key, scope, &body)).await;
    let stage = fixture.admin_event(
        EventKind::StrandStageSet,
        scope.clone(),
        json!({"strand_id":target,"stage":"in_progress"}),
    );
    native_phase(|| accepted_admin_domain_event(fixture, stage)).await;
    let body = target_body(identity, method, key, scope, Some(&target), false);
    native_phase(|| published(fixture, authority, key, scope, &body)).await;
}

async fn deny_target(
    fixture: &Fixture,
    install: &Installed,
    scope: &ScopeRef,
    strand: &arkret_wire::StrandId,
) -> Event {
    let id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let event=fixture.admin_event(EventKind::PolicySet,scope.clone(),json!({"policy_id":id,"expected_revision":null,"value":{
        "schema":"ak.schema.policy.v1","id":id,"realm_id":fixture.realm,"policy_kind":"applet","default_effect":"allow",
        "created_by":admin,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        "rules":[{"rule_id":"signed_strand_target","kind":"applet","effect":"deny","applet_operations":["execute"],
            "applet_target":{"kind":"installation","applet_id":install.package.applet_id,"effective_scope":scope},
            "resources":[{"kind":"strand","realm_id":fixture.realm,"resource_ref":strand}]}]}}));
    native_phase(|| accepted_admin_domain_event(fixture, event.clone())).await;
    event
}

async fn wrong_current_writer(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    identity: &arkret_mls::ArkretMlsIdentity,
    method: &str,
    scope: &ScopeRef,
    target: &arkret_wire::StrandId,
    spare: &arkret_wire::StrandId,
) {
    #[derive(diesel::QueryableByName)]
    struct Revision {
        #[diesel(sql_type=diesel::sql_types::Text)]
        commit: String,
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        position: i64,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let original=diesel::sql_query("SELECT current_commit_id AS commit,current_stream_position AS position FROM strand_current_results WHERE realm_id=$1 AND strand_id=$2")
        .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(target.as_str())
        .get_result::<Revision>(&mut conn).await.unwrap();
    assert_eq!(diesel::sql_query("UPDATE strand_current_results target SET current_commit_id=spare.current_commit_id,current_stream_position=spare.current_stream_position FROM strand_current_results spare WHERE target.realm_id=$1 AND target.strand_id=$2 AND spare.realm_id=$1 AND spare.strand_id=$3")
        .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(target.as_str()).bind::<diesel::sql_types::Text,_>(spare.as_str()).execute(&mut conn).await.unwrap(),1);
    drop(conn);
    let body = target_body(identity, method, key, scope, Some(target), false);
    let before = native_phase(|| snapshot(fixture)).await;
    let (status, error) =
        native_phase(|| upload_in_scope(fixture, authority, key, &body, scope)).await;
    let after = native_phase(|| snapshot(fixture)).await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("UPDATE strand_current_results SET current_commit_id=$3,current_stream_position=$4 WHERE realm_id=$1 AND strand_id=$2")
        .bind::<diesel::sql_types::Text,_>(fixture.realm.as_str()).bind::<diesel::sql_types::Text,_>(target.as_str())
        .bind::<diesel::sql_types::Text,_>(&original.commit).bind::<diesel::sql_types::BigInt,_>(original.position)
        .execute(&mut conn).await.unwrap();
    drop(conn);
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another Strand's real writer is not this target's source: {error}"
    );
    assert_eq!(before, after);
}
