use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn realm_devices_require_control_and_possession_without_account_authority() {
    let fixture = Box::pin(Fixture::new()).await;
    let install = Box::pin(fixture.install(true)).await;
    let namespace = install_namespace(&install);
    let ghost = fixture
        .ghost_body(&install, namespace, "device-first")
        .await;
    let (status, response) = fixture.ghost_commit(&install, &ghost, "device-ghost").await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let ghost = CreatedActor::accepted(&ghost, response);
    for creation in [&install.bot.event, &ghost.event] {
        let candidate: RealmActorCreatePayload =
            serde_json::from_value(json!(creation.payload)).unwrap();
        assert!(candidate.actor_id.as_account_id().is_none());
        let key = SigningKey::from_bytes(&[117; 32]);
        let device =
            arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let mut actions = std::collections::BTreeSet::from([
            "ak.event.read".to_owned(),
            "ak.object.read_content".to_owned(),
        ]);
        for operation in arkret_wire::ServiceOperationId::ALL {
            if let Some(arkret_wire::ManagedDeviceScopeRule::AllActions(required)) =
                arkret_wire::applet_managed_device_scope_rule(*operation)
            {
                actions.extend(required.iter().map(|action| action.as_str().to_owned()));
            }
        }
        let scopes = json!([{"effective_scope":candidate.creation_scope,"actions":actions}]);
        let (event, metadata, controller) = control::device_event(
            &fixture,
            creation,
            namespace,
            &key,
            device.clone(),
            scopes,
            None,
        )
        .await;
        let before = authority_snapshot(&fixture.pool).await;
        let mut wrong_possession = json!(event.payload);
        wrong_possession["device_signature"] = json!(arkret_canonical::base64url_encode([0; 64]));
        let wrong_possession = control::sign(
            &candidate,
            &controller,
            EventKind::DeviceAuthorize,
            wrong_possession,
        );
        let wrong_control = control::sign(
            &candidate,
            &SigningKey::from_bytes(&[11; 32]),
            EventKind::DeviceAuthorize,
            json!(event.payload),
        );
        for invalid in [&wrong_possession, &wrong_control] {
            let mut metadata = metadata.clone();
            metadata.nonce = random_nonce();
            let (status, response) = control::post(
                &fixture,
                &metadata,
                &candidate.control_method_kid,
                &controller,
                invalid,
            )
            .await;
            assert!(
                status.is_client_error(),
                "invalid Device authority accepted: {response}"
            );
            let after = authority_snapshot(&fixture.pool).await;
            assert_eq!(
                before, after,
                "invalid control cannot mutate accepted authority"
            );
        }
        let (status, response) = fixture
            .service_post(
                &install.package,
                "/_arkret/self/events",
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &creation_submission(event.clone()),
                &format!("service-device-{}", uuid::Uuid::now_v7()),
            )
            .await;
        assert!(
            status.is_client_error(),
            "Service carrier replaced independent control: {response}"
        );
        let (status, response) = control::post(
            &fixture,
            &metadata,
            &candidate.control_method_kid,
            &controller,
            &event,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let authority = fixture
            .state
            .test_persistence()
            .device_revocations()
            .applet_managed_device_authority(&candidate.actor_id, &device, chrono::Utc::now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authority.actor_id, candidate.actor_id);
        assert_eq!(authority.authorization_ref.event_id, event.event_id);
        assert_eq!(
            authority.authorization_ref.stream_ref,
            arkret_wire::CommitStreamRef::RealmControl {
                realm_id: fixture.realm.clone()
            }
        );
        assert_eq!(authority.current_device_generation_ref, 1);
        exercise_managed_device_http_authentication(&fixture, &authority, &key).await;
        let after = authority_snapshot(&fixture.pool).await;
        assert_eq!(
            before["device_generations"], after["device_generations"],
            "ordinary PCR generation is untouched"
        );
        assert_eq!(
            before["device_authorizations"], after["device_authorizations"],
            "ordinary Account devices are untouched"
        );
    }
}

#[tokio::test]
async fn realm_creation_initializes_private_generation_and_rolls_back_partial_current() {
    use diesel::sql_types::{Jsonb, Text};
    let fixture = Box::pin(Fixture::new()).await;
    let install = Box::pin(fixture.install(true)).await;
    let body = fixture
        .ghost_body(&install, install_namespace(&install), "generation")
        .await;
    let before = authority_snapshot(&fixture.pool).await;
    let mut connection = fixture.pool.get().await.unwrap();
    diesel::sql_query("CREATE FUNCTION fail_realm_generation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.selector->>'kind'='realm_actor_device_generation' THEN RAISE EXCEPTION 'private generation fault'; END IF; RETURN NEW; END $$").execute(&mut connection).await.unwrap();
    diesel::sql_query("CREATE TRIGGER fail_realm_generation BEFORE INSERT ON realm_actor_current_results FOR EACH ROW EXECUTE FUNCTION fail_realm_generation()").execute(&mut connection).await.unwrap();
    drop(connection);
    let (status, response) = fixture
        .ghost_commit(&install, &body, "generation-fault")
        .await;
    assert!(!status.is_success(), "{response}");
    assert_eq!(before, authority_snapshot(&fixture.pool).await);
    let mut connection = fixture.pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER fail_realm_generation ON realm_actor_current_results")
        .execute(&mut connection)
        .await
        .unwrap();
    diesel::sql_query("DROP FUNCTION fail_realm_generation()")
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let (status, response) = fixture
        .ghost_commit(&install, &body, "generation-fault")
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let ghost = CreatedActor::accepted(&body, response);
    for created in [&install.bot, &ghost] {
        let (source, value) = control::current(
            &fixture,
            &created.actor_id,
            json!({"kind":"realm_actor_device_generation","actor_id":created.actor_id}),
        )
        .await
        .unwrap();
        assert_eq!(source.event_id, created.event.event_id);
        assert_eq!(source.commit_id, created.commit.commit_id);
        assert_eq!(value["current_device_generation_ref"], 1);
        let device =
            arkret_wire::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        assert!(
            fixture
                .state
                .test_persistence()
                .device_revocations()
                .applet_managed_device_authority(&created.actor_id, &device, chrono::Utc::now())
                .await
                .unwrap()
                .is_none()
        );
    }
    let accepted = authority_snapshot(&fixture.pool).await;
    assert_eq!(before["device_generations"], accepted["device_generations"]);
    assert_eq!(
        before["device_authorizations"],
        accepted["device_authorizations"]
    );
    assert_eq!(
        before["profiles"], accepted["profiles"],
        "creation does not publish a Profile"
    );
    let (status, replay) = fixture
        .ghost_commit(&install, &body, "generation-exact-retry")
        .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(CreatedActor::accepted(&body, replay).commit, ghost.commit);
    let selector = json!({"kind":"realm_actor_device_generation","actor_id":ghost.actor_id});
    let mut connection = fixture.pool.get().await.unwrap();
    let deleted = diesel::sql_query(
        "DELETE FROM realm_actor_current_results WHERE realm_id=$1 AND selector=$2",
    )
    .bind::<Text, _>(fixture.realm.as_str())
    .bind::<Jsonb, _>(&selector)
    .execute(&mut connection)
    .await
    .unwrap();
    assert_eq!(deleted, 1);
    drop(connection);
    let damaged = authority_snapshot(&fixture.pool).await;
    assert!(
        control::current(&fixture, &ghost.actor_id, selector)
            .await
            .is_none()
    );
    let (status, replay) = fixture
        .ghost_commit(&install, &body, "generation-damaged-retry")
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "historical confirmation does not recreate current: {replay}"
    );
    assert_eq!(CreatedActor::accepted(&body, replay).commit, ghost.commit);
    assert_eq!(
        damaged["realm_actor_current"],
        authority_snapshot(&fixture.pool).await["realm_actor_current"]
    );
}
