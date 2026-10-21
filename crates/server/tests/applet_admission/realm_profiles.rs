//! Private subject Profiles use current control, with separate public-intent review.
use super::*;

struct Subject {
    creation: RealmActorCreatePayload,
    controller: SigningKey,
}

impl Subject {
    fn new(event: &Event, namespace: &str) -> Self {
        Self {
            creation: serde_json::from_value(json!(event.payload)).unwrap(),
            controller: control::controller(event, namespace),
        }
    }

    fn create(&self) -> Event {
        let role = match self.creation.actor_role {
            RealmActorCreatePayloadActorRole::Bot => "bot",
            RealmActorCreatePayloadActorRole::Ghost => "integration",
        };
        control::sign(
            &self.creation,
            &self.controller,
            EventKind::ProfileCreate,
            json!({
                "object": {
                    "actor_id":self.creation.actor_id,
                    "actor_kind":role, "display_name":"Realm subject",
                    "profile_fields":{"managed_by_applet":self.creation.applet_id,
                        "applet_interaction":{"effective_scope":self.creation.creation_scope,"mode":"private"}}
                }
            }),
        )
    }

    async fn update(&self, fixture: &Fixture, original: &Event, patch: Value) -> Event {
        let (source, _) = control::current(
            fixture,
            &self.creation.actor_id,
            json!({"kind":"realm_actor_profile","actor_id":self.creation.actor_id}),
        )
        .await
        .unwrap();
        control::sign(
            &self.creation,
            &self.controller,
            EventKind::ProfileUpdate,
            json!({
                "target_ref":arkret_wire::ActorProfileId::from_event_id(&original.event_id),
                "expected_revision":{"commit_id":source.commit_id,"stream_position":source.stream_position},
                "patch":patch
            }),
        )
    }

    async fn post(
        &self,
        fixture: &Fixture,
        event: &Event,
        approvals: Vec<arkret_wire::ApprovalSignature>,
    ) -> (StatusCode, Value) {
        let (control_ref, _) = control::current(
            fixture,
            &self.creation.actor_id,
            json!({"kind":"realm_actor_control","actor_id":self.creation.actor_id}),
        )
        .await
        .unwrap();
        control::post_with_approvals(
            fixture,
            &RealmActorControlHttpMetadata {
                actor_id: self.creation.actor_id.clone(),
                control_ref,
                nonce: random_nonce(),
            },
            &self.creation.control_method_kid,
            &self.controller,
            event,
            approvals,
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn realm_profiles_require_control_preserve_identity_and_stay_out_of_member_snapshots() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        let install = native_phase(|| fixture.install(true)).await;
        let namespace = install_namespace(&install);
        let ordinary_profiles = business(&fixture).await["profiles"].clone();
        let body = fixture.ghost_body(&install, namespace, "private-profile").await;
        let (status, outcome) = fixture.ghost_commit(&install, &body, "profile-ghost").await;
        assert_eq!(status, StatusCode::OK, "{outcome}");
        let ghost = CreatedActor::accepted(&body, outcome);
        for creation in [&install.bot.event, &ghost.event] {
            let subject = Subject::new(creation, namespace);
            let original = subject.create();
            let key = SigningKey::from_bytes(&[125;32]);
            let device = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
            let creation_value = json!(creation);
            let authority = native_phase(|| authorize_scopes(&fixture, &install, &creation_value, namespace, &key, device,
                json!([{"effective_scope":subject.creation.creation_scope,"actions":["ak.applet.publish","ak.event.read"]}]))).await;
            let before = business(&fixture).await;
            let mut wrong = original.clone();
            wrong.scope_ref = subject.creation.creation_scope.clone();
            wrong.authorization_ref = Some(installation_action_grant(&install.body, "ak.applet.publish").into());
            let wrong = sign_managed_device_event(wrong, &authority, &key, original.created_at);
            let (status, error) = native_phase(|| post(&fixture, &authority, &key, &wrong, vec![])).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "Device cannot replace subject control: {error}");
            assert!(error["type"].as_str().unwrap().ends_with("/unsupported_event_kind"));
            assert_eq!(before, business(&fixture).await);
            let (status, out) = native_phase(|| subject.post(&fixture, &original, vec![])).await;
            assert_eq!(status, StatusCode::OK, "private create: {out}");
            let update = subject.update(&fixture, &original, json!({"display_name":"Private maintained name"})).await;
            let (status, out) = native_phase(|| subject.post(&fixture, &update, vec![])).await;
            assert_eq!(status, StatusCode::OK, "private update: {out}");
            let before = business(&fixture).await;
            let (status, replay) = subject.post(&fixture, &original, vec![]).await;
            assert_eq!(status, StatusCode::OK, "{replay}");
            assert_eq!(before, business(&fixture).await);
            for patch in [json!({"principal_id":"ak:did_core:web:other.example"}), json!({"handle":"ordinary-account"}), json!({"accountable_principal_ids":[]})] {
                let wrong = subject.update(&fixture, &original, patch).await;
                let before = business(&fixture).await;
                let (status, error) = subject.post(&fixture, &wrong, vec![]).await;
                assert!(status.is_client_error(), "Account-only or identity mutation: {error}");
                assert_eq!(before, business(&fixture).await);
            }
            let selector = json!({"kind":"realm_actor_profile","actor_id":subject.creation.actor_id});
            let (_, current) = control::current(&fixture, &subject.creation.actor_id, selector).await.unwrap();
            assert_eq!(current["profile"]["actor_id"], json!(subject.creation.actor_id));
            assert!(current["profile"].get("principal_id").is_none());
            assert_eq!(current["profile"]["display_name"], "Private maintained name");
        }
        let snapshot = fixture.state.test_persistence().authority_commits()
            .realm_state_snapshot_material_for_account(&fixture.realm, &fixture.pcr.history.account).await.unwrap().unwrap();
        assert!(snapshot.current_state_entries.iter().all(|row| !matches!(row,
            arkret_wire::TypedCurrentRow::Value { selector:arkret_wire::CurrentSelector::RealmActorProfile { .. }, .. })));
        let state = business(&fixture).await;
        assert_eq!(state["profiles"], ordinary_profiles, "private profiles cannot populate ordinary Account projection");
    })).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn realm_public_profile_review_binds_control_cas_and_rolls_back_consumption() {
    tokio::spawn(native_phase(|| async {
        let fixture = native_phase(Fixture::new).await;
        fixture.enable_management_authority();
        let install = native_phase(|| fixture.install(false)).await;
        let subject = Subject::new(&install.bot.event, install_namespace(&install));
        let original = subject.create();
        let (status, out) = subject.post(&fixture, &original, vec![]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        publish_policy(&fixture, &install, "require_review").await;
        let opening = subject.update(&fixture, &original, json!({"profile_fields.applet_interaction.mode":"public"})).await;
        let before = business(&fixture).await;
        let (status, error) = subject.post(&fixture, &opening, vec![]).await;
        assert!(status.is_client_error(), "{error}");
        assert!(error.to_string().contains("approval_required"), "{error}");
        assert_eq!(before, business(&fixture).await);
        let (request, vote) = approved_profile(&fixture, &install, &opening).await;
        for table in ["realm_actor_current_results", "realm_actor_private_signer_facts"] {
            let before = business(&fixture).await;
            let mut connection = fixture.pool.get().await.unwrap();
            diesel::sql_query("CREATE FUNCTION fail_native_profile() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'profile atomic write fault'; END $$").execute(&mut connection).await.unwrap();
            diesel::sql_query(format!("CREATE TRIGGER fail_native_profile BEFORE INSERT OR UPDATE ON {table} FOR EACH ROW EXECUTE FUNCTION fail_native_profile()"))
                .execute(&mut connection).await.unwrap();
            drop(connection);
            let (status, error) = subject.post(&fixture, &opening, vec![vote.clone()]).await;
            let failed = business(&fixture).await;
            let mut connection = fixture.pool.get().await.unwrap();
            diesel::sql_query(format!("DROP TRIGGER fail_native_profile ON {table}")).execute(&mut connection).await.unwrap();
            diesel::sql_query("DROP FUNCTION fail_native_profile()").execute(&mut connection).await.unwrap();
            drop(connection);
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
            assert_eq!(before, failed, "failure cannot consume review or approval nonce");
        }
        let (status, out) = subject.post(&fixture, &opening, vec![vote.clone()]).await;
        assert_eq!(status, StatusCode::OK, "reviewed opening: {out}");
        let after = business(&fixture).await;
        assert_eq!(after["reviews"].as_array().unwrap().iter().find(|row| row["request_id"] == request.request_id).unwrap()["status"], "consumed");
        let (status, replay) = subject.post(&fixture, &opening, vec![vote]).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(out["commit"], replay["commit"]);
        assert_eq!(after, business(&fixture).await);
        let closing = subject.update(&fixture, &original, json!({"profile_fields.applet_interaction.mode":"private"})).await;
        let (status, out) = subject.post(&fixture, &closing, vec![]).await;
        assert_eq!(status, StatusCode::OK, "private transition: {out}");
        let stale_opening = subject.update(&fixture, &original, json!({"profile_fields.applet_interaction.mode":"public"})).await;
        let (_, stale_vote) = approved_profile(&fixture, &install, &stale_opening).await;
        let maintenance = subject.update(&fixture, &original, json!({"display_name":"New private revision"})).await;
        let (status, out) = subject.post(&fixture, &maintenance, vec![]).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let before = business(&fixture).await;
        let (status, error) = subject.post(&fixture, &stale_opening, vec![stale_vote]).await;
        assert!(status.is_client_error(), "stale approved CAS: {error}");
        assert_eq!(business_without_reviews(before), business_without_reviews(business(&fixture).await));
        publish_policy(&fixture, &install, "deny").await;
        let reopening = subject.update(&fixture, &original, json!({"profile_fields.applet_interaction.mode":"public"})).await;
        let before = business(&fixture).await;
        let (status, error) = subject.post(&fixture, &reopening, vec![]).await;
        assert!(status.is_client_error(), "denied public intent: {error}");
        assert_eq!(before, business(&fixture).await);
    })).await.unwrap();
}
