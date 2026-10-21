//! Widget inventory uses the shared native install fixture without creating a Bot Account or PCR.
use coland_storage::{
    AppletStore as _, AppletWidgetInstallSelector, AppletWidgetTokenGateSelector,
    AppletWidgetTokenRecord,
};
use coland_storage_postgres::PgAppletStore;

use super::*;
impl Fixture {
    async fn install_widget(&self) -> WidgetInstalled {
        let ghost = false;
        let endpoint = None;
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let id = format!("ak:applet:{}", uuid::Uuid::now_v7());
        let mut package =
            signed_applet_package(&id, &namespace, &self.state.service_core_id(), endpoint);
        package
            .claimed_profiles
            .push("ak.profile.applet_widget.v1".into());
        package.widget = Some(Widget {
            schema: "ak.schema.applet_widget_declaration.v1".into(),
            widget_origin: "https://widgets.example".parse().unwrap(),
            csp: "default-src 'none'; script-src https://widgets.example".into(),
            consent_required: true,
            token_scope: WidgetTokenScope {
                actions: vec!["ak.message.create".into(), "ak.strand.create".into()],
                resources: vec![arkret_wire::WireResourceSelector::realm(self.realm.clone())],
                realm_ids: Some(vec![self.realm.clone()]),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
                max_ttl_seconds: Some(600),
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        package
            .stamp_registration_epoch(&applet_registration_epoch_evidence(&package))
            .unwrap();
        package.stamp_package_digest().unwrap();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[13; 32]).verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
        let method = arkret_wire::DidUrl::new(format!("{did}#{multibase}")).unwrap();
        package
            .sign(
                &Ed25519PayloadSigner::from_did_key_seed([13; 32], did, method.clone()),
                &method,
            )
            .unwrap();
        ingest_applet_service_id_document(&self.state, &package).await;
        let evidence = applet_registration_epoch_evidence(&package);
        let registration = self.admin_event(
            EventKind::AppletRegistration,
            ScopeRef::Realm {
                realm_id: self.realm.clone(),
            },
            serde_json::to_value(package.to_registration(&evidence).unwrap()).unwrap(),
        );
        let actions = if ghost {
            vec![
                "ak.message.create",
                "ak.applet.bot.provision",
                "ak.applet.ghost.provision",
            ]
        } else {
            vec!["ak.message.create", "ak.applet.bot.provision"]
        };
        let grants = actions
            .iter()
            .map(|action| {
                let grant = CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(self.realm.clone()),
                    issuer_id: ActorId::account(self.pcr.history.account.clone()),
                    subject: CapabilitySubject::Actor(ActorId::service(package.service_id.clone())),
                    actions: vec![(*action).to_owned()],
                    resources: vec![
                        serde_json::from_value(json!({"kind":"realm","realm_id":self.realm}))
                            .unwrap(),
                    ],
                    constraints: vec![GrantConstraint::applet_authority(
                        package.applet_id.clone(),
                        ActorId::service(package.service_id.clone()),
                        package.registration_epoch.clone(),
                    )],
                    issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                        realm_id: self.realm.clone(),
                        authority_event_ref: self
                            .authority_event_ref
                            .as_ref()
                            .expect("accepted Realm genesis authority")
                            .clone(),
                        authority_generation: 0,
                    }],
                    issued_at: chrono::Utc::now(),
                };
                self.admin_event(
                    EventKind::CapabilityGrant,
                    ScopeRef::Realm {
                        realm_id: self.realm.clone(),
                    },
                    serde_json::to_value(CapabilityGrantPayload { grant }).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let basis:AppletInstallAuthoringRequestBasis=serde_json::from_value(json!({
            "schema":AppletInstallAuthoringRequestBasis::SCHEMA,"purpose":"install_service","target_station_id":self.state.service_core_id(),
            "install_actor_id":registration.actor_id,"applet_id":package.applet_id,"service_id":package.service_id,"package_digest":package.package_digest,
            "effective_scope":{"kind":"realm","realm_id":self.realm},"approval_request":{"approve_actions":actions,
                "ghost_actor_mode":if ghost {"policy_declared"} else {"disallowed"},"delegated_native_actors_allowed":false,"e2ee_join_allowed":false,"widget_allowed":true},
            "actor_policy":{"ghost_actor_mode":"policy_declared"},"e2ee_policy":{"mls_join_allowed":false},"widget_policy":{"widget_allowed":true},
            "registration_event":registration,"capability_grant_events":grants,
        })).unwrap();
        let preview_body = serde_json::to_value(AppletInstallPreviewRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis.clone(),
        })
        .unwrap();
        let (status, preview) = self
            .admin_post(
                "/_arkret/self/applets/install/preview",
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                &preview_body,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "install preview: {preview}");
        let plan: AppletInstallPlan = serde_json::from_value(preview["plan"].clone()).unwrap();
        let body = serde_json::to_value(AppletInstallRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis,
            plan_digest: plan.plan_digest,
        })
        .unwrap();
        let key = format!("install-{}", uuid::Uuid::now_v7());
        let (status, outcome) = self
            .admin_post(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &body,
                Some(&key),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "install commit: {outcome}");
        let outcome: AppletInstallOutcome = serde_json::from_value(outcome).unwrap();
        WidgetInstalled {
            package,
            outcome,
            body,
            key,
        }
    }
}

async fn widget_native_grant(fixture: &Fixture) -> arkret_wire::GrantId {
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        serde_json::to_value(CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
                realm_id: Some(fixture.realm.clone()),
                issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
                subject: CapabilitySubject::Actor(ActorId::account(
                    fixture.pcr.history.account.clone(),
                )),
                actions: vec!["ak.message.create".into(), "ak.strand.create".into()],
                resources: vec![arkret_wire::WireResourceSelector::realm(
                    fixture.realm.clone(),
                )],
                constraints: vec![],
                issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                    realm_id: fixture.realm.clone(),
                    authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
                    authority_generation: 0,
                }],
                issued_at: chrono::Utc::now(),
            },
        })
        .unwrap(),
    );
    let grant = arkret_wire::GrantId::from_event_id(&event.event_id);
    Box::pin(accepted_admin_domain_event(fixture, event)).await;
    grant
}
pub(super) async fn run_widget_inventory() {
    for mode in [
        arkret_wire::AppletRevokeMode::RevokeWidgetOnly,
        arkret_wire::AppletRevokeMode::RevokeRuntimeOnly,
        arkret_wire::AppletRevokeMode::RevokeAll,
    ] {
        let database = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let fixture = Box::new(Box::pin(Fixture::new(database.pool())).await);
        let install = Box::new(Box::pin(fixture.install_widget()).await);
        let grant = Box::pin(widget_native_grant(&fixture)).await;
        let selector = AppletWidgetInstallSelector {
            applet_id: install.package.applet_id.clone(),
            effective_scope: ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            registration_event_ref: install.outcome.registration_event_ref.clone(),
            registration_epoch: install.package.registration_epoch.clone(),
        };
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let actor = ActorId::account(fixture.pcr.history.account.clone());
        let mut token_scope = install.package.widget.as_ref().unwrap().token_scope.clone();
        token_scope.expires_at = at + chrono::Duration::minutes(5);
        let record = AppletWidgetTokenRecord {
            token_ref: format!("ak:widget_token:{}", uuid::Uuid::now_v7()),
            install: selector.clone(),
            token_digest: Hash::new(arkret_canonical::sha256_digest(
                uuid::Uuid::now_v7().as_bytes(),
            ))
            .unwrap(),
            token_scope: token_scope.clone(),
            consent_approved: true,
            actor_id: actor.clone(),
            authorization_ref: grant.clone(),
            issued_at: at,
            invalidated_at: None,
        };
        let store = PgAppletStore {
            pool: fixture.pool.clone(),
        };
        let before = widget_authority_snapshot(&fixture.pool).await;
        let mut no_consent = record.clone();
        no_consent.consent_approved = false;
        assert!(store.issue_widget_token(no_consent).await.is_err());
        let mut overbroad = record.clone();
        overbroad.token_scope.actions.push("ak.member.state".into());
        assert!(store.issue_widget_token(overbroad).await.is_err());
        let mut wrong_install = record.clone();
        wrong_install.install.registration_epoch =
            Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        assert!(store.issue_widget_token(wrong_install).await.is_err());
        assert_eq!(widget_authority_snapshot(&fixture.pool).await, before);
        assert!(
            store.widget_tokens(&selector, at).await.unwrap().is_empty(),
            "rejected issuance wrote widget inventory"
        );
        assert!(store.issue_widget_token(record.clone()).await.unwrap());
        assert!(!store.issue_widget_token(record.clone()).await.unwrap());
        assert_eq!(
            store.widget_tokens(&selector, at).await.unwrap(),
            vec![record.clone()]
        );
        let gate = AppletWidgetTokenGateSelector {
            actor_id: actor,
            authorization_ref: grant,
            token_digest: record.token_digest.clone(),
            install: selector.clone(),
            action: "ak.message.create".into(),
            target: arkret_wire::WireResourceSelector::realm(fixture.realm.clone()),
        };
        assert_eq!(store.check_widget_token(&gate, at).await.unwrap(), record);
        assert!(
            store
                .check_widget_token(&gate, token_scope.expires_at)
                .await
                .is_err()
        );
        // The opaque token is an additional gate on a real, originally
        // Device-signed Event. Its refusal precedes every canonical writer.
        let mut event = fixture.admin_event(EventKind::StrandCreate,
            ScopeRef::Realm { realm_id: fixture.realm.clone() },
            json!({"object":{"schema":"ak.schema.strand.v1","realm_id":fixture.realm,
                "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
                "metadata":{"title":"Widget accepted write"},"state":"active",
                "created_by":ActorId::account(fixture.pcr.history.account.clone()),"created_at":at}}));
        // admin_event supplies its own wall-clock timestamp. The original
        // Strand object must use the exact Event creation time; finalize both
        // before recomputing the real Device proof and EventId below.
        event.created_at = at;
        event.payload.get_mut("object").unwrap()["created_at"] = serde_json::to_value(at).unwrap();
        event.authorization_ref =
            Some(arkret_wire::AuthorizationRef::new(gate.authorization_ref.to_string()).unwrap());
        event = fixture.sign_admin(event);
        let authority_store = PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        };
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        let head = authority_store.stream_head(&stream).await.unwrap().unwrap();
        let previous = authority_store
            .committed_event_by_commit_id(&head.commit_id)
            .await
            .unwrap()
            .unwrap();
        let prior = coland_storage::AuthorityCommitTransaction {
            expected_authority: authority_store
                .current_authority(&fixture.realm)
                .await
                .unwrap()
                .unwrap(),
            event: previous.event,
            commit: previous.commit,
            producer_signer_fact: None,
            mls_state: None,
            welcomes: vec![],
            recipient_queue_capacity: 0,
        };
        let mut request = ordinary_realm::request_for_event(&prior, event.clone(), at);
        let device_selector = fixture
            .pcr
            .admit_founding_device(fixture.state.test_persistence().as_ref())
            .await
            .unwrap();
        request.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
            device_selector,
        ));
        request = Box::pin(ordinary_realm::source_request(&fixture.pool, request)).await;
        request.authority_commit.commit.signature =
            arkret_signatures::detached_object::sign_detached_object(
                &arkret_canonical::unsigned_value(&request.authority_commit.commit, &["signature"])
                    .unwrap(),
                arkret_wire::DetachedSignatureContext::RealmCommit,
                arkret_wire::DidUrl::new(format!(
                    "{}#federation-fanout-key",
                    fixture.state.service_did()
                ))
                .unwrap(),
                at,
                fixture.state.notary_signing_key().as_ref(),
            )
            .unwrap();
        let mut write_gate = gate.clone();
        write_gate.action = "ak.strand.create".into();
        request.widget_token_gate = Some(write_gate.clone());
        let uow = coland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone());
        use coland_storage::EventCommitUnitOfWork as _;
        let before_write = widget_authority_snapshot(&fixture.pool).await;
        let mut wrong_token = request.clone();
        wrong_token.widget_token_gate.as_mut().unwrap().token_digest =
            Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap();
        assert!(Box::pin(uow.commit_event(wrong_token)).await.is_err());
        assert_eq!(
            before_write,
            widget_authority_snapshot(&fixture.pool).await,
            "widget refusal partially wrote canonical data"
        );
        Box::pin(uow.commit_event(request)).await.unwrap();
        assert_accepted_event(&fixture, &event).await;
        let native_before = widget_authority_snapshot(&fixture.pool).await;
        let install_before = store
            .get(
                install.package.applet_id.as_str(),
                &coland_storage::applet_effective_scope_key(&selector.effective_scope).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let outcome = fixture.revoke_with_mode(&install, mode).await;
        let widget_steps=outcome.steps.iter().filter(|step|matches!(step,AppletRevokeStep::LocalEffect(local) if local.effect_kind==AppletRevokeLocalEffectKind::WidgetTokenInvalidation)).count();
        assert_eq!(
            widget_steps,
            usize::from(mode != arkret_wire::AppletRevokeMode::RevokeRuntimeOnly)
        );
        assert!(
            store
                .check_widget_token(&gate, chrono::Utc::now())
                .await
                .is_err()
        );
        if mode == arkret_wire::AppletRevokeMode::RevokeRuntimeOnly {
            assert_eq!(
                store
                    .widget_tokens(&selector, chrono::Utc::now())
                    .await
                    .unwrap()
                    .len(),
                1
            );
        } else {
            assert!(
                store
                    .widget_tokens(&selector, chrono::Utc::now())
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                store
                    .invalidate_widget_token(&selector, &record.token_ref, chrono::Utc::now())
                    .await
                    .unwrap(),
                coland_storage::AppletWidgetTokenInvalidation::AlreadyInvalidated
            );
        }
        if mode == arkret_wire::AppletRevokeMode::RevokeWidgetOnly {
            let after = widget_authority_snapshot(&fixture.pool).await;
            for key in [
                "events",
                "commits",
                "profiles",
                "grants",
                "managed",
                "claims",
                "namespace_claims",
            ] {
                assert_eq!(native_before[key], after[key], "widget-only mutated {key}");
            }
            let current = store
                .get(
                    install.package.applet_id.as_str(),
                    &coland_storage::applet_effective_scope_key(&selector.effective_scope).unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(current["revoked_at"], install_before["revoked_at"]);
            assert_eq!(current["status"], install_before["status"]);
        }
    }
}

struct WidgetInstalled {
    package: AppletPackage,
    outcome: AppletInstallOutcome,
    body: Value,
    key: String,
}

impl Fixture {
    fn revoke_with_mode<'a>(
        &'a self,
        install: &'a WidgetInstalled,
        revoke_mode: arkret_wire::AppletRevokeMode,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AppletRevokeOutcome> + Send + 'a>> {
        Box::pin(async move {
            let reason = arkret_wire::ReasonCode::from_wire("applet_revoked");
            let preview_body = serde_json::to_value(AppletRevokePreviewRequestBody {
                effective_scope: ScopeRef::Realm {
                    realm_id: self.realm.clone(),
                },
                reason_code: reason.clone(),
                revoke_mode,
            })
            .unwrap();
            let path = format!(
                "/_arkret/self/applets/{}/revoke/preview",
                install.package.applet_id
            );

            let (status, preview) = self
                .admin_post(
                    &path,
                    arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
                    &preview_body,
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "revoke preview: {preview}");

            let preview: AppletRevokePreviewOutcome = serde_json::from_value(preview).unwrap();
            let revoke_plan_digest =
                Hash::new(arkret_canonical::canonical_sha256(&preview.revoke_plan).unwrap())
                    .unwrap();
            let events = preview
                .revoke_plan
                .capability_revocations
                .iter()
                .map(|intent| arkret_wire::EventAdmissionSubmission {
                    event: self.admin_event(
                        EventKind::CapabilityRevoke,
                        ScopeRef::Realm {
                            realm_id: self.realm.clone(),
                        },
                        serde_json::to_value(
                            arkret_models_collaboration::events_payloads::CapabilityRevokePayload {
                                grant_id: intent.grant_id.clone(),
                                expected_revision: intent.expected_revision.clone(),
                                reason: Some(intent.reason_code.as_str().to_owned()),
                            },
                        )
                        .unwrap(),
                    ),
                    approval_signatures: None,
                })
                .collect();
            let members=preview.revoke_plan.membership_removals.iter().map(|intent| arkret_wire::EventAdmissionSubmission {
            event:self.admin_event(EventKind::MemberState,ScopeRef::Realm {realm_id:self.realm.clone()},json!({"member_id":intent.member_id,"membership":intent.membership,"reason":intent.reason_code})), approval_signatures:None,
        }).collect();
            let body = serde_json::to_value(AppletRevokeRequestBody {
                revoke_plan_digest,
                effective_scope: preview.revoke_plan.effective_scope,
                reason_code: reason,
                revoke_mode,
                capability_revoke_events: events,
                membership_state_events: members,
            })
            .unwrap();
            let path = format!("/_arkret/self/applets/{}/revoke", install.package.applet_id);

            let (status, outcome) = self
                .admin_post(
                    &path,
                    arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
                    &body,
                    Some(&format!("revoke-{}", uuid::Uuid::now_v7())),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "accepted Applet revoke: {outcome}");
            let outcome: AppletRevokeOutcome = serde_json::from_value(outcome).unwrap();
            assert_eq!(
                outcome.status,
                AppletRevokeSagaStatus::Complete,
                "revoke outcome: {outcome:?}"
            );
            outcome
        })
    }
}

async fn widget_authority_snapshot(pool: &PgPool) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let mut connection = pool.get().await.unwrap();
    let mut result = serde_json::Map::new();
    for (key, table) in [
        ("events", "canonical_events"),
        ("commits", "realm_commits"),
        ("profiles", "actor_profile_current_results"),
        ("grants", "capability_grant_current_results"),
        ("managed", "applet_managed_identities"),
        ("claims", "realm_actor_creations"),
        ("namespace_claims", "applet_namespace_claims"),
        ("tokens", "applet_widget_tokens"),
    ] {
        let row = diesel::sql_query(format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r"))
            .get_result::<Row>(&mut connection).await.unwrap();
        result.insert(key.to_owned(), row.value);
    }
    Value::Object(result)
}
