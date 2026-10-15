use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CurrentRevision, DidCoreId, Event, EventKind, InviteId,
    RealmCommit, RealmCommitId, RealmId, ScopeRef,
};
use coland_storage::{
    AuthorityCommitTransaction, CanonicalEventRecord, CurrentRealmAuthority, EventCommitRequest,
    OrdinaryRealmBootstrapCommitUnit, ProjectionEventRecord, RealmMetaRecord,
};
use coland_test_support::AppStateTestExt as _;
use salvo::test::{ResponseExt as _, TestClient};

use super::*;

fn at() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap()
}

fn account(name: &str, station: &DidCoreId) -> AccountId {
    AccountId::new(
        DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
        station.clone(),
    )
}

/// One Event by `actor` carrying a structural producer proof; these fixtures
/// exercise the governance read path, not signature verification.
fn fixture_event(
    kind: EventKind,
    scope_ref: ScopeRef,
    actor: &AccountId,
    payload: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        scope_ref,
        ActorId::account(actor.clone()),
        payload,
        at,
    )
    .unwrap();
    let digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(format!(
            "did:{}#key",
            actor
                .principal_id
                .as_str()
                .strip_prefix("ak:did_core:")
                .unwrap()
        ))
        .unwrap(),
        event_digest: digest.clone(),
        created_at: at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

fn commit_signature(
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: method.clone(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at: at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

/// A Realm governed by `station`, admitted through the ordinary bootstrap
/// unit exactly as production materializes its committed current results.
struct GovernedRealm {
    realm_id: RealmId,
    authority: CurrentRealmAuthority,
    method: arkret_wire::DidUrl,
    head: RealmCommit,
    founder: AccountId,
}

fn realm_transaction(
    authority: &CurrentRealmAuthority,
    method: &arkret_wire::DidUrl,
    event: &Event,
    position: u64,
    previous: Option<RealmCommitId>,
) -> AuthorityCommitTransaction {
    let at = event.created_at;
    let realm_id = authority.realm_id.clone();
    AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        event: event.clone(),
        commit: RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                format!("{}:{position}", event.event_id).as_bytes(),
            )),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: position,
            previous_commit_ref: previous,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: authority.authority_ref.clone(),
            committed_at: at,
            signature: commit_signature(method, at),
        },
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    }
}

async fn commit_projected_invite(
    store: &dyn coland_storage::PersistenceStore,
    transaction: AuthorityCommitTransaction,
) {
    let event = &transaction.event;
    let at = event.created_at;
    let event_id = event.event_id.to_string();
    let realm_id = event.realm_id.to_string();
    let kind = event.kind.as_str().to_owned();
    let payload = serde_json::to_value(&event.payload).unwrap();
    let request = EventCommitRequest {
        event: CanonicalEventRecord {
            event_id: event_id.clone(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(realm_id.clone()),
            kind: kind.clone(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest: event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
            canonical_bytes: arkret_canonical::canonical_json_bytes(
                &event.digest_payload().unwrap(),
            )
            .unwrap(),
            envelope: serde_json::to_value(event).unwrap(),
            received_at: at,
        },
        projections: vec![ProjectionEventRecord {
            event_id,
            realm_id,
            event_kind: kind,
            operation_kind: "create".to_owned(),
            operation_id: None,
            sender: Some(event.actor_id.to_string()),
            payload,
            created_at: at,
            received_at: at,
        }],
        authority_commit: transaction,
        self_producer_guard: None,
        applet_producer_guard: None,
        widget_token_gate: None,
        agent_grant_scope_evidence: None,
        call_media_binding_key: None,
        forwarded_producer_evidence: None,
        forwarded_agent_producer: None,
        agent_deployment_ceiling:
            arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL,
        parent_membership_admission: None,
        contact_projection: None,

        device_revocation_transition: None,
        device_revocation_gate: None,
        idempotency: None,
        outbox: Vec::new(),
        realm_fanout_source: None,
    };
    store
        .commit_event(request)
        .await
        .expect("Invite Event/Commit unit");
}

impl GovernedRealm {
    /// `method` is the governing Station's Commit signing method; the
    /// fixture signatures are structural only.
    async fn admit(
        store: &dyn coland_storage::PersistenceStore,
        station: &DidCoreId,
        method: arkret_wire::DidUrl,
    ) -> Self {
        use arkret_models_collaboration::authority_commit::{
            OrdinaryRealmBootstrapUnitKind, OrdinaryRealmBootstrapUnitSubmission,
            SelfAuthoritySubmitRequest,
        };

        let at = at();
        let founder = account("preview-founder", station);
        let genesis_salt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            arkret_canonical::sha256_bytes(uuid::Uuid::now_v7().to_string().as_bytes()),
        );
        let genesis = fixture_event(
            EventKind::RealmCreate,
            ScopeRef::RealmGenesis,
            &founder,
            serde_json::json!({"object":{
                "schema":"ak.schema.realm_genesis.v1",
                "purpose":"collaboration",
                "genesis_salt":genesis_salt,
                "trust_domain":"ak:trust_domain:preview.example",
                "security_class":"high_assurance",
                "governance_station_id":station,
                "initial_join_rule":"invite",
                "initial_history_access":"since_join",
                "initial_discoverability":"invite_only"
            }}),
            at,
        );
        let realm_id = genesis.realm_id.clone();
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let mut events = vec![genesis];
        for (kind, payload) in [
            (
                EventKind::RealmProfile,
                serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Preview Realm"}),
            ),
            (
                EventKind::RealmPolicyBundle,
                serde_json::json!({"policy_revision":1,"federation_policy":"closed"}),
            ),
            (
                EventKind::RealmJoinRule,
                serde_json::json!({"value":"invite"}),
            ),
            (
                EventKind::RealmHistoryAccess,
                serde_json::json!({"from":null,"to":"since_join"}),
            ),
            (
                EventKind::RealmDiscovery,
                serde_json::json!({"value":{"discoverability":"invite_only"}}),
            ),
            (
                EventKind::MemberState,
                serde_json::json!({
                    "member_id":ActorId::account(founder.clone()),
                    "membership":"join"
                }),
            ),
        ] {
            events.push(fixture_event(kind, scope.clone(), &founder, payload, at));
        }
        let authority = CurrentRealmAuthority {
            realm_id: realm_id.clone(),
            generation: 0,
            service_id: station.clone(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                events[0].event_id.clone(),
            ),
            last_handoff_ref: None,
        };
        let mut previous = None;
        let mut transactions = Vec::new();
        for (position, event) in events.iter().enumerate() {
            let transaction =
                realm_transaction(&authority, &method, event, position as u64, previous);
            previous = Some(transaction.commit.commit_id.clone());
            transactions.push(transaction);
        }
        let realm = Self {
            realm_id,
            authority,
            method,
            head: transactions.last().unwrap().commit.clone(),
            founder,
        };
        let submission = OrdinaryRealmBootstrapUnitSubmission {
            unit_kind: OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
            idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
            events: events
                .into_iter()
                .map(arkret_wire::EventAdmissionSubmission::new)
                .collect(),
        };
        let unit = OrdinaryRealmBootstrapCommitUnit {
            event_approvals: Vec::new(),
            exact_request_body: serde_json::to_vec(
                &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(submission.clone()),
            )
            .unwrap(),
            submission,
            transactions,
        };
        store
            .authority_commits()
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .expect("ordinary Realm bootstrap admitted");
        realm
    }

    /// Commit one directed `ak.invite.create` for `invitee` at the next Realm
    /// position and project its pending lifecycle.
    async fn invite(
        &mut self,
        store: &dyn coland_storage::PersistenceStore,
        invitee: &AccountId,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> InviteId {
        let event = fixture_event(
            EventKind::InviteCreate,
            ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            &self.founder,
            serde_json::json!({
                "invitee_account_id": invitee,
                "introduction_evidence_digest": format!("sha256:{}", "1".repeat(64)),
                "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
            }),
            at(),
        );
        let transaction = realm_transaction(
            &self.authority,
            &self.method,
            &event,
            self.head.stream_position + 1,
            Some(self.head.commit_id.clone()),
        );
        commit_projected_invite(store, transaction.clone()).await;
        self.head = transaction.commit;
        let invite_id = InviteId::from_event_id(&event.event_id);
        invite_id
    }

    async fn cancel_invite(
        &mut self,
        store: &dyn coland_storage::PersistenceStore,
        invite_id: &InviteId,
        invitee: &AccountId,
    ) {
        let event = fixture_event(
            EventKind::InviteCancel,
            ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            &self.founder,
            serde_json::json!({
                "invite_id": invite_id,
                "invitee_account_id": invitee,
                "previous_state": "pending",
                "target_state": "revoked",
            }),
            at(),
        );
        let transaction = realm_transaction(
            &self.authority,
            &self.method,
            &event,
            self.head.stream_position + 1,
            Some(self.head.commit_id.clone()),
        );
        commit_projected_invite(store, transaction.clone()).await;
        self.head = transaction.commit;
    }
}

async fn set_preview_metadata(
    store: &dyn coland_storage::PersistenceStore,
    realm_id: &RealmId,
    policy: Option<serde_json::Value>,
) {
    let now = at();
    store
        .realm_meta()
        .put(
            realm_id.as_str(),
            &RealmMetaRecord {
                owner: "ak:did_core:web:preview-founder.example".to_owned(),
                deleted: false,
                discoverability: "invite_only".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy_digest: policy
                    .as_ref()
                    .map(|_| format!("sha256:{}", "2".repeat(64))),
                preview_policy: policy,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: None,
                plaintext_visible_services: BTreeSet::new(),
                plaintext_visible_service_classes: BTreeMap::new(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
}

async fn set_preview_policy(
    store: &dyn coland_storage::PersistenceStore,
    realm: &mut GovernedRealm,
    policy: Option<serde_json::Value>,
) {
    let value = policy.unwrap_or_else(
        || serde_json::json!({"mode":"none","audiences":["anonymous"],"fields":["title"]}),
    );
    let event = fixture_event(
        EventKind::RealmPreviewPolicy,
        ScopeRef::Realm {
            realm_id: realm.realm_id.clone(),
        },
        &realm.founder,
        serde_json::json!({"value":value,"reason":"preview policy fixture"}),
        at(),
    );
    let transaction = realm_transaction(
        &realm.authority,
        &realm.method,
        &event,
        realm.head.stream_position + 1,
        Some(realm.head.commit_id.clone()),
    );
    commit_projected_invite(store, transaction.clone()).await;
    realm.head = transaction.commit;
}

fn station() -> (
    AppState,
    std::sync::Arc<dyn coland_storage::PersistenceStore>,
) {
    let config = crate::config::AppConfig {
        seed_demo_data: false,
        ..crate::config::AppConfig::test_default()
    };
    let service_did =
        AppState::new(config.clone(), coland_storage_postgres::Db { pool: None }).service_did();
    let persisted = coland_test_support::app_state_with_service_did(
        coland_test_support::app_config(),
        service_did,
    );
    let store = persisted.test_persistence();
    let state = AppState::new_with_persistence(
        config,
        coland_storage_postgres::Db { pool: None },
        store.clone(),
    );
    (state, store)
}

fn request(
    realm_id: &RealmId,
    requester: &AccountId,
    invite_id: Option<InviteId>,
) -> PeerRealmJoinPreviewRequestBody {
    PeerRealmJoinPreviewRequestBody {
        request_id: arkret_wire::RequestId::new_v7_at(1_750_000_000_000),
        realm_id: realm_id.clone(),
        requester_account_id: requester.clone(),
        invite_id,
    }
}

async fn assert_not_found(state: &AppState, request: &PeerRealmJoinPreviewRequestBody) {
    let error = governance_preview(state, request)
        .await
        .expect_err("undisclosed target");
    assert_eq!(error.wire_code(), "not_found", "{error:?}");
}

#[tokio::test]
async fn governance_preview_discloses_only_policy_fields_to_an_admitted_audience() {
    let (state, store) = station();
    let local = state.service_core_id();
    let mut realm = GovernedRealm::admit(
        store.as_ref(),
        &local,
        state.service_verification_method("notary-key").unwrap(),
    )
    .await;
    let bob = account("preview-bob", &local);
    let carol = account("preview-carol", &local);

    // Unknown Realm and a governed Realm with no effective preview policy
    // share one not_found.
    let unknown = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x42; 32],
    ));
    assert_not_found(&state, &request(&unknown, &bob, None)).await;
    assert_not_found(&state, &request(&realm.realm_id, &bob, None)).await;
    // An unconfirmed metadata cache cannot create a preview entitlement.
    set_preview_metadata(store.as_ref(), &realm.realm_id, Some(serde_json::json!({"mode":"directory_card","audiences":["anonymous"],"fields":["title"]}))).await;
    assert_not_found(&state, &request(&realm.realm_id, &bob, None)).await;

    // An invited-only policy discloses nothing to a requester without a
    // bound invite, and exactly the listed fields to the bound invitee.
    set_preview_policy(
        store.as_ref(),
        &mut realm,
        Some(serde_json::json!({
            "mode":"directory_card",
            "audiences":["invited"],
            "fields":["title","join_rule","history_access"]
        })),
    )
    .await;
    assert_not_found(&state, &request(&realm.realm_id, &bob, None)).await;
    let bob_invite = realm
        .invite(store.as_ref(), &bob, at() + chrono::Duration::hours(1))
        .await;
    let preview = governance_preview(
        &state,
        &request(&realm.realm_id, &bob, Some(bob_invite.clone())),
    )
    .await
    .expect("invitee preview");
    assert_eq!(
        preview,
        RealmPublicPreview {
            realm_id: realm.realm_id.clone(),
            join_rule: JoinRule::Invite,
            history_access: HistoryAccess::SinceJoin,
            governance_generation: 0,
            display_name: Some("Preview Realm".to_owned()),
        }
    );

    // The invite binds the exact complete AccountId: another account, the
    // same principal at another Station, and an unknown invite are refused.
    assert_not_found(
        &state,
        &request(&realm.realm_id, &carol, Some(bob_invite.clone())),
    )
    .await;
    let bob_elsewhere = AccountId::new(
        bob.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:elsewhere.example").unwrap(),
    );
    assert_not_found(
        &state,
        &request(&realm.realm_id, &bob_elsewhere, Some(bob_invite.clone())),
    )
    .await;
    let never_committed = InviteId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x17; 32],
    ));
    assert_not_found(
        &state,
        &request(&realm.realm_id, &bob, Some(never_committed)),
    )
    .await;

    // An expired invite and a terminal lifecycle are no longer live.
    let expired = realm
        .invite(store.as_ref(), &carol, at() - chrono::Duration::seconds(1))
        .await;
    assert_not_found(&state, &request(&realm.realm_id, &carol, Some(expired))).await;
    realm.cancel_invite(store.as_ref(), &bob_invite, &bob).await;
    assert_not_found(
        &state,
        &request(&realm.realm_id, &bob, Some(bob_invite.clone())),
    )
    .await;

    // A non-invited audience with no disclosable field gets the minimal
    // preview: only the required members, no display name.
    set_preview_policy(
        store.as_ref(),
        &mut realm,
        Some(serde_json::json!({
            "mode":"directory_card",
            "audiences":["authenticated"],
            "fields":["member_count_bucket"]
        })),
    )
    .await;
    let minimal = governance_preview(&state, &request(&realm.realm_id, &carol, None))
        .await
        .expect("authenticated audience preview");
    assert_eq!(minimal.display_name, None);
    assert_eq!(minimal.join_rule, JoinRule::Invite);

    // A current member is admitted by the realm_member audience only.
    set_preview_policy(
        store.as_ref(),
        &mut realm,
        Some(serde_json::json!({
            "mode":"directory_card",
            "audiences":["realm_member"],
            "fields":["title"]
        })),
    )
    .await;
    assert_not_found(&state, &request(&realm.realm_id, &carol, None)).await;
    let founder = realm.founder.clone();
    assert_eq!(
        governance_preview(&state, &request(&realm.realm_id, &founder, None))
            .await
            .expect("member preview")
            .display_name
            .as_deref(),
        Some("Preview Realm")
    );

    // The peer answer binds the requester to the calling Station: the same
    // disclosable request from another Source-Service-ID is not found, and
    // both answers sit in one timing bucket.
    let peer_request = request(&realm.realm_id, &founder, None);
    let started = std::time::Instant::now();
    let answered = answer_peer_preview(&state, local.as_str(), peer_request.clone())
        .await
        .expect("peer preview from the requester's Station");
    assert_eq!(answered.request_id, peer_request.request_id);
    answered
        .validate_for_request(&peer_request)
        .expect("peer outcome binds the request");
    assert!(started.elapsed() >= PEER_PREVIEW_TIMING_FLOOR);
    let started = std::time::Instant::now();
    let wrong_source = answer_peer_preview(
        &state,
        "ak:did_core:web:not-the-requester-station.example",
        peer_request,
    )
    .await
    .expect_err("a requester from another Station");
    assert_eq!(wrong_source.wire_code(), "not_found");
    assert!(started.elapsed() >= PEER_PREVIEW_TIMING_FLOOR);

    // Mode none is no preview at all.
    set_preview_policy(
        store.as_ref(),
        &mut realm,
        Some(serde_json::json!({
            "mode":"none",
            "audiences":["anonymous"],
            "fields":["title"]
        })),
    )
    .await;
    assert_not_found(&state, &request(&realm.realm_id, &founder, None)).await;

    // A Realm governed by another Station is not answered here, even with a
    // permissive policy in this Station's projection.
    let elsewhere = DidCoreId::new("ak:did_core:web:other-governance.example").unwrap();
    let mut foreign = GovernedRealm::admit(
        store.as_ref(),
        &elsewhere,
        arkret_wire::DidUrl::new("did:web:other-governance.example#authority").unwrap(),
    )
    .await;
    set_preview_policy(
        store.as_ref(),
        &mut foreign,
        Some(serde_json::json!({
            "mode":"directory_card",
            "audiences":["anonymous"],
            "fields":["title"]
        })),
    )
    .await;
    assert_not_found(&state, &request(&foreign.realm_id, &bob, None)).await;
}

#[test]
fn disclose_requires_the_committed_required_members() {
    let realm_id = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x33; 32],
    ));
    let policy: PreviewPolicyPayloadValue = serde_json::from_value(serde_json::json!({
        "mode":"directory_card",
        "audiences":["anonymous"],
        "fields":["title"]
    }))
    .unwrap();
    let audience = PreviewAudience {
        invited: false,
        member: false,
    };
    let stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let current = |selector: CurrentSelector, value: serde_json::Value| TypedCurrentRow::Value {
        selector,
        source_stream_ref: stream.clone(),
        revision: CurrentRevision {
            commit_id: RealmCommitId::from_digest([0x44; 32]),
            stream_position: 1,
        },
        value,
    };
    let join_rule = current(CurrentSelector::RealmJoinRule, serde_json::json!("knock"));
    let history = current(
        CurrentSelector::RealmHistoryAccess,
        serde_json::json!("since_join"),
    );
    let long_title = current(
        CurrentSelector::RealmProfile,
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"x".repeat(257)}),
    );
    assert!(disclose(&policy, audience, &realm_id, 3, &[join_rule.clone()]).is_none());
    assert!(disclose(&policy, audience, &realm_id, 3, &[history.clone()]).is_none());
    let preview = disclose(
        &policy,
        audience,
        &realm_id,
        3,
        &[join_rule, history, long_title],
    )
    .expect("required members are present");
    assert_eq!(preview.join_rule, JoinRule::Knock);
    assert_eq!(preview.governance_generation, 3);
    assert_eq!(
        preview.display_name, None,
        "an out-of-profile title is withheld, never truncated"
    );
}

#[tokio::test]
async fn preview_routes_authenticate_before_reading_the_body() {
    let service = crate::service(AppState::new(
        crate::config::AppConfig::test_default(),
        coland_storage_postgres::Db { pool: None },
    ));
    let post = |path: &str, operation: &str| {
        TestClient::post(format!("http://server{path}")).add_header(
            "Arkret-Operation",
            operation,
            true,
        )
    };
    let mut response = post(
        "/_arkret/self/realm-joins/preview",
        arkret_wire::ServiceOperationId::SELF_REALM_JOIN_READ_PREVIEW_V1,
    )
    .json(&serde_json::json!({}))
    .send(&service)
    .await;
    assert_eq!(
        response.status_code,
        Some(salvo::http::StatusCode::UNAUTHORIZED)
    );
    let body: serde_json::Value = response.take_json().await.unwrap();
    assert_eq!(
        body["type"], "https://arkret.org/problems/unauthenticated",
        "{body}"
    );

    // The peer preview is mounted and refuses an unsigned caller before any
    // governance read; it is never an unrecognized endpoint.
    let mut response = post(
        "/_arkret/peer/realm-joins/preview",
        arkret_wire::ServiceOperationId::PEER_REALM_JOIN_READ_PREVIEW_V1,
    )
    .json(&serde_json::json!({
        "request_id": "ak:request:0196419b-0000-7000-8000-000000000001",
        "realm_id": "ak:realm:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0",
        "requester_account_id": {
            "principal_id": "ak:did_core:web:bob.example",
            "station_id": "ak:did_core:web:bob-station.example"
        }
    }))
    .send(&service)
    .await;
    let status = response.status_code.expect("status");
    let body: serde_json::Value = response.take_json().await.unwrap();
    assert!(status.is_client_error(), "{status}: {body}");
    for unreachable in [
        "unrecognized_endpoint",
        "unsupported_operation_version",
        "not_found",
    ] {
        assert_ne!(
            body["type"],
            format!("https://arkret.org/problems/{unreachable}"),
            "{body}"
        );
    }
}
