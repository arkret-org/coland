#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "This current-result test uses a subset of the shared signed Realm fixture."
)]
mod ordinary_realm;
mod support;

use std::sync::OnceLock;

use coland_storage::{
    AuthorityCommitStore, AuthorityCommitTransaction, AuthorityCommitWriteOutcome,
    CapabilityGrantCurrentResultStore, CapabilityGrantCurrentStatus, CurrentRealmAuthority,
    PersistenceError,
};
use coland_storage_postgres::{
    Db, PgAuthorityCommitStore, PgCapabilityGrantCurrentResultStore, PgPool,
};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;

const REALM_ID: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
const GRANT_ID: &str = "ak:grant:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz";
const COMMIT_ID: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";

static TEST_POOL: OnceLock<PgPool> = OnceLock::new();

async fn test_pool() -> PgPool {
    if let Some(pool) = TEST_POOL.get() {
        return pool.clone();
    }
    let url = support::contract_database_url();
    support::ensure_contract_database(&url).await;
    let pool = Db::connect(Some(&url), Default::default())
        .await
        .expect("initialize test database")
        .pool
        .expect("a configured URL always yields a pool");
    let _ = TEST_POOL.set(pool.clone());
    pool
}

#[tokio::test]
async fn postgres_reads_capability_value_and_revision_from_one_current_row() {
    let pool = test_pool().await;
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let root = serde_json::json!({
        "kind":"realm_root",
        "realm_id":REALM_ID,
        "authority_event_ref":arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x55; 32],
        ),
        "authority_generation":0
    });
    let value = serde_json::json!({
        "id": GRANT_ID,
        "schema": "ak.schema.capability.v1",
        "realm_id": REALM_ID,
        "issuer_id": actor,
        "subject": actor,
        "actions": ["ak.message.create"],
        "resources": [{"kind":"realm", "realm_id":REALM_ID}],
        "issuer_authority_refs": [root.clone()],
        "authority_depth": 1,
        "authority_root_refs": [root],
        "issued_at": "2026-09-21T00:00:00.000Z",
        "status": "active"
    });
    let now = chrono::Utc::now();
    let event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x44; 32]);
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO capability_grant_current_results \
         (realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value,updated_at) \
         VALUES($1,$2,'active',$3,$4,$5,$6,$7,$8) \
         ON CONFLICT(realm_id,grant_id) DO UPDATE SET \
           status=EXCLUDED.status,current_event_id=EXCLUDED.current_event_id, \
           current_commit_id=EXCLUDED.current_commit_id,current_stream_ref=EXCLUDED.current_stream_ref, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(REALM_ID)
    .bind::<Text, _>(GRANT_ID)
    .bind::<Text, _>(event_id.as_str())
    .bind::<Text, _>(COMMIT_ID)
    .bind::<Jsonb, _>(&serde_json::json!({"kind":"realm","realm_id":REALM_ID}))
    .bind::<BigInt, _>(41_i64)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);

    let realm_id = REALM_ID.parse().unwrap();
    let grant_id = GRANT_ID.parse().unwrap();
    let store = PgCapabilityGrantCurrentResultStore { pool };
    let record = store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .expect("current grant row");
    assert_eq!(record.status, CapabilityGrantCurrentStatus::Active);
    assert_eq!(serde_json::to_value(&record.value).unwrap(), value);
    assert_eq!(record.revision.commit_id.as_str(), COMMIT_ID);
    assert_eq!(record.revision.stream_position, 41);

    let snapshot = store.snapshot_for_realm(&realm_id).await.unwrap();
    let listed = snapshot
        .into_iter()
        .find(|row| row.grant_id == grant_id)
        .expect("grant appears in the same-statement Realm snapshot");
    assert_eq!(
        serde_json::to_value(&listed.value).unwrap(),
        serde_json::to_value(&record.value).unwrap()
    );
    assert_eq!(listed.revision, record.revision);
}

fn fixture_did(core_id: &arkret_wire::DidCoreId) -> String {
    format!(
        "did:{}",
        core_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .expect("fixture core id")
    )
}

fn fixture_signature(
    service_id: &arkret_wire::DidCoreId,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context: arkret_wire::DetachedSignatureContext::RealmCommit,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new(format!(
            "{}#authority",
            fixture_did(service_id)
        ))
        .unwrap(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
        created_at,
        sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
    }
}

fn producer_event(
    kind: arkret_wire::EventKind,
    realm_id: &arkret_wire::RealmId,
    actor_id: &arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
    payload: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
) -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id.clone(),
        station_id.clone(),
        payload,
        created_at,
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
        verification_method: arkret_wire::DidUrl::new(format!("{}#device", fixture_did(actor_id)))
            .unwrap(),
        event_digest: digest.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(created_at),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

fn transaction(
    authority: &CurrentRealmAuthority,
    event: &arkret_wire::Event,
    stream_position: u64,
    previous_commit_ref: Option<arkret_wire::RealmCommitId>,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> AuthorityCommitTransaction {
    let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{stream_position}", event.event_id).as_bytes(),
    ));
    AuthorityCommitTransaction {
        expected_authority: authority.clone(),
        commit: arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id,
            realm_id: event.realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position,
            previous_commit_ref,
            event_ref: event.event_id.clone(),
            governance_generation: authority.generation,
            authority_ref: authority.authority_ref.clone(),
            committed_at,
            signature: fixture_signature(&authority.service_id, committed_at),
        },
        event: event.clone(),
        producer_signer_fact: None,
        mls_state: None,
        welcomes: Vec::new(),
        recipient_queue_capacity: 0,
    }
}

#[tokio::test]
async fn authority_transaction_admits_grants_without_subject_kind_branches() {
    let pool = test_pool().await;
    let realm_seed = format!("capability-current:{}", uuid::Uuid::now_v7());
    let realm_event_id = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(realm_seed.as_bytes()),
    );
    let realm_id = arkret_wire::RealmId::from_event_id(&realm_event_id);
    let station_id = arkret_wire::DidCoreId::new("ak:did_core:web:grant-station.example").unwrap();
    let actor_id = arkret_wire::DidCoreId::new("ak:did_core:web:grant-author.example").unwrap();
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        actor_id.clone(),
        station_id.clone(),
    ));
    let authority = CurrentRealmAuthority {
        realm_id: realm_id.clone(),
        generation: 0,
        service_id: station_id.clone(),
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            arkret_identifiers::EventIdentityKey::new(
                realm_id.digest_suite_code(),
                realm_id.digest_bytes(),
            )
            .event_id(),
        ),
        last_handoff_ref: None,
    };
    let authority_store = PgAuthorityCommitStore { pool: pool.clone() };
    authority_store
        .install_genesis_authority(&authority)
        .await
        .unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-21T00:00:00Z")
        .unwrap()
        .to_utc();
    let root_commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        b"capability-root-current",
    ));
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "INSERT INTO realm_authority_root_current_results \
         (realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) \
         VALUES($1,$2,0,0,$3,$4,0,$5)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&actor).unwrap())
    .bind::<Text, _>(realm_event_id.as_str())
    .bind::<Text, _>(root_commit_id.as_str())
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    // The same-cut evaluator also reads the Realm policy bundle and the
    // actor's membership; the controller is a joined member.
    diesel::sql_query(
        "INSERT INTO realm_policy_bundle_current_results \
         (realm_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,0,$3,$4)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(root_commit_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!({"policy_revision":1,"federation_policy":"closed"}))
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,'join',$3,0,$4,$5)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(actor.to_string())
    .bind::<Text, _>(root_commit_id.as_str())
    .bind::<Jsonb, _>(serde_json::json!({"membership":"join"}))
    .bind::<Timestamptz, _>(now)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let create = producer_event(
        arkret_wire::EventKind::CapabilityGrant,
        &realm_id,
        &actor_id,
        &station_id,
        serde_json::json!({
            "grant": {
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id.clone(),
                "issuer_id": actor.clone(),
                "subject": actor,
                "actions": ["ak.message.create"],
                "resources": [{"kind":"realm", "realm_id":realm_id.clone()}],
                "issuer_authority_refs": [{
                    "kind":"realm_root",
                    "realm_id":realm_id.clone(),
                    "authority_event_ref":realm_event_id.clone(),
                    "authority_generation":0
                }],
                "issued_at": "2026-09-21T00:00:00.000Z"
            }
        }),
        now,
    );
    let create_tx = transaction(&authority, &create, 0, None, now);
    let stale_agent_guard = coland_storage::SelfProducerCommitGuard::Agent {
        pcr_realm_id: realm_id.clone(),
        agent_id: actor_id.clone(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: create.event_id.clone(),
            commit_id: create_tx.commit.commit_id.clone(),
            stream_ref: create_tx.commit.stream_ref.clone(),
            stream_position: 0,
        },
        verification_method: create
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone(),
    };
    assert!(
        authority_store
            .admit_self_event_transaction(&create_tx, &stale_agent_guard, now)
            .await
            .is_err()
    );
    assert!(
        authority_store
            .queued_event(&create.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        authority_store
            .stream_head(&create_tx.commit.stream_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        authority_store
            .admit_event_transaction(&create_tx, now)
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Committed
    );
    let grant_id = arkret_wire::GrantId::from_event_id(&create.event_id);
    let current_store = PgCapabilityGrantCurrentResultStore { pool: pool.clone() };
    let created = current_store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.status, CapabilityGrantCurrentStatus::Active);
    assert_eq!(created.revision.commit_id, create_tx.commit.commit_id);

    assert_eq!(
        authority_store
            .admit_event_transaction(&create_tx, now)
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Duplicate
    );
    assert_eq!(
        current_store
            .get(&realm_id, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        created.revision
    );

    let stale = producer_event(
        arkret_wire::EventKind::CapabilityRevoke,
        &realm_id,
        &actor_id,
        &station_id,
        serde_json::json!({
            "grant_id": grant_id.clone(),
            "expected_revision": {
                "commit_id": COMMIT_ID,
                "stream_position": 999
            }
        }),
        now + chrono::TimeDelta::seconds(1),
    );
    let stale_tx = transaction(
        &authority,
        &stale,
        1,
        Some(create_tx.commit.commit_id.clone()),
        now + chrono::TimeDelta::seconds(1),
    );
    assert!(matches!(
        authority_store
            .admit_event_transaction(&stale_tx, now)
            .await,
        Err(PersistenceError::Conflict(_))
    ));
    assert!(
        authority_store
            .queued_event(&stale.event_id)
            .await
            .unwrap()
            .is_none(),
        "CAS failure must roll back the queued Event"
    );
    assert_eq!(
        current_store
            .get(&realm_id, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        created.revision
    );

    let revoke = producer_event(
        arkret_wire::EventKind::CapabilityRevoke,
        &realm_id,
        &actor_id,
        &station_id,
        serde_json::json!({
            "grant_id": grant_id,
            "expected_revision": created.revision
        }),
        now + chrono::TimeDelta::seconds(2),
    );
    let revoke_tx = transaction(
        &authority,
        &revoke,
        1,
        Some(create_tx.commit.commit_id.clone()),
        now + chrono::TimeDelta::seconds(2),
    );
    assert_eq!(
        authority_store
            .admit_event_transaction(&revoke_tx, now)
            .await
            .unwrap(),
        AuthorityCommitWriteOutcome::Committed
    );
    let revoked = current_store
        .get(&realm_id, &grant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.status, CapabilityGrantCurrentStatus::Revoked);
    assert_eq!(revoked.revision.commit_id, revoke_tx.commit.commit_id);
    assert_eq!(revoked.source.event_id, revoke.event_id);
    assert_eq!(
        revoked.value.status,
        arkret_models_collaboration::governance::grant_constraint::CapabilityGrantStatus::Revoked
    );
    assert_eq!(revoked.value.revoked_by.as_ref(), Some(&revoke.actor_id));

    // capabilities.md section 8: grant admission never branches on the subject
    // kind. Only registry `required_constraints` add constraints, for every
    // subject alike. `ak.message.mention.broadcast` lists `expires_at`, so a
    // grant without a finite global expiry is refused before the Event,
    // Commit, and typed result can be written.
    let grant_body = |subject: serde_json::Value, action: &str| {
        serde_json::json!({
            "schema": "ak.schema.capability.v1",
            "realm_id": realm_id,
            "issuer_id": actor,
            "subject": subject,
            "actions": [action],
            "resources": [{"kind":"realm", "realm_id":realm_id,"match_scope":"realm_wide"}],
            "issuer_authority_refs": [{
                "kind":"realm_root",
                "realm_id":realm_id,
                "authority_event_ref":realm_event_id,
                "authority_generation":0
            }],
            "issued_at": "2026-09-21T00:00:00.000Z"
        })
    };
    let service_subject =
        serde_json::to_value(arkret_wire::ActorId::service(station_id.clone())).unwrap();
    let registry_expiry = grant_body(service_subject.clone(), "ak.message.mention.broadcast");
    // `ak.applet.ghost.provision` is a profile non-event action: the Realm
    // root cannot grant it without an accepted Applet registration binding.
    let mut unbound_ghost_provision =
        grant_body(service_subject.clone(), "ak.applet.ghost.provision");
    unbound_ghost_provision["constraints"] = serde_json::json!([{
        "constraint_kind":"authority_control",
        "effect":"allow",
        "evaluation_class":"grant_local",
        "constraint_subkind":"applet_authority",
        "applet_id":"ak:applet:0192b0a4-7c3e-7f00-8000-000000000001",
        "executed_by":arkret_wire::ActorId::service(station_id.clone()),
        "registration_epoch":format!("sha256:{}", "7".repeat(64))
    }]);
    let cases = [
        (
            "registry_expiry_missing",
            registry_expiry.clone(),
            "failed_precondition",
        ),
        (
            "registry_expiry_action_scoped",
            {
                let mut body = registry_expiry;
                body["constraints"] = serde_json::json!([{
                    "constraint_kind":"temporal",
                    "effect":"allow",
                    "applies_to_actions":["ak.message.mention.broadcast"],
                    "expires_at":"2026-09-22T00:00:00.000Z"
                }]);
                body
            },
            "failed_precondition",
        ),
        (
            "non_event_action_without_registration",
            unbound_ghost_provision,
            "grant_exceeds_issuer_authority",
        ),
    ];
    for (name, grant, expected) in cases {
        let candidate = producer_event(
            arkret_wire::EventKind::CapabilityGrant,
            &realm_id,
            &actor_id,
            &station_id,
            serde_json::json!({"grant": grant}),
            now + chrono::TimeDelta::seconds(3),
        );
        let candidate_tx = transaction(
            &authority,
            &candidate,
            2,
            Some(revoke_tx.commit.commit_id.clone()),
            now + chrono::TimeDelta::seconds(3),
        );
        let error = authority_store
            .admit_event_transaction(&candidate_tx, now)
            .await
            .expect_err(name);
        assert!(
            matches!(&error, PersistenceError::Conflict(detail) if detail.starts_with(expected)),
            "{name}: {error:?}"
        );
        assert!(
            authority_store
                .queued_event(&candidate.event_id)
                .await
                .unwrap()
                .is_none(),
            "{name} wrote an Event before refusal"
        );
        assert!(
            current_store
                .get(
                    &realm_id,
                    &arkret_wire::GrantId::from_event_id(&candidate.event_id)
                )
                .await
                .unwrap()
                .is_none(),
            "{name} wrote a grant current result"
        );
        assert_eq!(
            authority_store
                .stream_head(&candidate_tx.commit.stream_ref)
                .await
                .unwrap()
                .expect("the earlier revoke remains the stream head")
                .commit_id,
            revoke_tx.commit.commit_id,
            "{name} advanced the Realm stream"
        );
    }

    // The same generic rules admit service and unclassified Account subjects
    // at every risk tier with a Realm-wide selector and no expiry. Admission
    // reads no Actor Profile, so no profile exists for either subject.
    let unclassified_subject =
        serde_json::to_value(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:grant-unclassified.example").unwrap(),
            station_id.clone(),
        )))
        .unwrap();
    let admitted = [
        (
            "service_low",
            grant_body(service_subject.clone(), "ak.event.read"),
        ),
        (
            "service_medium",
            grant_body(service_subject.clone(), "ak.message.create"),
        ),
        (
            "service_high",
            grant_body(service_subject, "ak.realm.admin"),
        ),
        (
            "account_low",
            grant_body(unclassified_subject.clone(), "ak.event.read"),
        ),
        (
            "account_medium",
            grant_body(unclassified_subject.clone(), "ak.message.create"),
        ),
        (
            "account_high",
            grant_body(unclassified_subject, "ak.realm.admin"),
        ),
    ];
    let mut head = revoke_tx.commit.commit_id.clone();
    for (offset, (name, grant)) in admitted.into_iter().enumerate() {
        let position = 2 + offset as u64;
        let at = now + chrono::TimeDelta::seconds(4 + offset as i64);
        let candidate = producer_event(
            arkret_wire::EventKind::CapabilityGrant,
            &realm_id,
            &actor_id,
            &station_id,
            serde_json::json!({"grant": grant}),
            at,
        );
        let candidate_tx = transaction(&authority, &candidate, position, Some(head.clone()), at);
        assert_eq!(
            authority_store
                .admit_event_transaction(&candidate_tx, now)
                .await
                .unwrap_or_else(|error| panic!("{name}: {error:?}")),
            AuthorityCommitWriteOutcome::Committed,
            "{name}"
        );
        let current = current_store
            .get(
                &realm_id,
                &arkret_wire::GrantId::from_event_id(&candidate.event_id),
            )
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{name} has no grant current result"));
        assert_eq!(
            current.status,
            CapabilityGrantCurrentStatus::Active,
            "{name}"
        );
        head = candidate_tx.commit.commit_id.clone();
    }
}

async fn owned_signed_request(
    fixture: &coland_test_support::agent_origin::OriginFixture,
    request: coland_storage::EventCommitRequest,
) -> coland_storage::EventCommitRequest {
    let pool = fixture.pool.clone();
    let method = fixture.method.clone();
    let issuer = fixture.issuer.clone();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let mut request = Box::pin(ordinary_realm::source_request(&pool, request)).await;
        coland_test_support::agent_origin::origin_seal(
            &mut request.authority_commit.commit,
            &method,
            &issuer,
        );
        request
    });
    tasks.join_next().await.unwrap().unwrap()
}

/// Actual signed controller PCR, provision and Agent genesis are accepted by
/// their original production stores. Collaboration writes use the production
/// unit of work and its current reducers; HTTP transport is tested separately.
#[tokio::test]
async fn owned_agent_signed_current_source_is_terminal_and_issuer_can_revoke_after_leave() {
    // Keep this long native acceptance journey off the default Tokio test
    // thread stack. The production operations and all assertions are unchanged.
    Box::pin(owned_agent_signed_current_source_journey()).await;
}

// Drive each deep production poll without retaining the long test journey's
// debug poll frame. JoinSet owns cancellation; no task survives a dropped
// fixture step, and every original store result is returned to its caller.
async fn owned_origin_fixture() -> coland_test_support::agent_origin::OriginFixture {
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async {
        let fixture = Box::pin(coland_test_support::agent_origin::OriginFixture::new()).await;
        Box::pin(fixture.admit_provision()).await;
        Box::pin(fixture.stage(&fixture.genesis)).await;
        Box::pin(fixture.admit_genesis()).await.unwrap();
        Box::pin(fixture.publish_agent_binding()).await;
        fixture
    });
    tasks.join_next().await.unwrap().unwrap()
}

async fn owned_commit_event(
    pool: &PgPool,
    request: coland_storage::EventCommitRequest,
) -> coland_storage::PersistenceResult<coland_storage::EventCommitOutcome> {
    use coland_storage::EventCommitUnitOfWork;
    let unit = coland_storage_postgres::PgEventCommitUnitOfWork::new(pool.clone());
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { unit.commit_event(request).await });
    tasks.join_next().await.unwrap().unwrap()
}

async fn owned_agent_signed_current_source_journey() {
    use arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef;
    use arkret_wire::{ActorId, CapabilityActionId, EventKind};
    let fixture = owned_origin_fixture().await;
    let pool = &fixture.pool;
    let controller = &fixture.controller.history.account;
    ordinary_realm::human_profile::register_fixture_signer(
        controller,
        fixture
            .controller
            .history
            .device_verification_method
            .clone(),
        fixture.controller.history.founding_device_signing_seed,
    );
    let founder = Box::pin(ordinary_realm::human_profile::admit_for_station_did(
        pool,
        fixture.station_did.clone(),
        "owned-current-founder",
    ))
    .await;
    assert_ne!(&founder, controller);
    let unit = ordinary_realm::bootstrap_unit_for_account(
        "owned-current-signed",
        &founder,
        &fixture.station_did,
    );
    let bootstrap_pool = pool.clone();
    let bootstrap_method = fixture.method.clone();
    let bootstrap_issuer = fixture.issuer.clone();
    let mut bootstrap_tasks = tokio::task::JoinSet::new();
    bootstrap_tasks.spawn(async move {
        let mut unit = Box::pin(ordinary_realm::source_bootstrap(&bootstrap_pool, unit)).await;
        let mut previous = None;
        for tx in &mut unit.transactions {
            tx.commit.previous_commit_ref = previous;
            coland_test_support::agent_origin::origin_seal(
                &mut tx.commit,
                &bootstrap_method,
                &bootstrap_issuer,
            );
            previous = Some(tx.commit.commit_id.clone());
        }
        PgAuthorityCommitStore {
            pool: bootstrap_pool,
        }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
        unit
    });
    let unit = bootstrap_tasks.join_next().await.unwrap().unwrap();
    let authority = PgAuthorityCommitStore { pool: pool.clone() };
    let parent = unit.transactions.last().unwrap();
    let realm = &parent.event.realm_id;
    let at = parent
        .commit
        .committed_at
        .max(fixture.genesis.commit.committed_at)
        + chrono::TimeDelta::seconds(1);
    let controller_join = ordinary_realm::next_request_for_actor(
        parent,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(controller.clone()),"membership":"join"}),
        at,
    );
    let controller_join = Box::pin(owned_signed_request(&fixture, controller_join)).await;
    owned_commit_event(pool, controller_join.clone())
        .await
        .unwrap();
    let agent_join = ordinary_realm::next_request_for_actor(
        &controller_join.authority_commit,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(fixture.agent.clone()),"membership":"join",
            "agent_controller_binding":{"controller_account_id":controller,
                "controller_membership_generation_ref":controller_join.authority_commit.event.event_id}}),
        at + chrono::TimeDelta::seconds(1),
    );
    let agent_join = Box::pin(owned_signed_request(&fixture, agent_join)).await;
    owned_commit_event(pool, agent_join.clone()).await.unwrap();
    let source = IssuerAuthorityRef::OwnedAgent {
        realm_id: realm.clone(),
        controller_account_id: controller.clone(),
        controller_join_event_id: controller_join.authority_commit.event.event_id.clone(),
        agent_join_event_id: agent_join.authority_commit.event.event_id.clone(),
    };
    let body = serde_json::json!({"schema":"ak.schema.capability.v1","realm_id":realm,
        "issuer_id":ActorId::account(controller.clone()),"subject":ActorId::account(fixture.agent.clone()),
        "actions":[CapabilityActionId::EventRead],"resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[{"constraint_kind":"authority_control","effect":"allow",
            "max_authority_depth":0,"authority_regrant_allowed":false}],
        "issuer_authority_refs":[source],
        "issued_at":arkret_canonical::format_timestamp_canonical(at + chrono::TimeDelta::seconds(2))});
    let currents = PgCapabilityGrantCurrentResultStore { pool: pool.clone() };
    // A wrong immutable generation and an unsupported admin action cannot
    // turn the current principal projection into an issuance source.
    for (name, invalid_body) in [
        ("stale_join", {
            let mut value = body.clone();
            value["issuer_authority_refs"][0]["agent_join_event_id"] = serde_json::json!(
                arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [92; 32])
            );
            value
        }),
        ("admin_action", {
            let mut value = body.clone();
            value["actions"] = serde_json::json!(["ak.capability.grant"]);
            value
        }),
    ] {
        let candidate = ordinary_realm::next_request_for_actor(
            &agent_join.authority_commit,
            EventKind::CapabilityGrant,
            ActorId::account(controller.clone()),
            serde_json::json!({"grant":invalid_body}),
            at + chrono::TimeDelta::seconds(2),
        );
        let candidate = Box::pin(owned_signed_request(&fixture, candidate)).await;
        assert!(
            owned_commit_event(pool, candidate.clone()).await.is_err(),
            "{name}"
        );
        assert!(
            authority
                .queued_event(&candidate.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            currents
                .get(
                    realm,
                    &arkret_wire::GrantId::from_event_id(
                        &candidate.authority_commit.event.event_id
                    )
                )
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            authority
                .stream_head(&agent_join.authority_commit.commit.stream_ref)
                .await
                .unwrap()
                .unwrap()
                .commit_id,
            agent_join.authority_commit.commit.commit_id
        );
    }
    #[derive(diesel::QueryableByName)]
    struct CurrentValue {
        #[diesel(sql_type=Jsonb)]
        value: serde_json::Value,
    }
    // Corrupt only the fixture's private current projection. Its actual
    // canonical signed source stays intact, so liveness cannot use raw rows.
    for (name, read, update, broken) in [
        (
            "provision_whole_value",
            "SELECT value FROM agent_provisioning_current_results WHERE agent_id=$1",
            "UPDATE agent_provisioning_current_results SET value=$2 WHERE agent_id=$1",
            "provision",
        ),
        (
            "status_whole_value",
            "SELECT value FROM agent_status_current_results WHERE agent_id=$1",
            "UPDATE agent_status_current_results SET value=$2 WHERE agent_id=$1",
            "status",
        ),
        (
            "accountability_whole_value",
            "SELECT value FROM identity_accountability_current_results WHERE subject_id=$1",
            "UPDATE identity_accountability_current_results SET value=$2 WHERE subject_id=$1",
            "accountability",
        ),
    ] {
        let mut conn = pool.get().await.unwrap();
        let original = diesel::sql_query(read)
            .bind::<Text, _>(fixture.agent.principal_id.as_str())
            .get_result::<CurrentValue>(&mut *conn)
            .await
            .unwrap()
            .value;
        let mut forged = original.clone();
        match broken {
            "provision" => {
                forged["requested_scope_digest"] =
                    serde_json::json!(format!("sha256:{}", "e".repeat(64)))
            }
            "status" => forged = serde_json::json!("paused"),
            "accountability" => {
                forged["not_before"] = serde_json::json!("2099-01-01T00:00:00.000Z")
            }
            _ => unreachable!(),
        }
        diesel::sql_query(update)
            .bind::<Text, _>(fixture.agent.principal_id.as_str())
            .bind::<Jsonb, _>(&forged)
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        let candidate = ordinary_realm::next_request_for_actor(
            &agent_join.authority_commit,
            EventKind::CapabilityGrant,
            ActorId::account(controller.clone()),
            serde_json::json!({"grant":body}),
            at + chrono::TimeDelta::seconds(2),
        );
        let candidate = Box::pin(owned_signed_request(&fixture, candidate)).await;
        assert!(
            owned_commit_event(pool, candidate.clone()).await.is_err(),
            "{name}"
        );
        assert!(
            authority
                .queued_event(&candidate.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_none(),
            "{name}"
        );
        assert!(
            currents
                .get(
                    realm,
                    &arkret_wire::GrantId::from_event_id(
                        &candidate.authority_commit.event.event_id
                    )
                )
                .await
                .unwrap()
                .is_none(),
            "{name}"
        );
        assert_eq!(
            authority
                .stream_head(&agent_join.authority_commit.commit.stream_ref)
                .await
                .unwrap()
                .unwrap()
                .commit_id,
            agent_join.authority_commit.commit.commit_id,
            "{name}"
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(update)
            .bind::<Text, _>(fixture.agent.principal_id.as_str())
            .bind::<Jsonb, _>(&original)
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    // Even an otherwise identical projection cannot prove acceptance when its
    // original native signer witness was lost.
    let mut conn = pool.get().await.unwrap();
    let original=diesel::sql_query("SELECT self_admission_provenance AS value FROM agent_producer_signer_keys WHERE commit_id=$1")
        .bind::<Text,_>(fixture.genesis.commit.commit_id.as_str()).get_result::<CurrentValue>(&mut *conn).await.unwrap().value;
    diesel::sql_query(
        "UPDATE agent_producer_signer_keys SET self_admission_provenance='{}'::jsonb WHERE commit_id=$1",
    )
    .bind::<Text, _>(fixture.genesis.commit.commit_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let missing = ordinary_realm::next_request_for_actor(
        &agent_join.authority_commit,
        EventKind::CapabilityGrant,
        ActorId::account(controller.clone()),
        serde_json::json!({"grant":body}),
        at + chrono::TimeDelta::seconds(2),
    );
    let missing = Box::pin(owned_signed_request(&fixture, missing)).await;
    assert!(owned_commit_event(pool, missing.clone()).await.is_err());
    assert!(
        authority
            .queued_event(&missing.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        currents
            .get(
                realm,
                &arkret_wire::GrantId::from_event_id(&missing.authority_commit.event.event_id)
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        authority
            .stream_head(&agent_join.authority_commit.commit.stream_ref)
            .await
            .unwrap()
            .unwrap()
            .commit_id,
        agent_join.authority_commit.commit.commit_id
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "UPDATE agent_producer_signer_keys SET self_admission_provenance=$2 WHERE commit_id=$1",
    )
    .bind::<Text, _>(fixture.genesis.commit.commit_id.as_str())
    .bind::<Jsonb, _>(original)
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    let create = ordinary_realm::next_request_for_actor(
        &agent_join.authority_commit,
        EventKind::CapabilityGrant,
        ActorId::account(controller.clone()),
        serde_json::json!({"grant":body}),
        at + chrono::TimeDelta::seconds(2),
    );
    let create = Box::pin(owned_signed_request(&fixture, create)).await;
    owned_commit_event(pool, create.clone()).await.unwrap();
    let grant_id = arkret_wire::GrantId::from_event_id(&create.authority_commit.event.event_id);
    let current = currents.get(realm, &grant_id).await.unwrap().unwrap();
    assert_eq!(current.value.authority_depth, 1);
    assert_eq!(
        serde_json::to_value(&current.value.authority_root_refs).unwrap(),
        serde_json::json!([source])
    );
    assert_eq!(
        current.source.event_id,
        create.authority_commit.event.event_id
    );
    assert_eq!(
        current.revision.commit_id,
        create.authority_commit.commit.commit_id
    );
    assert_eq!(
        current.value.issuer_id,
        ActorId::account(controller.clone())
    );
    let leave = ordinary_realm::next_request_for_actor(
        &create.authority_commit,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        serde_json::json!({"member_id":ActorId::account(controller.clone()),"membership":"leave"}),
        at + chrono::TimeDelta::seconds(3),
    );
    let leave = Box::pin(owned_signed_request(&fixture, leave)).await;
    owned_commit_event(pool, leave.clone()).await.unwrap();
    let revoke = ordinary_realm::next_request_for_actor(
        &leave.authority_commit,
        EventKind::CapabilityRevoke,
        ActorId::account(controller.clone()),
        serde_json::json!({"grant_id":grant_id,"expected_revision":current.revision}),
        at + chrono::TimeDelta::seconds(4),
    );
    let revoke = Box::pin(owned_signed_request(&fixture, revoke)).await;
    owned_commit_event(pool, revoke.clone()).await.unwrap();
    let terminal = currents.get(realm, &grant_id).await.unwrap().unwrap();
    assert_eq!(terminal.status, CapabilityGrantCurrentStatus::Revoked);
    assert_eq!(
        terminal.source.event_id,
        revoke.authority_commit.event.event_id
    );
    assert_eq!(
        terminal.revision.commit_id,
        revoke.authority_commit.commit.commit_id
    );
    let _ = owned_commit_event(pool, create).await;
    assert_eq!(
        currents
            .get(realm, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        terminal.revision
    );
    assert_eq!(
        currents
            .get(realm, &grant_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        CapabilityGrantCurrentStatus::Revoked
    );
}
