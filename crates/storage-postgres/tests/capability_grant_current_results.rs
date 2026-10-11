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
