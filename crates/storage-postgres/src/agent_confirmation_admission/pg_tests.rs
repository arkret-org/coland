//! Private request/draft and confirmation consumers on imported shared history.
//! Ownership uses the existing native PostgreSQL Origin fixture: a real
//! controller PCR, accepted provision/Agent genesis, binding and accountability.
//! Imported target history isolates consumption; HTTP producer tests are separate.
use coland_storage::{
    ActorPrivateEventEffect, ActorPrivateEventStore, ActorPrivateEventSubmission,
};
use diesel::sql_types::Binary;
use serde_json::json;

use super::*;
use crate::{PgActorPrivateEventStore, PgPool, device_authorization_history, pcr_genesis};
#[path = "../../../test-support/src/agent_origin.rs"]
#[expect(
    dead_code,
    reason = "These consumers use the accepted ownership subset of the shared Origin fixture."
)]
mod origin_fixture;

struct Fixture {
    origin: Box<origin_fixture::OriginFixture>,
}
impl Fixture {
    async fn new() -> Self {
        let origin = Box::new(Box::pin(origin_fixture::OriginFixture::new()).await);
        origin.stage(&origin.provision).await;
        origin.admit_provision().await;
        origin.stage(&origin.genesis).await;
        origin.admit_genesis().await.unwrap();
        origin.publish_agent_binding().await;
        Self { origin }
    }
}
fn owner(f: &Fixture) -> arkret_wire::AccountId {
    f.origin.controller.history.account.clone()
}
fn agent(f: &Fixture) -> arkret_wire::AccountId {
    f.origin.agent.clone()
}
fn at(f: &Fixture) -> chrono::DateTime<chrono::Utc> {
    f.origin.genesis.commit.committed_at + chrono::TimeDelta::minutes(1)
}
fn realm(_f: &Fixture) -> arkret_wire::RealmId {
    arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [21; 32],
    ))
}
fn event(
    f: &Fixture,
    kind: EventKind,
    actor: &arkret_wire::AccountId,
    payload: serde_json::Value,
    offset: i64,
) -> Event {
    let realm_id = if kind.wire_scope() == arkret_wire::EventWireScope::ActorPrivateEvent {
        if actor == &agent(f) {
            f.origin.genesis.event.realm_id.clone()
        } else {
            f.origin.controller.history.events[0].realm_id.clone()
        }
    } else {
        realm(f)
    };
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm { realm_id },
        ActorId::account(actor.clone()),
        payload,
        at(f) + chrono::TimeDelta::seconds(offset),
    )
    .unwrap();
    let created_at = event.created_at;
    signed(f, event, actor, created_at)
}
fn signed(
    f: &Fixture,
    mut event: Event,
    actor: &arkret_wire::AccountId,
    proof_at: chrono::DateTime<chrono::Utc>,
) -> Event {
    event.producer_proof = None;
    let (seed, method) = if actor == &agent(f) {
        ([0x61; 32], format!("{}#runtime", f.origin.agent_did))
    } else {
        (
            f.origin.controller.history.founding_device_signing_seed,
            f.origin
                .controller
                .history
                .device_verification_method
                .to_string(),
        )
    };
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(seed, method);
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(proof_at),
    )
    .unwrap();
    authored.into_event()
}
fn commit(f: &Fixture, event: &Event, position: u64) -> RealmCommit {
    let mut value = RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: arkret_wire::RealmCommitId::from_digest([position as u8 + 80; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        stream_position: position,
        previous_commit_ref: position
            .checked_sub(1)
            .map(|p| arkret_wire::RealmCommitId::from_digest([p as u8 + 80; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            event.event_id.clone(),
        ),
        committed_at: event.created_at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:station.example#authority")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
            created_at: event.created_at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
        },
    };
    origin_fixture::origin_seal(&mut value, &f.origin.method, &f.origin.issuer);
    value
}
async fn history(conn: &mut AsyncPgConnection, event: &Event, commit: &RealmCommit) {
    sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9)")
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Binary,_>(event.event_id.digest_bytes().to_vec())
        .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
        .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(json!(event)).bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(commit.realm_id.as_str()).bind::<Text,_>(arkret_canonical::canonical_json_string(&commit.stream_ref).unwrap())
        .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<BigInt,_>(commit.stream_position as i64)
        .bind::<Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id|id.as_str())).bind::<Jsonb,_>(json!(commit)).bind::<Timestamptz,_>(commit.committed_at)
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await.unwrap();
}
async fn seed(f: &Fixture, conn: &mut AsyncPgConnection) {
    sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,'{}')")
        .bind::<Text,_>(realm(f).as_str()).bind::<Text,_>(f.origin.station.as_str()).execute(&mut *conn).await.unwrap();
    let genesis = event(f, EventKind::RealmCreate, &owner(f), json!({}), 0);
    let source = commit(f, &genesis, 0);
    history(conn, &genesis, &source).await;
    sql_query("INSERT INTO agent_principals(id,controller_principal_id,principal_control_realm_id,controller_authorization_ref,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT(id) DO NOTHING")
        .bind::<Text,_>(agent(f).principal_id.as_str()).bind::<Text,_>(owner(f).principal_id.as_str())
        .bind::<Text,_>(f.origin.genesis.event.realm_id.as_str())
        .bind::<Text,_>(f.origin.provision.event.payload.get("controller_authorization_ref").and_then(serde_json::Value::as_str).unwrap())
        .bind::<Timestamptz,_>(f.origin.provision.event.created_at).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO realm_authority_root_current_results(realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) VALUES($1,$2,0,0,$3,$4,0,$5)")
        .bind::<Text,_>(realm(f).as_str()).bind::<Jsonb,_>(json!(ActorId::account(owner(f))))
        .bind::<Text,_>(genesis.event_id.as_str()).bind::<Text,_>(source.commit_id.as_str())
        .bind::<Timestamptz,_>(at(f)).execute(&mut *conn).await.unwrap();
}
fn message(f: &Fixture) -> Event {
    event(
        &f,
        EventKind::MessageCreate,
        &agent(&f),
        json!({"strand_id":arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[31;32])),"track_name":"discussion","content":{"kind":"ak.content.text","format":"plain","body":"requested publication"}}),
        10,
    )
}
async fn request(f: &Fixture, pool: &PgPool, target: &Event) {
    let action = if target.kind == EventKind::AgentKeyRevoke {
        "ak.agent.key.revoke"
    } else {
        "ak.message.create"
    };
    let payload = json!({"request_id":"request-1","agent_id":agent(&f).principal_id,"controller_account_id":owner(&f),"proposed_action":action,
        "target":{"kind":"realm","realm_id":realm(&f)},"request_canonical_digest":arkret_canonical::canonical_sha256(target).unwrap(),
        "expires_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(120)),"created_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(1))});
    let source = event(
        &f,
        EventKind::AgentActionRequest,
        &agent(&f),
        payload.clone(),
        1,
    );
    let submission = ActorPrivateEventSubmission {
        canonical_event_digest: arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&source).unwrap(),
        )
        .to_vec(),
        accepted_at: source.created_at,
        event: source,
        owner: owner(&f),
        producer_guard: None,
        effect: ActorPrivateEventEffect::AgentActionRequest(
            serde_json::from_value(payload).unwrap(),
        ),
    };
    assert!(matches!(
        PgActorPrivateEventStore::new(pool.clone())
            .submit(&submission)
            .await
            .unwrap(),
        coland_storage::ActorPrivateEventSubmitResult::Accepted(_)
    ));
}
fn approval(f: &Fixture, target: &Event, id: &str, nonce: &str) -> Event {
    let action = if target.kind == EventKind::AgentKeyRevoke {
        "ak.agent.key.revoke"
    } else {
        "ak.message.create"
    };
    event(
        &f,
        EventKind::AgentActionApprove,
        &owner(&f),
        json!({"approval_id":id,"request_id":"request-1","agent_id":agent(&f).principal_id,"proposed_action":action,
        "target":{"kind":"realm","realm_id":realm(&f)},"approved_event_id":target.event_id,"approval_nonce":nonce,
        "expires_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(10))}),
        2,
    )
}
async fn install(f: &Fixture, conn: &mut AsyncPgConnection, confirmation: &Event, position: u64) {
    let source = commit(&f, confirmation, position);
    history(conn, confirmation, &source).await;
    commit_confirmation(conn, confirmation, &source)
        .await
        .unwrap();
}
fn assert_required(result: PersistenceResult<()>) {
    let failure = result.unwrap_err();
    assert_eq!(
        failure.conflict_code(),
        Some(coland_storage::ConflictCode::ApprovalRequired),
        "{failure:?}"
    );
}

#[tokio::test]
async fn private_request_selects_agent_actor_and_confirmation_uses_covering_commit() {
    let f = Fixture::new().await;
    let pool = f.origin.pool.clone();
    let mut conn = pool.get().await.unwrap();
    seed(&f, &mut conn).await;
    let target = message(&f);
    let mut covering = commit(&f, &target, 2);
    // A direct reply retains its own admission. Attributed Agent execution
    // still owes fresh controller approval when it omits a private selection.
    require_publication(&mut conn, &target, &covering)
        .await
        .unwrap();
    let mut delegated = target.clone();
    delegated.actor_id = ActorId::account(owner(&f));
    delegated.executed_by = Some(ActorId::account(agent(&f)));
    delegated.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(
            event(&f, EventKind::RealmCreate, &owner(&f), json!({}), 0)
                .event_id
                .to_string(),
        )
        .unwrap(),
    );
    let delegated = signed(&f, delegated, &agent(&f), target.created_at);
    assert_required(require_publication(&mut conn, &delegated, &covering).await);
    request(&f, &pool, &target).await;
    assert_required(require_publication(&mut conn, &target, &covering).await);
    let mut wrong = approval(&f, &target, "approval-wrong", "BBBBBBBBBBBBBBBBBBBBBB");
    wrong
        .payload
        .insert("request_id".into(), json!("another-request"));
    let wrong = signed(
        &f,
        wrong,
        &owner(&f),
        at(&f) + chrono::TimeDelta::seconds(2),
    );
    install(&f, &mut conn, &wrong, 1).await;
    assert_required(require_publication(&mut conn, &target, &covering).await);
    let confirmed = approval(&f, &target, "approval-1", "AAAAAAAAAAAAAAAAAAAAAA");
    install(&f, &mut conn, &confirmed, 2).await;
    // The publication created_at is irrelevant. Equality at expires_at admits.
    covering.committed_at = at(&f) + chrono::TimeDelta::seconds(10);
    require_publication(&mut conn, &target, &covering)
        .await
        .unwrap();
    covering.committed_at += chrono::TimeDelta::milliseconds(1);
    assert_required(require_publication(&mut conn, &target, &covering).await);
    covering.committed_at = at(&f) + chrono::TimeDelta::seconds(10);
    let changed = signed(
        &f,
        target.clone(),
        &agent(&f),
        at(&f) + chrono::TimeDelta::seconds(11),
    );
    assert_eq!(changed.event_id, target.event_id);
    assert_ne!(
        arkret_canonical::canonical_sha256(&changed).unwrap(),
        arkret_canonical::canonical_sha256(&target).unwrap()
    );
    changed
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    assert_required(require_publication(&mut conn, &changed, &covering).await);
    // No nonce is newly allocated while the publication gate is evaluated.
    let reused = approval(&f, &target, "approval-2", "AAAAAAAAAAAAAAAAAAAAAA");
    assert!(
        commit_confirmation(&mut conn, &reused, &commit(&f, &reused, 2))
            .await
            .unwrap_err()
            .to_string()
            .contains("nonce has already been allocated")
    );
    let mut foreign = reused.clone();
    foreign.realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [22; 32],
    ));
    foreign.scope_ref = arkret_wire::ScopeRef::Realm {
        realm_id: foreign.realm_id.clone(),
    };
    let foreign = signed(
        &f,
        foreign,
        &owner(&f),
        at(&f) + chrono::TimeDelta::seconds(2),
    );
    assert!(
        commit_confirmation(&mut conn, &foreign, &commit(&f, &foreign, 1))
            .await
            .unwrap_err()
            .to_string()
            .contains("nonce has already been allocated")
    );
    let mut expired = commit(&f, &confirmed, 3);
    expired.committed_at =
        at(&f) + chrono::TimeDelta::seconds(10) + chrono::TimeDelta::milliseconds(1);
    assert!(
        admit_confirmation(&mut conn, &confirmed, &expired, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("covering committed_at is after expires_at")
    );
    sql_query("UPDATE agent_action_requests SET workflow_state='rejected',rejection_id='rejection-1' WHERE request_id='request-1'").execute(&mut conn).await.unwrap();
    assert_required(require_publication(&mut conn, &target, &covering).await);
}

#[tokio::test]
async fn private_request_selects_agent_actor_when_controller_is_the_producer() {
    let f = Fixture::new().await;
    let pool = f.origin.pool.clone();
    let mut conn = pool.get().await.unwrap();
    seed(&f, &mut conn).await;
    let mut target = event(
        &f,
        EventKind::AgentKeyRevoke,
        &agent(&f),
        json!({"agent_id":agent(&f).principal_id,"key_id":"runtime-key","revoked_by":owner(&f).principal_id,
            "revoked_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(10))}),
        10,
    );
    target.executed_by = Some(ActorId::account(owner(&f)));
    target.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(format!(
            "did:webvh:{}:agent.example#managed-controller",
            agent(&f)
                .principal_id
                .as_str()
                .strip_prefix("ak:did_core:webvh:")
                .unwrap()
        ))
        .unwrap(),
    );
    let target = signed(
        &f,
        target,
        &owner(&f),
        at(&f) + chrono::TimeDelta::seconds(10),
    );
    target
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request(&f, &pool, &target).await;
    assert_required(require_publication(&mut conn, &target, &commit(&f, &target, 2)).await);
    install(
        &f,
        &mut conn,
        &approval(&f, &target, "approval-1", "AAAAAAAAAAAAAAAAAAAAAA"),
        1,
    )
    .await;
    require_publication(&mut conn, &target, &commit(&f, &target, 2))
        .await
        .unwrap();
    // A same-principal controller at another Station is another Actor.
    let mut other = owner(&f);
    other.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    sql_query(
        "UPDATE realm_authority_root_current_results SET controller_actor_id=$1 WHERE realm_id=$2",
    )
    .bind::<Jsonb, _>(json!(ActorId::account(other.clone())))
    .bind::<Text, _>(realm(&f).as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    require_publication(&mut conn, &target, &commit(&f, &target, 2))
        .await
        .unwrap();
    sql_query("UPDATE agent_action_approval_current_results SET controller_actor_key=$1 WHERE approved_event_id=$2")
        .bind::<Text,_>(ActorId::account(other).to_string()).bind::<Text,_>(target.event_id.as_str())
        .execute(&mut conn).await.unwrap();
    assert_required(require_publication(&mut conn, &target, &commit(&f, &target, 2)).await);
}

#[tokio::test]
async fn private_request_selection_holds_its_workflow_lock_until_transaction_end() {
    let f = Fixture::new().await;
    let pool = f.origin.pool.clone();
    let mut conn = pool.get().await.unwrap();
    seed(&f, &mut conn).await;
    let target = message(&f);
    request(&f, &pool, &target).await;
    install(
        &f,
        &mut conn,
        &approval(&f, &target, "approval-1", "AAAAAAAAAAAAAAAAAAAAAA"),
        1,
    )
    .await;
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    require_publication(&mut conn, &target, &commit(&f, &target, 2))
        .await
        .unwrap();
    let rejection_pool = pool.clone();
    let mut rejection = tokio::spawn(async move {
        let mut conn = rejection_pool.get().await.unwrap();
        sql_query("UPDATE agent_action_requests SET workflow_state='rejected',rejection_id='rejection-1' WHERE request_id='request-1'").execute(&mut conn).await.unwrap()
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut rejection)
            .await
            .is_err()
    );
    sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), rejection)
            .await
            .unwrap()
            .unwrap(),
        1
    );
    assert_required(require_publication(&mut conn, &target, &commit(&f, &target, 2)).await);
}

#[tokio::test]
async fn private_draft_confirmation_uses_consumed_encrypted_source_without_shared_proposal() {
    use diesel_async::AsyncConnection;
    let f = Fixture::new().await;
    let pool = f.origin.pool.clone();
    let mut conn = pool.get().await.unwrap();
    seed(&f, &mut conn).await;
    // The native Origin fixture already established the controller PCR.
    let handoff = json!({"scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1","recipients":[{
        "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000001",
        "recipient_hpke_key_digest":arkret_canonical::canonical_sha256(&"recipient key").unwrap(),
        "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
        "ciphertext_digest":arkret_canonical::canonical_sha256(&"ciphertext").unwrap()}]});
    let content_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&"draft content").unwrap())
            .unwrap();
    let proposal = event(
        &f,
        EventKind::AgentDraftPropose,
        &agent(&f),
        json!({
        "draft_id":"draft-only","agent_id":agent(&f).principal_id,"controller_account_id":owner(&f),
        "proposed_action":"ak.message.create","target":{"kind":"realm","realm_id":realm(&f)},
        "content_digest":content_digest,"content_handoff":handoff,
        "expires_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(120)),
        "created_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(1))}),
        1,
    );
    let submission = ActorPrivateEventSubmission {
        event: proposal.clone(),
        owner: owner(&f),
        producer_guard: None,
        accepted_at: proposal.created_at,
        canonical_event_digest: arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&proposal).unwrap(),
        )
        .to_vec(),
        effect: ActorPrivateEventEffect::AgentDraftPropose(
            coland_storage::AgentDraftPendingIntentCommit {
                record: coland_storage::AgentDraftPendingIntentRecord {
                    controller_account_id: owner(&f),
                    agent_id: agent(&f).principal_id,
                    draft_id: "draft-only".into(),
                    proposed_action: "ak.message.create".into(),
                    target: json!({"kind":"realm","realm_id":realm(&f)}),
                    content_digest,
                    content_handoff: Some(handoff),
                    canonical_event_digest: arkret_wire::Hash::new(
                        arkret_canonical::canonical_sha256(&proposal).unwrap(),
                    )
                    .unwrap(),
                    accepted_event_id: proposal.event_id.clone(),
                    expires_at: at(&f) + chrono::TimeDelta::seconds(120),
                    created_at: proposal.created_at,
                    state: coland_storage::AgentDraftPendingIntentState::Available,
                    consumption: None,
                    expired_at: None,
                },
            },
        ),
    };
    assert!(matches!(
        PgActorPrivateEventStore::new(pool.clone())
            .submit(&submission)
            .await
            .unwrap(),
        coland_storage::ActorPrivateEventSubmitResult::Accepted(_)
    ));
    let target = message(&f);
    let confirmed = event(
        &f,
        EventKind::AgentActionApprove,
        &owner(&f),
        json!({
        "approval_id":"draft-approval","draft_id":"draft-only","agent_id":agent(&f).principal_id,
        "proposed_action":"ak.message.create","target":{"kind":"realm","realm_id":realm(&f)},
        "approved_event_id":target.event_id,"approval_nonce":"BBBBBBBBBBBBBBBBBBBBBB",
        "expires_at":arkret_canonical::format_timestamp_canonical(at(&f)+chrono::TimeDelta::seconds(10))}),
        2,
    );
    install(&f, &mut conn, &confirmed, 1).await;
    assert_required(require_publication(&mut conn, &target, &commit(&f, &target, 2)).await);
    let key =
        arkret_models_collaboration::events_payloads::account_data::agent_draft_account_data_key(
            &agent(&f).principal_id,
            "draft-only",
        )
        .unwrap();
    let encrypted = json!({"schema":"ak.schema.account_data_encrypted_value.v1","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"});
    let account_data = event(
        &f,
        EventKind::AccountDataSet,
        &owner(&f),
        json!({"key":key,"expected_server_revision":0,
        "encrypted_payload":encrypted,"source_pending_event_id":proposal.event_id}),
        3,
    );
    let admission = coland_storage::ActorPrivateAccountDataAdmission {
        canonical_event_digest: arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&account_data).unwrap(),
        )
        .to_vec(),
        accepted_at: account_data.created_at,
        event: account_data.clone(),
        producer_guard: None,
        cas: coland_storage::AccountDataCasCommit {
            record: coland_storage::AccountDataRecord {
                actor: account_data.actor_id.to_string(),
                account_data_key: key.clone(),
                revision: 1,
                payload: encrypted,
                tombstone: false,
                updated_at: account_data.created_at,
            },
            expected_revision: 0,
            conflict_code: "cas_conflict".into(),
        },
    };
    conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
        crate::boxed_future(|| {
            crate::unit_of_work::admit_actor_private_account_data_in_connection(conn, &admission)
        })
        .await
        .map_err(Into::into)
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
    .unwrap();
    // The proposal stays exclusively in the actor-private ledger.
    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type=diesel::sql_types::BigInt)]
        count: i64,
    }
    let shared = sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(proposal.event_id.token_bytes().to_vec())
        .get_result::<Count>(&mut conn)
        .await
        .unwrap();
    assert_eq!(shared.count, 0);
    require_publication(&mut conn, &target, &commit(&f, &target, 2))
        .await
        .unwrap();
    let mut expired = commit(&f, &target, 2);
    expired.committed_at += chrono::TimeDelta::milliseconds(1);
    assert_required(require_publication(&mut conn, &target, &expired).await);
    sql_query("UPDATE account_datas SET tombstone=TRUE WHERE actor_id=$1 AND account_data_key=$2")
        .bind::<Text, _>(ActorId::account(owner(&f)).to_string())
        .bind::<Text, _>(key)
        .execute(&mut conn)
        .await
        .unwrap();
    assert_required(require_publication(&mut conn, &target, &commit(&f, &target, 2)).await);
}

// This test exercises audit transaction semantics using imported accepted
// history. Approval qualification and native signatures have separate cases.
#[tokio::test]
async fn approval_audit_merges_independent_consumers_only_in_the_accepting_transaction() {
    use arkret_wire::{
        ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
        ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId,
    };
    let f = Fixture::new().await;
    let pool = f.origin.pool.clone();
    let mut conn = crate::pg_conn(&pool).await.unwrap();
    seed(&f, &mut conn).await;
    let target = message(&f);
    let covering = commit(&f, &target, 1);
    history(&mut conn, &target, &covering).await;
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::RealmGovernance {},
            approval_target: ApprovalTarget::Event {
                event_id: target.event_id.clone(),
            },
            request_canonical_digest: arkret_canonical::canonical_sha256(&target)
                .unwrap()
                .parse()
                .unwrap(),
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: CapabilityActionId::MessageCreate,
            realm_id: target.realm_id.clone(),
            initiating_actor_id: target.actor_id.clone(),
            approver_did: "did:web:controller.example".parse().unwrap(),
            approved_at: covering.committed_at,
            nonce: "audit-independent-consumers-128-bit".to_owned(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: arkret_wire::DidUrl::new("did:web:controller.example#approval")
                .unwrap(),
            jws: "audit-input-already-qualified".to_owned(),
        },
    };
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [19; 32],
        signature.proof.verification_method.as_str(),
    );
    signature.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&signature)
            .unwrap(),
    );
    let method = coland_storage::ApprovalHistoricalMethod {
        signature,
        public_key: signer.verifying_key().to_bytes(),
        native_control: None,
        control_history: None,
    };
    let mut qualified = crate::approval_admission::QualifiedApproval {
        method,
        qualification_basis: json!({"gate":"grant"}),
    };
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    crate::approval_admission::consume_and_audit(
        &mut conn,
        &target,
        &covering,
        &[qualified.clone()],
        &json!({"consumer":"producer"}),
    )
    .await
    .unwrap();
    qualified.qualification_basis = json!({"gate":"governance"});
    crate::approval_admission::consume_and_audit(
        &mut conn,
        &target,
        &covering,
        &[qualified.clone()],
        &json!({"consumer":"writer"}),
    )
    .await
    .unwrap();
    let mut substituted = qualified.clone();
    substituted.method.public_key = [20; 32];
    let error = crate::approval_admission::consume_and_audit(
        &mut conn,
        &target,
        &covering,
        &[substituted],
        &json!({"consumer":"substituted"}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::ApprovalNonceReused)
    );
    #[derive(diesel::QueryableByName)]
    struct AuditBasis {
        #[diesel(sql_type=Jsonb)]
        value: serde_json::Value,
    }
    let row = sql_query(
        "SELECT accepted_basis AS value FROM event_approval_private_audit WHERE event_id=$1",
    )
    .bind::<Text, _>(target.event_id.as_str())
    .get_result::<AuditBasis>(&mut conn)
    .await
    .unwrap();
    assert_eq!(row.value["qualifications"].as_array().unwrap().len(), 2);
    sql_query("COMMIT").execute(&mut conn).await.unwrap();
    let error = crate::approval_admission::consume_and_audit(
        &mut conn,
        &target,
        &covering,
        &[qualified],
        &json!({"consumer":"later_transaction"}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::ApprovalNonceReused)
    );
    let later = sql_query(
        "SELECT accepted_basis AS value FROM event_approval_private_audit WHERE event_id=$1",
    )
    .bind::<Text, _>(target.event_id.as_str())
    .get_result::<AuditBasis>(&mut conn)
    .await
    .unwrap();
    assert_eq!(row.value, later.value);
}
