//! Imported accepted Realm history isolates confirmation consumption. Private
//! requests use the real PG effect writer; producer/HTTP admission is separate.
use coland_storage::{
    ActorPrivateEventEffect, ActorPrivateEventStore, ActorPrivateEventSubmission,
};
use diesel::sql_types::Binary;
use serde_json::json;

use super::*;
use crate::test_database::TestDatabase;
use crate::{PgActorPrivateEventStore, PgPool};

fn account(principal: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        principal.parse().unwrap(),
        "ak:did_core:web:station.example".parse().unwrap(),
    )
}
fn owner() -> arkret_wire::AccountId {
    account("ak:did_core:web:controller.example")
}
fn agent() -> arkret_wire::AccountId {
    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]).verifying_key();
    account(&format!(
        "ak:did_core:webvh:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.as_bytes())
    ))
}
fn at() -> chrono::DateTime<chrono::Utc> {
    "2026-10-11T00:00:00.000Z".parse().unwrap()
}
fn realm() -> arkret_wire::RealmId {
    arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [21; 32],
    ))
}
fn event(
    kind: EventKind,
    actor: &arkret_wire::AccountId,
    payload: serde_json::Value,
    offset: i64,
) -> Event {
    let event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        arkret_wire::ScopeRef::Realm { realm_id: realm() },
        actor.principal_id.clone(),
        actor.station_id.clone(),
        payload,
        at() + chrono::TimeDelta::seconds(offset),
    )
    .unwrap();
    let created_at = event.created_at;
    signed(event, actor, created_at)
}

fn signed(
    mut event: Event,
    actor: &arkret_wire::AccountId,
    proof_at: chrono::DateTime<chrono::Utc>,
) -> Event {
    event.producer_proof = None;
    let seed = if actor == &agent() { 17 } else { 19 };
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [seed; 32],
        if actor == &agent() {
            format!(
                "did:webvh:{}:agent.example#key",
                actor
                    .principal_id
                    .as_str()
                    .strip_prefix("ak:did_core:webvh:")
                    .unwrap()
            )
        } else {
            format!(
                "{}#key",
                actor
                    .principal_id
                    .as_str()
                    .replacen("ak:did_core:", "did:", 1)
            )
        },
    );
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
fn commit(event: &Event, position: u64) -> RealmCommit {
    RealmCommit {
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
    }
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
async fn seed(conn: &mut AsyncPgConnection) {
    sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,'ak:did_core:web:station.example','{}')")
        .bind::<Text,_>(realm().as_str()).execute(&mut *conn).await.unwrap();
    let genesis = event(EventKind::RealmCreate, &owner(), json!({}), 0);
    let source = commit(&genesis, 0);
    history(conn, &genesis, &source).await;
    sql_query("INSERT INTO agent_principals(id,controller_principal_id,principal_control_realm_id,controller_authorization_ref,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$5)")
        .bind::<Text,_>(agent().principal_id.as_str()).bind::<Text,_>(owner().principal_id.as_str()).bind::<Text,_>(realm().as_str())
        .bind::<Text,_>(format!("did:webvh:{}:agent.example#managed-controller",agent().principal_id.as_str().strip_prefix("ak:did_core:webvh:").unwrap()))
        .bind::<Timestamptz,_>(at()).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO realm_authority_root_current_results(realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) VALUES($1,$2,0,0,$3,$4,0,$5)")
        .bind::<Text,_>(realm().as_str()).bind::<Jsonb,_>(json!(ActorId::account(owner()))).bind::<Text,_>(genesis.event_id.as_str()).bind::<Text,_>(source.commit_id.as_str()).bind::<Timestamptz,_>(at()).execute(&mut *conn).await.unwrap();
    sql_query("INSERT INTO agent_status_current_results(realm_id,current_key,agent_id,actor_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,'fixture-agent',$2,$3,$4,0,'\"active\"',$5)")
        .bind::<Text,_>(realm().as_str()).bind::<Text,_>(agent().principal_id.as_str()).bind::<Jsonb,_>(json!(ActorId::account(agent()))).bind::<Text,_>(source.commit_id.as_str()).bind::<Timestamptz,_>(at()).execute(&mut *conn).await.unwrap();
}
fn message() -> Event {
    event(
        EventKind::MessageCreate,
        &agent(),
        json!({"strand_id":arkret_wire::StrandId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[31;32])),"track_name":"discussion","content":{"kind":"ak.content.text","format":"plain","body":"requested publication"}}),
        10,
    )
}
async fn request(pool: &PgPool, target: &Event) {
    let action = if target.kind == EventKind::AgentKeyRevoke {
        "ak.agent.key.revoke"
    } else {
        "ak.message.create"
    };
    let payload = json!({"request_id":"request-1","agent_id":agent().principal_id,"controller_account_id":owner(),"proposed_action":action,
        "target":{"kind":"realm","realm_id":realm()},"request_canonical_digest":arkret_canonical::canonical_sha256(target).unwrap(),
        "expires_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(120)),"created_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(1))});
    let source = event(EventKind::AgentActionRequest, &agent(), payload.clone(), 1);
    let submission = ActorPrivateEventSubmission {
        canonical_event_digest: arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&source).unwrap(),
        )
        .to_vec(),
        accepted_at: source.created_at,
        event: source,
        owner: owner(),
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
fn approval(target: &Event, id: &str, nonce: &str) -> Event {
    let action = if target.kind == EventKind::AgentKeyRevoke {
        "ak.agent.key.revoke"
    } else {
        "ak.message.create"
    };
    event(
        EventKind::AgentActionApprove,
        &owner(),
        json!({"approval_id":id,"request_id":"request-1","agent_id":agent().principal_id,"proposed_action":action,
        "target":{"kind":"realm","realm_id":realm()},"approved_event_id":target.event_id,"approval_nonce":nonce,
        "expires_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(10))}),
        2,
    )
}
async fn install(conn: &mut AsyncPgConnection, confirmation: &Event, position: u64) {
    let source = commit(confirmation, position);
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
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = pool.get().await.unwrap();
    seed(&mut conn).await;
    let target = message();
    let mut covering = commit(&target, 2);
    // An ordinary Agent write and an ordinary delegated write have no private
    // selection and do not acquire an unsolicited confirmation obligation.
    require_publication(&mut conn, &target, &covering)
        .await
        .unwrap();
    let mut delegated = target.clone();
    delegated.actor_id = ActorId::account(owner());
    delegated.executed_by = Some(ActorId::account(agent()));
    delegated.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(
            event(EventKind::RealmCreate, &owner(), json!({}), 0)
                .event_id
                .to_string(),
        )
        .unwrap(),
    );
    let delegated = signed(delegated, &agent(), target.created_at);
    require_publication(&mut conn, &delegated, &covering)
        .await
        .unwrap();
    request(&pool, &target).await;
    assert_required(require_publication(&mut conn, &target, &covering).await);
    let mut wrong = approval(&target, "approval-wrong", "BBBBBBBBBBBBBBBBBBBBBB");
    wrong
        .payload
        .insert("request_id".into(), json!("another-request"));
    let wrong = signed(wrong, &owner(), at() + chrono::TimeDelta::seconds(2));
    install(&mut conn, &wrong, 1).await;
    assert_required(require_publication(&mut conn, &target, &covering).await);
    let confirmed = approval(&target, "approval-1", "AAAAAAAAAAAAAAAAAAAAAA");
    install(&mut conn, &confirmed, 2).await;
    // The publication created_at is irrelevant. Equality at expires_at admits.
    covering.committed_at = at() + chrono::TimeDelta::seconds(10);
    require_publication(&mut conn, &target, &covering)
        .await
        .unwrap();
    covering.committed_at += chrono::TimeDelta::milliseconds(1);
    assert_required(require_publication(&mut conn, &target, &covering).await);
    covering.committed_at = at() + chrono::TimeDelta::seconds(10);
    let changed = signed(
        target.clone(),
        &agent(),
        at() + chrono::TimeDelta::seconds(11),
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
    let reused = approval(&target, "approval-2", "AAAAAAAAAAAAAAAAAAAAAA");
    assert!(
        commit_confirmation(&mut conn, &reused, &commit(&reused, 2))
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
    let foreign = signed(foreign, &owner(), at() + chrono::TimeDelta::seconds(2));
    assert!(
        commit_confirmation(&mut conn, &foreign, &commit(&foreign, 1))
            .await
            .unwrap_err()
            .to_string()
            .contains("nonce has already been allocated")
    );
    let mut expired = commit(&confirmed, 3);
    expired.committed_at =
        at() + chrono::TimeDelta::seconds(10) + chrono::TimeDelta::milliseconds(1);
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
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = pool.get().await.unwrap();
    seed(&mut conn).await;
    let mut target = event(
        EventKind::AgentKeyRevoke,
        &agent(),
        json!({"agent_id":agent().principal_id,"key_id":"runtime-key","revoked_by":owner().principal_id,
            "revoked_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(10))}),
        10,
    );
    target.executed_by = Some(ActorId::account(owner()));
    target.authorization_ref = Some(
        arkret_wire::AuthorizationRef::new(format!(
            "did:webvh:{}:agent.example#managed-controller",
            agent()
                .principal_id
                .as_str()
                .strip_prefix("ak:did_core:webvh:")
                .unwrap()
        ))
        .unwrap(),
    );
    let target = signed(target, &owner(), at() + chrono::TimeDelta::seconds(10));
    target
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    request(&pool, &target).await;
    assert_required(require_publication(&mut conn, &target, &commit(&target, 2)).await);
    install(
        &mut conn,
        &approval(&target, "approval-1", "AAAAAAAAAAAAAAAAAAAAAA"),
        1,
    )
    .await;
    require_publication(&mut conn, &target, &commit(&target, 2))
        .await
        .unwrap();
    // A same-principal controller at another Station is another Actor.
    let mut other = owner();
    other.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    sql_query(
        "UPDATE realm_authority_root_current_results SET controller_actor_id=$1 WHERE realm_id=$2",
    )
    .bind::<Jsonb, _>(json!(ActorId::account(other)))
    .bind::<Text, _>(realm().as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert_required(require_publication(&mut conn, &target, &commit(&target, 2)).await);
}

#[tokio::test]
async fn private_request_selection_holds_its_workflow_lock_until_transaction_end() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = pool.get().await.unwrap();
    seed(&mut conn).await;
    let target = message();
    request(&pool, &target).await;
    install(
        &mut conn,
        &approval(&target, "approval-1", "AAAAAAAAAAAAAAAAAAAAAA"),
        1,
    )
    .await;
    sql_query("BEGIN").execute(&mut conn).await.unwrap();
    require_publication(&mut conn, &target, &commit(&target, 2))
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
    assert_required(require_publication(&mut conn, &target, &commit(&target, 2)).await);
}

#[tokio::test]
async fn private_draft_confirmation_uses_consumed_encrypted_source_without_shared_proposal() {
    use diesel_async::AsyncConnection;
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = pool.get().await.unwrap();
    seed(&mut conn).await;
    sql_query("INSERT INTO principal_resolutions(principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) VALUES($1,$2,$3,'fixture-genesis','fixture-current','{}', $4)")
        .bind::<Text,_>(owner().principal_id.as_str()).bind::<Text,_>(owner().station_id.as_str())
        .bind::<Text,_>(realm().as_str()).bind::<Timestamptz,_>(at()).execute(&mut conn).await.unwrap();
    let handoff = json!({"scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1","recipients":[{
        "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000001",
        "recipient_hpke_key_digest":arkret_canonical::canonical_sha256(&"recipient key").unwrap(),
        "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
        "ciphertext_digest":arkret_canonical::canonical_sha256(&"ciphertext").unwrap()}]});
    let content_digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&"draft content").unwrap())
            .unwrap();
    let proposal = event(
        EventKind::AgentDraftPropose,
        &agent(),
        json!({
        "draft_id":"draft-only","agent_id":agent().principal_id,"controller_account_id":owner(),
        "proposed_action":"ak.message.create","target":{"kind":"realm","realm_id":realm()},
        "content_digest":content_digest,"content_handoff":handoff,
        "expires_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(120)),
        "created_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(1))}),
        1,
    );
    let submission = ActorPrivateEventSubmission {
        event: proposal.clone(),
        owner: owner(),
        producer_guard: None,
        accepted_at: proposal.created_at,
        canonical_event_digest: arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&proposal).unwrap(),
        )
        .to_vec(),
        effect: ActorPrivateEventEffect::AgentDraftPropose(
            coland_storage::AgentDraftPendingIntentCommit {
                record: coland_storage::AgentDraftPendingIntentRecord {
                    controller_account_id: owner(),
                    agent_id: agent().principal_id,
                    draft_id: "draft-only".into(),
                    proposed_action: "ak.message.create".into(),
                    target: json!({"kind":"realm","realm_id":realm()}),
                    content_digest,
                    content_handoff: Some(handoff),
                    canonical_event_digest: arkret_wire::Hash::new(
                        arkret_canonical::canonical_sha256(&proposal).unwrap(),
                    )
                    .unwrap(),
                    accepted_event_id: proposal.event_id.clone(),
                    expires_at: at() + chrono::TimeDelta::seconds(120),
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
    let target = message();
    let confirmed = event(
        EventKind::AgentActionApprove,
        &owner(),
        json!({
        "approval_id":"draft-approval","draft_id":"draft-only","agent_id":agent().principal_id,
        "proposed_action":"ak.message.create","target":{"kind":"realm","realm_id":realm()},
        "approved_event_id":target.event_id,"approval_nonce":"BBBBBBBBBBBBBBBBBBBBBB",
        "expires_at":arkret_canonical::format_timestamp_canonical(at()+chrono::TimeDelta::seconds(10))}),
        2,
    );
    install(&mut conn, &confirmed, 1).await;
    assert_required(require_publication(&mut conn, &target, &commit(&target, 2)).await);
    let key =
        arkret_models_collaboration::events_payloads::account_data::agent_draft_account_data_key(
            &agent().principal_id,
            "draft-only",
        )
        .unwrap();
    let encrypted = json!({"schema":"ak.schema.account_data_encrypted_value.v1","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"});
    let account_data = event(
        EventKind::AccountDataSet,
        &owner(),
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
    require_publication(&mut conn, &target, &commit(&target, 2))
        .await
        .unwrap();
    let mut expired = commit(&target, 2);
    expired.committed_at += chrono::TimeDelta::milliseconds(1);
    assert_required(require_publication(&mut conn, &target, &expired).await);
    sql_query("UPDATE account_datas SET tombstone=TRUE WHERE actor_id=$1 AND account_data_key=$2")
        .bind::<Text, _>(ActorId::account(owner()).to_string())
        .bind::<Text, _>(key)
        .execute(&mut conn)
        .await
        .unwrap();
    assert_required(require_publication(&mut conn, &target, &commit(&target, 2)).await);
}

// This test exercises audit transaction semantics using imported accepted
// history. Approval qualification and native signatures have separate cases.
#[tokio::test]
async fn approval_audit_merges_independent_consumers_only_in_the_accepting_transaction() {
    use arkret_wire::{
        ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
        ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId,
    };
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = crate::pg_conn(&pool).await.unwrap();
    seed(&mut conn).await;
    let target = message();
    let covering = commit(&target, 1);
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
