//! Real PG grant-local approvals, independent from List WIP and governance.
//! Register under strand_position_authority after the shared grant gate lands.
use arkret_wire::{
    ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
    ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId, Did, DidUrl, GrantId, Hash,
};

use super::*;

fn approver(
    seed: u8,
    station: &arkret_wire::DidCoreId,
) -> (arkret_wire::ActorId, Did, DidUrl, [u8; 32]) {
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], "fixture");
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let fixture = ordinary_realm::human_profile::fixture(station, &approval_account_label(seed));
    let actor = arkret_wire::ActorId::account(fixture.history.account);
    let did = fixture.history.did;
    let method = DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
    (actor, did, method, signer.verifying_key().to_bytes())
}
fn proofs(
    request: &coland_storage::EventCommitRequest,
    grant_id: &GrantId,
    seeds: &[u8],
    governance: bool,
) -> coland_storage::EventApprovalCommit {
    proofs_for_action(
        request,
        grant_id,
        seeds,
        governance,
        CapabilityActionId::StrandMove,
    )
}

fn proofs_for_action(
    request: &coland_storage::EventCommitRequest,
    grant_id: &GrantId,
    seeds: &[u8],
    governance: bool,
    action: CapabilityActionId,
) -> coland_storage::EventApprovalCommit {
    let event = &request.authority_commit.event;
    let station = &request.authority_commit.expected_authority.service_id;
    let digest = arkret_canonical::canonical_sha256(event).unwrap();
    let methods = seeds
        .iter()
        .map(|seed| {
            let (_, did, method, _) = approver(*seed, station);
            let signer =
                arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], method.as_str());
            let mut signature = ApprovalSignature {
                input: ApprovalSignatureInput {
                    approval_context: if governance {
                        ApprovalContext::RealmGovernance {}
                    } else {
                        ApprovalContext::Grant {
                            grant_id: grant_id.clone(),
                        }
                    },
                    approval_target: ApprovalTarget::Event {
                        event_id: event.event_id.clone(),
                    },
                    request_canonical_digest: Hash::new(digest.clone()).unwrap(),
                    operation: "ak.self.events.command.submit.v1".to_owned(),
                    action,
                    realm_id: event.realm_id.clone(),
                    initiating_actor_id: event.actor_id.clone(),
                    approver_did: did,
                    approved_at: request.authority_commit.commit.committed_at,
                    nonce: format!("grant-approval-nonce-128-bit-{seed}"),
                },
                proof: ApprovalSignatureProof {
                    kind: ApprovalSignatureProofKind::DetachedJws,
                    verification_method: method,
                    jws: String::new(),
                },
            };
            signature.proof.jws = signer.sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(
                    &signature,
                )
                .unwrap(),
            );
            native_approval_method(signature, *seed, station)
        })
        .collect();
    coland_storage::EventApprovalCommit {
        carrier_binding: None,
        management_current: None,
        event_id: event.event_id.clone(),
        event_digest: digest,
        committed_at: request.authority_commit.commit.committed_at,
        methods,
    }
}
fn batch(
    request: coland_storage::EventCommitRequest,
    proof: coland_storage::EventApprovalCommit,
) -> coland_storage::EventBatchCommitRequest {
    coland_storage::EventBatchCommitRequest {
        audit_unit: None,
        events: vec![request],
        franking_replay_nonce: None,
        realm_organization_proof: None,
        invite_claim_proof: None,
        event_approvals: Some(proof),
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

fn signed_age(
    mut proof: coland_storage::EventApprovalCommit,
    age: chrono::TimeDelta,
) -> coland_storage::EventApprovalCommit {
    for (method, seed) in proof.methods.iter_mut().zip([81, 82]) {
        method.signature.input.approved_at = proof.committed_at - age;
        let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
            [70; 32],
            method.signature.proof.verification_method.as_str(),
        );
        method.signature.proof.jws = signer.sign_detached_jws(
            &arkret_signatures::approval_signature::approval_signature_signing_bytes(
                &method.signature,
            )
            .unwrap(),
        );
        *method =
            native_approval_method(method.signature.clone(), seed, &ordinary_realm::station());
    }
    proof
}

struct GrantSetup {
    opened: ordinary_realm::Discussion,
    head: coland_storage::AuthorityCommitTransaction,
    board_id: arkret_wire::SpaceId,
    list_id: arkret_wire::SpaceId,
    grant_id: GrantId,
    command: coland_storage::EventCommitRequest,
}

async fn message_write_counts(pool: &PgPool, realm: &arkret_wire::RealmId) -> Vec<i64> {
    let mut counts = Vec::new();
    for table in [
        "canonical_events",
        "realm_commits",
        "message_revision_current_states",
        "event_approval_private_audit",
    ] {
        counts.push(count(pool, realm, table).await);
    }
    let mut conn = pool.get().await.unwrap();
    let outbox = diesel::sql_query("SELECT COUNT(*) AS count FROM federation_outbox")
        .get_result::<Count>(&mut conn)
        .await
        .unwrap();
    counts.push(outbox.count);
    counts
}

#[tokio::test]
async fn message_create_consumes_two_layers_atomically_and_preserves_nonce_on_failure() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let fixture_pool = pool.clone();
    let setup =
        tokio::spawn(async move { Box::new(Box::pin(prepare_grant_setup(&fixture_pool)).await) })
            .await
            .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { Box::pin(message_create_approval_transaction(pool, setup)).await });
    tasks.join_next().await.unwrap().unwrap();
}

async fn message_create_approval_transaction(pool: PgPool, setup: Box<GrantSetup>) {
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut head = setup.head;
    let realm = head.event.realm_id.clone();
    let actor = head.event.actor_id.clone();
    let at = setup.opened.committed_at() + chrono::TimeDelta::seconds(120);
    let target =
        arkret_wire::WireResourceSelector::strand(realm.clone(), setup.opened.strand_id.clone());
    let mut roster = Vec::new();
    for seed in [81, 82] {
        let (approver, ..) = approver(seed, &ordinary_realm::station());
        roster.push(approver.signing_principal_id().clone());
        let grant = Box::pin(ordinary_realm::source_request(&pool, next_request(
            &head, arkret_wire::EventKind::CapabilityGrant, &founder(),
            json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,
                "issuer_id":actor,"subject":approver,"actions":["ak.message.create"],"resources":[target],"constraints":[],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":setup.opened.unit.transactions[0].event.event_id,"authority_generation":"0"}],
                "issued_at":arkret_canonical::format_timestamp_canonical(at)}}), at,
        ))).await;
        uow.commit_event(grant.clone()).await.unwrap();
        head = grant.authority_commit;
    }
    let requirement = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head, arkret_wire::EventKind::CapabilityGrant, &founder(),
        json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":actor,"subject":actor,"actions":["ak.message.create"],"resources":[target],
            "constraints":[{"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review","approval_required":true,
                "approval_mode":"before_commit","approval_actor_ids":roster,"approval_threshold":"majority","timeout":"PT60S"}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":setup.opened.unit.transactions[0].event.event_id,"authority_generation":"0"}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)}}), at,
    ))).await;
    let grant_id = GrantId::from_event_id(&requirement.authority_commit.event.event_id);
    uow.commit_event(requirement.clone()).await.unwrap();
    head = requirement.authority_commit;
    let config = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head, arkret_wire::EventKind::PolicyAction, &founder(),
        json!({"action_id":"message_review","value":{"action":"ak.message.create","approval_required":true,"approval_quorum":2,"policy_scope":realm}}), at,
    ))).await;
    uow.commit_event(config.clone()).await.unwrap();
    head = config.authority_commit;
    let command = Box::pin(ordinary_realm::source_request(
        &pool,
        setup.opened.message_after(&head, "approved Message", at),
    ))
    .await;
    let proof = |request: &coland_storage::EventCommitRequest, seeds: &[u8], governance| {
        proofs_for_action(
            request,
            &grant_id,
            seeds,
            governance,
            CapabilityActionId::MessageCreate,
        )
    };
    let before = message_write_counts(&pool, &realm).await;
    assert_eq!(
        uow.commit_event(command.clone())
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ApprovalRequired)
    );
    for (seeds, governance) in [(vec![81], false), (vec![81, 82], true)] {
        let failure = uow
            .commit_event_batch(batch(command.clone(), proof(&command, &seeds, governance)))
            .await
            .unwrap_err();
        assert_eq!(
            failure.conflict_code(),
            Some(ConflictCode::ApprovalRequired),
            "{failure:?}"
        );
        assert!(!failure.to_string().contains("policy_id"));
        assert!(!failure.to_string().contains("action_id"));
        assert_eq!(message_write_counts(&pool, &realm).await, before);
    }
    let mut invalid = proof(&command, &[81, 82], false);
    invalid.methods[0]
        .signature
        .input
        .nonce
        .push_str("-tampered");
    assert_eq!(
        uow.commit_event_batch(batch(command.clone(), invalid))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::SignatureInvalid)
    );
    assert_eq!(message_write_counts(&pool, &realm).await, before);
    // Qualification succeeds before a real message business rule fails. Both
    // canonical admission and private nonces must roll back on this connection.
    let malformed_reply = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head, arkret_wire::EventKind::MessageCreate, &founder(),
        json!({"strand_id":setup.opened.strand_id,"track_name":"discussion","content":{"kind":"ak.content.text","body":"unavailable reply","format":"plain"},
            "reply_to_id":arkret_wire::MessageId::from_event_id(&head.event.event_id)}), at,
    ))).await;
    let failure = uow
        .commit_event_batch(batch(
            malformed_reply.clone(),
            proof(&malformed_reply, &[81, 82], false),
        ))
        .await
        .unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("Message reference has no accepted creating Event"),
        "{failure:?}"
    );
    assert_eq!(message_write_counts(&pool, &realm).await, before);
    let accepted = proof(&command, &[81, 82], false);
    let outcome = uow
        .commit_event_batch(batch(command.clone(), accepted.clone()))
        .await
        .unwrap();
    assert!(outcome.event_inserted);
    let after = message_write_counts(&pool, &realm).await;
    assert_eq!(after[0], before[0] + 1);
    assert_eq!(after[1], before[1] + 1);
    assert_eq!(after[2], before[2] + 1);
    assert_eq!(after[3], before[3] + 2);
    let replay = uow
        .commit_event_batch(batch(command.clone(), accepted))
        .await
        .unwrap();
    assert!(!replay.event_inserted);
    assert_eq!(message_write_counts(&pool, &realm).await, after);
    let reused = Box::pin(ordinary_realm::source_request(
        &pool,
        setup
            .opened
            .message_after(&command.authority_commit, "reused approval nonce", at),
    ))
    .await;
    assert_eq!(
        uow.commit_event_batch(batch(reused.clone(), proof(&reused, &[81, 82], false)))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ApprovalNonceReused)
    );
    assert_eq!(message_write_counts(&pool, &realm).await, after);
}

async fn prepare_grant_setup(pool: &PgPool) -> GrantSetup {
    let opened = Box::pin(open_discussion(&pool, "grant-approval-roster")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut head = opened.head.authority_commit.clone();
    let realm = head.event.realm_id.clone();
    let actor = head.event.actor_id.clone();
    let at = head.commit.committed_at;
    let board = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &head,
            arkret_wire::EventKind::SpaceCreate,
            &founder(),
            space_payload(&realm, &actor, at, "board", "Grant review", None, json!({})),
            at,
        ),
    ))
    .await;
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    head = board.authority_commit;
    let list = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &head,
            arkret_wire::EventKind::SpaceCreate,
            &founder(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "Destination",
                Some(&board_id),
                json!({}),
            ),
            at,
        ),
    ))
    .await;
    let list_id = arkret_wire::SpaceId::from_event_id(&list.authority_commit.event.event_id);
    uow.commit_event(list.clone()).await.unwrap();
    head = list.authority_commit;
    let target = arkret_wire::WireResourceSelector::strand(realm.clone(), opened.strand_id.clone());
    let mut roster = Vec::new();
    for seed in [81, 82] {
        Box::pin(ordinary_realm::human_profile::admit(
            &pool,
            &ordinary_realm::station(),
            &approval_account_label(seed),
        ))
        .await;
        let (approver, ..) = approver(seed, &head.expected_authority.service_id);
        roster.push(approver.signing_principal_id().clone());
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO member_state_current_states(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join',$3,$4,'{\"membership\":\"join\"}'::jsonb,$5)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(approver.to_string()).bind::<Text,_>(head.commit.commit_id.as_str())
            .bind::<BigInt,_>(head.commit.stream_position as i64).bind::<diesel::sql_types::Timestamptz,_>(at).execute(&mut conn).await.unwrap();
        drop(conn);
        let grant = Box::pin(ordinary_realm::source_request(&pool, next_request(
            &head,
            arkret_wire::EventKind::CapabilityGrant,
            &founder(),
            json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":actor,"subject":approver,"actions":["ak.strand.move"],"resources":[target],"constraints":[],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":opened.unit.transactions[0].event.event_id,"authority_generation":"0"}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
            at,
        ))).await;
        uow.commit_event(grant.clone()).await.unwrap();
        head = grant.authority_commit;
    }
    let requirement = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head,
        arkret_wire::EventKind::CapabilityGrant,
        &founder(),
        json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,
        "issuer_id":actor,"subject":actor,"actions":["ak.strand.move"],"resources":[target],
        "constraints":[{"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"require_review","approval_required":true,"approval_mode":"before_commit","approval_actor_ids":roster,"approval_threshold":"majority","timeout":"PT60S"},
            {"constraint_kind":"temporal","effect":"allow","not_before":arkret_canonical::format_timestamp_canonical(at+chrono::TimeDelta::seconds(10))}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":opened.unit.transactions[0].event.event_id,"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    ))).await;
    let grant_id = GrantId::from_event_id(&requirement.authority_commit.event.event_id);
    uow.commit_event(requirement.clone()).await.unwrap();
    head = requirement.authority_commit;
    // Independent governance rows tighten the same operation. A false row's
    // large quorum never overrides true rows, and a narrower scope does not
    // override the Realm requirement. Grant-context evidence may count for both
    // layers only because this grant is an actual satisfied dependency.
    for (id, required, quorum, scope) in [
        ("realm_move_review", true, 2, realm.to_string()),
        ("disabled_review", false, 99, realm.to_string()),
        ("destination_review", true, 1, list_id.to_string()),
    ] {
        let config = Box::pin(ordinary_realm::source_request(
            &pool,
            next_request(
                &head,
                arkret_wire::EventKind::PolicyAction,
                &founder(),
                json!({
            "action_id":id,"value":{"action":"ak.strand.move","approval_required":required,
                "approval_quorum":quorum,"policy_scope":scope}}),
                at,
            ),
        ))
        .await;
        uow.commit_event(config.clone()).await.unwrap();
        head = config.authority_commit;
    }
    let command_at = at + chrono::TimeDelta::seconds(120);
    let command = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,"target_space_id":list_id,"rank":"a"}),
        command_at,
    ))).await;
    GrantSetup {
        opened,
        head,
        board_id,
        list_id,
        grant_id,
        command,
    }
}

#[tokio::test]
async fn grant_approval_roster_does_not_use_received_votes_as_the_threshold_denominator() {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let fixture_pool = pool.clone();
    let setup =
        tokio::spawn(async move { Box::new(Box::pin(prepare_grant_setup(&fixture_pool)).await) })
            .await
            .unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { Box::pin(grant_approval_roster_transaction(pool, setup)).await });
    tasks.join_next().await.unwrap().unwrap();
}

async fn grant_approval_roster_transaction(pool: PgPool, setup: Box<GrantSetup>) {
    let opened = &setup.opened;
    let head = &setup.head;
    let board_id = setup.board_id.clone();
    let list_id = setup.list_id.clone();
    let grant_id = setup.grant_id.clone();
    let command = setup.command.clone();
    let realm = head.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let command_at = at + chrono::TimeDelta::seconds(120);
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    for (seeds, governance) in [(vec![81], false), (vec![81, 82], true)] {
        let failure = uow
            .commit_event_batch(batch(
                command.clone(),
                proofs(&command, &grant_id, &seeds, governance),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            failure.conflict_code(),
            Some(ConflictCode::ApprovalRequired),
            "unexpected grant-vote failure: {failure:?}"
        );
        assert_eq!(
            before,
            (
                count(&pool, &realm, "canonical_events").await,
                count(&pool, &realm, "realm_commits").await
            )
        );
        assert_eq!(
            count(&pool, &realm, "event_approval_private_audit").await,
            0
        );
        assert!(!failure.to_string().contains("policy_id"));
        assert!(!failure.to_string().contains("action_id"));
    }
    // These signatures are inside the timeout but precede respectively issued_at
    // and the temporal not_before. Neither failure consumes their nonces.
    let early = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,"target_space_id":list_id,"rank":"a"}),
        at + chrono::TimeDelta::seconds(30),
    ))).await;
    for age in [
        chrono::TimeDelta::seconds(31),
        chrono::TimeDelta::seconds(25),
    ] {
        let proof = signed_age(proofs(&early, &grant_id, &[81, 82], false), age);
        let failure = uow
            .commit_event_batch(batch(early.clone(), proof))
            .await
            .unwrap_err();
        assert_eq!(
            failure.conflict_code(),
            Some(ConflictCode::ApprovalRequired),
            "{failure:?}"
        );
        assert_eq!(
            before,
            (
                count(&pool, &realm, "canonical_events").await,
                count(&pool, &realm, "realm_commits").await
            )
        );
        assert_eq!(
            count(&pool, &realm, "event_approval_private_audit").await,
            0
        );
    }
    // Two genuine signatures older than the grant's signed-time deadline do not
    // consume either nonce. The same nonces can then bind fresh valid evidence.
    let expired = signed_age(
        proofs(&command, &grant_id, &[81, 82], false),
        chrono::TimeDelta::seconds(61),
    );
    assert_eq!(
        uow.commit_event_batch(batch(command.clone(), expired))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ApprovalRequired)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        0
    );
    let proof = signed_age(
        proofs(&command, &grant_id, &[81, 82], false),
        chrono::TimeDelta::seconds(60),
    );
    uow.commit_event_batch(batch(command.clone(), proof.clone()))
        .await
        .unwrap();
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        2
    );
    uow.commit_event_batch(batch(command.clone(), proof))
        .await
        .unwrap();
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        2
    );
    assert_eq!(
        position(&pool, &board_id, &opened.strand_id).await.value,
        json!({"list_space_id":list_id,"rank":"a"})
    );
    let reused = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &command.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,"target_space_id":list_id,"rank":"b",
            "expected_position":{"list_space_id":list_id,"rank":"a"}}),
        command_at,
    ))).await;
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    let proof = proofs(&reused, &grant_id, &[81, 82], false);
    assert_eq!(
        uow.commit_event_batch(batch(reused, proof))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ApprovalNonceReused)
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        2
    );
    assert_eq!(
        position(&pool, &board_id, &opened.strand_id).await.value,
        json!({"list_space_id":list_id,"rank":"a"})
    );
}

// Ordinary and authored-target writers must consume the same typed evidence.
#[tokio::test]
async fn reaction_approval_consumes_both_layers_and_rolls_back_missing_target() {
    Box::pin(ordinary_writer_approval_transaction(
        arkret_wire::EventKind::ReactionAdd,
        CapabilityActionId::ReactionAdd,
        false,
    ))
    .await;
}
#[tokio::test]
async fn message_revise_approval_consumes_both_layers_and_exact_retry() {
    Box::pin(ordinary_writer_approval_transaction(
        arkret_wire::EventKind::MessageRevise,
        CapabilityActionId::MessageRevise,
        false,
    ))
    .await;
}
#[tokio::test]
async fn message_redact_approval_consumes_both_layers_and_exact_retry() {
    Box::pin(ordinary_writer_approval_transaction(
        arkret_wire::EventKind::MessageRedact,
        CapabilityActionId::MessageRedact,
        false,
    ))
    .await;
}

fn ordinary_command_payload(
    kind: arkret_wire::EventKind,
    message: &arkret_wire::MessageId,
    realm: &arkret_wire::RealmId,
    strand: &arkret_wire::StrandId,
) -> Value {
    match kind {
        arkret_wire::EventKind::ReactionAdd => json!({"target_ref":message,"key":"+1"}),
        arkret_wire::EventKind::MessageRevise => {
            json!({"message_id":message,"content":{"kind":"ak.content.text","body":"approved edit","format":"plain"}})
        }
        arkret_wire::EventKind::MessageRedact => json!({"message_id":message}),
        arkret_wire::EventKind::RealmSetDefaultStrand => {
            json!({"realm_id":realm,"strand_id":strand,"expected_default_strand_id":strand})
        }
        arkret_wire::EventKind::RealmArchive | arkret_wire::EventKind::RealmRestore => json!({}),
        _ => unreachable!(),
    }
}

async fn ordinary_writer_counts(pool: &PgPool, realm: &arkret_wire::RealmId) -> Vec<i64> {
    let mut values = message_write_counts(pool, realm).await;
    for table in [
        "message_reactions_current_states",
        "object_redaction_current_states",
    ] {
        values.push(count(pool, realm, table).await);
    }
    values
}

async fn ordinary_writer_approval_transaction(
    kind: arkret_wire::EventKind,
    action: CapabilityActionId,
    alternative: bool,
) {
    let db = TestDatabase::lease().await;
    let pool = db.pool();
    let fixture_pool = pool.clone();
    let setup =
        tokio::spawn(async move { Box::new(Box::pin(prepare_grant_setup(&fixture_pool)).await) })
            .await
            .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let message = Box::pin(ordinary_realm::source_request(
        &pool,
        setup.opened.message_after(
            &setup.head,
            "ordinary approval target",
            setup.opened.committed_at(),
        ),
    ))
    .await;
    uow.commit_event(message.clone()).await.unwrap();
    let message_id =
        arkret_wire::MessageId::from_event_id(&message.authority_commit.event.event_id);
    let mut head = message.authority_commit;
    let realm = head.event.realm_id.clone();
    let actor = head.event.actor_id.clone();
    let at = setup.opened.committed_at() + chrono::TimeDelta::seconds(120);

    let scoped = matches!(
        kind,
        arkret_wire::EventKind::ReactionAdd
            | arkret_wire::EventKind::MessageRevise
            | arkret_wire::EventKind::MessageRedact
    );
    let target = if scoped {
        arkret_wire::WireResourceSelector::strand(realm.clone(), setup.opened.strand_id.clone())
    } else {
        arkret_wire::WireResourceSelector::realm(realm.clone())
    };

    let mut roster = Vec::new();
    for seed in [81, 82] {
        let (approver, ..) = approver(seed, &ordinary_realm::station());
        roster.push(approver.signing_principal_id().clone());
        let grant = Box::pin(ordinary_realm::source_request(&pool, next_request(
            &head, arkret_wire::EventKind::CapabilityGrant, &founder(),
            json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,
                "issuer_id":actor,"subject":approver,"actions":[action.as_str()],"resources":[target],"constraints":[],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":setup.opened.unit.transactions[0].event.event_id,"authority_generation":"0"}],
                "issued_at":arkret_canonical::format_timestamp_canonical(at)}}), at,
        ))).await;
        uow.commit_event(grant.clone()).await.unwrap();
        head = grant.authority_commit;
    }
    let requirement = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head, arkret_wire::EventKind::CapabilityGrant, &founder(),
        json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,
            "issuer_id":actor,"subject":actor,"actions":[action.as_str()],"resources":[target],
            "constraints":[{"constraint_kind":"claim_based","constraint_subkind":"approval","effect":if alternative { "allow" } else { "require_review" },"approval_required":true,
                "approval_mode":"before_commit","approval_actor_ids":roster,"approval_threshold":if scoped { json!(1) } else { json!("majority") },"timeout":"PT60S"}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":setup.opened.unit.transactions[0].event.event_id,"authority_generation":"0"}],
            "issued_at":arkret_canonical::format_timestamp_canonical(at)}}), at,
    ))).await;
    let grant_id = GrantId::from_event_id(&requirement.authority_commit.event.event_id);
    uow.commit_event(requirement.clone()).await.unwrap();
    head = requirement.authority_commit;
    let config = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &head, arkret_wire::EventKind::PolicyAction, &founder(),
        json!({"action_id":"ordinary_event_review","value":{"action":action.as_str(),"approval_required":!alternative,"approval_quorum":2,"policy_scope":if scoped { json!(setup.opened.strand_id) } else { json!(realm) }}}), at,
    ))).await;
    uow.commit_event(config.clone()).await.unwrap();
    head = config.authority_commit;

    let command = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &head,
            kind.clone(),
            &founder(),
            ordinary_command_payload(kind.clone(), &message_id, &realm, &setup.opened.strand_id),
            at,
        ),
    ))
    .await;
    let proof = |request: &coland_storage::EventCommitRequest, seeds: &[u8], governance| {
        proofs_for_action(request, &grant_id, seeds, governance, action)
    };
    let before = ordinary_writer_counts(&pool, &realm).await;
    if alternative {
        let accepted = uow.commit_event(command).await.unwrap();
        assert!(accepted.event_inserted);
        assert_eq!(
            count(&pool, &realm, "event_approval_private_audit").await,
            before[3]
        );
        return;
    }
    let missing = uow.commit_event(command.clone()).await.unwrap_err();
    assert_eq!(
        missing.conflict_code(),
        Some(ConflictCode::ApprovalRequired),
        "{missing:?}"
    );
    for (seeds, governance) in [(vec![81], false), (vec![81, 82], true)] {
        let failure = uow
            .commit_event_batch(batch(command.clone(), proof(&command, &seeds, governance)))
            .await
            .unwrap_err();
        assert_eq!(
            failure.conflict_code(),
            Some(ConflictCode::ApprovalRequired),
            "{failure:?}"
        );
        assert_eq!(ordinary_writer_counts(&pool, &realm).await, before);
    }
    if kind != arkret_wire::EventKind::RealmArchive {
        let absent = arkret_wire::MessageId::from_event_id(&head.event.event_id);

        let mut bad_payload = ordinary_command_payload(
            kind.clone(),
            &absent,
            &realm,
            &arkret_wire::StrandId::from_event_id(&head.event.event_id),
        );
        if kind == arkret_wire::EventKind::RealmSetDefaultStrand {
            bad_payload["expected_default_strand_id"] = json!(setup.opened.strand_id);
        }
        let bad_target = Box::pin(ordinary_realm::source_request(
            &pool,
            next_request(&head, kind.clone(), &founder(), bad_payload, at),
        ))
        .await;
        let failure = uow
            .commit_event_batch(batch(
                bad_target.clone(),
                proof(&bad_target, &[81, 82], false),
            ))
            .await
            .unwrap_err();
        assert_ne!(
            failure.conflict_code(),
            Some(ConflictCode::ApprovalRequired),
            "{failure:?}"
        );
        assert_eq!(ordinary_writer_counts(&pool, &realm).await, before);
    }
    let approved = batch(command.clone(), proof(&command, &[81, 82], false));
    let (first, retry) = tokio::join!(
        uow.commit_event_batch(approved.clone()),
        uow.commit_event_batch(approved)
    );
    assert_ne!(first.unwrap().event_inserted, retry.unwrap().event_inserted);
    let after = ordinary_writer_counts(&pool, &realm).await;
    assert_eq!(after[0], before[0] + 1);
    assert_eq!(after[1], before[1] + 1);
    assert_eq!(after[3], before[3] + 2);
    let replay = uow.commit_event(command.clone()).await.unwrap();
    assert!(!replay.event_inserted);
    assert_eq!(ordinary_writer_counts(&pool, &realm).await, after);
    let reused = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &command.authority_commit,
            if kind == arkret_wire::EventKind::RealmArchive {
                arkret_wire::EventKind::RealmRestore
            } else {
                kind.clone()
            },
            &founder(),
            ordinary_command_payload(kind.clone(), &message_id, &realm, &setup.opened.strand_id),
            at + chrono::TimeDelta::seconds(1),
        ),
    ))
    .await;
    let failure = uow
        .commit_event_batch(batch(reused.clone(), proof(&reused, &[81, 82], false)))
        .await
        .unwrap_err();
    assert_eq!(
        failure.conflict_code(),
        Some(ConflictCode::ApprovalNonceReused),
        "{failure:?}"
    );
    assert_eq!(ordinary_writer_counts(&pool, &realm).await, after);
}

#[tokio::test]
async fn an_unproved_allow_approval_does_not_block_an_independent_owner_path() {
    Box::pin(ordinary_writer_approval_transaction(
        arkret_wire::EventKind::ReactionAdd,
        CapabilityActionId::ReactionAdd,
        true,
    ))
    .await;
}

#[tokio::test]
async fn default_strand_pointer_consumes_both_layers_and_rolls_back_bad_target() {
    Box::pin(ordinary_writer_approval_transaction(
        arkret_wire::EventKind::RealmSetDefaultStrand,
        CapabilityActionId::RealmSetDefaultStrand,
        false,
    ))
    .await;
}

#[tokio::test]
async fn realm_archive_and_restore_consume_exact_action_approvals() {
    Box::pin(ordinary_writer_approval_transaction(
        arkret_wire::EventKind::RealmArchive,
        CapabilityActionId::RealmArchive,
        false,
    ))
    .await;
}
