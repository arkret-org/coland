//! Included by strand_position_authority for its accepted Board/List harness.
use arkret_wire::{
    ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
    ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId, CurrentRevision, Did, DidUrl,
    Hash,
};

use super::*;

fn vote(
    request: &coland_storage::EventCommitRequest,
    list: &arkret_wire::SpaceId,
    revision: CurrentRevision,
    nonce: &str,
) -> coland_storage::EventApprovalCommit {
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], "fixture");
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let did = Did::new(format!("did:key:{multibase}")).unwrap();
    let method = DidUrl::new(format!("{did}#{multibase}")).unwrap();
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([70; 32], method.as_str());
    let station = &request.authority_commit.expected_authority.service_id;
    let approver = ordinary_realm::human_profile::fixture(station, &approval_account_label(43));
    let event = &request.authority_commit.event;
    let digest = arkret_canonical::canonical_sha256(event).unwrap();
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::ListWip {
                list_space_id: list.clone(),
                list_policy_revision: revision,
            },
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(digest.clone()).unwrap(),
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: CapabilityActionId::StrandMove,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actor_id.clone(),
            approver_did: approver.history.did,
            approved_at: request.authority_commit.commit.committed_at,
            nonce: nonce.to_owned(),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: method,
            jws: String::new(),
        },
    };
    signature.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&signature)
            .unwrap(),
    );
    coland_storage::EventApprovalCommit {
        carrier_binding: None,
        management_current: None,
        event_id: event.event_id.clone(),
        event_digest: digest,
        committed_at: request.authority_commit.commit.committed_at,
        methods: vec![native_approval_method(signature, 43, station)],
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

struct WipSetup {
    opened: ordinary_realm::Discussion,
    board_id: arkret_wire::SpaceId,
    list: coland_storage::EventCommitRequest,
    list_id: arkret_wire::SpaceId,
    second_id: arkret_wire::StrandId,
    first: coland_storage::EventCommitRequest,
}

async fn prepare_wip_setup(pool: &PgPool) -> WipSetup {
    let opened = Box::pin(open_discussion(&pool, "list-wip-approval")).await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let board = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &opened.head.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            &founder(),
            space_payload(&realm, &actor, at, "board", "Review Board", None, json!({})),
            at,
        ),
    ))
    .await;
    let board_id = arkret_wire::SpaceId::from_event_id(&board.authority_commit.event.event_id);
    uow.commit_event(board.clone()).await.unwrap();
    let list = Box::pin(ordinary_realm::source_request(
        &pool,
        next_request(
            &board.authority_commit,
            arkret_wire::EventKind::SpaceCreate,
            &founder(),
            space_payload(
                &realm,
                &actor,
                at,
                "list",
                "Review",
                Some(&board_id),
                json!({"wip_limit":1,"wip_limit_enforcement":"require_review"}),
            ),
            at,
        ),
    ))
    .await;
    let list_id = arkret_wire::SpaceId::from_event_id(&list.authority_commit.event.event_id);
    uow.commit_event(list.clone()).await.unwrap();
    let second = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &list.authority_commit,
        arkret_wire::EventKind::StrandCreate,
        &founder(),
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Second reviewed"},"state":"active","created_by":actor,"created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    ))).await;
    let second_id = arkret_wire::StrandId::from_event_id(&second.authority_commit.event.event_id);
    uow.commit_event(second.clone()).await.unwrap();
    let first = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &second.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":opened.strand_id,"target_space_id":list_id,"rank":"a"}),
        at,
    ))).await;
    uow.commit_event(first.clone()).await.unwrap();
    WipSetup {
        opened,
        board_id,
        list,
        list_id,
        second_id,
        first,
    }
}

async fn qualify_wip_review(pool: &PgPool, setup: &WipSetup) -> coland_storage::EventCommitRequest {
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list_id = setup.list_id.clone();
    let second_id = setup.second_id.clone();
    let first = &setup.first;
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let actor = opened.head.authority_commit.event.actor_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let revision = CurrentRevision {
        commit_id: setup.list.authority_commit.commit.commit_id.clone(),
        stream_position: setup.list.authority_commit.commit.stream_position,
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let review = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &first.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,"target_space_id":list_id,"rank":"b"}),
        at,
    ))).await;
    Box::pin(ordinary_realm::human_profile::admit(
        &pool,
        &ordinary_realm::station(),
        &approval_account_label(43),
    ))
    .await;
    let proof = vote(
        &review,
        &list_id,
        revision.clone(),
        "wip-nonce-128-bit-fixture-approval",
    );
    let principal =
        arkret_wire::project_did_to_core_id(&proof.methods[0].signature.input.approver_did)
            .unwrap();
    let approver = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal,
        first.authority_commit.expected_authority.service_id.clone(),
    ));
    // No grant and no joined membership means a mathematically valid vote is not an authority vote.
    let unqualified = uow
        .commit_event_batch(batch(review.clone(), proof.clone()))
        .await
        .unwrap_err();
    assert!(
        unqualified.to_string().contains("approval_required"),
        "unexpected unqualified-vote failure: {unqualified:?}"
    );
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        0
    );
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("INSERT INTO member_state_current_results(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join',$3,$4,'{\"membership\":\"join\"}'::jsonb,$5)")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(approver.to_string())
        .bind::<Text,_>(first.authority_commit.commit.commit_id.as_str()).bind::<BigInt,_>(first.authority_commit.commit.stream_position as i64)
        .bind::<diesel::sql_types::Timestamptz,_>(at).execute(&mut conn).await.unwrap();
    drop(conn);
    let grant = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &first.authority_commit,
        arkret_wire::EventKind::CapabilityGrant,
        &founder(),
        json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":actor,"subject":approver,"actions":["ak.space.update"],"resources":[arkret_wire::WireResourceSelector::space(realm.clone(),list_id.clone())],"constraints":[],"issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":opened.unit.transactions[0].event.event_id,"authority_generation":0}],"issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    ))).await;
    uow.commit_event(grant.clone()).await.unwrap();
    // A joined approver's exact-resource grant still needs the action's
    // registered allowed_space_kinds constraint before it can earn a vote.
    let incomplete_review = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &grant.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,"target_space_id":list_id,"rank":"b"}),
        at,
    ))).await;
    let incomplete_proof = vote(
        &incomplete_review,
        &list_id,
        revision.clone(),
        "wip-nonce-128-bit-fixture-approval",
    );
    let before_incomplete = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    let incomplete = uow
        .commit_event_batch(batch(incomplete_review, incomplete_proof))
        .await
        .unwrap_err();
    assert!(
        incomplete.to_string().contains("approval_required"),
        "unexpected incomplete-grant failure: {incomplete:?}"
    );
    assert_eq!(
        before_incomplete,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await,
        )
    );
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        0
    );
    let grant = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &grant.authority_commit,
        arkret_wire::EventKind::CapabilityGrant,
        &founder(),
        json!({"grant":{"schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":actor,"subject":approver,"actions":["ak.space.update"],"resources":[arkret_wire::WireResourceSelector::space(realm.clone(),list_id.clone())],"constraints":[{"constraint_kind":"kind_restriction","effect":"allow","allowed_space_kinds":["list"]}],"issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":opened.unit.transactions[0].event.event_id,"authority_generation":0}],"issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    ))).await;
    uow.commit_event(grant.clone()).await.unwrap();
    let review = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &grant.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,"target_space_id":list_id,"rank":"b"}),
        at,
    ))).await;
    review
}

#[tokio::test]
async fn list_wip_review_verifies_actual_signatures_and_consumes_only_at_success() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let setup = Box::pin(prepare_wip_setup(&pool)).await;
    let review = Box::pin(qualify_wip_review(&pool, &setup)).await;
    let opened = &setup.opened;
    let board_id = setup.board_id.clone();
    let list = &setup.list;
    let list_id = setup.list_id.clone();
    let second_id = setup.second_id.clone();
    let first = &setup.first;
    let realm = opened.head.authority_commit.event.realm_id.clone();
    let at = opened.head.authority_commit.commit.committed_at;
    let revision = CurrentRevision {
        commit_id: list.authority_commit.commit.commit_id.clone(),
        stream_position: list.authority_commit.commit.stream_position,
    };
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let proof = vote(
        &review,
        &list_id,
        revision,
        "wip-nonce-128-bit-fixture-approval",
    );
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    let mut bad = proof.clone();
    bad.methods[0].signature.input.nonce.push('x');
    assert!(
        uow.commit_event_batch(batch(review.clone(), bad))
            .await
            .unwrap_err()
            .to_string()
            .contains("approval_required")
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
    let mut stale = proof.clone();
    if let ApprovalContext::ListWip {
        list_policy_revision,
        ..
    } = &mut stale.methods[0].signature.input.approval_context
    {
        *list_policy_revision = CurrentRevision {
            commit_id: first.authority_commit.commit.commit_id.clone(),
            stream_position: first.authority_commit.commit.stream_position,
        };
    }
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [70; 32],
        stale.methods[0]
            .signature
            .proof
            .verification_method
            .as_str(),
    );
    stale.methods[0].signature.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(
            &stale.methods[0].signature,
        )
        .unwrap(),
    );
    assert!(
        uow.commit_event_batch(batch(review.clone(), stale))
            .await
            .unwrap_err()
            .to_string()
            .contains("approval_required")
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
    uow.commit_event_batch(batch(review.clone(), proof.clone()))
        .await
        .unwrap();
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        1
    );
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":list_id,"rank":"b"})
    );
    uow.commit_event_batch(batch(review.clone(), proof))
        .await
        .unwrap();
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        1
    );
    let reused = Box::pin(ordinary_realm::source_request(&pool, next_request(
        &review.authority_commit,
        arkret_wire::EventKind::StrandMove,
        &founder(),
        json!({"board_space_id":board_id,"strand_id":second_id,"target_space_id":list_id,"rank":"c",
            "expected_position":{"list_space_id":list_id,"rank":"b"}}),
        at,
    ))).await;
    let reused_proof = vote(
        &reused,
        &list_id,
        CurrentRevision {
            commit_id: list.authority_commit.commit.commit_id.clone(),
            stream_position: list.authority_commit.commit.stream_position,
        },
        "wip-nonce-128-bit-fixture-approval",
    );
    let before = (
        count(&pool, &realm, "canonical_events").await,
        count(&pool, &realm, "realm_commits").await,
    );
    assert_eq!(
        uow.commit_event_batch(batch(reused, reused_proof))
            .await
            .unwrap_err()
            .conflict_code(),
        Some(ConflictCode::ApprovalNonceReused)
    );
    assert_eq!(
        count(&pool, &realm, "event_approval_private_audit").await,
        1
    );
    assert_eq!(
        before,
        (
            count(&pool, &realm, "canonical_events").await,
            count(&pool, &realm, "realm_commits").await
        )
    );
    assert_eq!(
        position(&pool, &board_id, &second_id).await.value,
        json!({"list_space_id":list_id,"rank":"b"})
    );
}
