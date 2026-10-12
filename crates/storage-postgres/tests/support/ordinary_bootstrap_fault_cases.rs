use super::*;

#[tokio::test]
async fn shared_authority_objects_survive_the_postgres_json_boundary() {
    #[derive(diesel::QueryableByName)]
    struct Objects {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        commit: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        handoff: serde_json::Value,
    }
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let (commit, handoff) = arkret_test_kit::authority_objects::objects();
    let mut conn = pool.get().await.unwrap();
    let stored = diesel::sql_query("SELECT $1::jsonb AS commit,$2::jsonb AS handoff")
        .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(commit).unwrap())
        .bind::<diesel::sql_types::Jsonb, _>(serde_json::to_value(handoff).unwrap())
        .get_result::<Objects>(&mut conn)
        .await
        .unwrap();
    arkret_test_kit::authority_objects::assert_canonical_objects(
        &serde_json::from_value(stored.commit).unwrap(),
        &serde_json::from_value(stored.handoff).unwrap(),
    );
}

#[tokio::test]
async fn every_bootstrap_write_rolls_back_and_restart_replays_the_exact_unit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit_with_plaintext_service(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    let result = sql_fault_matrix::exhaust_writes(&pool, "ordinary_bootstrap", || {
        store.admit_ordinary_realm_bootstrap_unit(&unit, at)
    })
    .await;
    let OrdinaryRealmBootstrapCommitOutcome::Committed(commits) = result else {
        panic!("fresh unit");
    };
    assert_eq!(commits.len(), unit.submission.events.len());
    for (index, commit) in commits.iter().enumerate() {
        assert_eq!(commit.stream_position, index as u64);
        assert_eq!(
            commit.event_ref,
            unit.submission.events[index].event.event_id
        );
        assert_eq!(
            commit.previous_commit_ref,
            index.checked_sub(1).map(|i| commits[i].commit_id.clone())
        );
    }
    let before = sql_fault_matrix::snapshot(&pool).await;
    let restarted = coland_storage_postgres::Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap();
    let reopened = PgAuthorityCommitStore {
        pool: restarted.pool.unwrap(),
    };
    assert_eq!(
        reopened
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits.clone())
    );
    assert_eq!(
        reopened
            .ordinary_realm_bootstrap_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap(),
        Some(commits)
    );
    let mut different = unit.clone();
    different.submission.idempotency_key = arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
    different.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(different.submission.clone()),
    )
    .unwrap();
    assert_eq!(
        reopened
            .admit_ordinary_realm_bootstrap_unit(&different, at)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);

    let mut conflicting = super::unit(&pool).await;
    conflicting.submission.idempotency_key = unit.submission.idempotency_key;
    conflicting.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(conflicting.submission.clone()),
    )
    .unwrap();
    let before = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(
        reopened
            .ordinary_realm_bootstrap_replay(
                &conflicting.submission,
                &conflicting.exact_request_body
            )
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(
        reopened
            .admit_ordinary_realm_bootstrap_unit(&conflicting, at)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
}

fn approvals(unit: &mut OrdinaryRealmBootstrapCommitUnit, slot: usize) {
    use arkret_wire::*;
    let event = &unit.submission.events[slot].event;
    let at = unit.transactions[slot].commit.committed_at;
    let signer =
        arkret_signatures::Ed25519DetachedJwsSigner::from_seed([91; 32], "bootstrap-approval");
    let key =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
    let did = Did::new(format!("did:key:{key}")).unwrap();
    let method = DidUrl::new(format!("{did}#{key}")).unwrap();
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed([91; 32], method.as_str());
    let digest = arkret_canonical::canonical_sha256(event).unwrap();
    let mut signature = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::RealmGovernance {},
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(digest.clone()).unwrap(),
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: CapabilityActionId::RealmProfile,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actor_id.clone(),
            approver_did: did,
            approved_at: at,
            nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
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
    unit.event_approvals.resize(unit.transactions.len(), None);
    unit.event_approvals[slot] = Some(coland_storage::EventApprovalCommit {
        event_id: event.event_id.clone(),
        event_digest: digest,
        committed_at: at,
        methods: vec![coland_storage::ApprovalHistoricalMethod {
            signature: signature.clone(),
            public_key: signer.verifying_key().to_bytes(),
            native_control: None,
            control_history: None,
        }],
    });
    unit.submission.events[slot].approval_signatures = Some(vec![signature]);
    unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone()),
    )
    .unwrap();
}

fn resign_approval(
    unit: &mut OrdinaryRealmBootstrapCommitUnit,
    slot: usize,
    change: impl FnOnce(&mut arkret_wire::ApprovalSignature),
) {
    let prepared = unit.event_approvals[slot].as_mut().unwrap();
    let method = &mut prepared.methods[0];
    change(&mut method.signature);
    method.signature.validate().unwrap();
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [91; 32],
        method.signature.proof.verification_method.as_str(),
    );
    let bytes =
        arkret_signatures::approval_signature::approval_signature_signing_bytes(&method.signature)
            .unwrap();
    method.signature.proof.jws = signer.sign_detached_jws(&bytes);
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &method.signature.proof.jws,
            &bytes,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: method.public_key.to_vec(),
            },
        )
        .unwrap();
    unit.submission.events[slot].approval_signatures = Some(vec![method.signature.clone()]);
    unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone()),
    )
    .unwrap();
    unit.validate().unwrap();
}

fn original_bootstrap_digest(unit: &OrdinaryRealmBootstrapCommitUnit) -> arkret_wire::Hash {
    let mut original = unit.submission.clone();
    for event in &mut original.events {
        event.approval_signatures = None;
    }
    arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(&SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(
            original,
        ))
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn real_signed_bootstrap_approval_mismatches_are_zero_write_rejections() {
    use arkret_wire::*;
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut valid = unit(&pool).await;
    approvals(&mut valid, 1);
    let at = valid.transactions[0].commit.committed_at;
    let before = sql_fault_matrix::snapshot(&pool).await;
    let mut cases = Vec::new();
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.action = CapabilityActionId::RealmTombstone
    });
    cases.push(("wrong action", wrong, "signature_invalid"));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.approval_context = ApprovalContext::Grant {
            grant_id: GrantId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [71; 32],
            )),
        }
    });
    cases.push(("nonexistent dependency grant", wrong, "approval_required"));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.approval_context = ApprovalContext::Management {
            management_operation: ManagementOperation::Join,
            effective_scope: valid.submission.events[1].event.scope_ref.clone(),
            request_id: "ak:request:01970000-0000-7000-8000-000000000021".into(),
        }
    });
    cases.push(("nonexistent management ledger", wrong, "approval_required"));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.action = CapabilityActionId::StrandMove;
        vote.input.approval_context = ApprovalContext::ListWip {
            list_space_id: SpaceId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [72; 32],
            )),
            list_policy_revision: CurrentRevision {
                commit_id: valid.transactions[1].commit.commit_id.clone(),
                stream_position: 1,
            },
        }
    });
    cases.push(("nonexistent List authority", wrong, "approval_required"));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.approval_target = ApprovalTarget::Event {
            event_id: valid.submission.events[0].event.event_id.clone(),
        }
    });
    cases.push(("wrong Event target", wrong, "signature_invalid"));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.request_canonical_digest =
            Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap()
    });
    cases.push(("wrong Event digest", wrong, "signature_invalid"));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [73; 32],
        ));
    });
    cases.push(("wrong Realm", wrong, "signature_invalid"));
    let mut wrong = valid.clone();
    let other_actor = ActorId::account(AccountId::new(
        valid.submission.events[1]
            .event
            .actor_id
            .signing_principal_id()
            .clone(),
        DidCoreId::new("ak:did_core:web:other-bootstrap-station.example").unwrap(),
    ));
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.initiating_actor_id = other_actor
    });
    cases.push((
        "same principal at another Station",
        wrong,
        "signature_invalid",
    ));
    let mut wrong = valid.clone();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.approved_at += chrono::TimeDelta::days(1)
    });
    cases.push(("future approval", wrong, "signature_invalid"));
    let mut wrong = valid.clone();
    let fragment_digest = arkret_canonical::canonical_sha256(&EventAdmissionSubmission::new(
        valid.submission.events[1].event.clone(),
    ))
    .unwrap();
    resign_approval(&mut wrong, 1, |vote| {
        vote.input.approval_target = ApprovalTarget::Operation;
        vote.input.request_canonical_digest = Hash::new(fragment_digest).unwrap();
    });
    cases.push((
        "fabricated single-slot operation body",
        wrong,
        "signature_invalid",
    ));
    for (name, wrong, code) in cases {
        let error = store
            .admit_ordinary_realm_bootstrap_unit(&wrong, at)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(code), "{name}: {error}");
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before, "{name}");
        println!("bootstrap signed mismatch: {name}: {code}, zero durable rows changed");
    }
    assert!(matches!(
        store
            .admit_ordinary_realm_bootstrap_unit(&valid, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Committed(_)
    ));
}

#[tokio::test]
async fn operation_approval_binds_the_entire_bootstrap_and_replays_after_restart() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut unit = unit(&pool).await;
    approvals(&mut unit, 1);
    let digest = original_bootstrap_digest(&unit);
    resign_approval(&mut unit, 1, |vote| {
        vote.input.approval_target = arkret_wire::ApprovalTarget::Operation;
        vote.input.action = arkret_wire::CapabilityActionId::RealmOwner;
        vote.input.request_canonical_digest = digest;
    });
    approvals(&mut unit, 2);
    let repeated = unit.submission.events[1]
        .approval_signatures
        .as_ref()
        .unwrap()[0]
        .clone();
    resign_approval(&mut unit, 2, |vote| *vote = repeated);
    let at = unit.transactions[0].commit.committed_at;
    let mut wrong_identity = unit.clone();
    wrong_identity.submission.idempotency_key =
        arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap();
    wrong_identity.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(wrong_identity.submission.clone()),
    )
    .unwrap();
    wrong_identity.validate().unwrap();
    let before = sql_fault_matrix::snapshot(&pool).await;
    let mut different_evidence = unit.clone();
    resign_approval(&mut different_evidence, 2, |vote| {
        vote.input.action = arkret_wire::CapabilityActionId::RealmAdmin;
    });
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&different_evidence, at)
            .await
            .unwrap_err()
            .to_string()
            .contains("approval_nonce_reused")
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&wrong_identity, at)
            .await
            .unwrap_err()
            .to_string()
            .contains("signature_invalid")
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    let result =
        sql_fault_matrix::exhaust_writes(&pool, "ordinary_bootstrap_operation_approval", || {
            store.admit_ordinary_realm_bootstrap_unit(&unit, at)
        })
        .await;
    let OrdinaryRealmBootstrapCommitOutcome::Committed(commits) = result else {
        panic!("fresh operation target");
    };
    let snapshot = sql_fault_matrix::snapshot(&pool).await;
    let audit = snapshot["event_approval_private_audit"].as_array().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0]["accepted_basis"]["authority_cut"]["commits"],
        serde_json::to_value(&commits).unwrap()
    );
    assert_eq!(
        audit[0]["accepted_commit_id"],
        commits[1].commit_id.as_str()
    );
    assert_eq!(
        audit[0]["evidence"],
        serde_json::to_value(
            &unit.submission.events[1]
                .approval_signatures
                .as_ref()
                .unwrap()[0]
        )
        .unwrap()
    );
    let restarted = coland_storage_postgres::Db::connect(Some(database.url()), Default::default())
        .await
        .unwrap();
    let reopened = PgAuthorityCommitStore {
        pool: restarted.pool.unwrap(),
    };
    // Durable replay precedes live history resolution.
    let mut unresolved = unit.clone();
    unresolved.event_approvals.clear();
    assert_eq!(
        reopened
            .ordinary_realm_bootstrap_replay(&unresolved.submission, &unresolved.exact_request_body)
            .await
            .unwrap(),
        Some(commits.clone())
    );
    assert_eq!(
        reopened
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits)
    );
    let mut changed_bytes = unit.exact_request_body.clone();
    changed_bytes.push(b' ');
    assert_eq!(
        reopened
            .ordinary_realm_bootstrap_replay(&unit.submission, &changed_bytes)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::DuplicateConflict)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, snapshot);
}

#[tokio::test]
async fn bootstrap_approval_evidence_is_verified_consumed_atomically_and_replayed() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let mut unit = unit(&pool).await;
    approvals(&mut unit, 1);
    let at = unit.transactions[0].commit.committed_at;
    let before = sql_fault_matrix::snapshot(&pool).await;
    let mut missing = unit.clone();
    missing.event_approvals.clear();
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&missing, at)
            .await
            .unwrap_err()
            .to_string()
            .contains("approval history is incomplete")
    );
    let mut wrong = unit.clone();
    wrong.event_approvals[1].as_mut().unwrap().methods[0].public_key = [0; 32];
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&wrong, at)
            .await
            .unwrap_err()
            .to_string()
            .contains("signature_invalid")
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    let result = sql_fault_matrix::exhaust_writes(&pool, "ordinary_bootstrap_approval", || {
        store.admit_ordinary_realm_bootstrap_unit(&unit, at)
    })
    .await;
    let OrdinaryRealmBootstrapCommitOutcome::Committed(commits) = result else {
        panic!("fresh approval target");
    };
    let snapshot = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(
        snapshot["event_approval_private_audit"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        snapshot["event_approval_private_audit"][0]["accepted_commit_id"],
        commits[1].commit_id.as_str()
    );
    assert_eq!(
        snapshot["event_approval_private_audit"][0]["evidence"],
        serde_json::to_value(
            &unit.submission.events[1]
                .approval_signatures
                .as_ref()
                .unwrap()[0]
        )
        .unwrap()
    );
    let mut another = super::unit(&pool).await;
    approvals(&mut another, 1);
    let nonce = unit.submission.events[1]
        .approval_signatures
        .as_ref()
        .unwrap()[0]
        .input
        .nonce
        .clone();
    resign_approval(&mut another, 1, |vote| vote.input.nonce = nonce);
    let before_reused_nonce = sql_fault_matrix::snapshot(&pool).await;
    assert!(
        store
            .admit_ordinary_realm_bootstrap_unit(&another, at)
            .await
            .unwrap_err()
            .to_string()
            .contains("approval_nonce_reused")
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before_reused_nonce);
    assert_eq!(
        store
            .admit_ordinary_realm_bootstrap_unit(&unit, at)
            .await
            .unwrap(),
        OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits.clone())
    );
    // Exact durable replay requires no newly resolved historical method and
    // never consumes the accepted approval nonce again.
    assert_eq!(
        store
            .ordinary_realm_bootstrap_replay(&unit.submission, &unit.exact_request_body)
            .await
            .unwrap(),
        Some(commits)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before_reused_nonce);
}
