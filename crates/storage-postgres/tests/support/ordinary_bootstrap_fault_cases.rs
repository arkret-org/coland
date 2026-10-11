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
    unit.event_approvals = vec![None; unit.transactions.len()];
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
            .is_err()
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
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, snapshot);
}
