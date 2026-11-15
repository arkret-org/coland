//! Lower-level real-PG audit/consumption adapters. These tests do not claim
//! to replace the separate Service/HTTP full capture admission scenario.
use diesel_async::SimpleAsyncConnection;
use serde_json::json;

use super::*;

fn fixture(constraints: Value) -> (Event, RealmCommit, ActorRealmAuthorization) {
    let kat = arkret_schema_conformance::spec_json_artifact(
        "fixtures/security-transaction-resilience-fixture.json",
    )
    .unwrap()["single_submit_recovery_kat"]
        .clone();
    let actor: arkret_wire::ActorId = serde_json::from_value(
        kat["receipt"]["recovery_unit"]["events"][0]["event"]["actor_id"].clone(),
    )
    .unwrap();
    let realm = serde_json::from_value(
        kat["receipt"]["recovery_unit"]["events"][0]["event"]["realm_id"].clone(),
    )
    .unwrap();
    let at: DateTime<Utc> = "2026-11-14T12:00:00.000Z".parse().unwrap();
    let event_id = |value| {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [value; 32])
    };
    let cited = GrantId::from_event_id(&event_id(0x91));
    let mut start = arkret_test_kit::SignedEventFixtureBuilder::new("ak.call.recording.start", arkret_wire::ScopeRef::Realm { realm_id: realm }, actor.clone(), json!({
        "call_id":arkret_wire::CallId::from_event_id(&event_id(0x92)),"recording_id":"approval-source-adapter","recording_agent_id":"ak:did_core:web:recorder.example",
        "capture_kind":"recording","mode":"audio","visible_notice":true,"capture_metadata":{"key_ref":{"algorithm":"MLS","group_state_ref":event_id(0x90)},"retention":{"consent_confirmed":true}},
    })).with_created_at(at).build_unsigned().unwrap();
    start.authorization_ref = Some(arkret_wire::AuthorizationRef::new(cited.to_string()).unwrap());
    let method: arkret_wire::DidUrl =
        serde_json::from_value(kat["qualified_inputs"]["candidate_method"].clone()).unwrap();
    let did = method.as_str().split('#').next().unwrap().parse().unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        std::array::from_fn(|index| index as u8 + 1),
        did,
        method,
    );
    start = arkret_test_kit::sign_verifiable_event(
        start,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let mut commit: RealmCommit = serde_json::from_value(kat["native_commits"][0].clone()).unwrap();
    commit.event_ref = start.event_id.clone();
    commit.committed_at = at;
    commit.producer_signer_fact_digest = None;
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(
            &arkret_canonical::canonical::unsigned_value(&commit, &["commit_id", "signature"])
                .unwrap(),
        )
        .unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        commit.signature.verification_method.clone(),
        at,
        &ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|index| index as u8 + 33)),
    )
    .unwrap();
    validate_original(&start, &start, &commit, at).unwrap();
    let root = json!({"kind":"realm_root","realm_id":start.realm_id,"authority_event_ref":event_id(0x90),"authority_generation":"0"});
    let grant:CapabilityGrant = serde_json::from_value(json!({"id":cited,"schema":"ak.schema.capability.v1","realm_id":start.realm_id,"issuer_id":actor,"subject":actor,"actions":["ak.call.record"],"resources":[{"kind":"realm","realm_id":start.realm_id}],"constraints":constraints,"issuer_authority_refs":[root],"authority_depth":1,"authority_root_ref":root,"issued_at":arkret_canonical::format_timestamp_canonical(at-chrono::Duration::days(1)),"status":"active"})).unwrap();
    let grant_id = grant.id.clone();
    let sources = coland_storage::GrantAuthorityCut::new(
        start.realm_id.clone(),
        arkret_wire::RealmAuthorityRootValue {
            controller_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                "ak:did_core:web:current-owner.example".parse().unwrap(),
                "ak:did_core:web:station.example".parse().unwrap(),
            )),
            controller_epoch: 1,
            authority_generation: 0,
            authority_event_ref: event_id(0x90),
        },
        BTreeMap::from([(grant_id.clone(), grant)]),
        BTreeMap::from([(
            grant_id.clone(),
            arkret_wire::CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: 1,
            },
        )]),
    )
    .unwrap();
    let auth = ActorRealmAuthorization::from_source_cut(
        start.actor_id.clone(),
        at + chrono::Duration::hours(1),
        std::sync::Arc::new(sources),
        vec![grant_id],
        None,
    )
    .unwrap();
    (start, commit, auth)
}

fn approval_constraint() -> Value {
    json!({"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"allow","approval_required":true,"approval_threshold":1,"approval_principal_ids":["ak:did_core:web:reviewer.example"],"timeout":"PT60S"})
}

async fn store_approval(
    conn: &mut AsyncPgConnection,
    start: &Event,
    commit: &RealmCommit,
    auth: &ActorRealmAuthorization,
) {
    let grant = &auth.grants[0].grant;
    let constraint = &grant.constraints[0];
    let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
        [23; 32],
        "did:web:reviewer.example#key-1",
    );
    let mut vote = ApprovalSignature {
        input: arkret_wire::ApprovalSignatureInput {
            approval_context: ApprovalContext::Grant {
                grant_id: grant.id.clone(),
            },
            approval_target: arkret_wire::ApprovalTarget::Event {
                event_id: start.event_id.clone(),
            },
            request_canonical_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(start).unwrap(),
            )
            .unwrap(),
            operation: "ak.self.events.command.submit.v1".into(),
            action: CapabilityActionId::CallRecord,
            realm_id: start.realm_id.clone(),
            initiating_actor_id: start.actor_id.clone(),
            approver_did: "did:web:reviewer.example".parse().unwrap(),
            approved_at: commit.committed_at - chrono::Duration::seconds(30),
            nonce: "capture-approval-private-adapter-1".into(),
        },
        proof: arkret_wire::ApprovalSignatureProof {
            kind: arkret_wire::ApprovalSignatureProofKind::DetachedJws,
            verification_method: arkret_wire::DidUrl::new("did:web:reviewer.example#key-1")
                .unwrap(),
            jws: String::new(),
        },
    };
    vote.proof.jws = signer.sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote).unwrap(),
    );
    arkret_signatures::approval_signature::verify_event_approval_signature(
        &vote,
        start,
        "ak.self.events.command.submit.v1",
        CapabilityActionId::CallRecord,
        commit.committed_at,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    let basis = json!({"public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes()),"historical_method":vote.proof.verification_method,"qualifications":[{"voter":{"source":"original-adapter-fixture"},"consumer_authority_cut":{"call_axes":["ak.call.record"]},"grant_requirement":{"grant_id":grant.id,"constraint_digest":arkret_canonical::canonical_sha256(constraint).unwrap(),"constraint":constraint,"eligible_roster":[{"principal":"ak:did_core:web:reviewer.example","qualification":{"source":"original-adapter-fixture"}}],"effective_min_approver_count":1}}]});
    sql_query("INSERT INTO event_approval_private_audit(approval_context,approver_did,nonce,event_id,event_digest,realm_id,accepted_commit_id,evidence,accepted_basis,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind::<Text,_>(arkret_canonical::canonical_json_string(&vote.input.approval_context).unwrap()).bind::<Text,_>(vote.input.approver_did.as_str()).bind::<Text,_>(&vote.input.nonce)
        .bind::<Text,_>(start.event_id.as_str()).bind::<Text,_>(arkret_canonical::canonical_sha256(start).unwrap()).bind::<Text,_>(start.realm_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&vote).unwrap()).bind::<Jsonb,_>(basis).bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.unwrap();
}

#[tokio::test]
async fn original_private_approval_is_read_only_after_timeout_and_rejects_wrong_native_binding() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = pool.get().await.unwrap();
    let (start, commit, auth) = fixture(json!([approval_constraint()]));
    store_approval(&mut conn, &start, &commit, &auth).await;
    let approvals = read_accepted_approvals(
        &mut conn,
        &start,
        &commit,
        CapabilityActionId::CallRecord,
        &auth,
    )
    .await
    .unwrap();
    assert_eq!(approvals.len(), 1);
    let target = arkret_wire::WireResourceSelector::realm(start.realm_id.clone());
    assert!(
        matches!(
            auth.evaluate_with_approvals(
                &[CapabilityActionId::CALL_RECORD],
                &target,
                &coland_storage::OperationFacts::default(),
                &approvals
            ),
            GrantEvaluation::Allowed(_)
        ),
        "old accepted approval is history, not a fresh ready approval"
    );
    assert!(
        !crate::grant_approval_admission::grant_vote_is_current(
            &auth.grants[0].grant,
            CapabilityActionId::CallRecord,
            &serde_json::from_value::<ApprovalSignature>({
                #[derive(QueryableByName)]
                struct Body {
                    #[diesel(sql_type=Jsonb)]
                    evidence: Value,
                }
                sql_query("SELECT evidence FROM event_approval_private_audit")
                    .get_result::<Body>(&mut *conn)
                    .await
                    .unwrap()
                    .evidence
            })
            .unwrap(),
            auth.evaluated_at
        ),
        "fresh reuse would be expired"
    );
    let mut wrong = commit.clone();
    wrong.commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
    assert!(
        read_accepted_approvals(
            &mut conn,
            &start,
            &wrong,
            CapabilityActionId::CallRecord,
            &auth
        )
        .await
        .is_err()
    );
    for mutation in [
        "UPDATE event_approval_private_audit SET event_digest='sha256:'||repeat('0',64)",
        "UPDATE event_approval_private_audit SET evidence=jsonb_set(evidence,'{proof,jws}','\"invalid\"')",
        "UPDATE event_approval_private_audit SET accepted_basis=jsonb_set(accepted_basis,'{qualifications,0,grant_requirement,effective_min_approver_count}','2')",
        "UPDATE event_approval_private_audit SET accepted_basis=jsonb_set(accepted_basis,'{qualifications,0,grant_requirement,constraint_digest}',to_jsonb('sha256:'||repeat('0',64)))",
    ] {
        // Each mutation is isolated by a real transaction; no unsafe audit
        // row is allowed to survive to the next assertion.
        conn.batch_execute("BEGIN").await.unwrap();
        conn.batch_execute(mutation).await.unwrap();
        assert!(
            read_accepted_approvals(
                &mut conn,
                &start,
                &commit,
                CapabilityActionId::CallRecord,
                &auth
            )
            .await
            .is_err()
        );
        conn.batch_execute("ROLLBACK").await.unwrap();
    }
    let mut other = start.clone();
    other.event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [88; 32]);
    assert!(
        read_accepted_approvals(
            &mut conn,
            &other,
            &commit,
            CapabilityActionId::CallRecord,
            &auth
        )
        .await
        .unwrap()
        .is_empty()
    );
}

#[tokio::test]
async fn original_quota_consumption_survives_window_change_without_new_charge() {
    let db = crate::test_database::TestDatabase::lease().await;
    let pool = db.pool();
    let mut conn = pool.get().await.unwrap();
    let (start, commit, auth) = fixture(
        json!([{"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operation_count":1,"period":"PT1H","constraint_scope":"per_realm"}]),
    );
    let target = arkret_wire::WireResourceSelector::realm(start.realm_id.clone());
    let facts = coland_storage::OperationFacts::default();
    let actions = [CapabilityActionId::CALL_RECORD];
    let original = auth
        .original_quota_reservation_paths(&commit, &actions, &target, &facts, &[])
        .unwrap();
    let past = &original[0].1;
    let GrantEvaluation::Allowed(current) = auth.evaluate(&actions, &target, &facts) else {
        panic!("current quota shape")
    };
    assert_ne!(past[0].window_id, current[0].reservations[0].window_id);
    assert_eq!(
        reservation_bindings(past),
        reservation_bindings(&current[0].reservations)
    );
    conn.batch_execute("BEGIN").await.unwrap();
    assert!(!consumed_for_start(&mut conn, past, &start).await.unwrap());
    assert!(
        crate::capability_quota::try_reserve_in_connection(
            &mut conn,
            past,
            start.event_id.as_str()
        )
        .await
        .unwrap()
    );
    assert!(consumed_for_start(&mut conn, past, &start).await.unwrap());
    assert!(
        !consumed_for_start(&mut conn, &current[0].reservations, &start)
            .await
            .unwrap(),
        "current window must not masquerade as original consumption"
    );
    let mut other = start.clone();
    other.event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [99; 32]);
    assert!(!consumed_for_start(&mut conn, past, &other).await.unwrap());
    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type=BigInt)]
        count: i64,
    }
    let count = sql_query("SELECT sum(consumed)::bigint AS count FROM capability_quota_counters")
        .get_result::<Count>(&mut *conn)
        .await
        .unwrap()
        .count;
    assert_eq!(count, 1);
    conn.batch_execute("ROLLBACK").await.unwrap();
}
