//! Real native Org creation precedes each finite change. This is a trusted
//! storage-port regression, not a peer authentication or native handoff claim.

#[path = "support/organization_origin.rs"]
mod organization_origin;
#[path = "support/sql_fault_matrix.rs"]
mod sql_fault_matrix;

#[path = "support/organization_change.rs"]
mod organization_change;
use arkret_signatures::Ed25519DetachedJwsSigner;
use arkret_wire::*;
use chrono::Duration;
use coland_storage::AuthorityCommitStore as _;
use coland_storage_postgres::PgAuthorityCommitStore;
use diesel_async::RunQueryDsl as _;
use organization_change::{author_change, native_create, prepare, votes};
use organization_origin::OrganizationFixture;
use serde_json::json;

#[tokio::test]
async fn finite_service_change_uses_its_real_source_and_keeps_one_atomic_original_after_reopen() {
    let lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let pool = lease.pool();
    let mut fixture = OrganizationFixture::new(false, true);
    native_create(&pool, &fixture).await;
    let at = fixture.write.queued_at + Duration::seconds(5);
    let event = author_change(
        &fixture,
        fixture.write.transaction.event.event_id.clone(),
        fixture.write.transaction.commit.commit_id.clone(),
        &votes(&fixture, at),
        at,
    );
    let write = prepare(&pool, &fixture, event, at).await;
    assert_ne!(write.source_service_id, fixture.write.source_service_id);
    assert!(
        write
            .transaction
            .commit
            .producer_signer_fact_digest
            .is_none()
    );
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let result =
        sql_fault_matrix::exhaust_writes(&pool, "organization-finite-native-change", || {
            store.admit_organization_pcr_governance_change(&write)
        })
        .await;
    assert_eq!(
        result,
        AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit: write.transaction.commit.clone()
        }
    );
    assert_eq!(
        store
            .current_authority(&write.transaction.event.realm_id)
            .await
            .unwrap(),
        Some(fixture.write.transaction.expected_authority.clone())
    );
    let before = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(before["realm_commits"].as_array().unwrap().len(), 2);
    assert_eq!(
        before["organization_pcr_genesis_sources"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        before["agent_producer_signer_keys"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let reopened = PgAuthorityCommitStore { pool: pool.clone() };
    assert_eq!(
        reopened
            .admit_organization_pcr_governance_change(&write)
            .await
            .unwrap(),
        result
    );
    assert_eq!(
        reopened
            .organization_pcr_governance_change_original(&write.request, &write.source_service_id)
            .await
            .unwrap(),
        Some(result.clone())
    );
    // Today's new native policy does not reauthorize or erase an accepted result.
    let mut state = fixture.organization_state();
    let replacement = state["arkret_governance"]["threshold"]["allowed_kids"][1].clone();
    state["arkret_governance"] =
        json!({"threshold":{"min_signature_count":1,"allowed_kids":[replacement]}});
    fixture.append_organization_state(state, at + Duration::seconds(1));
    fixture.retain_current_histories(&pool).await;
    let after_policy = sql_fault_matrix::snapshot(&pool).await;
    assert_eq!(
        reopened
            .organization_pcr_governance_change_original(&write.request, &write.source_service_id)
            .await
            .unwrap(),
        Some(result)
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, after_policy);
    let mut conn = pool.get().await.unwrap();
    // Corruption follows a real accepted unit and real consumed nonce; no
    // accepted Event/Commit is fabricated to manufacture coverage.
    diesel::sql_query("DELETE FROM event_approval_private_audit WHERE event_id=$1")
        .bind::<diesel::sql_types::Text, _>(write.transaction.event.event_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(
        reopened
            .organization_pcr_governance_change_original(&write.request, &write.source_service_id)
            .await
            .is_err()
    );
    assert!(
        reopened
            .export_pcr_private_state(write.transaction.event.actor_id.as_account_id().unwrap())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bootstrap_delegation_partial_votes_host_identity_wrong_root_and_bad_head_are_zero_write() {
    for case in [
        "bootstrap_only",
        "partial_quorum",
        "old_host_source",
        "wrong_service",
        "wrong_root",
        "stale_head",
        "nonce_reuse",
    ] {
        let lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = lease.pool();
        let fixture = OrganizationFixture::new(case == "bootstrap_only", case == "partial_quorum");
        native_create(&pool, &fixture).await;
        let at = fixture.write.queued_at + Duration::seconds(5);
        let mut methods = votes(&fixture, at);
        if case == "bootstrap_only" {
            methods.clear();
        }
        if case == "partial_quorum" {
            methods.pop();
        }
        let root = if case == "wrong_root" {
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [75; 32])
        } else {
            fixture.write.transaction.event.event_id.clone()
        };
        let head = if case == "stale_head" {
            RealmCommitId::from_digest([76; 32])
        } else {
            fixture.write.transaction.commit.commit_id.clone()
        };
        let mut submission = author_change(&fixture, root, head, &methods, at);
        if case == "nonce_reuse" {
            let old = &fixture
                .write
                .request
                .event_submission
                .approval_signatures
                .as_ref()
                .unwrap()[0];
            let vote = &mut submission.approval_signatures.as_mut().unwrap()[0];
            vote.input.nonce = old.input.nonce.clone();
            vote.proof.jws = Ed25519DetachedJwsSigner::from_seed(
                [33; 32],
                vote.proof.verification_method.as_str(),
            )
            .sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(vote)
                    .unwrap(),
            );
        }
        let mut write = prepare(&pool, &fixture, submission, at).await;
        if case == "old_host_source" {
            write.source_service_id = fixture.write.source_service_id.clone();
        }
        if case == "wrong_service" {
            write.producer_service_resolution = None;
        }
        let before = sql_fault_matrix::snapshot(&pool).await;
        assert!(
            PgAuthorityCommitStore { pool: pool.clone() }
                .admit_organization_pcr_governance_change(&write)
                .await
                .is_err(),
            "{case}"
        );
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before, "{case}");
    }
}

#[tokio::test]
async fn change_votes_use_their_own_history_and_only_the_current_policy_selects_contributions() {
    for case in [
        "normal_rotation",
        "new_method_after_event",
        "current_policy_excludes_vote",
        "known_prefix_rollback",
    ] {
        let lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = lease.pool();
        let mut fixture = OrganizationFixture::new(false, false);
        native_create(&pool, &fixture).await;
        let at = fixture.write.queued_at + Duration::seconds(5);
        let old_entries = fixture.write.organization_log_entries.clone();
        let mut methods = votes(&fixture, at);
        let mut state = fixture.organization_state();
        if case == "normal_rotation" {
            for row in state["verificationMethod"].as_array_mut().unwrap() {
                if row["id"] == format!("{}#organization-control", fixture.organization_did) {
                    row["publicKeyMultibase"] =
                        json!(arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                            ed25519_dalek::SigningKey::from_bytes(&[38; 32])
                                .verifying_key()
                                .as_bytes()
                        ));
                }
            }
        } else {
            let method = fixture.add_governance_method(&mut state, 34);
            if case == "new_method_after_event" {
                methods = vec![(34, method.clone(), at - Duration::milliseconds(250))];
            } else {
                state["arkret_governance"] =
                    json!({"threshold":{"min_signature_count":1,"allowed_kids":[method]}});
            }
        }
        fixture.append_organization_state(state, at - Duration::milliseconds(500));
        fixture.retain_current_histories(&pool).await;
        let submission = author_change(
            &fixture,
            fixture.write.transaction.event.event_id.clone(),
            fixture.write.transaction.commit.commit_id.clone(),
            &methods,
            at,
        );
        let mut write = prepare(&pool, &fixture, submission, at).await;
        if case == "known_prefix_rollback" {
            write.organization_log_entries = old_entries.clone();
        }
        if case == "known_prefix_rollback" {
            let (origin, _) =
                arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
                    &fixture.write.request,
                    &fixture.write.source_service_id,
                    &old_entries,
                    &fixture.write.organization_witness_records,
                    fixture.write.producer_service_resolution.as_ref(),
                    fixture.write.queued_at,
                )
                .unwrap();
            arkret_identity::organization_pcr_genesis::verify_organization_pcr_governance_change_authority(
                &origin,&write.request.event_submission,&write.organization_log_entries,
                &write.organization_witness_records,at,
            ).unwrap();
        }
        let before = sql_fault_matrix::snapshot(&pool).await;
        let result = PgAuthorityCommitStore { pool: pool.clone() }
            .admit_organization_pcr_governance_change(&write)
            .await;
        if matches!(case, "normal_rotation" | "new_method_after_event") {
            assert!(result.is_ok(), "{case}: {result:?}");
        } else {
            assert!(result.is_err(), "{case}");
            assert_eq!(sql_fault_matrix::snapshot(&pool).await, before, "{case}");
        }
    }
}

#[tokio::test]
async fn private_preparation_preserves_the_exact_complete_change_source_and_refuses_missing_audit()
{
    let old_lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let old = old_lease.pool();
    let fixture = OrganizationFixture::new(false, true);
    native_create(&old, &fixture).await;
    let at = fixture.write.queued_at + Duration::seconds(5);
    let submission = author_change(
        &fixture,
        fixture.write.transaction.event.event_id.clone(),
        fixture.write.transaction.commit.commit_id.clone(),
        &votes(&fixture, at),
        at,
    );
    let write = prepare(&old, &fixture, submission, at).await;
    let store = PgAuthorityCommitStore { pool: old.clone() };
    let first = store
        .admit_organization_pcr_governance_change(&write)
        .await
        .unwrap();
    let holder = write.transaction.event.actor_id.as_account_id().unwrap();
    let (manifest, bytes) = store.export_pcr_private_state(holder).await.unwrap();
    let target_lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
    let target = target_lease.pool();
    let incoming = PgAuthorityCommitStore {
        pool: target.clone(),
    };
    // This explicitly exercises the trusted private-preparation port. It is
    // neither authenticated delivery nor the dual-signed activation endpoint.
    incoming
        .import_pcr_private_state(&manifest, &bytes)
        .await
        .unwrap();
    assert_eq!(
        incoming
            .organization_pcr_governance_change_original(&write.request, &write.source_service_id)
            .await
            .unwrap(),
        Some(first)
    );
    let (again, again_bytes) = incoming.export_pcr_private_state(holder).await.unwrap();
    assert_eq!(again.state_digest, manifest.state_digest);
    assert_eq!(again_bytes, bytes);
    let mut conn = target.get().await.unwrap();
    diesel::sql_query("DELETE FROM event_approval_private_audit WHERE event_id=$1")
        .bind::<diesel::sql_types::Text, _>(write.transaction.event.event_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(incoming.export_pcr_private_state(holder).await.is_err());
}

#[tokio::test]
async fn one_complete_change_source_owns_all_original_nonces_and_missing_any_vote_fails_closed() {
    for remove_owner in [true, false] {
        let lease = coland_storage_postgres::test_database::TestDatabase::lease().await;
        let pool = lease.pool();
        let fixture = OrganizationFixture::new(false, true);
        native_create(&pool, &fixture).await;
        let at = fixture.write.queued_at + Duration::seconds(5);
        let submission = author_change(
            &fixture,
            fixture.write.transaction.event.event_id.clone(),
            fixture.write.transaction.commit.commit_id.clone(),
            &votes(&fixture, at),
            at,
        );
        let write = prepare(&pool, &fixture, submission, at).await;
        let store = PgAuthorityCommitStore { pool: pool.clone() };
        let accepted = store
            .admit_organization_pcr_governance_change(&write)
            .await
            .unwrap();
        let snapshot = sql_fault_matrix::snapshot(&pool).await;
        let rows = snapshot["event_approval_private_audit"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["event_id"] == write.transaction.event.event_id.as_str())
            .cloned()
            .collect::<Vec<_>>();
        let approvals = write
            .request
            .event_submission
            .approval_signatures
            .as_ref()
            .unwrap();
        assert_eq!(rows.len(), 2, "this is the actual two-vote native quorum");
        assert_eq!(rows.len(), approvals.len());
        let ordering = |row: &serde_json::Value| {
            (
                row["approval_context"].as_str().unwrap().to_owned(),
                row["approver_did"].as_str().unwrap().to_owned(),
                row["nonce"].as_str().unwrap().to_owned(),
            )
        };
        let minimum = rows.iter().map(ordering).min().unwrap();
        let owners = rows
            .iter()
            .filter(|row| {
                row.pointer("/accepted_basis/authority_cut/organization_pcr_change_source")
                    .is_some()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owners.len(),
            1,
            "one existing nonce row owns the complete source"
        );
        assert_eq!(ordering(owners[0]), minimum);
        let expected_source = json!({
            "source_service_id":write.source_service_id,"peer_request":write.request,
            "organization_log_entries":write.organization_log_entries,
            "organization_witness_records":write.organization_witness_records,
            "producer_service_resolution":write.producer_service_resolution,
        });
        assert_eq!(
            owners[0]
                .pointer("/accepted_basis/authority_cut/organization_pcr_change_source")
                .unwrap(),
            &expected_source
        );
        assert_eq!(
            owners[0]
                .pointer("/accepted_basis/authority_cut/original_outcome")
                .unwrap(),
            &serde_json::to_value(&accepted).unwrap()
        );
        let mut full_source_slots = 0;
        for row in &rows {
            let original_vote = approvals
                .iter()
                .find(|approval| approval.input.nonce == row["nonce"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                row["evidence"],
                serde_json::to_value(original_vote).unwrap()
            );
            assert_eq!(
                row["event_digest"],
                arkret_canonical::canonical_sha256(&write.transaction.event).unwrap()
            );
            let basis = &row["accepted_basis"];
            full_source_slots += usize::from(
                basis["authority_cut"]
                    .get("organization_pcr_change_source")
                    .is_some(),
            );
            for qualification in basis["qualifications"].as_array().unwrap() {
                full_source_slots += usize::from(
                    qualification["consumer_authority_cut"]
                        .get("organization_pcr_change_source")
                        .is_some(),
                );
            }
            if ordering(row) != minimum {
                assert_eq!(basis["authority_cut"], json!({}));
                assert!(basis.pointer("/authority_cut/original_outcome").is_none());
            }
        }
        // The existing generic audit format retains two basis slots in its
        // one owner row. No generic API is changed to remove that small pair.
        assert_eq!(
            full_source_slots, 2,
            "two-vote source copies fall from four to two"
        );
        let reopened = PgAuthorityCommitStore { pool: pool.clone() };
        assert_eq!(
            reopened
                .organization_pcr_governance_change_original(
                    &write.request,
                    &write.source_service_id
                )
                .await
                .unwrap(),
            Some(accepted)
        );
        let victim = rows
            .iter()
            .find(|row| (ordering(row) == minimum) == remove_owner)
            .unwrap();
        // Corruption is injected only after a genuine accepted unit. Both
        // missing-owner and missing-other-vote must invalidate cold closure.
        let mut conn = pool.get().await.unwrap();
        let deleted = diesel::sql_query("DELETE FROM event_approval_private_audit WHERE event_id=$1 AND accepted_commit_id=$2 AND approval_context=$3 AND approver_did=$4 AND nonce=$5")
            .bind::<diesel::sql_types::Text,_>(write.transaction.event.event_id.as_str())
            .bind::<diesel::sql_types::Text,_>(write.transaction.commit.commit_id.as_str())
            .bind::<diesel::sql_types::Text,_>(victim["approval_context"].as_str().unwrap())
            .bind::<diesel::sql_types::Text,_>(victim["approver_did"].as_str().unwrap())
            .bind::<diesel::sql_types::Text,_>(victim["nonce"].as_str().unwrap())
            .execute(&mut *conn).await.unwrap();
        assert_eq!(deleted, 1);
        drop(conn);
        let corrupted = sql_fault_matrix::snapshot(&pool).await;
        assert!(
            reopened
                .organization_pcr_governance_change_original(
                    &write.request,
                    &write.source_service_id
                )
                .await
                .is_err()
        );
        assert!(
            reopened
                .export_pcr_private_state(write.transaction.event.actor_id.as_account_id().unwrap())
                .await
                .is_err()
        );
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, corrupted);
    }
}
