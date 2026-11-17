//! Real native acceptance, exact original replay and all-row rollback.
//! Authenticated peer source is a precondition of this storage port; HTTP
//! signature and serving-lifecycle coverage belongs to the HTTP regression.

#[path = "support/organization_origin.rs"]
mod organization_origin;
#[path = "support/sql_fault_matrix.rs"]
mod sql_fault_matrix;

use arkret_wire::{AuthoritySubmitResponseBody, GenesisGovernance};
use coland_storage::{ActorProfileStore as _, PrincipalResolutionStore as _};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgActorProfileStore, PgPrincipalResolutionStore};
use diesel_async::RunQueryDsl as _;
use organization_origin::OrganizationFixture;

#[tokio::test]
async fn organization_finite_quorum_and_original_delegation_accept_one_create_without_human_device()
{
    for (delegated, quorum) in [(false, false), (false, true), (true, false)] {
        let lease = TestDatabase::lease().await;
        let pool = lease.pool();
        let fixture = OrganizationFixture::new(delegated, quorum);
        fixture.retain_current_histories(&pool).await;
        let store = PgActorProfileStore { pool: pool.clone() };
        let event = &fixture.write.request.event_submission.event;
        assert_eq!(
            fixture.write.source_service_id,
            event.actor_id.as_account_id().unwrap().station_id
        );
        assert_ne!(
            event.actual_signer().signing_principal_id(),
            &fixture.write.source_service_id
        );
        assert!(matches!(
            GenesisGovernance::from_genesis(event),
            Ok(GenesisGovernance::Organization)
        ));
        let first = store
            .admit_organization_pcr_genesis(fixture.write.clone())
            .await
            .unwrap();
        let AuthoritySubmitResponseBody::Accepted { commit, .. } = &first else {
            panic!("native create refused")
        };
        assert_eq!(commit.stream_position, 0);
        assert_eq!(commit.governance_generation, 0);
        let before = sql_fault_matrix::snapshot(&pool).await;
        let reopened = PgActorProfileStore { pool: pool.clone() };
        assert_eq!(
            arkret_canonical::canonical_json_bytes(
                &reopened
                    .admit_organization_pcr_genesis(fixture.write.clone())
                    .await
                    .unwrap()
            )
            .unwrap(),
            arkret_canonical::canonical_json_bytes(&first).unwrap()
        );
        assert_eq!(
            reopened
                .organization_pcr_genesis_original(
                    &fixture.write.request,
                    &fixture.write.source_service_id
                )
                .await
                .unwrap(),
            Some(first)
        );
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
        for table in [
            "devices",
            "sessions",
            "pcr_genesis_units",
            "agent_status_current_states",
        ] {
            assert!(
                before[table].as_array().unwrap().is_empty(),
                "borrowed Human or Agent authority: {table}"
            );
        }
        assert_eq!(
            before["organization_pcr_genesis_sources"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(before["canonical_events"].as_array().unwrap().len(), 1);
        assert_eq!(before["realm_commits"].as_array().unwrap().len(), 1);
        let current = PgPrincipalResolutionStore { pool: pool.clone() }
            .by_account_id(event.actor_id.as_account_id().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.genesis_event, *event);
        assert_eq!(current.pcr_realm_id, event.realm_id);
    }
}

#[tokio::test]
async fn organization_invalid_authority_host_and_producer_leave_every_protocol_row_unchanged() {
    let lease = TestDatabase::lease().await;
    let pool = lease.pool();
    let store = PgActorProfileStore { pool: pool.clone() };
    let fixture = OrganizationFixture::new(false, false);
    let quorum = OrganizationFixture::new(false, true);
    fixture.retain_current_histories(&pool).await;
    quorum.retain_current_histories(&pool).await;
    let mut missing = fixture.write.clone();
    missing.request.event_submission.approval_signatures = None;
    let mut partial = quorum.write.clone();
    partial
        .request
        .event_submission
        .approval_signatures
        .as_mut()
        .unwrap()
        .pop();
    let mut foreign = fixture.write.clone();
    foreign.source_service_id = "ak:did_core:web:unaccepted-host.example".parse().unwrap();
    let mut history = fixture.write.clone();
    history.organization_log_entries[0]["state"]["id"] =
        serde_json::json!("did:web:changed.example");
    let mut producer = fixture.write.clone();
    producer.producer_service_resolution = None;
    for write in [missing, partial, foreign, history, producer] {
        let before = sql_fault_matrix::snapshot(&pool).await;
        assert!(store.admit_organization_pcr_genesis(write).await.is_err());
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    }
}

#[tokio::test]
async fn organization_native_unit_rolls_back_every_actual_row_write_and_requires_its_source_after_reopen()
 {
    let lease = TestDatabase::lease().await;
    let pool = lease.pool();
    let fixture = OrganizationFixture::new(false, true);
    let store = PgActorProfileStore { pool: pool.clone() };
    fixture.retain_current_histories(&pool).await;
    sql_fault_matrix::exhaust_writes(&pool, "organization-native-create", || {
        store.admit_organization_pcr_genesis(fixture.write.clone())
    })
    .await;
    let event = &fixture.write.request.event_submission.event;
    let reader = PgPrincipalResolutionStore { pool: pool.clone() };
    reader.for_realm(&event.realm_id).await.unwrap().unwrap();
    // This is destructive corruption after a real native admission, never a
    // fabricated accepted fixture. Bare Event/Commit and editable index rows
    // cannot replace the missing original authority/source closure.
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("DELETE FROM organization_pcr_genesis_sources WHERE realm_id=$1")
        .bind::<diesel::sql_types::Text, _>(event.realm_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    assert!(reader.for_realm(&event.realm_id).await.is_err());
    assert!(
        store
            .admit_organization_pcr_genesis(fixture.write)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn concurrent_different_creates_cannot_replace_one_full_organization_account_inception() {
    let lease = TestDatabase::lease().await;
    let pool = lease.pool();
    let mut fixture = OrganizationFixture::new(false, true);
    fixture.retain_current_histories(&pool).await;
    let first = fixture.write.clone();
    fixture
        .write
        .request
        .event_submission
        .event
        .payload
        .get_mut("object")
        .unwrap()["genesis_salt"] =
        serde_json::json!(arkret_canonical::base64url_encode([72u8; 32]));
    fixture.resign(true);
    let second = fixture.write.clone();
    assert_ne!(
        first.transaction.event.realm_id,
        second.transaction.event.realm_id
    );
    assert_eq!(
        first.transaction.event.actor_id,
        second.transaction.event.actor_id
    );
    let store = PgActorProfileStore { pool: pool.clone() };
    let (a, b) = tokio::join!(
        store.admit_organization_pcr_genesis(first.clone()),
        store.admit_organization_pcr_genesis(second.clone()),
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one immutable full-Account inception wins"
    );
    let (accepted, refused) = if a.is_ok() {
        (first, second)
    } else {
        (second, first)
    };
    let rows = sql_fault_matrix::snapshot(&pool).await;
    for table in [
        "organization_pcr_genesis_sources",
        "canonical_events",
        "realm_commits",
        "principal_resolutions",
        "principal_resolution_current_states",
    ] {
        assert_eq!(
            rows[table].as_array().unwrap().len(),
            1,
            "second inception changed {table}"
        );
    }
    assert!(
        store
            .organization_pcr_genesis_original(&accepted.request, &accepted.source_service_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .organization_pcr_genesis_original(&refused.request, &refused.source_service_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.admit_organization_pcr_genesis(refused).await.is_err());
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, rows);
}

#[tokio::test]
async fn current_organization_delegation_and_quorum_cannot_reuse_event_time_authority() {
    use chrono::Duration;
    use serde_json::json;
    for case in [
        "delegation_removed",
        "delegation_expired",
        "quorum_raised",
        "old_vote_excluded",
        "service_key_rotated",
    ] {
        let lease = TestDatabase::lease().await;
        let pool = lease.pool();
        let delegated = case.starts_with("delegation");
        let mut fixture = OrganizationFixture::new(delegated, false);
        fixture.retain_current_histories(&pool).await;
        if case == "service_key_rotated" {
            fixture.rotate_service_assertion();
        } else {
            let mut state = fixture.organization_state();
            match case {
                "delegation_removed" => state["arkret_governance"]["delegations"] = json!([]),
                "delegation_expired" => {
                    state["arkret_governance"]["delegations"][0]["expires_at"] =
                        json!(arkret_canonical::format_timestamp_canonical(
                            fixture.write.queued_at - Duration::milliseconds(250)
                        ))
                }
                "quorum_raised" => {
                    let second = fixture.add_governance_method(&mut state, 34);
                    state["arkret_governance"] = json!({"threshold":{"min_signature_count":2,"allowed_kids":[format!("{}#organization-control",fixture.organization_did),second]}});
                }
                "old_vote_excluded" => {
                    let second = fixture.add_governance_method(&mut state, 34);
                    state["arkret_governance"] =
                        json!({"threshold":{"min_signature_count":1,"allowed_kids":[second]}});
                }
                _ => unreachable!(),
            }
            fixture.append_organization_state(
                state,
                fixture.write.queued_at - Duration::milliseconds(500),
            );
        }
        // Keep the candidate Commit/source internally coherent so this
        // negative cannot pass merely because its old fact digest changed.
        fixture.bind_public_source_fact();
        assert!(
            arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
                &fixture.write.request,
                &fixture.write.source_service_id,
                &fixture.write.organization_log_entries,
                &fixture.write.organization_witness_records,
                fixture.write.producer_service_resolution.as_ref(),
                fixture.write.queued_at,
            )
            .is_err(),
            "{case}"
        );
        fixture.retain_current_histories(&pool).await;
        let before = sql_fault_matrix::snapshot(&pool).await;
        let store = PgActorProfileStore { pool: pool.clone() };
        assert!(
            store
                .admit_organization_pcr_genesis(fixture.write)
                .await
                .is_err(),
            "{case}"
        );
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before, "{case}");
    }
}

#[tokio::test]
async fn finite_historical_approval_survives_normal_rotation_and_later_control_can_approve_exact_old_event()
 {
    use chrono::Duration;
    use serde_json::json;
    for late_method in [false, true] {
        let lease = TestDatabase::lease().await;
        let pool = lease.pool();
        let mut fixture = OrganizationFixture::new(false, false);
        let signed_event = fixture.write.request.event_submission.event.clone();
        let signed_votes = fixture
            .write
            .request
            .event_submission
            .approval_signatures
            .clone();
        let mut state = fixture.organization_state();
        if late_method {
            let method = fixture.add_governance_method(&mut state, 34);
            fixture.append_organization_state(
                state,
                fixture.write.queued_at - Duration::milliseconds(500),
            );
            fixture.reauthor_for_control_method(
                &method,
                34,
                fixture.write.queued_at - Duration::milliseconds(250),
            );
        } else {
            for method in state["verificationMethod"].as_array_mut().unwrap() {
                if method["id"] == format!("{}#organization-control", fixture.organization_did) {
                    method["publicKeyMultibase"] =
                        json!(arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                            ed25519_dalek::SigningKey::from_bytes(&[38; 32])
                                .verifying_key()
                                .as_bytes()
                        ));
                }
            }
            fixture.append_organization_state(
                state,
                fixture.write.queued_at - Duration::milliseconds(500),
            );
            assert_eq!(fixture.write.request.event_submission.event, signed_event);
            assert_eq!(
                fixture.write.request.event_submission.approval_signatures,
                signed_votes
            );
        }
        fixture.bind_public_source_fact();
        fixture.retain_current_histories(&pool).await;
        let store = PgActorProfileStore { pool: pool.clone() };
        let first = store
            .admit_organization_pcr_genesis(fixture.write.clone())
            .await
            .unwrap();
        let mut later = fixture.organization_state();
        let replacement =
            arkret_wire::DidUrl::new(format!("{}#later-only", fixture.organization_did)).unwrap();
        later["verificationMethod"].as_array_mut().unwrap().push(json!({"id":replacement,"type":"Multikey","controller":fixture.organization_did,"publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(ed25519_dalek::SigningKey::from_bytes(&[39;32]).verifying_key().as_bytes())}));
        later["capabilityInvocation"]
            .as_array_mut()
            .unwrap()
            .push(json!(replacement));
        later["arkret_governance"] =
            json!({"threshold":{"min_signature_count":1,"allowed_kids":[replacement]}});
        fixture.append_organization_state(later, fixture.write.queued_at + Duration::seconds(1));
        fixture.retain_current_histories(&pool).await;
        let rows = sql_fault_matrix::snapshot(&pool).await;
        // Once accepted, a new remote governance change is not today's
        // reauthorization of the immutable result and original audit cut.
        assert_eq!(
            store
                .organization_pcr_genesis_original(
                    &fixture.write.request,
                    &fixture.write.source_service_id
                )
                .await
                .unwrap(),
            Some(first.clone())
        );
        let reopened = PgActorProfileStore { pool: pool.clone() };
        assert_eq!(
            reopened
                .admit_organization_pcr_genesis(fixture.write.clone())
                .await
                .unwrap(),
            first
        );
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, rows);
    }
}

#[tokio::test]
async fn a_valid_truncated_prefix_cannot_replace_the_known_current_native_head() {
    use chrono::Duration;
    use serde_json::json;
    let lease = TestDatabase::lease().await;
    let pool = lease.pool();
    let mut fixture = OrganizationFixture::new(true, false);
    let old = fixture.write.clone();
    let mut state = fixture.organization_state();
    state["arkret_governance"]["delegations"] = json!([]);
    fixture.append_organization_state(state, fixture.write.queued_at - Duration::milliseconds(500));
    fixture.retain_current_histories(&pool).await;
    let before = sql_fault_matrix::snapshot(&pool).await;
    let store = PgActorProfileStore { pool: pool.clone() };
    // The old prefix is still natively signed and passes its own historical
    // windows, but the real owner has already retained the later revocation.
    arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_authority(
        &old.request.event_submission,
        &old.organization_log_entries,
        &[],
        old.queued_at,
    )
    .unwrap();
    assert!(
        store
            .admit_organization_pcr_genesis(old.clone())
            .await
            .is_err()
    );
    use coland_storage::DeliveryPolicyStoreRegistry as _;
    let owner = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    let old_document = organization_origin::history_document(&old.organization_log_entries, &[]);
    let head = owner
        .webvh()
        .get_document(fixture.organization_did.as_str())
        .await
        .unwrap()
        .unwrap()
        .key_log_head;
    assert_eq!(
        owner
            .webvh()
            .ingest_verified_history(head, old_document)
            .await
            .unwrap(),
        coland_storage::WebvhLogCommitOutcome::Conflict
    );
    assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
}

fn original_application(
    pool: coland_storage_postgres::PgPool,
) -> coland_services::authority_commit::AuthorityCommitApplication {
    coland_services::authority_commit::AuthorityCommitApplication::new(
        coland_services::persistence::PersistenceHandle::new(std::sync::Arc::new(
            coland_storage_postgres::PgPersistenceStore::new(pool),
        )),
        1024,
    )
}

#[tokio::test]
async fn organization_commit_rejects_missing_or_other_source_even_with_a_real_governor_signature() {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
    let lease = TestDatabase::lease().await;
    let pool = lease.pool();
    let mut fixture = OrganizationFixture::new(false, true);
    fixture.retain_current_histories(&pool).await;
    let store = PgActorProfileStore { pool: pool.clone() };
    let valid = fixture.write.clone();
    fixture.sign_candidate_fact(None);
    let missing = fixture.write.clone();
    fixture.write = valid.clone();
    let Some(HistoricalProducerSignerFact::OrganizationGenesis(mut other)) =
        fixture.write.transaction.producer_signer_fact.clone()
    else {
        panic!("real author did not bind the Org source")
    };
    other.approval_signatures.as_mut().unwrap()[0]
        .input
        .nonce
        .push_str("-another-source");
    fixture.sign_candidate_fact(Some(HistoricalProducerSignerFact::OrganizationGenesis(
        other,
    )));
    let different = fixture.write.clone();
    for write in [missing, different] {
        write
            .transaction
            .commit
            .verify_commit_id_matches_content()
            .unwrap();
        arkret_signatures::detached_object::verify_detached_object_signature(
            &write.transaction.commit.signature,
            &arkret_canonical::unsigned_value(&write.transaction.commit, &["signature"]).unwrap(),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: ed25519_dalek::SigningKey::from_bytes(&fixture.governor.did_key_seed)
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )
        .unwrap();
        let before = sql_fault_matrix::snapshot(&pool).await;
        assert!(store.admit_organization_pcr_genesis(write).await.is_err());
        assert_eq!(sql_fault_matrix::snapshot(&pool).await, before);
    }
    assert!(store.admit_organization_pcr_genesis(valid).await.is_ok());
}

#[tokio::test]
async fn public_bundle_and_cold_reader_project_the_one_atomic_native_source_without_another_fact_row()
 {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact;
    use arkret_wire::*;
    use chrono::Duration;
    for (delegated, quorum) in [(false, false), (false, true), (true, false)] {
        let lease = TestDatabase::lease().await;
        let pool = lease.pool();
        let fixture = OrganizationFixture::new(delegated, quorum);
        fixture.retain_current_histories(&pool).await;
        let store = PgActorProfileStore { pool: pool.clone() };
        let result = store
            .admit_organization_pcr_genesis(fixture.write.clone())
            .await
            .unwrap();
        let AuthoritySubmitResponseBody::Accepted { commit, .. } = result else {
            panic!("real native unit did not accept")
        };
        let event = &fixture.write.request.event_submission.event;
        let (_, projected) =
            arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
                &fixture.write.request,
                &fixture.write.source_service_id,
                &fixture.write.organization_log_entries,
                &fixture.write.organization_witness_records,
                fixture.write.producer_service_resolution.as_ref(),
                commit.committed_at,
            )
            .unwrap();
        assert_eq!(
            commit.producer_signer_fact_digest.as_ref(),
            Some(&projected.digest().unwrap())
        );
        let before = sql_fault_matrix::snapshot(&pool).await;
        for table in [
            "agent_producer_signer_keys",
            "realm_actor_private_signer_facts",
        ] {
            assert!(
                before[table].as_array().unwrap().is_empty(),
                "second Org source: {table}"
            );
        }
        let app = original_application(pool.clone());
        let original = app
            .producer_signer_fact(event, &commit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            original,
            HistoricalProducerSignerFact::OrganizationGenesis(projected.clone())
        );
        // The handoff inventory uses this same source reader for each original.
        let originals = app.handoff_originals(&event.realm_id, 0).await.unwrap();
        assert_eq!(originals.len(), 1);
        assert_eq!(originals[0].event, *event);
        assert_eq!(originals[0].commit, commit);
        assert_eq!(
            app.producer_signer_fact(&originals[0].event, &originals[0].commit)
                .await
                .unwrap(),
            Some(original.clone())
        );

        let at = commit.committed_at + Duration::seconds(1);
        let route = arkret_identity::build_authenticated_webvh_service_resolution(
            fixture.write.source_service_id.clone(),
            "station".into(),
            serde_json::from_value(fixture.governor.log_entry["state"].clone()).unwrap(),
            vec![fixture.governor.log_entry.clone()],
            vec![],
            at,
        )
        .unwrap();
        let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([73u8; 32])).unwrap();
        let request = RealmAuthorityBundleRequestBody {
            realm_id: event.realm_id.clone(),
            nonce: nonce.clone(),
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&fixture.governor.did_key_seed);
        let method = DidUrl::new(&fixture.governor.did_key_id).unwrap();
        let bundle = app
            .authority_bundle(
                &request,
                &fixture.write.source_service_id,
                serde_json::to_value(&route).unwrap(),
                method.clone(),
                &key,
                at,
            )
            .await
            .unwrap();
        assert_eq!(
            bundle.producer_signer_fact,
            Some(serde_json::to_value(&projected).unwrap())
        );
        assert_eq!(bundle.genesis_commit, commit);
        let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
        for time in [
            commit.signature.created_at,
            bundle.current_assertion.signature.created_at,
        ] {
            keys.insert_at(
                &method,
                time,
                arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            );
        }
        arkret_identity::verify_realm_authority_bundle(
            &bundle,
            &arkret_identity::RealmAuthorityFreshness::new(at, nonce),
            &keys,
        )
        .unwrap();
        let reopened = original_application(pool.clone());
        assert_eq!(
            reopened.producer_signer_fact(event, &commit).await.unwrap(),
            Some(original)
        );
        assert_eq!(
            sql_fault_matrix::snapshot(&pool).await,
            before,
            "projection wrote a second source"
        );
        // Destructive corruption follows genuine admission; it cannot be
        // covered by a cache row, a bare Commit or a hand-authored accepted row.
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("DELETE FROM organization_pcr_genesis_sources WHERE realm_id=$1")
            .bind::<diesel::sql_types::Text, _>(event.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert!(reopened.producer_signer_fact(event, &commit).await.is_err());
        assert!(
            reopened
                .authority_bundle(
                    &request,
                    &fixture.write.source_service_id,
                    serde_json::to_value(route).unwrap(),
                    method,
                    &key,
                    at
                )
                .await
                .is_err()
        );
    }
}
