//! Real forwarded Human device evidence freezes with the first governance Commit.
#[path = "support/historical_human.rs"]
mod historical_human;
use coland_storage::{EventCommitUnitOfWork, ForwardedProducerDeviceEvidence, PersistenceStore};
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgPersistenceStore, PgPool};
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl;

async fn evidence_rows(pool: &PgPool) -> Vec<(String, String)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        commit_id: String,
        #[diesel(sql_type = Text)]
        evidence_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT commit_id,evidence_ref FROM forwarded_producer_device_evidence ORDER BY commit_id",
    )
    .load::<Row>(&mut conn)
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.commit_id, row.evidence_ref))
    .collect()
}

async fn commit_count(pool: &PgPool, commit_id: &str) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT count(*) AS count FROM realm_commits WHERE commit_id=$1")
        .bind::<Text, _>(commit_id)
        .get_result::<Count>(&mut conn)
        .await
        .unwrap()
        .count
}

#[tokio::test]
async fn forwarded_evidence_is_retained_with_the_first_commit_or_not_at_all() {
    let mut source_config = coland_test_support::app_config();
    source_config.public_base_url = "https://forward-evidence-governance.example".into();
    let (source_state, pool) = coland_test_support::app_state_with_pool(source_config);
    let mut origin_config = coland_test_support::app_config();
    origin_config.public_base_url = "https://forward-evidence-origin.example".into();
    let (origin_state, origin_pool) = coland_test_support::app_state_with_pool(origin_config);
    let governing = historical_human::HumanFixture::new(&pool, source_state.service_did()).await;
    governing.admit(&pool).await;
    let origin =
        historical_human::HumanFixture::new(&origin_pool, origin_state.service_did()).await;
    let previous = governing.unit.transactions.last().unwrap();
    let actor = arkret_wire::ActorId::account(origin.pcr.history.account.clone());
    let event = historical_human::signed_ordinary_event(
        &origin,
        previous,
        arkret_wire::EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,"membership":"join"}),
        previous.commit.committed_at + chrono::TimeDelta::seconds(1),
    );
    let mut request =
        historical_human::request_for_event(&origin, previous, event, previous.commit.committed_at);
    let evidence = coland_http::test_fresh_producer_device_evidence(
        &origin_state,
        &request.authority_commit.event,
        &governing.pcr.history.account.station_id,
    )
    .await
    .unwrap()
    .unwrap();
    let core = &evidence.device_projection_attestation.attestation;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_human_signer_fact(
        &evidence,
        &request.authority_commit.event,
        &origin.pcr.history.account.station_id,
        &governing.pcr.history.account.station_id,
        &core.event_authorization.forward_body_digest,
        arkret_canonical::DigestSuite::Sha256,
        core.attested_at,
    )
    .unwrap()
    .into_fact();
    request.authority_commit.producer_signer_fact = Some(fact.clone().into());
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.commit.committed_at = core.attested_at;
    request.self_producer_guard = None;
    let retained = ForwardedProducerDeviceEvidence::new(evidence, fact).unwrap();
    request.forwarded_producer_evidence = Some(retained.clone());
    request.realm_fanout_source = Some(arkret_wire::EventAdmissionSubmission::new(
        request.authority_commit.event.clone(),
    ));
    historical_human::seal_commit(
        &mut request.authority_commit.commit,
        &governing.pcr.history.station_did,
    );
    let origin_store = PgPersistenceStore::new(origin_pool.clone());
    let source = origin_store
        .account_device_signer_evidence()
        .forwarded_bound_human_signer_fact(
            &request.authority_commit.event,
            &request.authority_commit.commit,
            &governing.pcr.history.account.station_id,
        )
        .await
        .unwrap();
    assert_eq!(source.as_ref(), Some(&retained.producer_signer_fact));
    let mut wrong = request.authority_commit.commit.clone();
    wrong.producer_signer_fact_digest = None;
    assert!(
        origin_store
            .account_device_signer_evidence()
            .forwarded_bound_human_signer_fact(
                &request.authority_commit.event,
                &wrong,
                &governing.pcr.history.account.station_id,
            )
            .await
            .unwrap()
            .is_none()
    );
    wrong = request.authority_commit.commit.clone();
    wrong.event_ref = previous.event.event_id.clone();
    assert!(
        origin_store
            .account_device_signer_evidence()
            .forwarded_bound_human_signer_fact(
                &request.authority_commit.event,
                &wrong,
                &governing.pcr.history.account.station_id,
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        origin_store
            .account_device_signer_evidence()
            .forwarded_bound_human_signer_fact(
                &request.authority_commit.event,
                &request.authority_commit.commit,
                &origin.pcr.history.account.station_id,
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        origin_store
            .authority_commits()
            .replica_anchor_for_stream(&request.authority_commit.commit.stream_ref,)
            .await
            .unwrap()
            .is_none()
    );
    let commit_id = request.authority_commit.commit.commit_id.to_string();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut mismatched = request.clone();
    mismatched
        .forwarded_producer_evidence
        .as_mut()
        .unwrap()
        .evidence
        .device_projection_attestation
        .attestation
        .device_id =
        arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-00000000e0a2").unwrap();
    assert!(uow.commit_event(mismatched).await.is_err());
    assert_eq!(commit_count(&pool, &commit_id).await, 0);
    assert!(evidence_rows(&pool).await.is_empty());
    let mut both = request.clone();
    both.self_producer_guard = Some(coland_storage::SelfProducerCommitGuard::HumanDevice(
        origin.guard.clone(),
    ));
    assert!(uow.commit_event(both).await.is_err());
    assert_eq!(commit_count(&pool, &commit_id).await, 0);
    assert!(evidence_rows(&pool).await.is_empty());
    uow.commit_event(request.clone()).await.unwrap();
    let rows = evidence_rows(&pool).await;
    assert_eq!(
        rows,
        vec![(
            commit_id,
            serde_json::to_value(&retained.evidence_ref)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        )]
    );
    uow.commit_event(request).await.unwrap();
    assert_eq!(evidence_rows(&pool).await, rows);
}
