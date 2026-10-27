//! Real SDK, DPoP, production router and accepted PostgreSQL Realm reads.
use arkret_models_collaboration::governance::realm_governance::RealmLinkDirection;
use arkret_wire::ActorId;

use super::*;

async fn bootstrap(
    session: &GrantSession,
    fixture: &PcrGenesisFixture,
) -> coland_storage::OrdinaryRealmBootstrapCommitUnit {
    let persistence = session.state.test_persistence();
    let mut unit = ordinary_realm::bootstrap_unit_for_account(
        &format!("realm-read-{}", uuid::Uuid::now_v7()),
        &fixture.history.account,
        &session.state.service_did(),
    );
    let identity = coland_test_support::fixture_service_identity(session.state.config());
    let key = SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        session.state.config(),
        &identity,
    ));
    let mut previous = None;
    for (index, tx) in unit.transactions.iter_mut().enumerate() {
        tx.event.producer_proof = None;
        tx.event = coland_test_support::signed_event::sign_fixture_event(
            tx.event.clone(),
            fixture.history.did.as_str(),
            fixture.history.founding_device_id.as_str(),
            fixture.history.founding_device_signing_seed,
        );
        tx.producer_signer_fact = persistence
            .authority_commits()
            .prepare_account_device_signer_fact(&tx.event, tx.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        tx.commit.producer_signer_fact_digest = tx
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        tx.commit.previous_commit_ref = previous;
        seal(&session.state, &key, &mut tx.commit);
        previous = Some(tx.commit.commit_id.clone());
        unit.submission.events[index] =
            arkret_wire::EventAdmissionSubmission::new(tx.event.clone());
    }
    unit.exact_request_body = arkret_canonical::canonical_json_bytes(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(unit.submission.clone())).unwrap();
    unit.validate().unwrap();
    persistence
        .authority_commits()
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
    unit
}
fn seal(state: &AppState, key: &SigningKey, commit: &mut arkret_wire::RealmCommit) {
    commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(
            &arkret_canonical::canonical::unsigned_value(commit, &["commit_id", "signature"])
                .unwrap(),
        )
        .unwrap(),
    ));
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(commit, &["signature"]).unwrap(),
        arkret_wire::DetachedSignatureContext::RealmCommit,
        arkret_wire::DidUrl::new(format!("{}#notary-key", state.service_did())).unwrap(),
        commit.committed_at,
        key,
    )
    .unwrap();
}
async fn next(
    session: &GrantSession,
    fixture: &PcrGenesisFixture,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: Value,
) -> coland_storage::EventCommitRequest {
    ordinary_realm::human_profile::register_fixture_signer(
        &fixture.history.account,
        fixture.history.device_verification_method.clone(),
        fixture.history.founding_device_signing_seed,
    );
    let persistence = session.state.test_persistence();
    let request = ordinary_realm::next_human_request_for_actor(
        previous,
        kind,
        ActorId::account(fixture.history.account.clone()),
        payload,
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let mut request = request;
    request.authority_commit.producer_signer_fact = persistence
        .authority_commits()
        .prepare_account_device_signer_fact(
            &request.authority_commit.event,
            request.authority_commit.commit.committed_at,
        )
        .await
        .unwrap()
        .map(Into::into);
    request.authority_commit.commit.producer_signer_fact_digest = request
        .authority_commit
        .producer_signer_fact
        .as_ref()
        .map(|fact| fact.digest().unwrap());
    let identity = coland_test_support::fixture_service_identity(session.state.config());
    let key = SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        session.state.config(),
        &identity,
    ));
    seal(&session.state, &key, &mut request.authority_commit.commit);
    Box::pin(persistence.commit_event(request.clone()))
        .await
        .unwrap();
    request
}
async fn publish_fixture_status(session: &GrantSession, fixture: &PcrGenesisFixture) {
    use arkret_models_collaboration::account_status::{
        UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
    };
    use arkret_signatures::account_status::{
        sign_account_status_receipt, sign_account_status_record, verify_account_status_record,
    };
    let identity = coland_test_support::fixture_service_identity(session.state.config());
    let key = SigningKey::from_bytes(&coland_test_support::fixture_signing_seed(
        session.state.config(),
        &identity,
    ));
    let method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", session.state.service_did())).unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let record = sign_account_status_record(
        UnsignedAccountStatusRecord {
            schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.into(),
            account_authority_id: fixture.history.account.station_id.clone(),
            account_id: fixture.history.account.clone(),
            principal_control_realm_id: fixture.unit.transactions[0].event.realm_id.clone(),
            binding_version: 1,
            status_sequence: 1,
            previous_account_status_record_id: None,
            status: arkret_models_collaboration::objects::account_status::AccountStatus::Active,
            reason_code: None,
            reason: None,
            issued_at: at,
            expires_at: None,
        },
        method.clone(),
        &key,
    )
    .unwrap();
    verify_account_status_record(
        &record,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().to_bytes().to_vec(),
        },
    )
    .unwrap();
    let receipt = sign_account_status_receipt(
        UnsignedAccountStatusReceipt {
            receipt_id: arkret_wire::ReceiptId::new(format!("ak:receipt:{}", uuid::Uuid::now_v7()))
                .unwrap(),
            account_status_record_id: record.account_status_record_id.clone(),
            record_digest: record.payload_digest().unwrap(),
            account_authority_id: record.account_authority_id.clone(),
            account_id: record.account_id.clone(),
            status_sequence: 1,
            receiver_id: session.state.service_core_id(),
            accepted_at: at,
            verification_method: method,
        },
        &key,
    )
    .unwrap();
    assert!(matches!(
        session
            .state
            .test_persistence()
            .account_status_replicas()
            .append(&record, &receipt)
            .await
            .unwrap(),
        coland_storage::AccountStatusReplicaAppend::Accepted(_)
    ));
}

fn sdk(base: &str, session: &GrantSession) -> arkret_http_client::Client {
    let key = session.holder_key.clone();
    arkret_http_client::Client::builder(url::Url::parse(base).unwrap())
        .allow_insecure_localhost()
        .auth(arkret_http_client::Auth::Dpop(
            arkret_http_client::DpopAuth::with_dpop_token(session.token.clone(), move |request| {
                arkret_signatures::dpop::build_dpop_proof(&request, &key)
                    .map(|proof| proof.header_value)
                    .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
            }),
        ))
        .build()
        .unwrap()
}
#[tokio::test]
async fn sdk_realm_reads_enforce_visibility_and_use_durable_lifecycle_after_cold_state() {
    Box::pin(async {
        use salvo::conn::Listener;
        let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0").try_bind().await.unwrap();
        let base = format!("http://{}", acceptor.local_addr().unwrap());
        let mut config = test_config(); config.public_base_url = base.clone();
        let did = coland_test_support::fixture_service_identity(&config).identity().unwrap().did.clone();
        let fixture = PcrGenesisFixture::new(did.clone());
        let session = Box::pin(account_grant_session_at(&fixture, Some(base.clone()))).await;
        let unit = Box::pin(bootstrap(&session, &fixture)).await;
        let realm = unit.transactions[0].event.realm_id.clone();
        let other = PcrGenesisFixture::new(did);
        Box::pin(other.admit(&session.state)).await.unwrap();
        let hidden_unit = Box::pin(bootstrap(&session, &other)).await;
        let hidden = hidden_unit.transactions[0].event.realm_id.clone();
        let store = session.state.test_persistence();
        let alien = ActorId::account(arkret_wire::AccountId::new(fixture.history.account.principal_id.clone(), arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap()));
        assert!(store.authority_commits().realm_lifecycle_for_actor(&realm, &alien).await.unwrap().is_none());
        let link = Box::pin(next(&session, &fixture, unit.transactions.last().unwrap(), EventKind::RealmLink, json!({"target_realm_id":hidden,"link_kind":"governed_by","status":"active","label":"explicit source reference"}))).await;
        let inbound = Box::pin(next(&session, &other, hidden_unit.transactions.last().unwrap(), EventKind::RealmLink, json!({"target_realm_id":realm,"link_kind":"governed_by","status":"active","label":"private inbound source"}))).await;
        let frozen = Box::pin(next(&session, &fixture, &link.authority_commit, EventKind::RealmFreeze, json!({}))).await;
        Box::pin(publish_fixture_status(&session,&fixture)).await;
        let cold_state = Box::pin(coland_test_support::app_state_with_persistence(session.state.config().clone(), store.clone())).await;
        let cold_state = cold_state.with_local_account_authority(session.authority.clone()).unwrap();
        let session = GrantSession { state:cold_state, token:session.token, holder_key:session.holder_key, authority:session.authority };
        let state = session.state.clone();
        let server = tokio::spawn(async move { salvo::Server::new(acceptor).serve(service(state)).await; });
        let client = sdk(&base, &session);
        let view = client.realm_get(&realm).await.unwrap();
        assert!(view.frozen); assert!(!view.archived); assert!(!view.deleted);
        assert_eq!(view.member_ids, vec![ActorId::account(fixture.history.account.clone())]);
        assert!(client.realm_links_list(&realm, RealmLinkDirection::Inbound, None).await.unwrap().links.is_empty());
        let outbound = client.realm_links_list(&realm, RealmLinkDirection::Outbound, None).await.unwrap();
        assert_eq!(outbound.links.len(), 1); assert_eq!(outbound.links[0].target_realm_id, hidden);
        let unknown = arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7").unwrap();
        for result in [client.realm_get(&unknown).await.map(|_| ()), client.realm_export(&unknown).await.map(|_| ()), client.realm_links_list(&unknown, RealmLinkDirection::Both, None).await.map(|_| ()), client.realm_get(&hidden).await.map(|_| ()), client.realm_export(&hidden).await.map(|_| ()), client.realm_links_list(&hidden, RealmLinkDirection::Both, None).await.map(|_| ())] {
            assert!(matches!(result, Err(arkret_http_client::Error::Api { status:404, .. })), "{result:?}");
        }
        let export = client.realm_export(&realm).await.unwrap();
        assert!(export.events.iter().any(|row| row.get("event_kind")==Some(&json!("ak.realm.freeze"))));
        assert!(export.events.iter().all(|row| row.get("realm_id").is_none_or(|id| id == &json!(realm))));
        use arkret_models_collaboration::governance::membership_invite::{MembershipPayload, MembershipPayloadState};
        let reader = ActorId::account(fixture.history.account.clone());
        let joined = Box::pin(next(&session,&fixture,&inbound.authority_commit,EventKind::MemberState,MembershipPayload::join(hidden.clone(),reader.clone(),"explicit reader join").to_value().unwrap())).await;
        let hidden_view = client.realm_get(&hidden).await.unwrap();
        assert!(hidden_view.member_ids.contains(&reader));
        assert!(client.realm_links_list(&realm,RealmLinkDirection::Inbound,None).await.unwrap().links.is_empty(), "join must not reveal a link Event before its history floor");
        let hidden_export = client.realm_export(&hidden).await.unwrap();
        assert!(hidden_export.events.iter().all(|row| row.get("event_kind")!=Some(&json!("ak.realm.link"))));
        let observation = store.account_status_replicas().current(fixture.history.account.station_id.as_str(), &fixture.history.account).await.unwrap().map(coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve).unwrap();
        let input = coland_storage::AccountContentDeliveryInput { realms:vec![realm.clone()], realm_lifecycle_reads:vec![view.clone()], realm_link_reads:vec![(outbound.clone(),None)], realm_exports:vec![export.clone()], credential_expires_at:Some(chrono::Utc::now()+chrono::Duration::seconds(30)), account_status_observations:vec![observation.clone()], ..Default::default() };
        let guard = Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account, &session.state.service_core_id(), &input)).await.unwrap().expect("ordinary reads retain an actual delivery transaction");
        assert!(guard.permits_handoff());
        let blocked = tokio::time::timeout(std::time::Duration::from_millis(100), Box::pin(next(&session,&fixture,&frozen.authority_commit,EventKind::RealmUnfreeze,json!({})))).await;
        assert!(blocked.is_err(), "lifecycle writer must wait for the response cut");
        guard.finish().await.unwrap();
        let reopened = Box::pin(next(&session,&fixture,&frozen.authority_commit,EventKind::RealmUnfreeze,json!({}))).await;
        assert!(Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account, &session.state.service_core_id(), &input)).await.is_err(), "stale lifecycle/export must not be delivered");
        assert!(!client.realm_get(&realm).await.unwrap().frozen);
        let mut stale_links = input.clone(); stale_links.realm_lifecycle_reads.clear(); stale_links.realm_exports.clear();
        let changed = Box::pin(next(&session,&fixture,&reopened.authority_commit,EventKind::RealmLink,json!({"target_realm_id":hidden,"link_kind":"governed_by","status":"rejected","label":"withdrawn secret edge"}))).await;
        assert!(Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account, &session.state.service_core_id(), &stale_links)).await.is_err(), "stale link must not be delivered");
        let current = client.realm_get(&realm).await.unwrap();
        let expiring = coland_storage::AccountContentDeliveryInput { realms:vec![realm.clone()], realm_lifecycle_reads:vec![current], credential_expires_at:Some(chrono::Utc::now()+chrono::Duration::seconds(2)), account_status_observations:vec![observation.clone()], ..Default::default() };
        let guard = Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account, &session.state.service_core_id(), &expiring)).await.unwrap().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert!(!guard.permits_handoff(), "physical credential expiry must refuse the body");
        guard.finish().await.unwrap();
        let hidden_input = coland_storage::AccountContentDeliveryInput { realms:vec![hidden.clone()], realm_lifecycle_reads:vec![hidden_view], realm_exports:vec![hidden_export], account_status_observations:vec![observation], credential_expires_at:Some(chrono::Utc::now()+chrono::Duration::seconds(30)), ..Default::default() };
        let held = Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account,&session.state.service_core_id(),&hidden_input)).await.unwrap().unwrap(); held.finish().await.unwrap();
        let _left = Box::pin(next(&session,&fixture,&joined.authority_commit,EventKind::MemberState,MembershipPayload::transition(MembershipPayloadState::Leave,reader,"reader left").with_realm_id(hidden.clone()).to_value().unwrap())).await;
        assert!(Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account,&session.state.service_core_id(),&hidden_input)).await.is_err(), "accepted membership loss must refuse stale full output");
        assert!(matches!(client.realm_get(&hidden).await,Err(arkret_http_client::Error::Api{status:404,..})));
        let before_withdrawal = client.realm_links_list(&realm,RealmLinkDirection::Outbound,None).await.unwrap();
        assert_eq!(before_withdrawal.links[0].label.as_deref(),Some("withdrawn secret edge"));
        let withdrawal_input = coland_storage::AccountContentDeliveryInput { realms:vec![realm.clone()], realm_link_reads:vec![(before_withdrawal,None)], account_status_observations:hidden_input.account_status_observations.clone(), credential_expires_at:hidden_input.credential_expires_at, ..Default::default() };
        let withdrawal = coland_storage::RetentionTombstoneRecord { event_id:changed.authority_commit.event.event_id.to_string(), realm_id:realm.to_string(), reason:"expired".into(), policy_ttl_seconds:1, expired_at:changed.authority_commit.event.created_at+chrono::Duration::seconds(1), tombstoned_at:chrono::Utc::now(), sealed:true };
        let held = Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account,&session.state.service_core_id(),&withdrawal_input)).await.unwrap().unwrap();
        let writer_store = store.clone(); let writer_record = withdrawal.clone();
        let writer = tokio::spawn(async move { writer_store.retention_tombstones().put(&writer_record).await });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!writer.is_finished(), "withdrawal must wait for the actual read body cut");
        held.finish().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5),writer).await.unwrap().unwrap().unwrap();
        let mut wrong_realm = withdrawal.clone(); wrong_realm.realm_id = hidden.to_string();
        assert!(store.retention_tombstones().put(&wrong_realm).await.is_err(), "withdrawal cannot lock another Realm than its Event");
        assert!(client.realm_links_list(&realm,RealmLinkDirection::Outbound,None).await.unwrap().links.is_empty());
        assert!(Box::pin(store.authority_commits().acquire_committed_content_delivery(&fixture.history.account,&session.state.service_core_id(),&withdrawal_input)).await.is_err());
        let withdrawn_export = client.realm_export(&realm).await.unwrap();
        let withheld = withdrawn_export.events.iter().find(|row| row.get("commit").and_then(|commit|commit.get("commit_id"))==Some(&json!(changed.authority_commit.commit.commit_id))).unwrap();
        assert_eq!(withheld.get("event_disclosure"),Some(&json!({"status":"withheld"}))); assert!(!withheld.contains_key("payload"));
        assert!(!serde_json::to_string(&withdrawn_export).unwrap().contains("withdrawn secret edge"));
        let tombstone = arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload { reason:"replaced in fixture".into(), successor_realm_id:hidden.clone(), replacement_event_id:None };
        let _terminal = Box::pin(next(&session,&fixture,&changed.authority_commit,EventKind::RealmTombstone,serde_json::to_value(tombstone).unwrap())).await;
        let terminal = client.realm_get(&realm).await.unwrap();
        assert!(terminal.deleted); assert_eq!(terminal.terminal_state.as_deref(),Some("tombstoned")); assert_eq!(terminal.successor_realm_id,Some(hidden));
        server.abort(); let _ = server.await;
    }).await;
}
