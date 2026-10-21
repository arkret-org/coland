//! A Realm subject uses its Realm governor, never an Account-origin forwarding proof.
use super::*;

async fn account_forward_archive(fixture: &Fixture) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut connection = fixture.pool.get().await.unwrap();
    diesel::sql_query("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY evidence_ref),'[]'::jsonb) AS value FROM account_device_signer_evidence r")
        .get_result::<Row>(&mut connection).await.unwrap().value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn realm_subject_cannot_be_forwarded_as_an_account_device() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        let fixture = &context.fixture;
        let destination: arkret_wire::DidCoreId =
            "ak:did_core:web:unrelated.example".parse().unwrap();
        let before = account_forward_archive(fixture).await;
        for (authority, key, grant) in &context.actors {
            assert!(authority.actor_id.as_realm_actor_id().is_some());
            let event = native_message(
                fixture,
                &context.install,
                authority,
                key,
                grant,
                &context.strand,
                "Realm actor has no Account origin",
            );
            let result = coland_http::test_fresh_producer_forward_request(
                &fixture.state,
                &event,
                &destination,
            )
            .await;
            let request = result.unwrap();
            assert!(request.producer_device_evidence.is_none());
            assert!(request.producer_agent_evidence.is_none());
            assert_eq!(before, account_forward_archive(fixture).await);
        }
    }))
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn realm_device_address_cannot_swap_owning_realm_or_use_account_branch() {
    tokio::spawn(native_phase(|| async {
        let context = native_phase(native_sources_setup).await;
        let fixture = &context.fixture;
        for (authority, key, grant) in &context.actors {
            let original = native_message(
                fixture,
                &context.install,
                authority,
                key,
                grant,
                &context.strand,
                "complete Realm address",
            );
            let mut other_realm = authority.actor_id.as_realm_actor_id().unwrap().clone();
            other_realm.realm_id =
                RealmId::from_event_id(&fixture.pcr.unit.transactions[1].event.event_id);
            let account = arkret_wire::AccountId {
                principal_id: authority.actor_id.signing_principal_id().clone(),
                station_id: fixture.state.service_core_id(),
            };
            for actor in [ActorId::realm(other_realm), ActorId::account(account)] {
                let mut metadata = managed_device_metadata(authority);
                metadata.actor_id = actor;
                // The closed Realm-only header rejects an Account before transmission.
                if metadata.actor_id.as_account_id().is_some() {
                    assert!(metadata.to_header_value().is_err());
                    continue;
                }
                let before = business(fixture).await;
                let body = creation_submission(original.clone());
                let mut response = managed_device_http_request_body(
                    &fixture.state,
                    authority,
                    &metadata,
                    ServiceOperationId::SelfEventsCommandSubmitV1,
                    key,
                    Some(arkret_canonical::canonical_json_bytes(&body).unwrap()),
                )
                .send(&service(fixture.state.clone()))
                .await;
                let status = response.status_code.unwrap();
                let result: Value = response.take_json().await.unwrap();
                assert!(
                    !status.is_success(),
                    "wrong owning Realm accepted: {result}"
                );
                assert_eq!(before, business(fixture).await);
            }
        }
    }))
    .await
    .unwrap();
}
