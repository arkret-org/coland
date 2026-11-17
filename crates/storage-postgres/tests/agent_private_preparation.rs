//! Pairing cache atomicity uses an actually admitted controller and Agent source.
use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentProvisionComplete, AgentProvisionCompleteStatus,
    AgentProvisionResponseBody,
};
use arkret_wire::{ActorId, DidUrl, OpaqueLocalId};
use chrono::{Duration, Utc};
use coland_storage::{
    AgentPrincipalRecord, AgentStore, IdempotencyRecord, IdentityStoreRegistry as _,
};
use coland_storage_postgres::{PgAgentStore, PgPersistenceStore};
use coland_test_support::agent_origin::OriginFixture;
use diesel::sql_query;
use diesel::sql_types::Text;
use horme::RunQueryDsl;

async fn fixture() -> OriginFixture {
    let fixture = Box::pin(OriginFixture::new()).await;
    let persistence = PgPersistenceStore::new(fixture.pool.clone());
    let owner = &fixture.controller.history.account;
    persistence
        .accounts()
        .put(&coland_storage::AccountRecord {
            pk: coland_storage::AccountPk(0),
            principal_id: owner.principal_id.clone(),
            station_id: owner.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: fixture.controller.history.commits[0].committed_at,
        })
        .await
        .unwrap();
    fixture.stage(&fixture.provision).await;
    fixture.admit_provision().await;
    fixture.stage(&fixture.genesis).await;
    fixture.admit_genesis().await.unwrap();
    fixture
}

fn candidate(fixture: &OriginFixture, label: &str) -> (AgentPrincipalRecord, IdempotencyRecord) {
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let authority: DidUrl = serde_json::from_value(
        fixture.provision.event.payload["controller_authorization_ref"].clone(),
    )
    .unwrap();
    let mut principal = AgentPrincipalRecord::new(
        fixture.agent.principal_id.to_string(),
        fixture.controller.history.account.principal_id.to_string(),
        fixture.genesis.event.realm_id.to_string(),
        authority.clone(),
        AgentLifecycleState::Active,
        now,
    );
    let pairing = OpaqueLocalId::new(format!("pairing-{label}")).unwrap();
    principal.pairing_request_id = Some(pairing.clone());
    principal.pairing_code = Some(label.into());
    principal.pairing_expires_at = Some(now + Duration::minutes(5));
    let outcome = AgentProvisionResponseBody::Complete(AgentProvisionComplete {
        status: AgentProvisionCompleteStatus::Complete,
        agent_id: fixture.agent.principal_id.clone(),
        did: fixture.agent_did.clone(),
        initial_resolution: serde_json::from_value(
            fixture.genesis.event.payload["object"]["initial_resolution"].clone(),
        )
        .unwrap(),
        principal_control_realm_id: fixture.genesis.event.realm_id.clone(),
        controller_authorization_ref: authority,
        pairing_request_id: pairing,
        pairing_code: principal.pairing_code.clone(),
        expires_at: principal.pairing_expires_at.unwrap(),
    });
    let record = IdempotencyRecord {
        authenticated_actor: ActorId::account(fixture.controller.history.account.clone()),
        operation_id: "ak.self.agent.command.provision".into(),
        idempotency_key: "same-original-request".into(),
        request_hash: arkret_canonical::sha256_digest(b"one-canonical-provision-request"),
        response_status: 200,
        response_body: serde_json::to_value(outcome).unwrap(),
        created_at: now,
        expires_at: now + Duration::days(30),
    };
    (principal, record)
}

#[tokio::test]
async fn real_source_pairing_concurrency_keeps_the_first_handle_and_exact_outcome_together() {
    let fixture = Box::pin(fixture()).await;
    let store = PgAgentStore {
        pool: fixture.pool.clone(),
    };
    let (left, left_record) = candidate(&fixture, "left-code");
    let (right, right_record) = candidate(&fixture, "right-code");
    let (a, b) = tokio::join!(
        store.put_pairing_preparation(left, &left_record),
        store.put_pairing_preparation(right, &right_record)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a, b);
    let original = store
        .get(fixture.agent.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    let body: AgentProvisionResponseBody = serde_json::from_value(a.response_body.clone()).unwrap();
    let AgentProvisionResponseBody::Complete(body) = body else {
        panic!("complete actual outcome expected")
    };
    assert_eq!(original.pairing_request_id, Some(body.pairing_request_id));
    assert_eq!(original.pairing_code, body.pairing_code);
    assert_eq!(original.pairing_expires_at, Some(body.expires_at));
    let (mut late, record) = candidate(&fixture, "late-unrelated-code");
    late.pairing_code = Some("must-not-replace-original".into());
    assert_eq!(
        store.put_pairing_preparation(late, &record).await.unwrap(),
        a
    );
    assert_eq!(
        store
            .get(fixture.agent.principal_id.as_str())
            .await
            .unwrap()
            .unwrap()
            .pairing_code,
        original.pairing_code
    );
}

#[tokio::test]
async fn accepted_agent_source_survives_controller_terminal_state_without_private_pairing_recreation()
 {
    let fixture = Box::pin(fixture()).await;
    let store = PgAgentStore {
        pool: fixture.pool.clone(),
    };
    let (principal, record) = candidate(&fixture, "old-code");
    store
        .put_pairing_preparation(principal.clone(), &record)
        .await
        .unwrap();
    let owner = &fixture.controller.history.account;
    let mut conn = fixture.pool.get().await.unwrap();
    sql_query("WITH held AS MATERIALIZED(SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE) INSERT INTO account_lifecycle(account_pk,state,changed_at) SELECT pk,'erasure_pending',NOW() FROM held")
        .bind::<Text,_>(owner.principal_id.as_str()).bind::<Text,_>(owner.station_id.as_str()).execute(&mut *conn).await.unwrap();
    drop(conn);
    assert_eq!(
        store
            .controller_account(fixture.agent.principal_id.as_str())
            .await
            .unwrap(),
        Some(owner.clone())
    );
    assert_eq!(
        store
            .put_pairing_preparation(principal.clone(), &record)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::AccountErased)
    );
    // A previously accepted public projection may finish, while its private
    // pairing adjunct is removed rather than resurrected by the callback.
    store.put_accepted_projection(principal).await.unwrap();
    let retained = store
        .get(fixture.agent.principal_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert!(retained.pairing_request_id.is_none());
    assert!(retained.pairing_code.is_none());
    assert!(retained.provision_event_refs.is_none());
    assert_eq!(retained.id, fixture.agent.principal_id.as_str());
    assert_eq!(
        retained.principal_control_realm_id,
        fixture.genesis.event.realm_id.as_str()
    );
}
