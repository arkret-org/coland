//! Real production prepare consumer and finite two-record PG contract.
//! These are post-authentication handler-port tests with actual accepted
//! Account/Device/PCR originals, not browser login or Contact acceptance.

use coland_storage::{IdempotencyStore as _, IdentityStoreRegistry as _};
use coland_storage_postgres::PgIdempotencyStore;
use diesel::sql_types::{BigInt, Text};
use diesel_async::RunQueryDsl as _;
use futures_util::FutureExt as _;

use super::*;
use crate::routing::identity::contact_federation::pg_contracts::{admit_peer, fixture_and_state};

const OPERATION: &str = "org.arkret.coland.contact.prepare.v1";

async fn session(fixture: &coland_test_support::agent_origin::OriginFixture) -> SessionRecord {
    let account = &fixture.controller.history.account;
    let store = coland_storage_postgres::PgPersistenceStore::new(fixture.pool.clone());
    let actual = store.accounts().get(account).await.unwrap().unwrap();
    SessionRecord {
        token_hash: "contact-handler-port".into(),
        account_pk: Some(actual.pk),
        actor: account.principal_id.to_string(),
        endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
            device_id: fixture.controller.history.founding_device_id.to_string(),
        },
        audience: account.station_id.to_string(),
        session_public_key: None,
        session_grant: None,
        expires_at: now() + chrono::Duration::minutes(10),
        created_at: now(),
        revoked_at: None,
    }
}

fn command(peer: ContactPeer) -> ContactPrepareRequestBody {
    ContactPrepareRequestBody {
        phase: ContactPreparePhase::Prepare,
        operation_id: ProtocolOperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("contact-prepare-{}", uuid::Uuid::now_v7()))
            .unwrap(),
        peer,
        granted_to_peer_scopes: vec![ContactScope::Presence],
        introduction_evidence: ContactIntroductionEvidence::SameStation,
        message: Some("private Contact preparation".into()),
    }
}

fn branch(body: &ContactPrepareRequestBody) -> ContactReservationBranch {
    ContactReservationBranch::Request {
        peer: body.peer.clone(),
        granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
        initial_contact_round_id: None,
        introduction_evidence: Box::new(body.introduction_evidence.clone()),
    }
}

fn payload(state: &AppState, body: &ContactPrepareRequestBody) -> ContactRequestedPayload {
    ContactRequestedPayload {
        trust_domain_id: state.config().trust_domain.clone(),
        initial_contact_round_id: None,
        version: 1,
        predecessor_event_ref: None,
        peer: body.peer.clone(),
        granted_to_peer_scopes: body.granted_to_peer_scopes.clone(),
        introduction_evidence_digest: contact_hash(
            "ak.contact.introduction-evidence.v1",
            &body.introduction_evidence,
        )
        .unwrap(),
        message: body.message.clone(),
    }
}

async fn context(
    state: &AppState,
    session: &SessionRecord,
    body: &ContactPrepareRequestBody,
) -> PrepareContext<arkret_wire::event_spec::ContactRequested> {
    let (context, replay) = prepare_context::<arkret_wire::event_spec::ContactRequested, _>(
        state,
        session,
        body,
        &body.idempotency_key,
        &body.peer,
    )
    .await
    .unwrap();
    assert!(replay.is_none());
    context
}

#[tokio::test]
async fn production_contact_prepare_concurrent_new_reservations_return_the_one_durable_original() {
    let (fixture, state) = Box::pin(fixture_and_state()).await;
    let peer = Box::pin(admit_peer(&fixture, 151)).await;
    let session = session(&fixture).await;
    let body = command(ContactPeer::Human {
        account_id: peer.history.account.clone(),
    });
    // Both real preflights observe no outcome before either handler authors
    // its own random reservation. The actual PG port selects the winner.
    let (left_context, right_context) = tokio::join!(
        context(&state, &session, &body),
        context(&state, &session, &body)
    );
    let (left, right) = tokio::join!(
        prepare::<arkret_wire::event_spec::ContactRequested>(
            &state,
            &session,
            left_context,
            body.operation_id.clone(),
            body.idempotency_key.clone(),
            branch(&body),
            payload(&state, &body)
        ),
        prepare::<arkret_wire::event_spec::ContactRequested>(
            &state,
            &session,
            right_context,
            body.operation_id.clone(),
            body.idempotency_key.clone(),
            branch(&body),
            payload(&state, &body)
        ),
    );
    let left = left.unwrap().0;
    let right = right.unwrap().0;
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&left).unwrap(),
        arkret_canonical::canonical_json_bytes(&right).unwrap()
    );
    let actor = ActorId::account(fixture.controller.history.account.clone());
    let store = PgIdempotencyStore {
        pool: fixture.pool.clone(),
    };
    let primary = store
        .get(
            &actor,
            OPERATION,
            &contact_phase_idempotency_key("prepare", &body.idempotency_key),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.response_body, serde_json::to_value(&left).unwrap());
    let ContactOperationResponseBody::Prepared {
        outcome:
            ContactPreparedResponseBody::Request {
                reservation_handle,
                event_draft,
                ..
            },
    } = &left
    else {
        panic!("request preparation must retain its typed outcome")
    };
    let context = store
        .get(
            &actor,
            OPERATION,
            &contact_reservation_key(reservation_handle),
        )
        .await
        .unwrap()
        .unwrap();
    let retained: ContactReservation = serde_json::from_value(context.response_body).unwrap();
    assert_eq!(retained.reservation_handle, *reservation_handle);
    assert_eq!(
        serde_json::to_value(prepared_outcome(&retained)).unwrap(),
        primary.response_body
    );
    assert_eq!(retained.branch.peer(), &body.peer);
    assert_eq!(
        retained.event_draft.event_id().unwrap(),
        event_draft.event_id().unwrap()
    );
    assert_eq!(
        retained
            .event_draft
            .unsigned_event()
            .unwrap()
            .event()
            .actor_id,
        actor
    );
    assert_eq!(
        retained
            .event_draft
            .unsigned_event()
            .unwrap()
            .event()
            .scope_ref
            .realm_id_opt(),
        Some(&fixture.controller.history.events[0].realm_id)
    );
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        value: i64,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let count = diesel::sql_query(
        "SELECT COUNT(*) AS value FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2",
    )
    .bind::<Text, _>(actor.canonical_key().unwrap())
    .bind::<Text, _>(OPERATION)
    .get_result::<Count>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        count.value, 2,
        "a losing reservation must not create its context row"
    );
    drop(conn);
    let replay = request(
        &state,
        &session,
        ContactOperationRequestBody::Prepare(body.clone()),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(serde_json::to_value(replay).unwrap(), primary.response_body);
    let mut changed = body.clone();
    changed.message = Some("different private intent under the same wire key".into());
    let conflict = request(
        &state,
        &session,
        ContactOperationRequestBody::Prepare(changed),
    )
    .await
    .unwrap_err();
    assert_eq!(conflict.code, crate::error::ErrorCode::DuplicateConflict);
    assert_eq!(conflict.http_status().as_u16(), 409);
    assert_eq!(
        store
            .get(&actor, OPERATION, &primary.idempotency_key)
            .await
            .unwrap()
            .unwrap(),
        primary
    );
}

#[tokio::test]
async fn production_contact_prepare_context_insert_failure_rolls_back_both_rows() {
    let (fixture, state) = Box::pin(fixture_and_state()).await;
    let peer = Box::pin(admit_peer(&fixture, 161)).await;
    let session = session(&fixture).await;
    let body = command(ContactPeer::Human {
        account_id: peer.history.account.clone(),
    });
    let context = context(&state, &session, &body).await;
    let actor = ActorId::account(fixture.controller.history.account.clone());
    let actor_literal = actor.canonical_key().unwrap().replace('\'', "''");
    let result = std::panic::AssertUnwindSafe(async {
        let mut conn = fixture.pool.get().await.unwrap();
        diesel::sql_query(format!("CREATE FUNCTION contact_preparation_owned_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor_key='{actor_literal}' AND NEW.operation_id='{OPERATION}' AND starts_with(NEW.idempotency_key,'contact-reservation:') THEN RAISE EXCEPTION 'owned context insert fault' USING ERRCODE='40001'; END IF; RETURN NEW; END; $$"))
            .execute(&mut *conn).await.unwrap();
        diesel::sql_query("CREATE TRIGGER contact_preparation_owned_fault BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION contact_preparation_owned_fault()")
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        let error = prepare::<arkret_wire::event_spec::ContactRequested>(&state, &session, context, body.operation_id.clone(), body.idempotency_key.clone(), branch(&body), payload(&state, &body)).await.unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::TemporarilyUnavailable);
        assert_eq!(error.http_status().as_u16(), 503);
        let store = PgIdempotencyStore { pool: fixture.pool.clone() };
        assert!(store.get(&actor, OPERATION, &contact_phase_idempotency_key("prepare", &body.idempotency_key)).await.unwrap().is_none());
        #[derive(diesel::QueryableByName)]
        struct Count { #[diesel(sql_type = BigInt)] value: i64 }
        let mut conn = fixture.pool.get().await.unwrap();
        let count = diesel::sql_query("SELECT COUNT(*) AS value FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2")
            .bind::<Text,_>(actor.canonical_key().unwrap()).bind::<Text,_>(OPERATION).get_result::<Count>(&mut *conn).await.unwrap();
        assert_eq!(count.value, 0, "the first insert must roll back with the failed context");
    }).catch_unwind().await;
    let mut conn = fixture.pool.get().await.unwrap();
    diesel::sql_query("DROP TRIGGER IF EXISTS contact_preparation_owned_fault ON idempotency_keys")
        .execute(&mut *conn)
        .await
        .unwrap();
    diesel::sql_query("DROP FUNCTION IF EXISTS contact_preparation_owned_fault()")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    let recovered = request(
        &state,
        &session,
        ContactOperationRequestBody::Prepare(body.clone()),
    )
    .await
    .unwrap()
    .0;
    let replay = request(&state, &session, ContactOperationRequestBody::Prepare(body))
        .await
        .unwrap()
        .0;
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&recovered).unwrap(),
        arkret_canonical::canonical_json_bytes(&replay).unwrap()
    );
}
