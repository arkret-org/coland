//! Shared challenge consumption and replay retention on real PostgreSQL.

use arkret_wire::WebOrigin;
use chrono::{Duration, Utc};
use coland_storage::{WebsocketAuthChallengeRecord, WebsocketAuthReplayRecord, WebsocketAuthStore};
use coland_storage_postgres::PgWebsocketAuthStore;
use coland_storage_postgres::test_database::TestDatabase;

fn challenge(connection: &str, nonce: &str) -> WebsocketAuthChallengeRecord {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let expires_at = issued_at + Duration::seconds(5);
    WebsocketAuthChallengeRecord {
        connection_id: connection.to_owned(),
        nonce: nonce.to_owned(),
        canonical_origin: WebOrigin::new("https://client.example").unwrap(),
        canonical_base_url: "wss://station.example/_arkret/ws".to_owned(),
        issued_at,
        expires_at,
        consumed: false,
        retain_until: expires_at + Duration::seconds(300),
    }
}

fn replay(jti: &str) -> WebsocketAuthReplayRecord {
    let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    WebsocketAuthReplayRecord {
        cnf_jkt: "holder-thumbprint".to_owned(),
        jti: jti.to_owned(),
        proof_context: arkret_wire::websocket_binding::WEBSOCKET_AUTH_REPLAY_CONTEXT.to_owned(),
        consumed_at: at,
        retain_until: at + Duration::seconds(300),
    }
}

#[tokio::test]
async fn shared_atomic_consume_allows_one_winner_and_rolls_back_the_other_half() {
    let database = TestDatabase::lease().await;
    let first = PgWebsocketAuthStore {
        pool: database.pool(),
    };
    let second = PgWebsocketAuthStore {
        pool: database.pool(),
    };
    let c = challenge("connection", "first");
    first.prepare_challenge(&c).await.unwrap();
    assert!(second.prepare_challenge(&c).await.is_err());
    assert_eq!(
        second
            .get_challenge(&c.connection_id, &c.nonce)
            .await
            .unwrap(),
        Some(c.clone())
    );
    let r = replay("proof-one");
    let (a, b) = tokio::join!(
        first.consume_challenge(&c.connection_id, &c.nonce, &r),
        second.consume_challenge(&c.connection_id, &c.nonce, &r),
    );
    assert_ne!(a.unwrap(), b.unwrap());
    assert!(
        second
            .get_challenge(&c.connection_id, &c.nonce)
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
    assert!(
        first
            .replay_ledger_contains(&r.cnf_jkt, &r.jti, &r.proof_context)
            .await
            .unwrap()
    );

    let next = challenge("other-connection", "second");
    second.prepare_challenge(&next).await.unwrap();
    assert!(
        !second
            .consume_challenge(&next.connection_id, &next.nonce, &r)
            .await
            .unwrap()
    );
    assert!(
        !first
            .get_challenge(&next.connection_id, &next.nonce)
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
    let fresh = replay("proof-two");
    assert!(
        !second
            .consume_challenge(&c.connection_id, &c.nonce, &fresh)
            .await
            .unwrap()
    );
    assert!(
        !first
            .replay_ledger_contains(&fresh.cnf_jkt, &fresh.jti, &fresh.proof_context)
            .await
            .unwrap()
    );
    assert!(
        first
            .consume_challenge(&next.connection_id, &next.nonce, &fresh)
            .await
            .unwrap()
    );
    assert_eq!(
        first
            .prune_expired(c.issued_at + Duration::seconds(299))
            .await
            .unwrap(),
        0
    );
    assert!(
        second
            .get_challenge(&c.connection_id, &c.nonce)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        first
            .prune_expired(Utc::now() + Duration::seconds(306))
            .await
            .unwrap(),
        4
    );
}

#[tokio::test]
async fn expired_or_unknown_challenge_consumes_no_replay_entry() {
    let database = TestDatabase::lease().await;
    let store = PgWebsocketAuthStore {
        pool: database.pool(),
    };
    let mut c = challenge("expired-connection", "expired-nonce");
    c.issued_at -= Duration::seconds(10);
    c.expires_at -= Duration::seconds(10);
    store.prepare_challenge(&c).await.unwrap();
    let r = replay("never-accepted");
    assert!(
        !store
            .consume_challenge(&c.connection_id, &c.nonce, &r)
            .await
            .unwrap()
    );
    assert!(
        !store
            .consume_challenge("unknown", "unknown", &r)
            .await
            .unwrap()
    );
    assert!(
        !store
            .replay_ledger_contains(&r.cnf_jkt, &r.jti, &r.proof_context)
            .await
            .unwrap()
    );
    assert!(
        !store
            .get_challenge(&c.connection_id, &c.nonce)
            .await
            .unwrap()
            .unwrap()
            .consumed
    );
}

#[tokio::test]
async fn connection_quotas_are_shared_atomic_and_expired_leases_are_reusable() {
    use coland_storage::WebsocketConnectionLease;
    let database = TestDatabase::lease().await;
    let first = PgWebsocketAuthStore {
        pool: database.pool(),
    };
    let second = PgWebsocketAuthStore {
        pool: database.pool(),
    };
    let lease = |id: &str, session: char| WebsocketConnectionLease {
        connection_id: id.to_owned(),
        session_binding: session.to_string().repeat(43),
        device_binding: "d".repeat(43),
        expires_at: arkret_canonical::normalize_timestamp_canonical(
            Utc::now() + Duration::seconds(30),
        ),
    };
    let a = lease("a", 'a');
    let b = lease("b", 'a');
    let c = lease("c", 'a');
    let (a_result, b_result, c_result) = tokio::join!(
        first.reserve_connection(&a),
        second.reserve_connection(&b),
        first.reserve_connection(&c)
    );
    assert_eq!(
        [a_result.unwrap(), b_result.unwrap(), c_result.unwrap()]
            .into_iter()
            .filter(|allowed| *allowed)
            .count(),
        2
    );
    for id in ["a", "b", "c"] {
        first.release_connection(id).await.unwrap();
    }
    for (id, session) in [("a", 'a'), ("b", 'a'), ("c", 'b'), ("d", 'b')] {
        assert!(first.reserve_connection(&lease(id, session)).await.unwrap());
    }
    assert!(
        !second
            .reserve_connection(&lease("over-device", 'c'))
            .await
            .unwrap()
    );
    assert!(!second.reserve_connection(&lease("a", 'b')).await.unwrap());
    assert!(second.reserve_connection(&lease("a", 'c')).await.unwrap());
    let mut steal = lease("a", 'c');
    steal.device_binding = "x".repeat(43);
    assert!(!second.reserve_connection(&steal).await.unwrap());
    first.release_connection("b").await.unwrap();
    assert!(
        second
            .reserve_connection(&lease("replacement", 'a'))
            .await
            .unwrap()
    );
    let mut invalid = lease("expired", 'z');
    invalid.expires_at = Utc::now() - Duration::seconds(1);
    assert!(first.reserve_connection(&invalid).await.is_err());
    assert_eq!(
        second
            .prune_expired(Utc::now() + Duration::seconds(31))
            .await
            .unwrap(),
        4
    );
    assert!(
        second
            .reserve_connection(&lease("after-expiry", 'a'))
            .await
            .unwrap()
    );
}
