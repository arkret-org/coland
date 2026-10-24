use arkret_wire::{
    AccountId, ActorId, CircleId, CommitStreamHead, CommitStreamRef, CurrentRevision,
    CurrentSelector, CurrentState, DidCoreId, EventId, RealmCommitId, RealmId,
};
use diesel::sql_types::Jsonb;
use serde_json::json;

use super::*;
use crate::test_database::TestDatabase;

#[derive(diesel::QueryableByName)]
struct StoredValue {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn head(stream_ref: CommitStreamRef, stream_position: u64, digest: u8) -> CommitStreamHead {
    CommitStreamHead {
        stream_ref,
        stream_position,
        commit_id: RealmCommitId::from_digest([digest; 32]),
    }
}

fn entry(
    selector: CurrentSelector,
    source_stream_ref: CommitStreamRef,
    stream_position: u64,
    digest: u8,
    value: Value,
) -> CurrentState {
    CurrentState::Value {
        selector,
        source_stream_ref,
        revision: CurrentRevision {
            stream_position,
            commit_id: RealmCommitId::from_digest([digest; 32]),
        },
        value,
    }
}

async fn install(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    heads: &[CommitStreamHead],
    entries: &[CurrentState],
) -> PersistenceResult<()> {
    install_snapshot_at_heads_in_connection(
        conn,
        realm,
        &heads[0],
        heads,
        entries,
        chrono::Utc::now(),
    )
    .await
}

#[tokio::test]
async fn circle_snapshot_replacement_keeps_selector_revision_monotonic() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let create = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [31; 32]);
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [32; 32],
    ));
    let circle = CircleId::from_event_id(&create);
    let member = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:circle-member.example").unwrap(),
        DidCoreId::new("ak:did_core:web:circle-station.example").unwrap(),
    ));
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let circle_stream = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    let circle_selector = CurrentSelector::Circle {
        circle_id: circle.clone(),
    };
    let member_selector = CurrentSelector::CircleMemberState {
        circle_id: circle.clone(),
        member_actor_id: member.clone(),
    };
    let circle_value = json!({
        "id": circle,
        "realm_id": realm,
        "display": {"short_name": "Circle"},
        "state": "active"
    });
    let member_value = json!({
        "membership": "join",
        "parent_membership_revision": {
            "commit_id": RealmCommitId::from_digest([1; 32]),
            "stream_position": 1
        },
        "effective_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    });
    let baseline = [
        entry(
            circle_selector.clone(),
            realm_stream.clone(),
            5,
            5,
            circle_value.clone(),
        ),
        entry(
            member_selector.clone(),
            circle_stream.clone(),
            2,
            2,
            member_value.clone(),
        ),
    ];
    let heads = [
        head(realm_stream.clone(), 8, 8),
        head(circle_stream.clone(), 4, 4),
    ];
    for _ in 0..2 {
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        install(&mut conn, &realm, &heads, &baseline).await.unwrap();
        diesel::sql_query("COMMIT")
            .execute(&mut conn)
            .await
            .unwrap();
    }

    let mut changed_circle = circle_value.clone();
    changed_circle["state"] = json!("archived");
    let mut changed_member = member_value.clone();
    changed_member["membership"] = json!("leave");
    changed_member
        .as_object_mut()
        .unwrap()
        .remove("parent_membership_revision");
    let refusals = [
        [
            entry(
                circle_selector.clone(),
                realm_stream.clone(),
                4,
                3,
                circle_value.clone(),
            ),
            baseline[1].clone(),
        ],
        [
            entry(
                circle_selector.clone(),
                realm_stream.clone(),
                5,
                6,
                circle_value.clone(),
            ),
            baseline[1].clone(),
        ],
        [
            entry(
                circle_selector.clone(),
                realm_stream.clone(),
                5,
                5,
                changed_circle.clone(),
            ),
            baseline[1].clone(),
        ],
        [
            baseline[0].clone(),
            entry(
                member_selector.clone(),
                circle_stream.clone(),
                1,
                1,
                member_value.clone(),
            ),
        ],
        [
            baseline[0].clone(),
            entry(
                member_selector.clone(),
                circle_stream.clone(),
                2,
                3,
                member_value.clone(),
            ),
        ],
        [
            baseline[0].clone(),
            entry(
                member_selector.clone(),
                circle_stream.clone(),
                2,
                2,
                changed_member.clone(),
            ),
        ],
    ];
    for entries in refusals {
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        assert!(matches!(
            install(&mut conn, &realm, &heads, &entries).await,
            Err(PersistenceError::Conflict(_))
        ));
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
    }
    let circle_stored =
        diesel::sql_query("SELECT value FROM circle_current_states WHERE circle_id=$1")
            .bind::<Text, _>(circle.as_str())
            .get_result::<StoredValue>(&mut conn)
            .await
            .unwrap()
            .value;
    let member_stored = diesel::sql_query(
        "SELECT value FROM circle_member_state_current_states WHERE circle_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(circle.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(circle_stored, circle_value);
    assert_eq!(member_stored, member_value);

    let next = [
        entry(
            circle_selector,
            realm_stream.clone(),
            6,
            9,
            changed_circle.clone(),
        ),
        entry(
            member_selector,
            circle_stream.clone(),
            3,
            7,
            changed_member.clone(),
        ),
    ];
    let next_heads = [head(realm_stream, 9, 10), head(circle_stream, 5, 8)];
    diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
    install(&mut conn, &realm, &next_heads, &next)
        .await
        .unwrap();
    diesel::sql_query("COMMIT")
        .execute(&mut conn)
        .await
        .unwrap();
    let circle_stored =
        diesel::sql_query("SELECT value FROM circle_current_states WHERE circle_id=$1")
            .bind::<Text, _>(circle.as_str())
            .get_result::<StoredValue>(&mut conn)
            .await
            .unwrap()
            .value;
    let member_stored = diesel::sql_query(
        "SELECT value FROM circle_member_state_current_states WHERE circle_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(circle.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(circle_stored, changed_circle);
    assert_eq!(member_stored, changed_member);
}

#[tokio::test]
async fn circle_member_event_writer_rejects_stale_and_forked_current() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [41; 32],
    ));
    let circle = CircleId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [42; 32],
    ));
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:writer-member.example").unwrap(),
        DidCoreId::new("ak:did_core:web:writer-station.example").unwrap(),
    ));
    let at = chrono::Utc::now();
    let make = |membership: &str, position: u64, digest: u8, realm: &RealmId| {
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.circle.member.state",
            arkret_wire::ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle.clone(),
            },
            actor.clone(),
            {
                let mut payload = json!({
                    "circle_id":circle,
                    "member_id":actor,
                    "membership":membership,
                    "effective_at":arkret_canonical::format_timestamp_canonical(at)
                });
                if membership == "join" {
                    payload["parent_membership_revision"] = json!({
                        "commit_id": RealmCommitId::from_digest([2; 32]),
                        "stream_position": 2
                    });
                }
                payload
            },
            at,
        )
        .unwrap();
        let commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: RealmCommitId::from_digest([digest; 32]),
            realm_id: realm.clone(),
            stream_ref: CommitStreamRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle.clone(),
            },
            stream_position: position,
            previous_commit_ref: None,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:writer-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at,
                signature: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        };
        (event, commit)
    };
    let original = make("join", 7, 7, &realm);
    crate::circle_current_states::commit_in_connection(&mut conn, &original.0, &original.1)
        .await
        .unwrap();
    crate::circle_current_states::commit_in_connection(&mut conn, &original.0, &original.1)
        .await
        .unwrap();
    for (membership, position, digest) in [("leave", 6, 6), ("join", 7, 8), ("leave", 7, 7)] {
        let candidate = make(membership, position, digest, &realm);
        assert!(matches!(
            crate::circle_current_states::commit_in_connection(
                &mut conn,
                &candidate.0,
                &candidate.1,
            )
            .await,
            Err(PersistenceError::Conflict(_))
        ));
    }
    let foreign = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [43; 32],
    ));
    let cross_realm = make("leave", 8, 9, &foreign);
    assert!(matches!(
        crate::circle_current_states::commit_in_connection(
            &mut conn,
            &cross_realm.0,
            &cross_realm.1,
        )
        .await,
        Err(PersistenceError::Conflict(_))
    ));
    let next = make("leave", 8, 8, &realm);
    crate::circle_current_states::commit_in_connection(&mut conn, &next.0, &next.1)
        .await
        .unwrap();
    let stored = diesel::sql_query(
        "SELECT value FROM circle_member_state_current_states WHERE circle_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(circle.as_str())
    .bind::<Text, _>(actor.to_string())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(stored["membership"], "leave");
}
