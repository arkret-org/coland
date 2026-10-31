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

#[tokio::test]
async fn circle_observation_continuation_preserves_same_cut_without_reviving_reset_rows() {
    // This is a trusted-caller storage proof test, not a network/signature
    // bootstrap test. The HTTP fixture verifies the real governor separately.
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [81; 32],
    ));
    let create = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [82; 32]);
    let circle = CircleId::from_event_id(&create);
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    diesel::sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,$3)")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>("ak:did_core:web:circle-governor.example")
        .bind::<Jsonb,_>(json!(arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(create)))
        .execute(&mut conn).await.unwrap();
    let current = entry(
        CurrentSelector::Circle {
            circle_id: circle.clone(),
        },
        stream.clone(),
        5,
        83,
        json!({"id":circle,"realm_id":realm,"display":{"short_name":"Private"},"state":"active"}),
    );
    let first = head(stream.clone(), 8, 84);
    install(
        &mut conn,
        &realm,
        std::slice::from_ref(&first),
        std::slice::from_ref(&current),
    )
    .await
    .unwrap();
    assert!(
        !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap(),
        "missing actual Station must remain unproved, never caller-ID/native fallback"
    );
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>("ak:did_core:web:circle-observer.example")
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );
    let retained = diesel::sql_query(
        "SELECT to_jsonb(r) AS value FROM replica_authorization_rows r WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    let first_cut = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    for _ in 0..2 {
        install(&mut conn, &realm, std::slice::from_ref(&first), &[])
            .await
            .unwrap();
        let after = diesel::sql_query(
            "SELECT to_jsonb(r) AS value FROM replica_authorization_rows r WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<StoredValue>(&mut conn)
        .await
        .unwrap()
        .value;
        assert_eq!(
            after, retained,
            "a narrower same-cut Account must not touch another Account's value or observation"
        );
        assert!(
            crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
                .await
                .unwrap()
        );
    }
    // Exercise the trusted successor writer separately from qualified
    // snapshot installation. These structural receipts are not crypto proof.
    let at = chrono::Utc::now();
    let event_ref = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [88; 32]);
    let next = arkret_wire::RealmCommit {
        producer_signer_fact_digest: None,
        commit_id: RealmCommitId::from_digest([89; 32]),
        realm_id: realm.clone(),
        stream_ref: stream.clone(),
        stream_position: 9,
        previous_commit_ref: Some(first.commit_id.clone()),
        event_ref: event_ref.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event_ref),
        committed_at: at,
        signature: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::RealmCommit,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new(
                "did:web:circle-governor.example#authority",
            )
            .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: at,
            signature: arkret_wire::Base64UrlString::new("c2ln".to_owned()).unwrap(),
        },
    };
    let before_refusal = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    let mut gap = next.clone();
    gap.stream_position = 10;
    assert!(
        crate::replica_authorization::advance_verified_head(&mut conn, &gap)
            .await
            .is_err()
    );
    let mut fork = next.clone();
    fork.previous_commit_ref = Some(RealmCommitId::from_digest([90; 32]));
    assert!(
        crate::replica_authorization::advance_verified_head(&mut conn, &fork)
            .await
            .is_err()
    );
    let after_refusal = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        before_refusal, after_refusal,
        "gap/fork refusal has no cut writes"
    );
    crate::replica_authorization::advance_verified_head(&mut conn, &next)
        .await
        .unwrap();
    let continued = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        continued["circle_continuation_id"],
        first_cut["circle_continuation_id"]
    );
    assert_eq!(
        continued["circle_effect_base_commit_id"],
        json!(first.commit_id)
    );
    assert_eq!(continued["head_commit_id"], json!(next.commit_id));
    let unchanged = diesel::sql_query(
        "SELECT to_jsonb(r) AS value FROM replica_authorization_rows r WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        unchanged, retained,
        "ordinary tail may update one cut, never omitted selector rows"
    );
    assert!(
        crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );
    let higher = head(stream.clone(), 12, 85);
    install(&mut conn, &realm, std::slice::from_ref(&higher), &[])
        .await
        .unwrap();
    let higher_cut = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_ne!(
        first_cut["circle_continuation_id"],
        higher_cut["circle_continuation_id"]
    );
    assert_eq!(
        higher_cut["circle_effect_base_commit_id"],
        json!(higher.commit_id)
    );
    assert!(
        !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap(),
        "a legitimate higher cut does not refresh an omitted row"
    );
    let after_jump = diesel::sql_query(
        "SELECT to_jsonb(r) AS value FROM replica_authorization_rows r WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(after_jump, retained);
    install(
        &mut conn,
        &realm,
        std::slice::from_ref(&higher),
        std::slice::from_ref(&current),
    )
    .await
    .unwrap();
    assert!(
        crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );

    // A semantic reset may occur on a different source while this source's
    // coordinates stay exactly H. Recreating H must still get a new ID.
    crate::replica_authorization::invalidate_circle_continuation(&mut conn, &realm)
        .await
        .unwrap();
    assert!(
        !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );
    install(&mut conn, &realm, std::slice::from_ref(&higher), &[])
        .await
        .unwrap();
    let recreated = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_ne!(
        recreated["circle_continuation_id"],
        higher_cut["circle_continuation_id"]
    );
    assert!(
        !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );
    install(
        &mut conn,
        &realm,
        std::slice::from_ref(&higher),
        std::slice::from_ref(&current),
    )
    .await
    .unwrap();
    assert!(
        crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );
    diesel::sql_query("DELETE FROM replica_authorization_cuts WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    install(&mut conn, &realm, std::slice::from_ref(&higher), &[])
        .await
        .unwrap();
    let deleted_recreated = diesel::sql_query(
        "SELECT to_jsonb(h) AS value FROM replica_authorization_cuts h WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_ne!(
        deleted_recreated["circle_continuation_id"],
        recreated["circle_continuation_id"]
    );
    assert!(
        !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap()
    );
    install(
        &mut conn,
        &realm,
        std::slice::from_ref(&higher),
        std::slice::from_ref(&current),
    )
    .await
    .unwrap();
    // The actual authority writer, not a test-side UUID rewrite, must end
    // the old tenure even when none of the frozen source heads changes.
    {
        use coland_storage::AuthorityCommitStore as _;
        let store = crate::authority_commit::PgAuthorityCommitStore {
            pool: database.pool(),
        };
        let local = DidCoreId::new("ak:did_core:web:circle-observer.example").unwrap();
        let authority = store.current_authority(&realm).await.unwrap().unwrap();
        store
            .record_remote_authority(&authority, &local)
            .await
            .unwrap();
        assert!(
            crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
                .await
                .unwrap()
        );
        let handoff = arkret_wire::RealmAuthorityHandoffId::from_digest([87; 32]);
        let mut next = authority;
        next.generation += 1;
        next.service_id = DidCoreId::new("ak:did_core:web:next-circle-governor.example").unwrap();
        next.authority_ref = arkret_wire::RealmCommitAuthorityRef::Handoff(handoff.clone());
        next.last_handoff_ref = Some(handoff);
        store.record_remote_authority(&next, &local).await.unwrap();
        assert!(
            !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
                .await
                .unwrap()
        );
        install(&mut conn, &realm, std::slice::from_ref(&higher), &[])
            .await
            .unwrap();
        assert!(
            !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
                .await
                .unwrap(),
            "same-head new tenure omission cannot revive the old row"
        );
        install(
            &mut conn,
            &realm,
            std::slice::from_ref(&higher),
            std::slice::from_ref(&current),
        )
        .await
        .unwrap();
        assert!(
            crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
                .await
                .unwrap(),
            "qualified new-tenure disclosure may seed the unchanged historical value revision"
        );
    }
    diesel::sql_query(
        "UPDATE replica_authorization_rows SET observed_anchor_commit_id=$2 WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(RealmCommitId::from_digest([86; 32]).as_str())
    .execute(&mut conn)
    .await
    .unwrap();
    assert!(
        !crate::replica_authorization::circle_entry_proved(&mut conn, &realm, &current)
            .await
            .unwrap(),
        "position equality cannot prove a forked observation"
    );
}

#[tokio::test]
async fn native_parent_without_canonical_original_cannot_borrow_matching_replica_snapshot() {
    let database = TestDatabase::lease().await;
    let mut conn = database.pool().get().await.unwrap();
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [91; 32],
    ));
    let station = DidCoreId::new("ak:did_core:web:native-parent.example").unwrap();
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:native-parent-account.example").unwrap(),
        station.clone(),
    ));
    let origin = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [92; 32]);
    diesel::sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
        .bind::<Text, _>(station.as_str())
        .execute(&mut conn)
        .await
        .unwrap();
    diesel::sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,$3)")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(station.as_str()).bind::<Jsonb,_>(json!(arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(origin)))
        .execute(&mut conn).await.unwrap();
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let parent = entry(
        CurrentSelector::MemberState {
            actor_id: actor.clone(),
        },
        stream.clone(),
        5,
        93,
        json!({"membership":"join"}),
    );
    let cut = head(stream, 8, 94);
    install(
        &mut conn,
        &realm,
        std::slice::from_ref(&cut),
        std::slice::from_ref(&parent),
    )
    .await
    .unwrap();
    let CurrentState::Value { revision, .. } = &parent;
    assert_eq!(
        crate::replica_authorization::parent_binding_superseded(
            &mut conn, &realm, &actor, revision
        )
        .await
        .unwrap(),
        None,
        "actual native role requires the canonical parent, even with matching cached snapshot and physical projection"
    );
    let before = diesel::sql_query(
        "SELECT to_jsonb(r) AS value FROM replica_authorization_rows r WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        crate::replica_authorization::parent_binding_superseded(
            &mut conn, &realm, &actor, revision
        )
        .await
        .unwrap(),
        None
    );
    let after = diesel::sql_query(
        "SELECT to_jsonb(r) AS value FROM replica_authorization_rows r WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<StoredValue>(&mut conn)
    .await
    .unwrap()
    .value;
    assert_eq!(
        after, before,
        "unknown parent reads must not manufacture or refresh proof"
    );
}
