//! RSVP current is an authority-ordered whole-entry register per responder.

#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ordinary_realm::{next_request, next_request_for_actor, open_discussion, station};
use serde_json::{Value, json};

#[derive(Clone, diesel::QueryableByName, Debug, PartialEq)]
struct Current {
    #[diesel(sql_type = Text)]
    event_ref: String,
    #[diesel(sql_type = Jsonb)]
    occurrence: Value,
    #[diesel(sql_type = Jsonb)]
    responder_actor_id: Value,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct RootRef {
    #[diesel(sql_type = Text)]
    authority_event_ref: String,
}

async fn root_event_ref(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> String {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootRef>(&mut conn)
    .await
    .unwrap()
    .authority_event_ref
}

async fn current(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> Option<Current> {
    use diesel::OptionalExtension as _;
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query(
        "SELECT event_ref,occurrence,responder_actor_id,current_commit_id,current_stream_position,value \
         FROM rsvp_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result(&mut conn)
    .await
    .optional()
    .unwrap()
}

async fn realm_counts(pool: &PgPool, realm_id: &arkret_wire::RealmId) -> (i64, i64) {
    let mut conn = pool.get().await.unwrap();
    let events: Count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM canonical_events WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
    let commits: Count =
        diesel::sql_query("SELECT COUNT(*) AS count FROM realm_commits WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
    (events.count, commits.count)
}

fn encrypted_entry(basis: &arkret_wire::EventId, ciphertext: &str) -> Value {
    json!({
        "schedule_basis_refs": [basis],
        "encrypted_response": {
            "version": "1.0",
            "content_type": "application/vnd.arkret.calendar-rsvp-response+json",
            "encryption_context": {
                "epoch": 7,
                "group_state_ref": "ak:event:Af-qizSfVETcKiliXG093VVneO4nQF194ZXGkMWJijix"
            },
            "ciphertext": ciphertext
        }
    })
}

#[tokio::test]
async fn rsvp_current_accepts_encrypted_entry_and_rejects_without_partial_commit() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let discussion = open_discussion(&pool, "rsvp-current-encrypted").await;
    let author = discussion
        .head
        .authority_commit
        .event
        .actor_id
        .signing_principal_id()
        .clone();
    let realm_id = discussion.head.authority_commit.event.realm_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let calendar = next_request(
        &discussion.head.authority_commit,
        arkret_wire::EventKind::StrandUpdate,
        &author,
        json!({
            "target_ref": discussion.strand_id,
            "patch": {
                "schema_refs": {"$op":"set", "value":["ak.schema.calendar_event.v1"]},
                "metadata.fields.calendar": {"$op":"set", "value":{
                    "start":"2026-06-22", "end":"2026-06-23", "timezone":"UTC",
                    "tzdb_version":"2025b", "all_day":true, "status":"confirmed"
                }}
            }
        }),
        at,
    );
    uow.commit_event(calendar.clone()).await.unwrap();
    let basis = &calendar.authority_commit.event.event_id;
    let responder = calendar.authority_commit.event.actor_id.clone();
    let grant = next_request(
        &calendar.authority_commit,
        arkret_wire::EventKind::CapabilityGrant,
        &author,
        json!({"grant": {
            "schema": "ak.schema.capability.v1",
            "realm_id": realm_id,
            "issuer_id": responder,
            "subject": responder,
            "actions": ["ak.rsvp.set"],
            "resources": [{"kind":"strand", "realm_id":realm_id, "strand_id":discussion.strand_id}],
            "issuer_authority_refs": [{
                "kind":"realm_root", "realm_id":realm_id,
                "authority_event_ref":root_event_ref(&pool, &realm_id).await,
                "authority_generation":0
            }],
            "issued_at": arkret_canonical::format_timestamp_canonical(at)
        }}),
        at,
    );
    uow.commit_event(grant.clone()).await.unwrap();
    let response = |ciphertext: &str| {
        json!({
            "event_ref": discussion.strand_id,
            "occurrence": null,
            "entry": encrypted_entry(basis, ciphertext)
        })
    };
    let first = next_request(
        &grant.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        &author,
        response("rsvpAlpha"),
        at,
    );
    assert!(
        uow.commit_event(first.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let first_current = current(&pool, &realm_id).await.unwrap();
    assert_eq!(first_current.event_ref, discussion.strand_id.as_str());
    assert_eq!(first_current.occurrence, Value::Null);
    assert_eq!(
        first_current.responder_actor_id,
        serde_json::to_value(&first.authority_commit.event.actor_id).unwrap()
    );
    assert_eq!(first_current.value, encrypted_entry(basis, "rsvpAlpha"));
    assert_eq!(
        first_current.current_commit_id,
        first.authority_commit.commit.commit_id.as_str()
    );

    let second = next_request(
        &first.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        &author,
        response("rsvpBravo"),
        at,
    );
    assert!(
        uow.commit_event(second.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let settled = current(&pool, &realm_id).await.unwrap();
    assert_eq!(settled.value, encrypted_entry(basis, "rsvpBravo"));
    assert_eq!(
        settled.current_commit_id,
        second.authority_commit.commit.commit_id.as_str()
    );
    assert!(settled.current_stream_position > first_current.current_stream_position);
    let snapshot = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material_for_account(
            &realm_id,
            responder
                .as_account_id()
                .expect("RSVP responder is an Account"),
        )
        .await
        .unwrap()
        .expect("joined responder sees the complete RSVP current");
    assert!(snapshot.current_state_entries.iter().any(|entry| matches!(
        entry,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Rsvp {
                event_ref,
                occurrence: None,
                responder_actor_id,
            },
            source_stream_ref,
            revision,
            value,
        } if event_ref == &discussion.strand_id
            && responder_actor_id == &responder
            && source_stream_ref == &second.authority_commit.commit.stream_ref
            && revision.commit_id == second.authority_commit.commit.commit_id
            && value == &encrypted_entry(basis, "rsvpBravo")
    )));
    assert!(
        !uow.commit_event(second.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let counts = realm_counts(&pool, &realm_id).await;
    assert_eq!(current(&pool, &realm_id).await, Some(settled.clone()));

    let plaintext = next_request(
        &second.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        &author,
        json!({
            "event_ref": discussion.strand_id, "occurrence": null,
            "entry": {"schedule_basis_refs":[basis], "response":{"status":"accepted"}}
        }),
        at,
    );
    let wrong_basis = next_request(
        &second.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        &author,
        json!({
            "event_ref": discussion.strand_id, "occurrence": null,
            "entry": encrypted_entry(&discussion.head.authority_commit.event.event_id, "rsvpCharlie")
        }),
        at,
    );
    let invalid_occurrence = next_request(
        &second.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        &author,
        json!({
            "event_ref": discussion.strand_id, "occurrence": "2026-02-30",
            "entry": encrypted_entry(basis, "rsvpDelta")
        }),
        at,
    );
    let unknown_target = next_request(
        &second.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        &author,
        json!({
            "event_ref": arkret_wire::StrandId::from_event_id(&second.authority_commit.event.event_id),
            "occurrence": null,
            "entry": encrypted_entry(basis, "rsvpFoxtrot")
        }),
        at,
    );
    let outsider = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:rsvp-outsider.example").unwrap(),
        station(),
    ));
    let unauthorized = next_request_for_actor(
        &second.authority_commit,
        arkret_wire::EventKind::RsvpSet,
        outsider,
        response("rsvpEcho"),
        at,
    );
    for (request, reason) in [
        (plaintext, "unsupported_feature"),
        (wrong_basis, "basis"),
        (invalid_occurrence, "occurrence"),
        (unknown_target, "capability_denied"),
        (unauthorized, "capability_denied"),
    ] {
        let error = uow.commit_event(request).await.unwrap_err().to_string();
        assert!(error.contains(reason), "{error}");
        assert_eq!(current(&pool, &realm_id).await, Some(settled.clone()));
        assert_eq!(realm_counts(&pool, &realm_id).await, counts);
    }
}
