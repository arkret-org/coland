//! Departing membership travels through real signed production HTTPS fanout.
//! The opening signed snapshot is the same explicit precondition as its parent.
use coland_services::authority_commit::AuthorityProtocolPort as _;

use super::*;

#[tokio::test]
async fn last_hosted_member_leave_closes_live_authority() {
    Box::pin(departure("leave", false)).await;
}

#[tokio::test]
async fn last_hosted_member_ban_closes_live_authority() {
    Box::pin(departure("ban", false)).await;
}

#[tokio::test]
async fn another_hosted_member_preserves_authority_after_leave() {
    Box::pin(departure("leave", true)).await;
}

#[tokio::test]
async fn another_hosted_member_preserves_authority_after_ban() {
    Box::pin(departure("ban", true)).await;
}

async fn assert_delivered(source: &LiveStation, request: &coland_storage::EventCommitRequest) {
    let rows = terminal_persistent_rows(&source.pool).await;
    let row = fanout_row(&rows, &request.authority_commit.commit.commit_id);
    assert_eq!(row["state"], "delivered", "{row}");
    assert_eq!(row["last_http_status"], 200, "{row}");
}

async fn live_basis(receiver: &LiveStation, join: &coland_storage::EventCommitRequest) -> bool {
    receiver
        .state
        .authority_commits()
        .replica_stream_has_hosted_member(
            &join.authority_commit.commit.stream_ref,
            &receiver.state.service_core_id(),
        )
        .await
        .unwrap()
        .unwrap()
}

async fn departure(membership: &str, another_member_remains: bool) {
    let source = LiveStation::start().await;
    let receiver = LiveStation::start().await;
    install_verified_route(&source.state, &receiver.state).await;
    install_verified_route(&receiver.state, &source.state).await;
    let owner = Box::pin(admitted_owner(&source, &receiver)).await;
    let member = Box::pin(historical_human::HumanFixture::new(
        &receiver.pool,
        receiver.state.service_did(),
    ))
    .await;
    let actor = ActorId::account(member.pcr.history.account.clone());
    let session = authenticated_context(&receiver.pool, &member).await;
    let mut join = Box::pin(foreign_request(
        &receiver.state,
        &member,
        &owner,
        owner.unit.transactions.last().unwrap(),
        EventKind::MemberState,
        serde_json::json!({"realm_id":owner.unit.transactions[0].event.realm_id,
            "member_id":actor,"membership":"join","reason":"departure holder"}),
    ))
    .await;
    seal_service_commit(&mut join.authority_commit.commit, &source.state);
    let uow = PgEventCommitUnitOfWork::new(source.pool.clone());
    Box::pin(uow.commit_event(join.clone())).await.unwrap();
    Box::pin(install_opening_anchor(&source, &receiver, &member, &join)).await;
    let dispatcher =
        crate::routing::federation::outbox::FederationDispatcher::new(source.state.clone());
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &join.authority_commit.commit.commit_id,
    ))
    .await;
    assert_delivered(&source, &join).await;
    assert!(live_basis(&receiver, &join).await);
    let store = receiver.state.authority_commits();
    assert!(
        store
            .signal_recipient_realms(&actor)
            .await
            .unwrap()
            .contains(&join.authority_commit.event.realm_id)
    );
    let mut previous = join.authority_commit.clone();
    let other = if another_member_remains {
        let other = Box::pin(historical_human::HumanFixture::new(
            &receiver.pool,
            receiver.state.service_did(),
        ))
        .await;
        let other_actor = ActorId::account(other.pcr.history.account.clone());
        let mut other_join = Box::pin(foreign_request(
            &receiver.state,
            &other,
            &owner,
            &previous,
            EventKind::MemberState,
            serde_json::json!({"realm_id":previous.event.realm_id,"member_id":other_actor,
                "membership":"join","reason":"independently qualified holder"}),
        ))
        .await;
        seal_service_commit(&mut other_join.authority_commit.commit, &source.state);
        Box::pin(uow.commit_event(other_join.clone()))
            .await
            .unwrap();
        let rows = terminal_persistent_rows(&source.pool).await;
        let row = fanout_row(&rows, &other_join.authority_commit.commit.commit_id);
        assert_eq!(
            row["realm_fanout"]["authority_witnesses"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        Box::pin(dispatch_due(
            &dispatcher,
            &source,
            &other_join.authority_commit.commit.commit_id,
        ))
        .await;
        assert_delivered(&source, &other_join).await;
        assert!(
            store
                .accepted_current_member_joined(&previous.event.realm_id, &other_actor)
                .await
                .unwrap()
        );
        previous = other_join.authority_commit;
        Some(other)
    } else {
        None
    };
    // Both self-leave and owner-authored ban use a real admitted source candidate.
    let departing = if membership == "leave" {
        let mut request = Box::pin(foreign_request(
            &receiver.state,
            &member,
            &owner,
            &previous,
            EventKind::MemberState,
            serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,
                "membership":membership,"reason":"holder departure"}),
        ))
        .await;
        seal_service_commit(&mut request.authority_commit.commit, &source.state);
        request
    } else {
        owner_candidate(
            &owner,
            &source.state,
            &previous,
            EventKind::MemberState,
            serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,
                "membership":membership,"reason":"governing administrator ban"}),
        )
    };
    Box::pin(uow.commit_event(departing.clone())).await.unwrap();
    let planned = terminal_persistent_rows(&source.pool).await;
    let row = fanout_row(&planned, &departing.authority_commit.commit.commit_id);
    let basis = row["realm_fanout"]["authority_witnesses"]
        .as_array()
        .unwrap();
    assert!(basis.iter().any(|witness| witness["member_id"]
        == serde_json::to_value(&actor).unwrap()
        && witness["membership_event_ref"] == departing.authority_commit.event.event_id.as_str()));

    // Membership/current and all other accepting effects must roll back together.
    execute(&receiver.pool, "CREATE OR REPLACE FUNCTION reject_departing_current() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.membership IN ('leave','ban') THEN RAISE EXCEPTION 'departure rollback'; END IF; RETURN NEW; END $$").await;
    execute(&receiver.pool, "CREATE TRIGGER reject_departing_current BEFORE UPDATE ON member_state_current_results FOR EACH ROW EXECUTE FUNCTION reject_departing_current()").await;
    let before = terminal_persistent_rows(&receiver.pool).await;
    Box::pin(dispatch_due(
        &dispatcher,
        &source,
        &departing.authority_commit.commit.commit_id,
    ))
    .await;
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, before);
    assert!(live_basis(&receiver, &join).await);
    let pending = terminal_persistent_rows(&source.pool).await;
    let pending = fanout_row(&pending, &departing.authority_commit.commit.commit_id);
    assert_eq!(pending["state"], "pending", "{pending}");
    assert_eq!(pending["payload_json"], row["payload_json"]);
    assert_eq!(pending["idempotency_key"], row["idempotency_key"]);
    execute(
        &receiver.pool,
        "DROP TRIGGER reject_departing_current ON member_state_current_results",
    )
    .await;
    execute(&receiver.pool, "DROP FUNCTION reject_departing_current()").await;
    execute(
        &source.pool,
        "UPDATE federation_outbox SET next_attempt_at=0 WHERE state IN ('pending','pending_route')",
    )
    .await;
    Box::pin(dispatcher.run_one_pass()).await.unwrap();
    assert_delivered(&source, &departing).await;
    let installed = store
        .committed_event(&departing.authority_commit.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installed.event, departing.authority_commit.event);
    assert_eq!(installed.commit, departing.authority_commit.commit);
    assert_eq!(live_basis(&receiver, &join).await, another_member_remains);
    assert!(
        !store
            .accepted_current_member_joined(&previous.event.realm_id, &actor)
            .await
            .unwrap()
    );
    assert!(
        !store
            .signal_recipient_realms(&actor)
            .await
            .unwrap()
            .contains(&previous.event.realm_id)
    );
    let departed = terminal_persistent_rows(&receiver.pool).await;
    let member_row = departed["member_state_current_results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| {
            row["realm_id"] == previous.event.realm_id.as_str()
                && row["member_id"] == actor.to_string()
        })
        .unwrap();
    assert_eq!(member_row["membership"], membership);
    assert_eq!(
        member_row["current_commit_id"],
        departing.authority_commit.commit.commit_id.as_str()
    );
    assert!(
        departed["realm_bootstrap_current_results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["result_family"] != "realm_tombstone"
                && row["result_family"] != "realm_destroy")
    );

    let fresh = historical_human::signed_ordinary_event(
        &member,
        &departing.authority_commit,
        EventKind::RealmProfile,
        serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"departed writer"}),
        arkret_canonical::normalize_timestamp_canonical(Utc::now()),
    );
    if let Some(other) = &other {
        let other_actor = ActorId::account(other.pcr.history.account.clone());
        assert!(
            store
                .signal_recipient_realms(&other_actor)
                .await
                .unwrap()
                .contains(&previous.event.realm_id)
        );
        let ordinary = historical_human::signed_ordinary_event(
            other,
            &departing.authority_commit,
            EventKind::RealmProfile,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"live writer candidate"}),
            arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        );
        // This positive only asserts the origin live gate; governing capability
        // admission of this candidate is deliberately not claimed.
        super::super::require_live_forward(&receiver.state, &ordinary)
            .await
            .unwrap();
    } else {
        let error = Box::pin(
            receiver
                .state
                .submit_self_event(&session, EventAdmissionSubmission::new(fresh)),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("held stream has no live hosted-member authority"),
            "{error}"
        );
        let after = terminal_persistent_rows(&receiver.pool).await;
        assert_eq!(
            after, departed,
            "closed proxy must not write an Event, signer root or forward evidence"
        );
    }
    let body = replication_body(&departing);
    let (status, value) = Box::pin(send_replication(
        &source.state,
        &receiver.state,
        &body,
        row["idempotency_key"].as_str().unwrap(),
        false,
    ))
    .await;
    assert_eq!(status, 200, "{value}");
    assert_replication_outcome(
        value,
        &body,
        PeerCommittedReplicationOutcomeRecord::Duplicate {},
    );
    assert_eq!(terminal_persistent_rows(&receiver.pool).await, departed);

    let terminal = owner_candidate(
        &owner,
        &source.state,
        &departing.authority_commit,
        EventKind::RealmTombstone,
        arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload::new(
            "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"
                .parse()
                .unwrap(),
            "migration after hosted departure",
        )
        .to_value()
        .unwrap(),
    );
    Box::pin(uow.commit_event(terminal.clone())).await.unwrap();
    let planned = terminal_persistent_rows(&source.pool).await;
    if another_member_remains {
        let row = fanout_row(&planned, &terminal.authority_commit.commit.commit_id);
        let witnesses = row["realm_fanout"]["authority_witnesses"]
            .as_array()
            .unwrap();
        assert_eq!(witnesses.len(), 1);
        let other_actor = ActorId::account(other.as_ref().unwrap().pcr.history.account.clone());
        assert_eq!(
            witnesses[0]["member_id"],
            serde_json::to_value(other_actor).unwrap()
        );
        Box::pin(dispatch_due(
            &dispatcher,
            &source,
            &terminal.authority_commit.commit.commit_id,
        ))
        .await;
        assert_delivered(&source, &terminal).await;
        let installed = store
            .committed_event(&terminal.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(installed.event, terminal.authority_commit.event);
        assert_eq!(installed.commit, terminal.authority_commit.commit);
    } else {
        assert!(
            planned["federation_outbox"].as_array().unwrap().iter().all(
                |row| row["idempotency_key"]
                    != format!(
                        "realm-fanout:{}",
                        terminal.authority_commit.commit.commit_id
                    )
            ),
            "departed Station is absent from terminal targets"
        );
        let body = replication_body(&terminal);
        // A late source-signed canonical successor cannot extend the held prefix.
        for _ in 0..2 {
            let (status, value) = Box::pin(send_replication(
                &source.state,
                &receiver.state,
                &body,
                "late-terminal-after-departure",
                false,
            ))
            .await;
            assert_eq!(status, 200, "{value}");
            assert_replication_outcome(
                value,
                &body,
                PeerCommittedReplicationOutcomeRecord::Rejected {
                    reason_code: "capability_denied".into(),
                },
            );
            assert_eq!(terminal_persistent_rows(&receiver.pool).await, departed);
        }
    }
    assert!(
        terminal_persistent_rows(&receiver.pool).await["federation_outbox"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
