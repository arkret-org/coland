use super::*;

const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const REALM_B: &str = "ak:realm:AR8FzptqPhujyMqtDIr2CTaKC301-QQGktovEDdHy_6R";
const POLL_EVENT: &str = "ak:event:AVH4Dy1ng6HIwqHRIemmcRdGF6ErKqNeNOzRpc2sGDV2";
const POLL_ID: &str = "ak:message:AVH4Dy1ng6HIwqHRIemmcRdGF6ErKqNeNOzRpc2sGDV2";
const STRAND_A: &str = "ak:strand:ARkwFWDTPrObvpqVAL9kBsWkK8GrMr5FDO--3PcMFEwU";
const STRAND_B: &str = "ak:strand:AUzgWk6FQOO5CNGEhXKtRw7FKYOAXGqzSVCLuwh5qmkk";
const CIRCLE_A: &str = "ak:circle:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu";
const CIRCLE_B: &str = "ak:circle:AbJ9TrPb-MFmDgVNN0uDVC6CIm3VNDxuUzlM5QBHZ8_Z";

fn seed_strand(state: &mut ProjectionState, strand_id: &str, circle_id: Option<&str>) {
    let now = chrono::Utc::now();
    state.strands.insert(
        strand_id.to_owned(),
        StrandProjection {
            strand_id: strand_id.to_owned(),
            realm_id: REALM_A.to_owned(),
            tracks: crate::reducer::projections::default_strand_tracks(),
            title: "Poll".to_owned(),
            summary: None,
            content: None,
            encrypted_content: None,
            fields: BTreeMap::new(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: "ak:did_core:web:alice.example".to_owned(),
            created_at: now,
            updated_by: None,
            updated_at: None,
            scope_circle_id: circle_id.map(ToOwned::to_owned),
            schema_refs: Vec::new(),
            schedule_revision_source: None,
        },
    );
}

fn create_poll(state: &mut ProjectionState, hlc: &ServerHlc) {
    create_poll_with_limit(state, hlc, 1);
}

fn create_poll_with_limit(state: &mut ProjectionState, hlc: &ServerHlc, max_selection_count: u32) {
    if !state.strands.contains_key(STRAND_A) {
        seed_strand(state, STRAND_A, None);
    }
    let mut operation = make_operation(
        arkret_wire::EventKind::MessageCreate,
        REALM_A,
        serde_json::json!({
            "event_id": POLL_EVENT,
            "strand_id": STRAND_A,
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.poll",
                "body": "Choose",
                "poll": {
                    "kind": "disclosed",
                    "max_selection_count": max_selection_count,
                    "answers": [
                        {"id": "yes", "text": {"kind": "ak.content.text", "body": "Yes"}},
                        {"id": "no", "text": {"kind": "ak.content.text", "body": "No"}}
                    ]
                }
            }
        }),
    );
    if let Some(circle_id) = state.strand_scope_circle_id(STRAND_A) {
        operation.context.accepted_scope_ref = arkret_wire::ScopeRef::Circle {
            realm_id: arkret_wire::RealmId::new(REALM_A).unwrap(),
            circle_id: arkret_wire::CircleId::new(circle_id).unwrap(),
        };
    }
    operation = at_position(operation, 1);
    let effect = state.apply(&operation, hlc);
    assert!(matches!(effect, ProjectionEffect::MessageCreated(_)));
    assert!(state.poll(POLL_ID).is_some());
}

#[test]
fn poll_reducer_accepts_valid_multi_selection() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    create_poll_with_limit(&mut state, &hlc, 2);
    assert!(matches!(
        response(&mut state, &hlc, REALM_A, serde_json::json!(["yes", "no"]),),
        ProjectionEffect::Ignored
    ));
    // A response settles the actor's selection list verbatim, in the order the
    // signed payload named it.
    assert_eq!(
        state.poll(POLL_ID).unwrap().votes.values().next().unwrap(),
        &vec!["yes".to_owned(), "no".to_owned()]
    );
}

fn response(
    state: &mut ProjectionState,
    hlc: &ServerHlc,
    realm: &str,
    selections: Value,
) -> ProjectionEffect {
    state.apply(&response_operation(realm, selections), hlc)
}

fn response_operation(
    realm: &str,
    selections: Value,
) -> arkret_event_draft::ProjectedEventOperation {
    response_operation_on_strand(realm, STRAND_A, selections)
}

fn response_operation_on_strand(
    realm: &str,
    strand_id: &str,
    selections: Value,
) -> arkret_event_draft::ProjectedEventOperation {
    at_position(
        make_operation(
            arkret_wire::EventKind::MessageCreate,
            realm,
            serde_json::json!({
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {
                    "kind": "ak.content.poll.response",
                    "body": "vote",
                    "poll_response": {"poll_ref": POLL_ID, "selections": selections}
                }
            }),
        ),
        2,
    )
}

fn at_position(
    operation: arkret_event_draft::ProjectedEventOperation,
    position: u64,
) -> arkret_event_draft::ProjectedEventOperation {
    let stream_ref = arkret_wire::CommitStreamRef::from_scope(
        &operation.context.accepted_scope_ref,
        Some(operation.realm_id.clone()),
    )
    .unwrap();
    let reference = arkret_wire::CommittedEventRef {
        event_id: operation.context.accepted_event_id.clone(),
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("poll-test-{position}-{}", operation.context.event_id).as_bytes(),
        )),
        stream_ref,
        stream_position: position,
    };
    operation.with_committed_ref(reference).unwrap()
}

#[test]
fn poll_vote_winner_uses_commit_position_when_delivery_is_reversed() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-order-test");
    create_poll(&mut state, &hlc);
    let newer = at_position(response_operation(REALM_A, serde_json::json!(["no"])), 3);
    let older = at_position(response_operation(REALM_A, serde_json::json!(["yes"])), 2);
    assert!(matches!(
        state.apply(&newer, &hlc),
        ProjectionEffect::Ignored
    ));
    assert!(matches!(
        state.apply(&older, &hlc),
        ProjectionEffect::Ignored
    ));
    let poll = state.poll(POLL_ID).unwrap();
    assert_eq!(poll.responses.len(), 2);
    assert_eq!(poll.votes.values().next().unwrap(), &vec!["no".to_owned()]);
    assert_eq!(state.messages.len(), 1);
}

#[test]
fn poll_response_without_accepting_commit_fails_closed() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-no-commit-test");
    create_poll(&mut state, &hlc);
    let mut operation = response_operation(REALM_A, serde_json::json!(["yes"]));
    operation.context.committed_ref = None;
    assert!(
        matches!(state.apply(&operation,&hlc),ProjectionEffect::Rejected { ref reason } if reason=="poll_accepting_commit_unavailable")
    );
    assert!(state.poll(POLL_ID).unwrap().votes.is_empty());
    assert!(state.poll(POLL_ID).unwrap().responses.is_empty());
}

#[test]
fn poll_reducer_rejects_same_realm_different_circle_scope() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    seed_strand(&mut state, STRAND_A, Some(CIRCLE_A));
    seed_strand(&mut state, STRAND_B, Some(CIRCLE_B));
    create_poll(&mut state, &hlc);

    let mut response = response_operation_on_strand(REALM_A, STRAND_B, serde_json::json!(["yes"]));
    response.context.accepted_scope_ref = arkret_wire::ScopeRef::Circle {
        realm_id: arkret_wire::RealmId::new(REALM_A).unwrap(),
        circle_id: arkret_wire::CircleId::new(CIRCLE_B).unwrap(),
    };
    let effect = state.apply(&response, &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "poll_ref_cross_scope"
    ));
}

#[test]
fn poll_reducer_accepts_only_exact_scope_known_answers_within_limit() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    create_poll(&mut state, &hlc);

    assert!(matches!(
        response(&mut state, &hlc, REALM_A, serde_json::json!(["yes"])),
        ProjectionEffect::Ignored
    ));
    let vote = state.poll(POLL_ID).unwrap().votes.values().next().unwrap();
    assert_eq!(vote, &vec!["yes".to_owned()]);

    for (realm, selections, reason) in [
        (
            REALM_A,
            serde_json::json!(["unknown"]),
            "poll_selection_unknown_answer",
        ),
        (
            REALM_A,
            serde_json::json!(["yes", "no"]),
            "poll_selection_over_max",
        ),
        (REALM_B, serde_json::json!(["yes"]), "poll_ref_cross_scope"),
    ] {
        let effect = response(&mut state, &hlc, realm, selections);
        assert!(
            matches!(effect, ProjectionEffect::Rejected { reason: ref actual } if actual == reason)
        );
    }
}

#[test]
fn poll_reducer_rejects_unknown_poll_instead_of_silently_ignoring() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-test");
    let effect = response(&mut state, &hlc, REALM_A, serde_json::json!(["yes"]));
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { ref reason } if reason == "poll_ref_unknown"
    ));
}

#[test]
fn poll_response_with_reply_does_not_materialize_timeline_or_reply_relation() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("poll-response-reply");
    create_poll(&mut state, &hlc);
    let response = at_position(
        make_operation(
            arkret_wire::EventKind::MessageCreate,
            REALM_A,
            serde_json::json!({"strand_id":STRAND_A,"track_name":"discussion","reply_to_id":POLL_ID,
            "content":{"kind":"ak.content.poll.response","body":"vote",
                "poll_response":{"poll_ref":POLL_ID,"selections":["yes"]}}}),
        ),
        2,
    );
    let messages_before = state.messages.len();
    let relations_before = state.relations.len();
    assert!(matches!(
        state.apply(&response, &hlc),
        ProjectionEffect::Ignored
    ));
    assert_eq!(state.messages.len(), messages_before);
    assert_eq!(state.relations.len(), relations_before);
    assert_eq!(state.poll(POLL_ID).unwrap().responses.len(), 1);
}
