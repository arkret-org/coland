use super::*;
const REALM: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const AGENT: &str = "ak:did_core:web:agent.example";
const CONTROLLER: &str = "ak:did_core:web:controller.example";
const REQUEST: &str = "action-request-01904100-0000-7000-8000-cfc039892037";

/// Assert an Operation was rejected for exactly `expected`, printing the real
/// effect when it was not. A bare `matches!` here hides the reason that makes
/// the failure diagnosable.
#[track_caller]
fn expect_rejected(effect: ProjectionEffect, expected: &str) {
    match effect {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, expected),
        other => panic!("expected Rejected({expected}), got {other:?}"),
    }
}

fn agent_operation(kind: arkret_wire::EventKind, payload: serde_json::Value) -> Operation {
    let mut operation = make_operation(kind, REALM, payload);
    operation.context.sender = account_actor(AGENT);
    operation
}

fn action_approve(request_id: &str) -> Operation {
    let mut operation = agent_operation(
        arkret_wire::EventKind::AgentActionApprove,
        serde_json::json!({
            "approval_id": "approval-01904100-0000-7000-8000-cfc039892038",
            "request_id": request_id,
            "agent_id": AGENT,
            "proposed_action": "ak.message.create",
            "target": { "kind": "realm", "realm_id": REALM },
            "approved_event_id": "ak:event:AbuDfbb-uv82LvhWbTydj5wUDvzph0PSFjJTtTJxq7P5",
            "approval_nonce": "nonce-01904100",
            "expires_at": "2026-06-19T00:10:10.000Z"
        }),
    );
    operation.context.sender = account_actor(CONTROLLER);
    operation
}

fn pause_agent() -> Operation {
    agent_operation(
        arkret_wire::EventKind::SelfAgentPause,
        serde_json::json!({
            "status_changed_at": "2026-06-19T00:00:00.000Z"
        }),
    )
}

fn resume_agent() -> Operation {
    agent_operation(
        arkret_wire::EventKind::SelfAgentResume,
        serde_json::json!({
            "status_changed_at": "2026-06-19T00:01:00.000Z"
        }),
    )
}

fn deactivate_agent() -> Operation {
    agent_operation(
        arkret_wire::EventKind::SelfAgentDeactivate,
        serde_json::json!({
            "status_changed_at": "2026-06-19T00:02:00.000Z"
        }),
    )
}

#[test]
fn lifecycle_transitions_are_guarded_and_deactivate_is_terminal() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    let effect = state.apply(&pause_agent(), &hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::AgentLifecycleProjected {
            agent_id,
            new_state: AgentLifecycleState::Paused,
        } if agent_id == AGENT
    ));
    state.apply(&resume_agent(), &hlc);
    state.apply(&deactivate_agent(), &hlc);
    expect_rejected(state.apply(&resume_agent(), &hlc), "agent_deactivated");
}

/// Action requests and rejections are actor-private: they are admitted only
/// into the controller's private store, so the shared reducer refuses them
/// and holds no request state. The approval is a durable confirmation fact.
#[test]
fn actor_private_agent_kinds_never_reach_the_shared_reducer() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    for kind in [
        arkret_wire::EventKind::AgentActionRequest,
        arkret_wire::EventKind::AgentActionReject,
        arkret_wire::EventKind::AgentDraftPropose,
        arkret_wire::EventKind::DevicePushRoute,
    ] {
        let effect = state.apply(
            &agent_operation(kind.clone(), serde_json::json!({"request_id": REQUEST})),
            &hlc,
        );
        assert!(
            matches!(effect, ProjectionEffect::Rejected { .. }),
            "{kind} reached the shared reducer: {effect:?}"
        );
    }
    assert!(matches!(
        state.apply(&action_approve(REQUEST), &hlc),
        ProjectionEffect::DurableFactRetained {
            kind: arkret_wire::EventKind::AgentActionApprove,
            ..
        }
    ));
}
