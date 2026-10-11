use super::{
    FederationOutboxOutcome, FederationOutboxState, FederationOutboxTransition,
    classify_federation_outbox_completion,
};

fn transition(outcome: FederationOutboxOutcome) -> FederationOutboxTransition {
    FederationOutboxTransition {
        id: "outbox-1".to_owned(),
        lease_token: "lease-1".to_owned(),
        attempts: 2,
        semantic_attempts: 1,
        last_http_status: None,
        last_error_code: None,
        last_response_excerpt: None,
        observed_at: 42,
        outcome,
    }
}

#[test]
fn completion_projects_retry_and_terminal_fields_once() {
    let retry = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::Retry {
            next_attempt_at: 99,
        }),
    )
    .unwrap();
    assert_eq!(retry.state, FederationOutboxState::Pending);
    assert_eq!(retry.next_attempt_at, 99);
    assert_eq!(retry.completed_at, None);
    assert_eq!(retry.policy_version, None);

    let suppressed = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::PolicySuppressed {
            policy_version: "policy-v2".to_owned(),
        }),
    )
    .unwrap();
    assert_eq!(suppressed.state, FederationOutboxState::PolicySuppressed);
    assert_eq!(suppressed.next_attempt_at, 42);
    assert_eq!(suppressed.completed_at, Some(42));
    assert_eq!(suppressed.policy_version.as_deref(), Some("policy-v2"));
}

#[test]
fn completion_rejects_outcomes_from_the_other_lifecycle() {
    let direct_route_failure = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::RouteUnavailable {
            next_attempt_at: 99,
        }),
    );
    assert!(direct_route_failure.is_err());

    let realm_route_retry = classify_federation_outbox_completion(
        true,
        &transition(FederationOutboxOutcome::RouteUnavailable {
            next_attempt_at: 99,
        }),
    );
    assert!(realm_route_retry.is_ok());

    let direct_policy_suppression = classify_federation_outbox_completion(
        false,
        &transition(FederationOutboxOutcome::PolicySuppressed {
            policy_version: "policy-v2".to_owned(),
        }),
    );
    assert!(direct_policy_suppression.is_ok());

    let realm_policy_suppression = classify_federation_outbox_completion(
        true,
        &transition(FederationOutboxOutcome::PolicySuppressed {
            policy_version: "policy-v2".to_owned(),
        }),
    );
    assert!(realm_policy_suppression.is_err());
}
