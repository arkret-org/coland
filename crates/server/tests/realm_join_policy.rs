//! Reducer-level tests for Join Policy `principal_admission`.
//!
//! The gate is a hard pre-admission constraint: when the projected
//! the `ak.realm.policy_bundle` payload path `join_policy` contains it, `membership=join`
//! must pass before the member transition is updated.

use arkret_event_draft::ProjectedEventOperation as Operation;
use chrono::{Duration, Utc};
use coland_domain::hlc::ServerHlc;
use coland_domain::reducer::{ProjectionEffect, ProjectionState};
use serde_json::{Value, json};

const REALM_A: &str = "ak:realm:AZpEa1TBWdyQensfzl-MJg8_sdcSNKSeAKHbyCN5ZXjb";
const REALM_PARENT: &str = "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW";
const BOB: &str = "ak:did_core:web:bob.example";
const MALLORY: &str = "ak:did_core:web:mallory.example";
const CAPTCHA_PROVIDER_DID: &str = "did:webvh:z6mkfixture:captcha.example";

fn member_actor(principal: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal).unwrap(),
        coland_test_support::fixture_station_id(),
    ))
}

fn op(kind: impl AsRef<str>, realm_id: &str, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        kind.as_ref(),
        payload,
    )
}

fn apply_policy(state: &mut ProjectionState, hlc: &ServerHlc, join_policy: Value) {
    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": join_policy
            }),
        ),
        hlc,
    );
    assert!(
        matches!(effect, ProjectionEffect::RealmPolicyBundleProjected { .. }),
        "policy_bundle projection must write the canonical cell, got {effect:?}"
    );
}

fn apply_join_rule(state: &mut ProjectionState, join_rule: &str) {
    let payload = json!({"value": join_rule});
    let operation = op(arkret_wire::EventKind::RealmJoinRule, REALM_A, payload);
    let effect = state.apply(&operation, &ServerHlc::new("join-policy-test"));
    assert!(
        matches!(
            effect,
            ProjectionEffect::RealmBootstrapFacetProjected { .. }
        ),
        "join-rule projection must write the canonical Realm cell, got {effect:?}"
    );
}

fn join_op(member: &str) -> Operation {
    op(
        arkret_wire::EventKind::MemberState,
        REALM_A,
        json!({
            "realm_id": REALM_A,
            "member_id": member_actor(member),
            "membership": "join"
        }),
    )
}

fn member_state_op(realm_id: &str, member: &str, membership: &str) -> Operation {
    let operation = op(
        arkret_wire::EventKind::MemberState,
        realm_id,
        json!({
            "realm_id": realm_id,
            "member_id": member_actor(member),
            "membership": membership
        }),
    );
    operation
        .typed_payload::<arkret_wire::event_spec::MemberState>()
        .expect("join-policy fixture membership payload");
    operation
}

/// The digest a gate proof binds itself to: the accepted `join_policy`
/// component this join is evaluated against.
fn policy_digest(state: &ProjectionState) -> String {
    let policy = state
        .realm_join_policy_value(REALM_A)
        .expect("join policy cell must be projected");
    arkret_canonical::canonical_sha256(policy).expect("canonical policy digest")
}

/// A `challenge_response` item in the registered `join_gate_proof` shape.
///
/// The binding tuple is carried as wire members, so the fixture has to name the
/// same Realm, applicant and policy revision the reducer is evaluating; that is
/// exactly what the private pre-ruling shape could not express.
fn challenge_proof(
    state: &ProjectionState,
    gate_id: &str,
    member: &str,
    created_at: chrono::DateTime<Utc>,
) -> Value {
    json!({
        "gate_id": gate_id,
        "kind": "challenge_response",
        "realm_id": REALM_A,
        "applicant_actor_id": member_actor(member),
        "policy_digest": policy_digest(state),
        "created_at": arkret_canonical::format_timestamp_canonical(created_at),
        "challenge_kind": "captcha",
        "challenge_id": "chg_01HXY9PM0AB6Y7VN2C7M4WG5KQ",
        "proofs": [{
            "kind": "detached_jws",
            "verification_method": format!("{CAPTCHA_PROVIDER_DID}#challenge-1"),
            "payload_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "created_at": arkret_canonical::format_timestamp_canonical(created_at),
            "jws": "ZXlKaGJHY2lPaUpGWkRJMU5URTVJbjA..c2ln"
        }]
    })
}

#[test]
fn principal_admission_did_method_fails_closed_without_did_evidence() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "public");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "principal-webvh",
                "kind": "principal_admission",
                "auto_resolve": true,
                "allowed_did_methods": ["did:webvh"]
            }],
            "combinator": "all"
        }),
    );

    assert!(
        state.realm_policy_bundle_value(REALM_A).is_some(),
        "policy_bundle cell must be projected"
    );

    let unresolved = join_op("ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x");
    assert!(matches!(
        state.apply(&unresolved, &hlc),
        ProjectionEffect::Rejected { reason } if reason == "gate_check_failed"
    ));

    let rejected = join_op("ak:did_core:web:users.acme.example:mallory");
    match state.apply(&rejected, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
    assert!(
        state
            .member(
                REALM_A,
                &member_actor("ak:did_core:web:users.acme.example:mallory").to_string()
            )
            .is_none()
    );
}

#[test]
fn principal_admission_denylist_wins_over_allowlist() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let blocked = "ak:did_core:web:blocked.example";
    apply_join_rule(&mut state, "public");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [{
                "gate_id": "principal-did-list",
                "kind": "principal_admission",
                "auto_resolve": true,
                "allowed_did_methods": ["did:web"],
                "allowed_principal_ids": [blocked],
                "denied_principal_ids": [blocked]
            }],
            "combinator": "all"
        }),
    );

    match state.apply(&join_op(blocked), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn principal_admission_requires_selector_on_policy_write() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "principal-empty",
                        "kind": "principal_admission",
                        "auto_resolve": true
                    }],
                    "combinator": "all"
                }
            }),
        ),
        &hlc,
    );

    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "principal_admission_requires_selector");
        }
        other => panic!("expected Rejected(principal_admission_requires_selector), got {other:?}"),
    }
}

#[test]
fn join_policy_requires_explicit_combinator_on_policy_write() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "principal-web",
                        "kind": "principal_admission",
                        "auto_resolve": true,
                        "allowed_did_methods": ["did:web"]
                    }]
                }
            }),
        ),
        &hlc,
    );

    match effect {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, "schema_violation");
        }
        other => panic!("expected Rejected(schema_violation), got {other:?}"),
    }
}

#[test]
fn parent_membership_gate_never_uses_projection_cache_as_authority() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let parent_join = member_state_op(REALM_PARENT, BOB, "join");
    assert!(matches!(
        state.apply(&parent_join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
    apply_join_rule(&mut state, "restricted");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "g-parent",
                    "kind": "parent_membership",
                    "auto_resolve": true,
                    "membership_source_realm_ids": [REALM_PARENT],
                    "require_min_membership": "join"
                },
                {
                    "gate_id": "g-captcha",
                    "kind": "challenge_response",
                    "auto_resolve": true,
                    "provider_did": CAPTCHA_PROVIDER_DID,
                    "challenge_kinds": ["captcha"],
                    "max_proof_age": "PT5M"
                }
            ],
            "combinator": "any"
        }),
    );

    match state.apply(&join_op(BOB), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
    match state.apply(&join_op(MALLORY), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn all_combinator_requires_parent_membership_and_challenge_proof() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let parent_join = member_state_op(REALM_PARENT, BOB, "join");
    assert!(matches!(
        state.apply(&parent_join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
    apply_join_rule(&mut state, "restricted");

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "g-parent",
                    "kind": "parent_membership",
                    "auto_resolve": true,
                    "membership_source_realm_ids": [REALM_PARENT],
                    "require_min_membership": "join"
                },
                {
                    "gate_id": "g-captcha",
                    "kind": "challenge_response",
                    "auto_resolve": true,
                    "provider_did": CAPTCHA_PROVIDER_DID,
                    "challenge_kinds": ["captcha"],
                    "max_proof_age": "PT5M"
                }
            ],
            "combinator": "all"
        }),
    );

    match state.apply(&join_op(BOB), &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }

    let now = Utc::now();
    let mut accepted = join_op(BOB);
    accepted.created_at = now;
    accepted.payload["gate_proofs"] = json!([challenge_proof(
        &state,
        "g-captcha",
        BOB,
        now - Duration::minutes(1)
    )]);
    match state.apply(&accepted, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn cooldown_gate_denies_independently_of_any_combinator() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    let leave_at = Utc::now() - Duration::minutes(10);
    apply_join_rule(&mut state, "public");
    let mut initial_join = member_state_op(REALM_A, BOB, "join");
    initial_join.created_at = leave_at - Duration::minutes(10);
    assert!(matches!(
        state.apply(&initial_join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
    let mut leave = member_state_op(REALM_A, BOB, "leave");
    leave.created_at = leave_at;
    assert!(matches!(
        state.apply(&leave, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));

    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "leave-cooldown",
                    "kind": "cooldown",
                    "auto_resolve": true,
                    "min_interval_since_leave": "PT1H"
                },
                {
                    "gate_id": "g-captcha",
                    "kind": "challenge_response",
                    "auto_resolve": true,
                    "provider_did": CAPTCHA_PROVIDER_DID,
                    "challenge_kinds": ["captcha"],
                    "max_proof_age": "PT5M"
                }
            ],
            "combinator": "any"
        }),
    );

    let join_at = leave_at + Duration::minutes(20);
    let mut challenged = join_op(BOB);
    challenged.created_at = join_at;
    challenged.payload["gate_proofs"] = json!([challenge_proof(
        &state,
        "g-captcha",
        BOB,
        join_at - Duration::minutes(1)
    )]);
    match state.apply(&challenged, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn manual_review_gate_is_rejected_as_non_v1_policy() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "restricted");

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "review",
                        "kind": "manual_review",
                        "auto_resolve": false
                    }],
                    "combinator": "any",
                    "review_capability": "ak.realm.admin"
                }
            }),
        ),
        &hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::Rejected { reason } if reason == "schema_violation"
    ));
    assert!(state.realm_policy_bundle_value(REALM_A).is_none());
}

/// join-policy.md §2: `restricted` and `knock_restricted` promise an entry
/// gate. A policy carrying only the `principal_admission` / `cooldown` hard
/// gates admits exactly the set `public` admits, so the pair is a
/// contradictory declaration and the reducer refuses to write it.
#[test]
fn restricted_join_rule_rejects_a_policy_without_an_automatic_gate() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "restricted");

    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "allowlist",
                        "kind": "principal_admission",
                        "allowed_principal_ids": [BOB]
                    }],
                    "combinator": "all"
                }
            }),
        ),
        &hlc,
    );
    assert!(
        matches!(
            &effect,
            ProjectionEffect::Rejected { reason } if reason == "join_rule_policy_mismatch"
        ),
        "got {effect:?}"
    );
    assert!(state.realm_policy_bundle_value(REALM_A).is_none());
}

#[test]
fn knock_restricted_accepts_a_policy_that_carries_an_automatic_gate() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "knock_restricted");
    apply_policy(
        &mut state,
        &hlc,
        json!({
            "gates": [
                {
                    "gate_id": "allowlist",
                    "kind": "principal_admission",
                    "allowed_principal_ids": [BOB]
                },
                {
                    "gate_id": "employee",
                    "kind": "claim_required",
                    "required_claims": ["employee"],
                    "trusted_issuer_ids": ["ak:did_core:web:issuer.example"]
                }
            ],
            "combinator": "all"
        }),
    );
    assert!(state.realm_policy_bundle_value(REALM_A).is_some());
}

#[test]
fn a_claim_gate_without_an_issuer_boundary_is_not_an_admissible_policy() {
    // join-policy.md 3.1 makes `trusted_issuer_ids` required material: without
    // it the gate would accept a claim the applicant issued to themselves, so
    // the policy is refused rather than stored and evaluated leniently. The
    // closed gate type rejects it while parsing, which is earlier than the
    // reducer's own check on the same field — both are kept, because a lane
    // that reaches the reducer without the typed parse must not be lenient.
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "restricted");
    let effect = state.apply(
        &op(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM_A,
            json!({
                "policy_revision": 1,
                "join_policy": {
                    "gates": [{
                        "gate_id": "employee",
                        "kind": "claim_required",
                        "auto_resolve": true,
                        "required_claims": ["employee"]
                    }],
                    "combinator": "all"
                }
            }),
        ),
        &hlc,
    );
    match effect {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "schema_violation"),
        other => panic!("expected the policy to be refused, got {other:?}"),
    }
    assert!(state.realm_join_policy_value(REALM_A).is_none());

    // The reducer's own check, reached directly.
    assert_eq!(
        coland_domain::reducer::validate_join_policy_payload(&json!({
            "gates": [{
                "gate_id": "employee",
                "kind": "claim_required",
                "auto_resolve": true,
                "required_claims": ["employee"]
            }],
            "combinator": "all"
        })),
        Err("claim_required_trusted_issuers_invalid")
    );
}

/// The other half of the same rule: a `restricted` Realm that has no automatic
/// gate must not admit a self-authored join, which is exactly what an empty
/// `all` gate list used to do vacuously.
#[test]
fn restricted_without_an_automatic_gate_never_admits_a_join() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    // The write guard refuses the pair, so reach the evaluation path the way a
    // Realm that never wrote a policy bundle does.
    apply_join_rule(&mut state, "restricted");

    let effect = state.apply(&join_op(MALLORY), &hlc);
    assert!(
        matches!(
            &effect,
            ProjectionEffect::Rejected { reason } if reason == "gate_check_failed"
        ),
        "got {effect:?}"
    );
}

// `join-policy.md` section 4 rule 4 — the binding tuple every `join_gate_proof`
// carries. Each of these mutates exactly one member of the tuple and asserts the
// join is refused, so a proof cannot be lifted across Realms, applicants or
// policy revisions. The outward verdict stays the single non-enumerable
// `gate_check_failed` in every case.

fn captcha_policy() -> Value {
    json!({
        "gates": [{
            "gate_id": "g-captcha",
            "kind": "challenge_response",
            "auto_resolve": true,
            "provider_did": CAPTCHA_PROVIDER_DID,
            "challenge_kinds": ["captcha"],
            "max_proof_age": "PT5M"
        }],
        "combinator": "all"
    })
}

/// A `restricted` Realm whose only gate is the captcha challenge, plus the join
/// Event that would clear it. The caller mutates the proof before applying.
fn captcha_join(mutate: impl FnOnce(&mut Value)) -> (ProjectionState, ServerHlc, Operation) {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("test");
    apply_join_rule(&mut state, "restricted");
    apply_policy(&mut state, &hlc, captcha_policy());

    let now = Utc::now();
    let mut join = join_op(BOB);
    join.created_at = now;
    let mut proof = challenge_proof(&state, "g-captcha", BOB, now - Duration::minutes(1));
    mutate(&mut proof);
    join.payload["gate_proofs"] = json!([proof]);
    (state, hlc, join)
}

fn assert_gate_check_failed(mutate: impl FnOnce(&mut Value)) {
    let (mut state, hlc, join) = captcha_join(mutate);
    match state.apply(&join, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn an_unmutated_gate_proof_admits_the_applicant() {
    // The control for every mutation below: without it the negatives could all
    // be passing for an unrelated reason.
    let (mut state, hlc, join) = captcha_join(|_| {});
    assert!(matches!(
        state.apply(&join, &hlc),
        ProjectionEffect::MembershipChanged { .. }
    ));
}

#[test]
fn a_gate_proof_bound_to_another_realm_is_refused() {
    assert_gate_check_failed(|proof| {
        proof["realm_id"] = json!(REALM_PARENT);
    });
}

#[test]
fn a_gate_proof_bound_to_another_applicant_is_refused() {
    assert_gate_check_failed(|proof| {
        proof["applicant_actor_id"] = serde_json::to_value(member_actor(MALLORY)).unwrap();
    });
}

#[test]
fn a_gate_proof_bound_to_another_policy_revision_is_refused() {
    assert_gate_check_failed(|proof| {
        proof["policy_digest"] = json!(format!("sha256:{}", "b".repeat(64)));
    });
}

#[test]
fn a_gate_proof_older_than_max_proof_age_is_refused() {
    assert_gate_check_failed(|proof| {
        let stale = Utc::now() - Duration::minutes(30);
        proof["created_at"] = json!(arkret_canonical::format_timestamp_canonical(stale));
    });
}

#[test]
fn a_gate_proof_stamped_after_the_event_is_refused() {
    // Freshness is measured against the Event's own signed created_at, so a
    // proof from the future was not in the applicant's hands when they signed.
    assert_gate_check_failed(|proof| {
        let ahead = Utc::now() + Duration::minutes(5);
        proof["created_at"] = json!(arkret_canonical::format_timestamp_canonical(ahead));
    });
}

#[test]
fn a_gate_proof_for_an_unaccepted_challenge_family_is_refused() {
    assert_gate_check_failed(|proof| {
        proof["challenge_kind"] = json!("pow");
    });
}

#[test]
fn a_gate_proof_whose_kind_contradicts_the_gate_is_refused() {
    assert_gate_check_failed(|proof| {
        proof["kind"] = json!("claim_required");
        proof["issuer_id"] = json!("ak:did_core:web:issuer.example");
        proof["claims"] = json!(["employee"]);
        proof.as_object_mut().unwrap().remove("challenge_kind");
        proof.as_object_mut().unwrap().remove("challenge_id");
    });
}

#[test]
fn a_gate_proof_in_the_pre_ruling_private_shape_is_refused() {
    // The shape coland used to accept: member names it invented, with no
    // binding tuple at all. It is not the registered carrier, so the payload
    // does not parse and the Move is refused before any gate is evaluated.
    let (mut state, hlc, join) = captcha_join(|proof| {
        *proof = json!({
            "gate_id": "g-captcha",
            "challenge_proof": {
                "challenge_id": "chg_01HXY9PM0AB6Y7VN2C7M4WG5KQ",
                "issued_by": CAPTCHA_PROVIDER_DID,
                "challenge_kind": "captcha",
                "issued_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
                "proof": "base64url:test-proof"
            }
        });
    });
    match state.apply(&join, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "schema_violation"),
        other => panic!("expected Rejected(schema_violation), got {other:?}"),
    }
}

#[test]
fn a_claim_gate_only_accepts_claims_from_a_trusted_issuer() {
    let issuer = "ak:did_core:web:issuer.example";
    let policy = json!({
        "gates": [{
            "gate_id": "g-vc",
            "kind": "claim_required",
            "auto_resolve": true,
            "required_claims": ["employee"],
            "trusted_issuer_ids": [issuer]
        }],
        "combinator": "all"
    });
    let claim_proof = |state: &ProjectionState, issuer_id: &str, claims: Value| {
        let now = Utc::now();
        json!({
            "gate_id": "g-vc",
            "kind": "claim_required",
            "realm_id": REALM_A,
            "applicant_actor_id": member_actor(BOB),
            "policy_digest": policy_digest(state),
            "created_at": arkret_canonical::format_timestamp_canonical(now),
            "issuer_id": issuer_id,
            "claims": claims,
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": "did:web:issuer.example#vc-1",
                "payload_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "created_at": arkret_canonical::format_timestamp_canonical(now),
                "jws": "ZXlKaGJHY2lPaUpGWkRJMU5URTVJbjA..c2ln"
            }]
        })
    };

    let apply_claim = |issuer_id: &str, claims: Value| {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("test");
        apply_join_rule(&mut state, "restricted");
        apply_policy(&mut state, &hlc, policy.clone());
        let mut join = join_op(BOB);
        join.created_at = Utc::now();
        join.payload["gate_proofs"] = json!([claim_proof(&state, issuer_id, claims)]);
        state.apply(&join, &hlc)
    };

    assert!(matches!(
        apply_claim(issuer, json!(["employee"])),
        ProjectionEffect::MembershipChanged { .. }
    ));

    // An issuer outside the gate's boundary is a self-signed claim.
    match apply_claim("ak:did_core:web:attacker.example", json!(["employee"])) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }

    // Claims that do not cover what the gate requires.
    match apply_claim(issuer, json!(["contractor"])) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "gate_check_failed"),
        other => panic!("expected Rejected(gate_check_failed), got {other:?}"),
    }
}

#[test]
fn two_proofs_for_one_gate_are_a_schema_violation() {
    let (mut state, hlc, mut join) = captcha_join(|_| {});
    let proof = join.payload["gate_proofs"][0].clone();
    join.payload["gate_proofs"] = json!([proof.clone(), proof]);
    match state.apply(&join, &hlc) {
        ProjectionEffect::Rejected { reason } => assert_eq!(reason, "schema_violation"),
        other => panic!("expected Rejected(schema_violation), got {other:?}"),
    }
}
