use serde_json::{Value, json};

use super::*;

const REALM: &str = "ak:realm:Af9DRPZ6jo28Ku6bsJX3iOs5fu2GLdPa5mI-lkvcujvM";
const INVITE: &str = "ak:invite:AUftf_3k2fRKMG0NFlHe5iEMBOUpxMwYMRu-yhMJl-yz";
const INVITER: &str = "ak:did_core:web:alice.example";
const SUBJECT: &str = "ak:did_core:web:bob.example";
const SUBJECT_STATION: &str = "ak:did_core:web:station.example";
const SUBJECT_METHOD: &str = "did:web:bob.example#device-1";
const SERVICE: &str = "ak:did_core:web:verify.example";
const VERIFICATION_METHOD: &str = "did:web:verify.example#invite-key";
const TOKEN_COMMITMENT: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn third_party_invite(expires_at: &str) -> Value {
    json!({
        "event_id": INVITE.replacen("ak:invite:", "ak:event:", 1),
        "sender": INVITER,
        "expires_at": expires_at,
        "third_party_invite": {
            "oob_code_kind": "offline_token",
            "token_commitment": TOKEN_COMMITMENT,
            "token_salt_id": "salt-1",
            "token_entropy_bits": 128,
            "verification_id": SERVICE,
            "verification_public_key": VERIFICATION_METHOD,
            "max_claim_count": 1
        }
    })
}

fn claim_payload(nonce: &str, token_commitment: &str, service_id: &str) -> Value {
    let subject_account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(SUBJECT).unwrap(),
        arkret_identifiers::DidCoreId::new(SUBJECT_STATION).unwrap(),
    );
    let binding_proof = json!({
        "verification_id": service_id,
        "verification_method": VERIFICATION_METHOD,
        "subject_account_id": subject_account_id,
        "realm_id": REALM,
        "audience": "arkret.invite.claim",
        "claim_nonce": nonce,
        "expires_at": "2099-01-01T00:00:00.000Z",
        "signature": "test-signature"
    });
    let binding_digest = arkret_canonical::canonical_sha256(&binding_proof).unwrap();
    let transcript_digest = arkret_models_collaboration::governance::membership_invite::invite_subject_proof_transcript_digest(
        &subject_account_id,
        INVITE,
        REALM,
        token_commitment,
        nonce,
        service_id,
        binding_digest.as_str(),
    )
    .unwrap();
    json!({
        "invite_id": INVITE,
        "subject_account_id": subject_account_id,
        "token_commitment": token_commitment,
        "claim_nonce": nonce,
        "binding_proof": binding_proof,
        "subject_proof": {
            "verification_method": SUBJECT_METHOD,
            "signature_algorithm": "Ed25519",
            "transcript_digest": transcript_digest,
            "signature": "subject-signature"
        }
    })
}

fn seed_invite(state: &mut ProjectionState, hlc: &ServerHlc, expires_at: &str) {
    let mut operation = make_operation(
        arkret_wire::EventKind::InviteThirdParty,
        REALM,
        third_party_invite(expires_at),
    );
    operation.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let effect = state.apply(&operation, hlc);
    assert!(matches!(
        effect,
        ProjectionEffect::InviteStateChanged { ref state, .. } if state == "pending"
    ));
}

fn seed_realm_policy_allowlist(state: &mut ProjectionState, hlc: &ServerHlc, services: Vec<&str>) {
    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::RealmPolicyBundle,
            REALM,
            json!({
                "policy_revision": 1,
                "allowed_third_party_invite_verification_ids": services
            }),
        ),
        hlc,
    );
    assert!(matches!(
        effect,
        ProjectionEffect::RealmPolicyBundleProjected { .. }
    ));
}

#[test]
fn invite_claim_converts_third_party_invite_to_claimed_invite() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![SERVICE]);

    let effect = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload("nonce-0000000001", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );

    let subject = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(SUBJECT).unwrap(),
        arkret_identifiers::DidCoreId::new(SUBJECT_STATION).unwrap(),
    ))
    .to_string();
    assert!(matches!(
        effect,
        ProjectionEffect::InviteStateChanged {
            ref invite_id,
            ref state,
            ref invitee_id,
            ..
        } if invite_id == INVITE && state == "claimed" && invitee_id.as_deref() == Some(subject.as_str())
    ));
    let invite = state.invites.get(INVITE).expect("invite projected");
    assert_eq!(invite.state, "claimed");
    assert_eq!(invite.invitee_id.as_deref(), Some(subject.as_str()));
    assert!(
        invite
            .claim_nonces
            .get("nonce-0000000001")
            .is_some_and(|operation_id| operation_id.starts_with("ak:operation:"))
    );
    let third_party_invite = invite
        .third_party_invite
        .as_ref()
        .expect("third_party_invite");
    assert_eq!(
        third_party_invite
            .token_commitment
            .as_ref()
            .map(|h| h.as_str()),
        Some(TOKEN_COMMITMENT)
    );
    assert!(third_party_invite.token_salt_id.is_none());
    let member = state
        .member(REALM, &subject)
        .expect("claimed subject should have an invite membership proposal");
    assert_eq!(member.state, "invite");
}

#[test]
fn invite_claim_rejects_reused_claim_nonce() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-nonce");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![SERVICE]);

    assert!(!matches!(
        state.apply(
            &make_operation(
                arkret_wire::EventKind::InviteClaim,
                REALM,
                claim_payload("nonce-0000000001", TOKEN_COMMITMENT, SERVICE),
            ),
            &hlc,
        ),
        ProjectionEffect::Rejected { .. }
    ));

    let replay = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload("nonce-0000000001", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        replay,
        ProjectionEffect::Rejected { ref reason } if reason == "duplicate_conflict"
    ));
}

#[test]
fn invite_claim_rejects_bad_commitment_without_recording_nonce() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-commitment");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload(
                "nonce-bad-commitment",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                SERVICE,
            ),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "not_found"
    ));
    let invite = state.invites.get(INVITE).expect("invite projected");
    assert_eq!(invite.state, "pending");
    assert!(!invite.claim_nonces.contains_key("nonce-bad-commitment"));
}

#[test]
fn invite_claim_rechecks_verification_service_authorization() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-allowlist");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![SERVICE]);

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload(
                "nonce-service-0001",
                TOKEN_COMMITMENT,
                "ak:did_core:web:other.example",
            ),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
}

#[test]
fn invite_claim_rejects_invite_bound_service_without_current_policy_allowlist() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-policy-dropped");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload("nonce-no-policy-01", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
    let subject = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(SUBJECT).unwrap(),
        arkret_identifiers::DidCoreId::new(SUBJECT_STATION).unwrap(),
    ));
    assert!(
        state.member(REALM, &subject.to_string()).is_none(),
        "missing current Realm allowlist must not create membership proposal"
    );
}

#[test]
fn invite_claim_rejects_when_current_policy_no_longer_allows_bound_service() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-policy-rotated");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec!["ak:did_core:web:other.example"]);

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload("nonce-policy-rotated", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
}

#[test]
fn invite_claim_rejects_empty_policy_allowlist() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-empty-allowset");
    seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
    seed_realm_policy_allowlist(&mut state, &hlc, vec![]);

    let rejected = state.apply(
        &make_operation(
            arkret_wire::EventKind::InviteClaim,
            REALM,
            claim_payload("nonce-empty-allowset", TOKEN_COMMITMENT, SERVICE),
        ),
        &hlc,
    );
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "verification_service_not_authorized"
    ));
}

/// Only the normative top-level
/// `allowed_third_party_invite_verification_ids` component grants
/// claim authority. Any other spelling, and any nested occurrence of the
/// normative name, is inert data.
#[test]
fn invite_claim_ignores_non_normative_allowlist_spellings() {
    for decoy in [
        json!({
            "policy_revision": 1,
            "third_party_invite_verification_services": [SERVICE]
        }),
        json!({
            "policy_revision": 1,
            "allowed_verification_ids": [SERVICE]
        }),
        json!({
            "policy_revision": 1,
            "join_policy": {
                "allowed_third_party_invite_verification_ids": [SERVICE]
            }
        }),
    ] {
        let mut state = ProjectionState::new();
        let hlc = ServerHlc::new("invite-claim-decoy-allowset");
        seed_invite(&mut state, &hlc, "2099-01-01T00:00:00.000Z");
        state.apply(
            &make_operation(arkret_wire::EventKind::RealmPolicyBundle, REALM, decoy),
            &hlc,
        );

        let rejected = state.apply(
            &make_operation(
                arkret_wire::EventKind::InviteClaim,
                REALM,
                claim_payload("nonce-decoy-allowset", TOKEN_COMMITMENT, SERVICE),
            ),
            &hlc,
        );
        assert!(
            matches!(
                rejected,
                ProjectionEffect::Rejected { ref reason }
                    if reason == "verification_service_not_authorized"
            ),
            "non-normative allowlist carrier must not authorize a verification service"
        );
    }
}

#[test]
fn expired_claim_is_rejected_without_mutating_the_pending_invite() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("invite-claim-expiry");
    seed_invite(&mut state, &hlc, "2026-06-01T00:00:00.000Z");

    let mut claim = make_operation(
        arkret_wire::EventKind::InviteClaim,
        REALM,
        claim_payload("nonce-expired-001", TOKEN_COMMITMENT, SERVICE),
    );
    claim.created_at = chrono::DateTime::parse_from_rfc3339("2026-06-02T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let rejected = state.apply(&claim, &hlc);
    assert!(matches!(
        rejected,
        ProjectionEffect::Rejected { ref reason } if reason == "expired_invite_token"
    ));
    let invite = state.invites.get(INVITE).expect("invite remains projected");
    assert_eq!(invite.state, "pending");
    assert!(invite.claim_nonces.is_empty());
    let third_party_invite = invite
        .third_party_invite
        .as_ref()
        .expect("third_party_invite remains");
    assert_eq!(
        third_party_invite
            .token_commitment
            .as_ref()
            .map(|h| h.as_str()),
        Some(TOKEN_COMMITMENT)
    );
    assert_eq!(third_party_invite.token_salt_id.as_deref(), Some("salt-1"));
}
