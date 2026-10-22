use serde_json::{Value, json};

use super::*;
use crate::reducer::{MlsEffect, ProjectionEffect, ProjectionState};

fn fixture_actor(principal_id: &str) -> arkret_wire::ActorId {
    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(principal_id.to_owned()).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
    ))
}

fn realm_scope() -> Value {
    json!({
        "kind": "realm",
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1"
    })
}

fn scope_group(scope: &Value) -> String {
    serde_json::from_value::<arkret_wire::ScopeRef>(scope.clone())
        .unwrap()
        .canonical_mls_group_id()
        .unwrap()
        .to_string()
}

fn realm_group() -> &'static str {
    static GROUP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    GROUP.get_or_init(|| scope_group(&realm_scope())).as_str()
}

fn publish_projection(
    id: &str,
    actor: &str,
    device: &str,
    not_after: i64,
    last_resort: bool,
) -> MlsKeyPackagePublishProjection {
    let key_package_bytes = b"opaque-keypackage-bytes".to_vec();
    MlsKeyPackagePublishProjection {
        keypackage_id: id.to_owned(),
        keypackage_ref: id.to_owned(),
        keypackage_digest: arkret_canonical::sha256_digest(&key_package_bytes),
        owner_actor_id: fixture_actor(actor),
        effective_scope: None,
        actor_id: fixture_actor(actor).to_string(),
        device_id: Some(device.to_owned()),
        lifetime: KeyPackageLifetimeProjection {
            not_before: 1,
            not_after,
        },
        key_package_bytes,
        capabilities: Vec::new(),
        last_resort,
        trust_anchor: MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
            "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa".to_owned(),
        ),
        created_at: 100,
    }
}

const DEVICE_AUTHORIZE: &str = "ak:event:ATyaOl1JkDDCC-6ZytsgoAKvlQJ6s6NJuDC_bmWKARBa";

fn claim_projection(id: &str, group_id: &str, claimed_at: i64) -> MlsKeyPackageClaimProjection {
    MlsKeyPackageClaimProjection {
        keypackage_id: id.to_owned(),
        group_id: group_id.to_owned(),
        intended_realm_id: None,
        trust_binding: KeyPackageTrustBinding::device_authorize(DEVICE_AUTHORIZE.to_owned()),
        claim_expires_at_unix_ms: None,
        claimed_at,
    }
}

#[test]
fn keypackage_publish_then_claim_succeeds() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-01",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let effect = apply_keypackage_upload_projection(&mut state, &publish);
    assert!(matches!(
        effect,
        ProjectionEffect::Mls(MlsEffect::KeyPackagePublished { ref keypackage_id, .. })
            if keypackage_id == "keypackage-01"
    ));
    assert!(
        state
            .mls_key_packages
            .get("keypackage-01")
            .unwrap()
            .claimed_by
            .is_none()
    );

    let claim = claim_projection("keypackage-01", realm_group(), 200);
    match apply_keypackage_claim_projection(&mut state, &claim) {
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
            keypackage_id,
            group_id,
            claimed_at,
            ..
        }) => {
            assert_eq!(keypackage_id, "keypackage-01");
            assert_eq!(group_id, realm_group());
            assert_eq!(claimed_at, 200);
        }
        other => panic!("expected KeyPackageClaimed, got {other:?}"),
    }
    let row = state.mls_key_packages.get("keypackage-01").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some(realm_group()));
    assert_eq!(row.claimed_at, Some(200));
    assert_eq!(row.consumed_at, None);
}

#[test]
fn keypackage_claim_twice_second_fails() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-02",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    // First claim wins.
    let e1 = apply_keypackage_claim_projection(
        &mut state,
        &claim_projection("keypackage-02", "mls-group-first", 200),
    );
    assert!(matches!(
        e1,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));

    // Second claim must be rejected by the CAS.
    let e2 = apply_keypackage_claim_projection(
        &mut state,
        &claim_projection("keypackage-02", "mls-group-second", 201),
    );
    match e2 {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_ALREADY_CLAIMED);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    // The winning group must still own the row: a loser never overwrites.
    let row = state.mls_key_packages.get("keypackage-02").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("mls-group-first"));
    assert_eq!(row.claimed_at, Some(200));
    assert_eq!(row.consumed_at, None);
}

#[test]
fn keypackage_claim_same_group_renews_instead_of_conflicting() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-renew",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    let claim = |at: i64| MlsKeyPackageClaimProjection {
        claim_expires_at_unix_ms: Some((at + 300) * 1000),
        ..claim_projection("keypackage-renew", "mls-group-same", at)
    };
    let e1 = apply_keypackage_claim_projection(&mut state, &claim(200));
    assert!(matches!(
        e1,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));

    // Re-claim by the SAME group (an interrupted materialization retrying after
    // the claim window lapsed) is idempotent renewal, not a CAS conflict.
    let e2 = apply_keypackage_claim_projection(&mut state, &claim(600));
    assert!(matches!(
        e2,
        ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed { .. })
    ));
    let row = state.mls_key_packages.get("keypackage-renew").unwrap();
    assert_eq!(row.claimed_by.as_deref(), Some("mls-group-same"));
    assert_eq!(row.claimed_at, Some(600));
    assert_eq!(row.claim_expires_at_unix_ms, Some(900_000));

    // A different group is still rejected by the CAS.
    match apply_keypackage_claim_projection(
        &mut state,
        &claim_projection("keypackage-renew", "mls-group-other", 700),
    ) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_ALREADY_CLAIMED);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn last_resort_keypackage_reuses_within_realm_only() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-last-resort",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        true,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    for group_id in ["mls-group-first", "mls-group-second"] {
        let claim = MlsKeyPackageClaimProjection {
            intended_realm_id: Some("ak:realm:alpha".to_owned()),
            ..claim_projection("keypackage-last-resort", group_id, 200)
        };
        assert!(matches!(
            apply_keypackage_claim_projection(&mut state, &claim),
            ProjectionEffect::Mls(MlsEffect::KeyPackageClaimed {
                last_resort: true,
                ..
            })
        ));
    }

    let row = state
        .mls_key_packages
        .get("keypackage-last-resort")
        .unwrap();
    assert!(row.claimed_by.is_none());
    assert!(row.consumed_at.is_none());
    assert_eq!(row.last_resort_realm_id.as_deref(), Some("ak:realm:alpha"));

    let cross_realm = MlsKeyPackageClaimProjection {
        intended_realm_id: Some("ak:realm:beta".to_owned()),
        ..claim_projection("keypackage-last-resort", "mls-group-other", 201)
    };
    match apply_keypackage_claim_projection(&mut state, &cross_realm) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_REALM_MISMATCH);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn revoked_last_resort_keypackage_cannot_be_reused() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-revoked-last-resort",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        true,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);
    state
        .mls_key_packages
        .get_mut("keypackage-revoked-last-resort")
        .unwrap()
        .claimed_by = Some("revoked".to_owned());

    let claim = MlsKeyPackageClaimProjection {
        intended_realm_id: Some("ak:realm:alpha".to_owned()),
        ..claim_projection("keypackage-revoked-last-resort", "mls-group-first", 200)
    };
    match apply_keypackage_claim_projection(&mut state, &claim) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, REASON_KEYPACKAGE_NOT_FOUND);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn keypackage_claim_rejects_mismatched_device_authorization() {
    let mut state = ProjectionState::default();
    let publish = publish_projection(
        "keypackage-03",
        "ak:did_core:web:alice.example",
        "ak:device:alice-desktop",
        1_000_000,
        false,
    );
    let _ = apply_keypackage_upload_projection(&mut state, &publish);

    let claim = MlsKeyPackageClaimProjection {
        trust_binding: KeyPackageTrustBinding::device_authorize(
            "ak:event:Af7kHhjQt9bXM9MVmV6uu7VNZY1P_sjoIUGS2rxLV8Qt".to_owned(),
        ),
        ..claim_projection("keypackage-03", realm_group(), 200)
    };
    match apply_keypackage_claim_projection(&mut state, &claim) {
        ProjectionEffect::Rejected { reason } => {
            assert_eq!(reason, arkret_wire::ReasonCode::DEVICE_GENERATION_FENCED);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    let row = state.mls_key_packages.get("keypackage-03").unwrap();
    assert!(row.claimed_by.is_none());
    assert_eq!(
        row.device_authorize_event_id.as_deref(),
        Some(DEVICE_AUTHORIZE)
    );
}
