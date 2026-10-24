use super::*;

#[test]
fn event_admission_rejects_bare_and_legacy_batch_carriers() {
    for body in [
        json!({"kind": "ak.message.create", "payload": {"text": "bare"}}),
        json!({"event": {}, "unregistered_sidecar": {}}),
        json!({"events": [], "unregistered_sidecar": {}}),
        json!({"unit_kind": "direct_conversation_founding", "events": []}),
    ] {
        assert!(serde_json::from_value::<arkret_wire::EventAdmissionSubmission>(body).is_err());
    }
}
#[test]
fn terminal_realm_blocks_non_audit_kind() {
    let blocked = terminal_realm_check(true, "ak.message.create");
    assert!(matches!(blocked, Some((ErrorCode::FailedPrecondition, _))));
    let audit_ok = terminal_realm_check(true, "ak.audit.accessed");
    assert!(audit_ok.is_none());
    let live_ok = terminal_realm_check(false, "ak.message.create");
    assert!(live_ok.is_none());
}

#[test]
fn frozen_realm_blocks_ordinary_write_but_allows_lifecycle_escape() {
    assert!(frozen_realm_check(true, "ak.message.create", &json!({})).is_some());
    assert!(
        frozen_realm_check(
            true,
            arkret_wire::EventKind::RealmFreeze.as_str(),
            &json!({})
        )
        .is_none()
    );
    assert!(
        frozen_realm_check(
            true,
            arkret_wire::EventKind::RealmDestroy.as_str(),
            &json!({})
        )
        .is_none()
    );
    assert!(frozen_realm_check(true, "ak.audit.accessed", &json!({})).is_none());
    assert!(frozen_realm_check(false, "ak.message.create", &json!({})).is_none());
}

#[test]
fn lifecycle_escape_preserves_terminal_and_authority_boundaries() {
    for kind in [
        "ak.realm.restore",
        "ak.realm.unfreeze",
        "ak.capability.revoke",
        "ak.device.revoke",
    ] {
        assert!(frozen_realm_check(true, kind, &json!({})).is_none());
        assert!(terminal_realm_check(true, kind).is_some());
    }
    assert!(frozen_realm_check(true, "ak.member.state", &json!({"membership":"leave"})).is_none());
    for membership in ["join", "knock", "ban"] {
        assert!(
            frozen_realm_check(true, "ak.member.state", &json!({"membership":membership}))
                .is_some()
        );
    }
    for kind in [
        "ak.realm.policy_bundle",
        "ak.capability.grant",
        "ak.message.create",
    ] {
        assert!(frozen_realm_check(true, kind, &json!({})).is_some());
    }
}

#[test]
fn realm_policy_bundle_media_plaintext_authorization() {
    let payload = json!({"media_service_decryption_allowed": true});
    let err = realm_policy_bundle_check(&payload, false).unwrap_err();
    assert_eq!(err.0, ErrorCode::FailedPrecondition);
    realm_policy_bundle_check(&payload, true).unwrap();
}

#[test]
fn parent_membership_policy_shape_is_admitted_for_durable_transaction_validation() {
    let payload = json!({
        "join_policy": {
            "gates": [{
                "gate_id": "same-station-parent",
                "kind": "parent_membership",
                "auto_resolve": true,
                "membership_source_realm_ids": [
                    "ak:realm:AYCKiTPA1bjQa3rIKg4O1PGpeq_EXPw1fnNCfHYhPsdG"
                ],
                "require_min_membership": "join"
            }],
            "combinator": "all"
        }
    });
    realm_policy_bundle_check(&payload, false).unwrap();
}

#[test]
fn media_plaintext_authority_requires_matching_service_and_data_class() {
    let service_id =
        "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service";
    assert!(payload_declares_media_plaintext_service(
        &json!({
            "plaintext_visible_services": [{
                "service_id": service_id,
                "data_classes": ["media_plaintext"],
                "purposes": ["human-readable only"]
            }]
        }),
        service_id,
    ));
    for payload in [
        json!({"plaintext_visible_services": [service_id]}),
        json!({"plaintext_visible_services": ["media_plaintext"]}),
        json!({
            "plaintext_visible_services": [{
                "service_id": service_id,
                "purpose": "media_plaintext"
            }]
        }),
        json!({
            "plaintext_visible_services": [{
                "service_id": "ak:did_core:web:other.example",
                "data_classes": ["media_plaintext"]
            }]
        }),
        json!({
            "plaintext_visible_services": [{
                "service_id": service_id,
                "data_classes": ["message_content"],
                "purposes": ["media_plaintext"]
            }]
        }),
    ] {
        assert!(!payload_declares_media_plaintext_service(
            &payload, service_id
        ));
    }
}
