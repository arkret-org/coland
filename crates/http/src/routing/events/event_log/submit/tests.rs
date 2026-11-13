use super::*;

#[test]
fn identity_creation_proof_allows_bounded_cross_service_clock_skew() {
    let now = chrono::Utc::now();
    let accepted_issued_at =
        now + chrono::Duration::seconds(IDENTITY_CREATION_CONTROL_PROOF_MAX_FUTURE_SKEW_SECONDS);
    let rejected_issued_at = accepted_issued_at + chrono::Duration::milliseconds(1);

    assert!(identity_creation_control_proof_window_valid(
        accepted_issued_at,
        accepted_issued_at + chrono::Duration::minutes(5),
        now,
    ));
    assert!(!identity_creation_control_proof_window_valid(
        rejected_issued_at,
        rejected_issued_at + chrono::Duration::minutes(5),
        now,
    ));
}

mod event_collision_reason_tests {
    use super::*;

    #[test]
    fn storage_collision_maps_to_registered_witness_disagreement_reason() {
        let error = map_event_hash_collision(
            "ak:event:fixture",
            &coland_services::ServiceError::Conflict("event_hash_collision".to_owned()),
        )
        .expect("storage collision must be externally quarantined");

        assert_eq!(error.code(), "witness_disagreement");
        assert_eq!(
            error.quarantine_event_id().as_deref(),
            Some("ak:event:fixture")
        );
    }

    #[test]
    fn semantic_schema_violation_keeps_machine_reason_in_details() {
        let error = SubmitOneError::semantic_schema_violation("private_view_requires_account_data");

        assert_eq!(error.code(), "schema_violation");
        assert_eq!(
            error
                .details()
                .and_then(|details| details.get("reason_code"))
                .and_then(Value::as_str),
            Some("private_view_requires_account_data")
        );
    }
}

mod circle_error_mapping_tests {
    use super::*;

    #[test]
    fn non_realm_member_is_failed_precondition_with_registered_subreason() {
        let error = submit_one_error_to_app_error(
            "circle member admission",
            StatusCode::UNPROCESSABLE_ENTITY,
            arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER.to_owned(),
            "target actor is not a Realm member",
        );

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.http_status(),
            coland_http::error::error_http_status(error.code)
        );
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::CIRCLE_MEMBER_MUST_BE_REALM_MEMBER)
        );
    }

    #[test]
    fn missing_circle_manage_capability_stays_capability_denied() {
        let error = submit_one_error_to_app_error(
            "circle member admission",
            StatusCode::FORBIDDEN,
            "circle_member_manage_capability_required".to_owned(),
            "caller lacks Circle member management authority",
        );

        assert_eq!(error.code, ErrorCode::CapabilityDenied);
        assert_eq!(error.http_status(), StatusCode::FORBIDDEN);
        // Not a registered reason code: the internal discriminator rides the
        // unstable `reason_detail` channel instead of `reason_code`.
        assert_eq!(error.reason_code, None);
        assert_eq!(
            error.reason_detail.as_deref(),
            Some("circle_member_manage_capability_required")
        );
    }
}

mod relation_error_mapping_tests {
    use super::*;

    #[test]
    fn cross_realm_structural_relation_uses_registered_failed_precondition_binding() {
        let error = submit_one_error_to_app_error(
            "relation admission",
            StatusCode::PRECONDITION_FAILED,
            arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION.to_owned(),
            "structural relation endpoints cross Realm boundaries",
        );

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.http_status(),
            coland_http::error::error_http_status(error.code)
        );
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
        );
    }
}

mod grant_error_mapping_tests {
    use super::*;

    #[test]
    fn grant_beyond_issuer_authority_is_failed_precondition_with_registered_reason() {
        let error = submit_one_error_to_app_error(
            "Applet admission",
            StatusCode::CONFLICT,
            arkret_wire::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY.to_owned(),
            "conflict: grant_exceeds_issuer_authority",
        );

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            error.http_status(),
            coland_http::error::error_http_status(error.code)
        );
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY)
        );
    }
}

mod applet_formal_admission_tests {
    use super::*;

    fn session(actor_id: &str) -> SessionRecord {
        let now = Utc::now();
        SessionRecord {
            account_pk: None,
            token_hash: "fixture".to_owned(),
            actor: actor_id.to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::ServiceSynthetic,
            audience: "ak:did_core:web:ps.example".to_owned(),
            session_public_key: None,
            session_grant: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        }
    }

    #[test]
    fn staged_applet_authority_is_exactly_bound_to_event_coordinates_and_method() {
        let actor_id = "ak:did_core:web:applet.example";
        let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K";
        let applet_id =
            arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let method =
            arkret_wire::DidUrl::new("did:web:applet.example#event-key".to_owned()).unwrap();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[7_u8; 32]);
        let key = arkret_wire::DidKey::new(format!("did:key:{multibase}")).unwrap();
        let admission = InternalEventAdmission::applet_formal(
            realm_id,
            arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(actor_id).unwrap()),
            arkret_wire::EventKind::ProfileCreate.as_str(),
            "event-exact",
            applet_id.clone(),
            Some((method.clone(), key.clone())),
        );
        let session = session(actor_id);
        let mut object = serde_json::json!({
            "event_id": "event-exact",
            "kind": arkret_wire::EventKind::ProfileCreate.as_str(),
            "actor_id": arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(actor_id).unwrap()),
            "realm_id": realm_id,
            "applet_id": applet_id,
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(
            admission.applet_formal_producer_signing_key(&session, &object, method.as_str(),),
            Some(&key)
        );
        assert!(
            admission
                .applet_formal_producer_signing_key(
                    &session,
                    &object,
                    "did:web:applet.example#other-key",
                )
                .is_none()
        );

        object.insert(
            "event_id".to_owned(),
            Value::String("event-other".to_owned()),
        );
        assert!(
            admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none()
        );
        object.insert(
            "event_id".to_owned(),
            Value::String("event-exact".to_owned()),
        );
        object.insert(
            "applet_id".to_owned(),
            Value::String("ak:applet:01974100-0000-7000-8000-000000000002".to_owned()),
        );
        assert!(
            admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none()
        );
        object.insert(
            "applet_id".to_owned(),
            Value::String(applet_id.as_str().to_owned()),
        );

        let mut wrong_session_actor = session.clone();
        wrong_session_actor.actor = "ak:did_core:web:other.example".to_owned();
        assert!(
            admission
                .applet_formal_producer_signing_key(&wrong_session_actor, &object, method.as_str(),)
                .is_none()
        );

        let mut wrong_session_device = session.clone();
        wrong_session_device.endpoint =
            coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "device-other".to_owned(),
            };
        assert!(
            admission
                .applet_formal_producer_signing_key(
                    &wrong_session_device,
                    &object,
                    method.as_str(),
                )
                .is_none()
        );

        for (field, wrong_value) in [
            ("realm_id", "ak:realm:Awrong"),
            ("actor_id", "ak:did_core:web:other.example"),
            ("kind", arkret_wire::EventKind::CircleCreate.as_str()),
        ] {
            let original = object
                .insert(field.to_owned(), Value::String(wrong_value.to_owned()))
                .unwrap();
            assert!(
                admission
                    .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                    .is_none(),
                "staged authority must reject a mismatched {field}"
            );
            object.insert(field.to_owned(), original);
        }

        object.remove("realm_id");
        assert!(
            admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none(),
            "a non-genesis Event cannot omit its Realm coordinate"
        );

        let genesis_event_id =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9_u8; 32]);
        let genesis_realm_id = arkret_wire::RealmId::from_event_id(&genesis_event_id);
        let genesis_admission = InternalEventAdmission::applet_formal(
            genesis_realm_id.as_str(),
            arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(actor_id).unwrap()),
            arkret_wire::EventKind::RealmCreate.as_str(),
            genesis_event_id.as_str(),
            applet_id,
            Some((method.clone(), key.clone())),
        );
        object.insert(
            "event_id".to_owned(),
            Value::String(genesis_event_id.to_string()),
        );
        object.insert(
            "kind".to_owned(),
            Value::String(arkret_wire::EventKind::RealmCreate.as_str().to_owned()),
        );
        assert_eq!(
            genesis_admission.applet_formal_producer_signing_key(
                &session,
                &object,
                method.as_str(),
            ),
            Some(&key)
        );

        object.insert(
            "event_id".to_owned(),
            Value::String(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [8_u8; 32],
                )
                .to_string(),
            ),
        );
        assert!(
            genesis_admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none(),
            "a genesis Event with a different derived Realm coordinate is rejected"
        );

        object.insert(
            "event_id".to_owned(),
            Value::String(genesis_event_id.to_string()),
        );
        object.insert(
            "realm_id".to_owned(),
            Value::String("ak:realm:Awrong".to_owned()),
        );
        assert!(
            genesis_admission
                .applet_formal_producer_signing_key(&session, &object, method.as_str(),)
                .is_none(),
            "an explicitly wrong genesis Realm coordinate is never replaced by derivation"
        );
    }
}

mod received_at_stamp_tests {
    use super::*;

    fn operation_for_kind(kind: impl AsRef<str>, suffix: u32) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{suffix:012x}"
            ))
            .unwrap(),
            RealmId::new("ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned())
                .unwrap(),
            kind.as_ref(),
            json!({ "actor_id": "ak:did_core:web:alice.example" }),
        )
    }

    #[test]
    fn received_at_stamp_only_mutates_membership_projection_payloads() {
        let received_at = DateTime::parse_from_rfc3339("2026-07-07T05:20:58.398662Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut device_authorize = operation_for_kind("ak.device.authorize", 1);
        let mut member_state = operation_for_kind(arkret_wire::EventKind::MemberState, 2);
        let mut circle_member_state =
            operation_for_kind(arkret_wire::EventKind::CircleMemberState, 3);

        stamp_projection_operation_received_at(&mut device_authorize, received_at);
        stamp_projection_operation_received_at(&mut member_state, received_at);
        stamp_projection_operation_received_at(&mut circle_member_state, received_at);

        assert!(device_authorize.payload.get("event_received_at").is_none());
        assert_eq!(
            member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398Z")
        );
        assert_eq!(
            circle_member_state
                .payload
                .get("event_received_at")
                .and_then(Value::as_str),
            Some("2026-07-07T05:20:58.398Z")
        );
    }
}
