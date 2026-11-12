/// The `event_id` a fixture Operation carries so [`capability_add_dot`] can
/// derive its registered dot, mirroring what
/// `sdk_projection::projection_operation_from_event` injects on the submit
/// path.
///
/// Hashes the fixture Operation id into a valid v1 SHA-256 Event identity.
/// Fixtures that reuse one Operation id across calls keep sharing one dot —
/// the idempotent re-add the previous `ak:operation:` tag also produced.
fn fixture_event_id_for_operation(operation_id: &str) -> String {
    let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(operation_id))
        .expect("fixture digest is typed");
    arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("SHA-256 is a registered Event digest suite")
        .to_string()
}

mod agent_key_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::EventKind;
    use serde_json::json;

    use crate::reducer::ProjectionState;

    const AGENT: &str = "ak:did_core:web:agent.example";
    const REALM: &str = "ak:realm:AfCwsnvdJeIf2T8CEXlUwnunThfVLY8R2SI54sTEapiS";
    const REALM_OWNER: &str = "ak:did_core:web:alice.example";

    fn actor(value: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(value).unwrap())
    }

    fn op(event_kind: EventKind, mut payload: serde_json::Value) -> Operation {
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000ff";
        let issuer = payload
            .get("sender")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                payload
                    .get("grant")
                    .and_then(|grant| grant.get("issuer_id"))
                    .and_then(|value| {
                        serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()
                    })
                    .map(|actor| actor.signing_principal_id().to_string())
            })
            .unwrap_or_else(|| REALM_OWNER.to_owned());
        let object = payload.as_object_mut().expect("test payload object");
        object
            .entry("sender".to_owned())
            .or_insert_with(|| serde_json::Value::String(issuer.clone()));
        if let Some(accepted_event_id) = object.remove("accepted_event_id") {
            object.insert("event_id".to_owned(), accepted_event_id);
        }
        object.entry("event_id".to_owned()).or_insert_with(|| {
            serde_json::Value::String(super::fixture_event_id_for_operation(OPERATION_ID))
        });
        let accepted_scope_ref = object.remove("accepted_scope_ref");
        let executed_by = object.remove("executed_by");
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            event_kind,
            payload,
        );
        operation.context.sender = actor(&issuer);
        if let Some(accepted_scope_ref) = accepted_scope_ref {
            operation.context.accepted_scope_ref =
                serde_json::from_value(accepted_scope_ref).unwrap();
        }
        if let Some(executed_by) = executed_by {
            operation.context.executed_by = Some(serde_json::from_value(executed_by).unwrap());
        }
        operation
    }

    #[test]
    fn runtime_replacement_requires_exact_supersedes_and_is_atomic() {
        let mut state = ProjectionState::default();
        let old_event = "ak:event:AVI3AO2X2rB2hMfALczp6qgYt73z3AwmGo2isSyuWZGo";
        let new_event = "ak:event:AQ985E-2w6lvWUxeIPTXvhe07EuX-DPPiDaS3_w-r37V";
        let old_key = "runtime-key-old";
        let new_key = "runtime-key-new";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                EventKind::AgentKeyAuthorize,
                json!({
                    "agent_id": AGENT,
                    "key_id": old_key,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": new_key,
                "accepted_event_id": new_event,
            }),
        ));
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "agent_key_supersedes_state_mismatch"
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(old_key.to_owned(), old_event.to_owned())],
            "a rejected replacement must not partially alter active authorization state"
        );

        let accepted = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": new_key,
                "accepted_event_id": new_event,
                "supersedes": [{
                    "key_id": old_key,
                    "authorized_event_ref": old_event,
                }],
            }),
        ));
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(new_key.to_owned(), new_event.to_owned())]
        );
    }

    #[test]
    fn pairing_replacement_of_same_key_requires_exact_supersedes() {
        let mut state = ProjectionState::default();
        let old_event = "ak:event:AV97PI2Y6Qum1pZ62jB1P6M_I7KjPy5KVQxs3bDBUkws";
        let new_event = "ak:event:AcQWkV0enAXbpr18oGw1oRi_yX4oOxV_-eTJTh_5RzRv";
        let key_id = "runtime-key-stable";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                EventKind::AgentKeyAuthorize,
                json!({
                    "agent_id": AGENT,
                    "key_id": key_id,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": key_id,
                "accepted_event_id": new_event,
                "approval_evidence": { "kind": "pairing_request" },
            }),
        ));
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "agent_key_supersedes_state_mismatch"
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(key_id.to_owned(), old_event.to_owned())]
        );

        let accepted = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": key_id,
                "accepted_event_id": new_event,
                "approval_evidence": { "kind": "pairing_request" },
                "supersedes": [{
                    "key_id": key_id,
                    "authorized_event_ref": old_event,
                }],
            }),
        ));
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(key_id.to_owned(), new_event.to_owned())]
        );
    }
}

mod realm_owner_authority_tests {
    use arkret_wire::CapabilityActionId;

    #[test]
    fn owner_never_reaches_the_two_root_control_only_actions() {
        for action in ["ak.realm.destroy", "ak.realm.tombstone"] {
            assert!(
                !arkret_policy::owner_may_grant(action).unwrap(),
                "{action} is root_control_only and is not owner-grantable"
            );
            assert!(
                !arkret_policy::action_covers_event_kinds(CapabilityActionId::REALM_OWNER, action)
                    .unwrap(),
                "{action} is outside the owner aggregate's operational coverage"
            );
        }
    }
}
