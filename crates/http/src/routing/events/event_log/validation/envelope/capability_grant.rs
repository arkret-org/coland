use super::*;

/// Enforce the grant-body invariants that are bound by the Event proof.
///
/// `CapabilityGrant` deliberately has no nested `proofs` carrier: the only
/// durable issuer signature is the surrounding Event envelope proof.
pub(super) fn validate_capability_grant_body(
    kind: &str,
    actor_id: &arkret_wire::ActorId,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::event_kind_str::CAPABILITY_GRANT {
        return Ok(());
    }
    let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(object.get("payload").cloned().unwrap_or(Value::Null)).map_err(
            |error| {
                event_validation_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "schema_violation",
                    format!("invalid capability grant payload: {error}"),
                )
            },
        )?;
    if &payload.grant.issuer_id != actor_id {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "capability grant issuer must equal the Event actor",
        ));
    }
    Ok(())
}

mod tests {
    use serde_json::json;

    use super::*;

    fn fixture_actor(actor: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(actor).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ))
    }

    fn event(actor: &str) -> Value {
        let actor = fixture_actor(actor);
        json!({
            "payload": {
                "grant": {
                    "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                    "realm_id": "ak:realm:AcnJ4V0xcEtprkV1EojkpKLTdP6Jene1sZpnjB6IqB8I",
                    "issuer_id": actor,
                    "subject": actor,
                    "actions": ["ak.realm.configure"],
                    "resources": [{
                        "kind": "realm",
                        "realm_id": "ak:realm:AcnJ4V0xcEtprkV1EojkpKLTdP6Jene1sZpnjB6IqB8I",
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-07-21T08:00:00.000Z",
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": "ak:realm:AcnJ4V0xcEtprkV1EojkpKLTdP6Jene1sZpnjB6IqB8I",
                        "authority_event_ref": "ak:event:AcnJ4V0xcEtprkV1EojkpKLTdP6Jene1sZpnjB6IqB8I",
                        "authority_generation": 0
                    }]
                }
            }
        })
    }

    #[test]
    fn accepts_grant_without_a_nested_proof() {
        let actor = "ak:did_core:web:alice.example";
        let event = event(actor);
        validate_capability_grant_body(
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            &fixture_actor(actor),
            event.as_object().unwrap(),
        )
        .expect("the Event proof is the sole durable signature");
    }

    #[test]
    fn rejects_actor_mismatch() {
        let actor = "ak:did_core:web:alice.example";
        let event = event(actor);
        assert!(
            validate_capability_grant_body(
                arkret_wire::EventKind::CapabilityGrant.as_str(),
                &fixture_actor("ak:did_core:web:mallory.example"),
                event.as_object().unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_same_principal_at_another_station() {
        let principal = "ak:did_core:web:alice.example";
        let event = event(principal);
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(
            validate_capability_grant_body(
                arkret_wire::EventKind::CapabilityGrant.as_str(),
                &actor,
                event.as_object().unwrap(),
            )
            .is_err()
        );
    }
}
