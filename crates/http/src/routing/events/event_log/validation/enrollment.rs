use arkret_event_draft::EventPayloadExt as _;

use super::super::*;

/// Enforce the closed device-authorization source model. Root-anchored
/// authorizations exist only inside the exact genesis/re-anchor unit passed by
/// the batch validator. Pairing requires a current, accepted authorizing
/// device; DID service/delegation state is never consulted.
pub(crate) async fn validate_device_authorization_binding(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    realm_bootstrap_contexts: &[RealmBootstrapBatchContext],
) -> Result<(), EventValidationError> {
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    };

    let event = serde_json::from_value::<arkret_wire::Event>(Value::Object(object.clone()))
        .map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("invalid typed ak.device.authorize Event: {error}"),
            )
        })?;
    let payload: DeviceAuthorizePayload = event
        .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
        .map_err(|error| {
            event_validation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "schema_violation",
                format!("invalid ak.device.authorize payload: {error}"),
            )
        })?;
    let Some(subject_account_id) = event.actor_id.as_account_id() else {
        return Err(device_authorization_invalid(
            "device authorization requires an account actor",
        ));
    };
    if subject_account_id.principal_id.as_str() != actor_id {
        return Err(device_authorization_invalid(
            "device authorization actor mismatch",
        ));
    }
    match (&payload.authorization_binding_kind, &payload.authorized_by) {
        (
            DeviceAuthorizationBindingKind::RegistrationAnchor
            | DeviceAuthorizationBindingKind::PcrRecovery,
            DeviceOrPrincipalRef::Principal(root),
        ) => {
            let staged = realm_bootstrap_contexts.iter().any(|context| {
                context.actor_id == event.actor_id.to_string()
                    && context.identity_anchor_event_id.is_some()
                    && context
                        .identity_anchor_candidate_device
                        .as_ref()
                        .is_some_and(|candidate| {
                            candidate.device_id == payload.device_id
                                && candidate.device_public_key_did == payload.device_public_key_did
                                && candidate.hpke_key == payload.hpke_key
                                && candidate.algorithms == payload.algorithms
                                && candidate.authorized_generation_ref
                                    == payload.authorized_generation_ref
                                && candidate.authorization_binding_kind
                                    == payload.authorization_binding_kind
                        })
            });
            if root.as_str() != actor_id || !staged {
                return Err(device_authorization_invalid(
                    "root_anchored authorization is outside a closed identity-anchor unit",
                ));
            }
        }
        (
            DeviceAuthorizationBindingKind::AcceptedDevice,
            DeviceOrPrincipalRef::DeviceId(authorizer),
        ) => {
            let proof_methods = event
                .producer_proof
                .iter()
                .map(|proof| proof.verification_method.as_str())
                .collect::<Vec<_>>();
            if proof_methods.is_empty()
                || proof_methods.iter().any(|method| {
                    crate::jws_verify::validate_verification_method_controller(actor_id, method)
                        .is_err()
                        || method.rsplit_once('#').map(|(_, fragment)| fragment)
                            != Some(authorizer.as_str())
                })
            {
                return Err(device_authorization_invalid(
                    "accepted_device authorization must be Event-signed by the declared authorizing device",
                ));
            }
            let record = state
                .identities()
                .find_device(coland_services::identity::FindDeviceQuery {
                    actor_id: actor_id.to_owned(),
                    device_id: authorizer.to_string(),
                })
                .await
                .map_err(|error| {
                    event_validation_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        format!("authorizing device lookup failed: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    device_authorization_invalid("authorizing device is not accepted")
                })?;
            let current = crate::routing::identity::device_generation::current_device_generation(
                state, actor_id,
            )
            .await
            .map_err(|error| {
                event_validation_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    format!("device generation state unavailable: {error}"),
                )
            })?
            .ok_or_else(|| device_authorization_invalid("device generation is unavailable"))?;
            if record.verification_state != "verified"
                || record.revoked_at.is_some()
                || payload.authorized_generation_ref != current.current_ref
                || record
                    .payload
                    .get("authorized_generation_ref")
                    .and_then(Value::as_u64)
                    != Some(current.current_ref)
            {
                return Err(device_authorization_invalid(
                    "authorizing device is not active at the current generation",
                ));
            }
        }
        _ => {
            return Err(device_authorization_invalid(
                "device authorization binding is not a closed v1 variant",
            ));
        }
    }
    crate::routing::identity::device_signing::validate_device_authorize_binding(
        state,
        &payload,
        subject_account_id,
    )
    .map_err(device_authorization_invalid)
}

fn device_authorization_invalid(message: impl Into<String>) -> EventValidationError {
    event_validation_error(StatusCode::CONFLICT, "failed_precondition", message)
}

#[cfg(test)]
mod realm_device_enrollment_isolation_tests {
    use arkret_models_collaboration::events_payloads::{DeviceAuthorizePayload, SignatureMaterial};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn candidate(as_account: bool) -> arkret_wire::Event {
        let realm = arkret_wire::RealmId::from_event_id(&arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x71; 32],
        ));
        let principal =
            arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkappletmanagedbot").unwrap();
        let native = arkret_wire::ActorId::realm(arkret_wire::RealmActorId::new(
            realm.clone(),
            principal.clone(),
        ));
        let key = SigningKey::from_bytes(&[0x37; 32]);
        let public =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        let mut hpke = vec![0xec, 0x01];
        hpke.extend([0x44; 32]);
        let applet =
            arkret_wire::AppletId::new("ak:applet:01904100-0000-7000-8000-00000000a001").unwrap();
        let mut payload: DeviceAuthorizePayload = serde_json::from_value(serde_json::json!({
            "device_id":"ak:device:01904100-0000-7000-8000-00000000d001",
            "device_public_key_did":format!("did:key:{public}"),
            "hpke_key":arkret_canonical::encode_multibase_base58btc(hpke),
            "algorithms":[arkret_wire::HpkeSuiteId::X25519_AEAD_CHACHA20POLY1305_V1],
            "device_key_algorithm":"Ed25519","authorized_by":principal,
            "scopes":[{"effective_scope":{"kind":"realm","realm_id":realm},"actions":["ak.event.read"]}],
            "not_before":"2026-10-20T00:00:00.000Z","expires_at":"2026-12-15T00:00:00.000Z",
            "authorization_binding_kind":"realm_managed_delegation","authorized_generation_ref":1,
            "device_signature":"AA","applet_id":applet,
            "expected_control_revision":{"commit_id":arkret_wire::RealmCommitId::from_digest([42;32]),"stream_position":0},
            "expected_device_revision":null
        })).unwrap();
        let input = payload
            .realm_device_possession_signature_input(&native)
            .unwrap();
        payload.device_signature = SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new(arkret_canonical::base64url_encode(
                key.sign(&input).to_bytes(),
            ))
            .unwrap(),
        );
        let (actor, scope) = if as_account {
            (
                arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    principal,
                    arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                arkret_wire::ScopeRef::Realm { realm_id: realm },
            )
        } else {
            (
                native,
                arkret_wire::ScopeRef::RealmControl { realm_id: realm },
            )
        };
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::DeviceAuthorize.as_str(),
            scope,
            actor,
            serde_json::to_value(payload).unwrap(),
            "2026-10-21T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap();
        event.applet_id = Some(applet);
        if as_account {
            event.authorization_ref = Some(
                arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [43; 32],
                ))
                .into(),
            );
        }
        event
    }

    #[tokio::test]
    async fn ordinary_enrollment_never_accepts_realm_control_or_borrowed_account_identity() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        for (as_account, reason) in [
            (false, "device authorization requires an account actor"),
            (
                true,
                "device authorization binding is not a closed v1 variant",
            ),
        ] {
            let event = candidate(as_account);
            let envelope = serde_json::to_value(&event)
                .unwrap()
                .as_object()
                .unwrap()
                .clone();
            let error = validate_device_authorization_binding(
                &state,
                &envelope,
                event.actor_id.signing_principal_id().as_str(),
                &[],
            )
            .await
            .unwrap_err();
            assert!(format!("{error:?}").contains(reason), "{error:?}");
        }
    }
}
