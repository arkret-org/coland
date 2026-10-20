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
mod applet_managed_delegation_tests {
    use arkret_models_collaboration::events_payloads::SignatureMaterial;
    use arkret_models_collaboration::events_payloads::device_identity::{
        AppletManagedDeviceScope, AppletManagedDeviceScopes, DeviceAuthorizationBindingKind,
        DeviceAuthorizationScopes, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const MANAGED_PRINCIPAL: &str = "ak:did_core:webvh:z6mkappletmanagedbot";
    const OTHER_PRINCIPAL: &str = "ak:did_core:webvh:z6mkappletmanagedghost";
    const STATION: &str = "ak:did_core:web:station.example";
    const APPLET: &str = "ak:applet:01904100-0000-7000-8000-00000000a001";

    fn signed_delegation_payload(
        account: &arkret_wire::AccountId,
        authorized_by: &arkret_wire::DidCoreId,
    ) -> Value {
        let key = SigningKey::from_bytes(&[0x37; 32]);
        let public =
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
        let mut hpke = vec![0xec, 0x01];
        hpke.extend([0x44; 32]);
        let mut payload = DeviceAuthorizePayload {
            device_id: arkret_identifiers::DeviceId::new(
                "ak:device:01904100-0000-7000-8000-00000000d001",
            )
            .unwrap(),
            device_public_key_did: arkret_wire::NonEmptyString::new(format!("did:key:{public}"))
                .unwrap(),
            hpke_key: arkret_wire::NonEmptyString::new(
                arkret_canonical::encode_multibase_base58btc(hpke),
            )
            .unwrap(),
            algorithms: vec![
                arkret_wire::NonEmptyString::new(
                    arkret_wire::HpkeSuiteId::X25519_AEAD_CHACHA20POLY1305_V1,
                )
                .unwrap(),
            ],
            device_key_algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
            authorized_by: DeviceOrPrincipalRef::Principal(authorized_by.clone()),
            scopes: Some(DeviceAuthorizationScopes::AppletManaged(
                AppletManagedDeviceScopes::new(vec![AppletManagedDeviceScope {
                    effective_scope: arkret_wire::ScopeRef::Realm {
                        realm_id: arkret_wire::RealmId::from_event_id(
                            &arkret_identifiers::EventId::from_digest(
                                arkret_canonical::DigestSuite::Sha256,
                                [0x71; 32],
                            ),
                        ),
                    },
                    actions: vec![arkret_wire::CapabilityActionId::EventRead],
                }])
                .unwrap(),
            )),
            not_before: "2026-09-15T00:00:00.000Z".parse().unwrap(),
            expires_at: Some(Some("2026-12-15T00:00:00.000Z".parse().unwrap())),
            authorization_binding_kind: DeviceAuthorizationBindingKind::AppletManagedDelegation,
            authorized_generation_ref: 1,
            device_signature: SignatureMaterial::NonEmptyString(
                arkret_wire::NonEmptyString::new("pending").unwrap(),
            ),
            recovery_session_id: None,
            pairing_challenge_transcript_digest: None,
            applet_id: Some(arkret_wire::AppletId::new(APPLET).unwrap()),
        };
        payload
            .validate_wire_constraints()
            .expect("5.2.3 payload shape");
        // The transcript self-anchors against the signing account, so a
        // cross-principal case has to sign under the principal it names.
        let anchor = arkret_wire::AccountId::new(
            authorized_by.clone(),
            arkret_wire::DidCoreId::new(STATION.to_owned()).unwrap(),
        );
        let input = payload
            .device_possession_signature_input(if authorized_by == &account.principal_id {
                account
            } else {
                &anchor
            })
            .expect("possession transcript");
        payload.device_signature = SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new(arkret_canonical::base64url_encode(
                key.sign(&input).to_bytes(),
            ))
            .unwrap(),
        );
        serde_json::to_value(payload).expect("payload serializes")
    }

    fn delegation_event(actor: &str, authorized_by: &str) -> arkret_wire::Event {
        let station = arkret_wire::DidCoreId::new(STATION.to_owned()).unwrap();
        let actor_id = arkret_wire::DidCoreId::new(actor.to_owned()).unwrap();
        let account = arkret_wire::AccountId::new(actor_id.clone(), station.clone());
        let payload = signed_delegation_payload(
            &account,
            &arkret_wire::DidCoreId::new(authorized_by.to_owned()).unwrap(),
        );
        arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::DeviceAuthorize.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::from_event_id(
                    &arkret_identifiers::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x71; 32],
                    ),
                ),
            },
            actor_id,
            station,
            payload,
        )
        .expect("fixture delegated device authorize")
    }

    fn envelope(event: &arkret_wire::Event) -> serde_json::Map<String, Value> {
        serde_json::to_value(event)
            .expect("envelope serializes")
            .as_object()
            .expect("envelope is an object")
            .clone()
    }

    /// 5.2.3 precondition: without an accepted managed-actor provision and
    /// `applet_managed_control` genesis there is no exact install to anchor to,
    /// so the branch has to fail closed rather than fall through to the
    /// possession check.
    #[tokio::test]
    async fn delegation_fails_closed_without_a_provisioned_managed_principal() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let event = delegation_event(MANAGED_PRINCIPAL, MANAGED_PRINCIPAL);
        let error = validate_device_authorization_binding(
            &state,
            &envelope(&event),
            MANAGED_PRINCIPAL,
            &[],
        )
        .await
        .expect_err("an unprovisioned principal cannot delegate a device");
        assert!(
            format!("{error:?}").contains("Applet-managed principal"),
            "unexpected rejection: {error:?}"
        );
    }

    /// 15 / applet-integration.md 12: the authority is the principal's own
    /// controller method, so this Event MUST NOT arrive dressed as an
    /// Applet-delegated write.
    #[tokio::test]
    async fn delegation_rejects_borrowed_applet_envelope_authority() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let mut event = delegation_event(MANAGED_PRINCIPAL, MANAGED_PRINCIPAL);
        // The envelope schema pairs the two fields, so a borrowed Applet
        // authority can only ever arrive as the complete pair.
        event.applet_id = Some(arkret_wire::AppletId::new(APPLET).unwrap());
        event.authorization_ref = Some(
            arkret_wire::GrantId::new("ak:grant:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
                .unwrap()
                .into(),
        );
        let error = validate_device_authorization_binding(
            &state,
            &envelope(&event),
            MANAGED_PRINCIPAL,
            &[],
        )
        .await
        .expect_err("a delegated device authorization is not an Applet-delegated write");
        assert!(
            format!("{error:?}").contains("Applet capability grant"),
            "unexpected rejection: {error:?}"
        );
    }

    /// 5.2.3 self-anchor: `authorized_by` MUST be the Event's own principal,
    /// never the Applet `service_id` or any other principal.
    #[tokio::test]
    async fn delegation_rejects_a_cross_principal_authorizer() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let event = delegation_event(MANAGED_PRINCIPAL, OTHER_PRINCIPAL);
        let error = validate_device_authorization_binding(
            &state,
            &envelope(&event),
            MANAGED_PRINCIPAL,
            &[],
        )
        .await
        .expect_err("applet_managed_delegation must self-anchor");
        assert!(
            format!("{error:?}").contains("self-anchor"),
            "unexpected rejection: {error:?}"
        );
    }
}
