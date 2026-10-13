//! Producer proof preflight for the current self authority endpoint.
//!
//! This resolves live local signer material from accepted PCR/Agent state.
//! A human-device producer follows the single rule of device-lifecycle
//! §8.2.2 for every Event kind: its Station reads the local PCR
//! `device_authorization`/`device_generation`, and a refusal carries the
//! registered device code. The authority transaction still has to freeze and
//! recheck the same authorization cut before the Event becomes committed.

use arkret_models_identity::session_credential::{
    SessionGrantCredentialClass, SessionGrantHolderBinding,
};
use arkret_wire::{AccountId, ActorId, DeviceId, Did, Event};
use coland_services::identity::{SessionGrantAuthorizationState, SessionIdentityState};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::SelfProducerCommitGuard;

use super::AppState;

fn rejected(message: impl Into<String>) -> ServiceError {
    ServiceError::Conflict(message.into())
}

fn method_device_id(
    method: &arkret_wire::DidUrl,
    principal: &arkret_wire::DidCoreId,
) -> Option<DeviceId> {
    let (controller, fragment) = method.as_str().rsplit_once('#')?;
    let did = Did::new(controller.to_owned()).ok()?;
    if &arkret_wire::project_did_to_core_id(&did).ok()? != principal {
        return None;
    }
    DeviceId::new(fragment.to_owned()).ok()
}

fn standard_grant_for_account<'a>(
    session: &'a SessionIdentityState,
    account: &AccountId,
) -> ServiceResult<&'a SessionGrantAuthorizationState> {
    let grant = session
        .session_grant
        .as_ref()
        .ok_or_else(|| rejected("self Event needs an authenticated standard grant"))?;
    if grant.credential_class != SessionGrantCredentialClass::Standard
        || grant.account_id != *account
    {
        return Err(rejected("self Event grant does not bind the exact Account"));
    }
    Ok(grant)
}

pub(crate) async fn verify_self_event_producer(
    state: &AppState,
    session: &SessionIdentityState,
    event: &Event,
) -> ServiceResult<SelfProducerCommitGuard> {
    verify_self_event_producer_key(state, session, event)
        .await
        .map(|(guard, _)| guard)
}

/// [`verify_self_event_producer`] that also returns the exact key the
/// producer proof verified under, for objects the same producer seals
/// alongside the Event (an MLS Commit's Welcome deliveries).
pub(crate) async fn verify_self_event_producer_key(
    state: &AppState,
    session: &SessionIdentityState,
    event: &Event,
) -> ServiceResult<(
    SelfProducerCommitGuard,
    arkret_signatures::PublicKeyMaterial,
)> {
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let actor = crate::routing::identity::session_actor::validated_session_actor(state, session)
        .await
        .map_err(|error| rejected(format!("authenticated Account unavailable: {error}")))?;
    if event.actor_id != actor || event.executed_by.is_some() {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::CapabilityDenied,
            "self Event requires the exact authenticated actor without delegated execution"
                .to_owned(),
        ));
    }
    let account = actor
        .as_account_id()
        .ok_or_else(|| rejected("self Event actor must be an AccountId"))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| ServiceError::SchemaViolation("self Event has no producer proof".into()))?;
    let grant = standard_grant_for_account(session, account)?;
    let (key, guard) = match &grant.holder_binding {
        SessionGrantHolderBinding::HumanDevice { .. } => {
            human_producer_key(state, session, account, proof).await?
        }
        SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
        } => {
            if agent_id != &account.principal_id
                || verification_method != &proof.verification_method
                || session.agent_session().is_none()
                || grant.device_binding.is_some()
            {
                return Err(rejected("Agent grant triple differs from Event producer"));
            }
            let committed = state
                .authority_commits()
                .committed_event(agent_key_authorization_ref)
                .await?
                .ok_or_else(|| rejected("Agent grant authorization Event is not committed"))?;
            if committed.event.event_id != *agent_key_authorization_ref
                || committed.commit.event_ref != *agent_key_authorization_ref
                || committed.event.kind != arkret_wire::EventKind::AgentKeyAuthorize
            {
                return Err(rejected("Agent grant authorization Commit is invalid"));
            }
            let authorized: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
                serde_json::from_value(
                    serde_json::to_value(&committed.event.payload)
                        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
                )
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
            if authorized.agent_id != *agent_id
                || authorized.verification_method != *verification_method
            {
                return Err(rejected(
                    "Agent grant authorization differs from accepted Event",
                ));
            }
            // encryption-and-audit.md §2.5.2: an Agent runtime whose authorize
            // is revoked, replaced or expired is refused with the universal
            // `capability_denied`.
            let not_current = |detail: &str| {
                ServiceError::protocol(arkret_wire::ErrorCode::CapabilityDenied, detail.to_owned())
            };
            let (current, current_authorization) =
                crate::routing::identity::current_signer_evidence::current_agent_producer_binding(
                    state, event,
                )
                .await
                .map_err(|error| not_current(&error))?;
            if current_authorization.event_id != *agent_key_authorization_ref
                || current_authorization.commit_id != committed.commit.commit_id
                || current_authorization.stream_ref != committed.commit.stream_ref
                || current_authorization.stream_position != committed.commit.stream_position
            {
                return Err(not_current(
                    "Agent grant authorization is no longer current",
                ));
            }
            let accepted = arkret_signatures::agent::validate_agent_runtime_public_key(
                &authorized.public_key,
                &authorized.verification_method,
            )
            .map_err(|error| rejected(error.to_string()))?;
            if current != accepted.raw_public_key {
                return Err(not_current(
                    "Agent grant key differs from current accepted key",
                ));
            }
            (
                arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: current.to_vec(),
                },
                SelfProducerCommitGuard::Agent {
                    pcr_realm_id: current_authorization.stream_ref.realm_id().clone(),
                    agent_id: agent_id.clone(),
                    authorization_ref: current_authorization,
                    verification_method: verification_method.clone(),
                },
            )
        }
        _ => return Err(rejected("self Event grant holder cannot sign this Event")),
    };
    let digest_suite = state
        .projections()
        .realm_digest_suite(event.realm_id.as_str());
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let verified = arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        digest_suite,
    );
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_ACCEPTED_BINDING,
        verified.is_ok(),
    );
    verified.map_err(|error| {
        ServiceError::protocol(
            arkret_wire::ErrorCode::SignatureInvalid,
            format!("Event producer proof invalid: {error}"),
        )
    })?;
    Ok((guard, key))
}

/// Verify that one device of `account`, active at its PCR cut and at its
/// revocation gate, signed `event`'s producer proof: the executing
/// controller of a delegated Agent Event is judged by the same single rule
/// as any human-device producer (device-lifecycle §8.2.2).
pub(crate) async fn verify_account_device_producer(
    state: &AppState,
    account: &AccountId,
    event: &Event,
) -> ServiceResult<()> {
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| ServiceError::SchemaViolation("Event has no producer proof".into()))?;
    let (key, _) = Box::pin(account_device_producer_key(
        state,
        account,
        &proof.verification_method,
    ))
    .await?;
    let digest_suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        digest_suite,
    )
    .map_err(|error| {
        ServiceError::protocol(
            arkret_wire::ErrorCode::SignatureInvalid,
            format!("Event producer proof invalid: {error}"),
        )
    })
}

/// Independently authenticated MIMI transports carry producer-signed Events,
/// never a fabricated human session. Freeze the verified device's actual PCR gate.
pub(crate) async fn verify_mimi_binding_producer(
    state: &AppState,
    event: &Event,
) -> ServiceResult<SelfProducerCommitGuard> {
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| rejected("MIMI binding producer must be an Account"))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected("MIMI binding proof missing"))?;
    let (key, guard) =
        account_device_producer_key(state, account, &proof.verification_method).await?;
    let digest_suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|e| rejected(e.to_string()))?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|e| rejected(e.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        digest_suite,
    )
    .map_err(|e| rejected(e.to_string()))?;
    Ok(guard)
}

/// Verify a detached-JWS payload proof by one device of `account`, active at
/// its PCR cut and at its revocation gate: a controller's own proof over a
/// private object it authorizes (device-lifecycle §8.2.2), never a key read
/// from its DID Document, which lists no device keys.
pub(crate) async fn verify_account_device_payload_proof(
    state: &AppState,
    account: &AccountId,
    proof: &arkret_wire::PayloadProof,
    binding: &[u8],
) -> ServiceResult<()> {
    let (key, _) = account_device_producer_key(state, account, &proof.verification_method).await?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(proof, binding, &key).map_err(
        |error| {
            ServiceError::protocol(
                arkret_wire::ErrorCode::SignatureInvalid,
                format!("device payload proof invalid: {error}"),
            )
        },
    )
}

/// Resolve the human device that actually signed the Event.
///
/// Decision 0107: self submit requires only that the signer is a device of the
/// authenticated principal, not the session's own device. The signing device
/// is judged by the single §8.2.2 rule -- its local PCR
/// `device_authorization`/`device_generation` status -- and a refusal carries
/// the registered device code.
async fn human_producer_key(
    state: &AppState,
    session: &SessionIdentityState,
    account: &AccountId,
    proof: &arkret_wire::ProducerEventProof,
) -> ServiceResult<(
    arkret_signatures::PublicKeyMaterial,
    SelfProducerCommitGuard,
)> {
    session
        .session_grant
        .as_ref()
        .and_then(|grant| grant.device_binding.as_ref())
        .ok_or_else(|| rejected("human grant has no accepted device binding"))?;
    account_device_producer_key(state, account, &proof.verification_method).await
}

/// The accepted key of the device of `account` named by `proof`, after its
/// PCR-cut and revocation-gate admission.
pub(super) async fn account_device_producer_key(
    state: &AppState,
    account: &AccountId,
    verification_method: &arkret_wire::DidUrl,
) -> ServiceResult<(
    arkret_signatures::PublicKeyMaterial,
    SelfProducerCommitGuard,
)> {
    let device_id =
        method_device_id(verification_method, &account.principal_id).ok_or_else(|| {
            ServiceError::protocol(
                arkret_wire::ErrorCode::SignatureInvalid,
                "Event proof method is not a device of the authenticated account",
            )
        })?;
    let admission = state
        .persistence()
        .pcr_device_admission(account, &device_id, chrono::Utc::now())
        .await?;
    if let Some(refusal) = ServiceError::device_admission_refusal(
        admission,
        "Event producer device is not active at the PCR cut",
    ) {
        return Err(refusal);
    }
    let selector =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            account.principal_id.as_str(),
            device_id.as_str(),
        )
        .await?;
    let gate = state
        .persistence()
        .device_revocation_gate_status(&selector)
        .await?;
    if let Some(refusal) = ServiceError::device_admission_refusal(
        gate.admission_decision(),
        "Event producer device is not admitted by its revocation gate",
    ) {
        return Err(refusal);
    }
    let facet = Box::pin(
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            account.principal_id.as_str(),
            device_id.as_str(),
        ),
    )
    .await?;
    let authorization = Box::pin(
        crate::routing::identity::device_signing::current_device_authorization(
            state,
            &ActorId::account(account.clone()),
            &device_id,
            &facet,
        ),
    )
    .await?
    .ok_or_else(|| {
        ServiceError::protocol(
            arkret_wire::ErrorCode::DeviceUnauthorized,
            "Event producer device authorization is unavailable",
        )
    })?;
    if facet.device_authorize_event_id.as_ref() != Some(&selector.authorization_ref.event_id) {
        return Err(rejected(
            "Event producer device authorization is not its current confirmed instance",
        ));
    }
    let (evidence, _) = Box::pin(
        crate::routing::identity::keys::prepare_current_account_device_signer_evidence(
            state, account, &device_id, &facet,
        ),
    )
    .await?
    .ok_or_else(|| rejected("native original Account Device root is unavailable"))?;
    let multibase = authorization
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| rejected("accepted device key is not did:key"))?;
    Ok((
        arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        },
        SelfProducerCommitGuard::HumanDeviceEvidence {
            selector,
            evidence: Box::new(evidence),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_bearer_session_without_grant_cannot_produce_self_event() {
        let account = AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let now = chrono::Utc::now();
        let session = SessionIdentityState {
            token_hash: "local-only".to_owned(),
            account_pk: None,
            actor: account.principal_id.as_str().to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: "ak:device:01904100-0000-7000-8000-0000000000a1".to_owned(),
            },
            audience: account.station_id.as_str().to_owned(),
            session_public_key: None,
            session_grant: None,
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            revoked_at: None,
        };
        assert!(standard_grant_for_account(&session, &account).is_err());
    }

    fn human_session(
        account: &AccountId,
        device_id: &DeviceId,
        authorization_event_id: &arkret_wire::EventId,
    ) -> SessionIdentityState {
        let now = chrono::Utc::now();
        SessionIdentityState {
            token_hash: "human-session".to_owned(),
            account_pk: None,
            actor: account.principal_id.as_str().to_owned(),
            endpoint: coland_services::identity::SessionEndpointState::HumanDevice {
                device_id: device_id.as_str().to_owned(),
            },
            audience: account.station_id.as_str().to_owned(),
            session_public_key: None,
            session_grant: Some(SessionGrantAuthorizationState {
                grant_id: arkret_identifiers::SessionGrantId::from_issuance_digest([0x42; 32]),
                revocation_ref: "fixture".to_owned(),
                account_id: account.clone(),
                issuer_id: account.station_id.clone(),
                scopes: Vec::new(),
                credential_class: SessionGrantCredentialClass::Standard,
                holder_binding: SessionGrantHolderBinding::HumanDevice {
                    device_binding: "fixture".to_owned(),
                },
                device_binding: Some(
                    arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                        device_id: device_id.clone(),
                        authorization_event_id: authorization_event_id.clone(),
                        model_generation_ref: 1,
                    },
                ),
                cnf_jkt: "fixture".to_owned(),
            }),
            expires_at: now + chrono::Duration::hours(1),
            created_at: now,
            revoked_at: None,
        }
    }

    fn signed_by(
        account: &AccountId,
        realm_id: &arkret_wire::RealmId,
        method: &arkret_wire::DidUrl,
        seed: [u8; 32],
    ) -> Event {
        coland_test_support::device_authorization_history::sign_event(
            arkret_wire::test_support::raw_event(
                arkret_wire::EventKind::MessageCreate.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                account.principal_id.clone(),
                account.station_id.clone(),
                serde_json::json!({}),
            )
            .unwrap(),
            method.clone(),
            seed,
        )
    }

    /// Decision 0107: the session's device and the signing device need only
    /// share the principal. The signer is resolved from the proof fragment and
    /// judged by its own PCR status; an unknown device or another principal's
    /// device is refused with a registered code, never a bare conflict.
    #[tokio::test]
    async fn another_active_device_of_the_session_principal_may_sign() {
        // Complete native Service history is part of issuing the ordinary
        // Account Device root; a bare test AppState has no durable identity.
        let mut fixture_config = coland_test_support::app_config();
        fixture_config.notary_signing_key_seed = Some([83; 32]);
        fixture_config.seed_demo_data = false;
        let (leased_state, pool) = coland_test_support::app_state_with_pool(fixture_config.clone());
        let state = AppState::new_with_service_identity(
            crate::config::AppConfig {
                public_base_url: fixture_config.public_base_url.clone(),
                notary_signing_key_seed: fixture_config.notary_signing_key_seed,
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db {
                pool: Some(pool.clone()),
            },
            std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(pool)),
            coland_test_support::fixture_service_identity(&fixture_config),
            leased_state
                .service_resolution_commitment()
                .as_ref()
                .clone(),
            [83; 32],
        );
        let persistence = state.test_persistence();
        let mut fixture =
            coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        let founding = fixture
            .admit_founding_device(persistence.as_ref())
            .await
            .expect("accepted PCR genesis");
        let second = fixture
            .admit_accepted_device(persistence.as_ref(), [61; 32])
            .await
            .expect("second device accepted by the founding device");
        let account = fixture.history.account.clone();
        let realm_id = fixture.history.events[0].realm_id.clone();
        let session = human_session(
            &account,
            &fixture.history.founding_device_id,
            &founding.authorization_ref.event_id,
        );

        let event = signed_by(
            &account,
            &realm_id,
            &second.verification_method,
            second.signing_seed,
        );
        let (_, guard) = human_producer_key(
            &state,
            &session,
            &account,
            event.producer_proof.as_ref().unwrap(),
        )
        .await
        .expect("a second active device of the same principal signs a self Event");
        let Some(selector) = guard.human_device_selector() else {
            panic!("a human producer yields a device guard");
        };
        assert_eq!(selector.device_id, second.authorization.device_id);
        assert_eq!(
            selector.authorization_ref,
            second.authorization.authorization_ref
        );

        let unknown = DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap();
        let unknown_method =
            arkret_wire::DidUrl::new(format!("{}#{unknown}", fixture.history.did)).unwrap();
        let refused = human_producer_key(
            &state,
            &session,
            &account,
            signed_by(&account, &realm_id, &unknown_method, [62; 32])
                .producer_proof
                .as_ref()
                .unwrap(),
        )
        .await
        .expect_err("a device without accepted authorization cannot sign");
        assert!(
            !refused
                .detail()
                .contains("differs from authenticated device"),
            "{refused:?}"
        );

        let foreign = arkret_wire::DidUrl::new(format!(
            "did:webvh:z6Mkother:bob.example#{}",
            second.authorization.device_id
        ))
        .unwrap();
        let refused = human_producer_key(
            &state,
            &session,
            &account,
            signed_by(&account, &realm_id, &foreign, second.signing_seed)
                .producer_proof
                .as_ref()
                .unwrap(),
        )
        .await
        .expect_err("another principal's device cannot sign");
        assert!(
            refused.detail().starts_with("signature_invalid"),
            "{refused:?}"
        );
    }

    #[test]
    fn human_method_must_name_the_exact_account_did_and_device_fragment() {
        let controller = Did::new("did:webvh:z6Mkfull:alice.example".to_owned()).unwrap();
        let principal = arkret_wire::project_did_to_core_id(&controller).unwrap();
        let device =
            DeviceId::new("ak:device:01904100-0000-7000-8000-a11ce0000001".to_owned()).unwrap();
        let method = arkret_wire::DidUrl::new(format!("{}#{}", controller, device)).unwrap();
        assert_eq!(method_device_id(&method, &principal), Some(device.clone()));
        let other = arkret_wire::DidUrl::new(format!("did:webvh:z6Mkother:bob.example#{}", device))
            .unwrap();
        assert_eq!(method_device_id(&other, &principal), None);
    }
}
