//! Activation of a pre-imported, planned authority migration. The wire body
//! never substitutes for the complete private durable state transfer.

use arkret_models_collaboration::authority_commit::AuthorityHandoffRequest;
use arkret_wire::{DetachedSignatureContext, RealmAuthorityHandoff};
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

fn refused(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::SchemaViolation(format!("invalid planned authority handoff: {error}"))
}

fn key_unavailable(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!(
        "temporarily_unavailable: handoff method history is unavailable: {error}"
    ))
}

fn chain_refused(error: arkret_identity::RealmAuthorityChainError) -> ServiceError {
    use arkret_identity::RealmAuthorityChainError as E;
    match &error {
        E::MaterialIncomplete(_) | E::NotFresh(_) => key_unavailable(error),
        E::RouteMismatch(_) => signature_refused(error),
        E::ChainBroken(_) => refused(error),
        _ => signature_refused(error),
    }
}

fn signature_refused(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("signature_invalid: {error}"))
}

pub(crate) async fn install(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: AuthorityHandoffRequest,
) -> ServiceResult<RealmAuthorityHandoff> {
    request.validate_new_handoff().map_err(refused)?;
    let local = state.service_core_id();
    let counterpart = if local == request.handoff.to_service_id {
        &request.handoff.from_service_id
    } else if local == request.handoff.from_service_id {
        &request.handoff.to_service_id
    } else {
        return Err(ServiceError::Conflict(
            "capability_denied: this Station is not a party to the handoff".into(),
        ));
    };
    if &peer.source_service_id != counterpart {
        return Err(ServiceError::Conflict(
            "capability_denied: the authenticated peer is not the handoff counterpart".into(),
        ));
    }
    // RFC 9421 binds this exact body and its sender; the assertion still has
    // to satisfy its signed freshness window and authenticated DID route.
    let nonce = request.authority_bundle.current_assertion.nonce.clone();
    let mut keys =
        crate::routing::realm_join::verified_bundle_keys(state, &request.authority_bundle)
            .await
            .map_err(|error| key_unavailable(error.message))?;
    let authority = arkret_identity::verify_realm_authority_bundle(
        &request.authority_bundle,
        &arkret_identity::RealmAuthorityFreshness::new(crate::wire::now(), nonce.clone()),
        &keys,
    )
    .map_err(chain_refused)?;
    crate::routing::realm_join::insert_historical_method_key(
        state,
        &mut keys,
        &request.snapshot.signature.verification_method,
        request.snapshot.signature.created_at,
    )
    .await
    .map_err(|error| key_unavailable(error.message))?;
    let snapshot_key = arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
        &keys,
        &request.snapshot.signature.verification_method,
        request.snapshot.signature.created_at,
    )
    .ok_or_else(|| {
        key_unavailable("outgoing Snapshot method is unavailable at its signature time")
    })?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &request.snapshot.signature,
        &arkret_canonical::unsigned_value(&request.snapshot, &["signature"]).map_err(refused)?,
        DetachedSignatureContext::RealmSnapshot,
        &snapshot_key,
    )
    .map_err(signature_refused)?;
    let originals = state
        .authority_commits()
        .handoff_originals(&request.handoff.realm_id, request.handoff.from_generation)
        .await?;
    request
        .validate_imported_signer_facts(&originals)
        .map_err(refused)?;
    for full in &originals {
        crate::routing::realm_join::insert_historical_method_key(
            state,
            &mut keys,
            &full.commit.signature.verification_method,
            full.commit.signature.created_at,
        )
        .await
        .map_err(|error| key_unavailable(error.message))?;
        authority
            .verify_committed_item(full, &keys)
            .map_err(chain_refused)?;
        if full.commit.producer_signer_fact_digest.is_none() {
            verify_uninventoried_producer(state, full, &originals).await?;
        }
    }
    arkret_identity::account_device_signer_evidence::verify_handoff_account_device_signer_inventory(
        &request, &originals, &authority, &keys,
    )
    .map_err(signature_refused)?;
    request
        .authority_bundle
        .validate_for_request(
            &arkret_wire::AuthorityBundleRequest {
                realm_id: request.handoff.realm_id.clone(),
                nonce,
            },
            crate::wire::now(),
        )
        .map_err(key_unavailable)?;
    drop(originals);
    // Storage rechecks the frozen heads, complete current and signer inventory
    // under the same authority lock that every writer takes. Network checks
    // cannot race activation into accepting a different durable cut.
    state.authority_commits().install_handoff(&request).await?;
    Ok(request.handoff)
}

/// Native PCR and Agent originals do not carry the Human/Service inventory
/// digest. They still require their original producer proof and historical key.
async fn verify_uninventoried_producer(
    state: &AppState,
    full: &arkret_wire::CommittedEventFullView,
    originals: &[arkret_wire::CommittedEventFullView],
) -> ServiceResult<()> {
    use arkret_models_identity::{
        HistoricalSignerKeyQuerySender, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    };
    let event = &full.event;
    let producer = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| signature_refused("imported Event lacks producer proof"))?;
    let suite = event.event_id.digest_suite_code().digest_suite();
    let native_key = native_genesis_key(state, full, originals).await?;
    if native_key.is_none() {
        event
            .verify_producer_proof_self_consistency(suite)
            .map_err(signature_refused)?;
    }
    let key_bytes = if let Some(key) = native_key {
        key
    } else if event.actual_signer().as_account_id().is_some() {
        let target = arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: full.commit.commit_id.clone(),
            stream_ref: full.commit.stream_ref.clone(),
            stream_position: full.commit.stream_position,
        };
        let sender = match event.account_device_producer().map_err(refused)? {
            Some(human) => HistoricalSignerKeyQuerySender::AccountDevice {
                actor: event.actual_signer().clone(),
                device_id: human.device_id,
                verification_method: producer.verification_method.clone(),
                committed_event_ref: target,
            },
            None => HistoricalSignerKeyQuerySender::Agent {
                actor: event.actual_signer().clone(),
                verification_method: producer.verification_method.clone(),
                committed_event_ref: target,
            },
        };
        let selector = SignerKeyQuerySelector::HistoricalEvent { sender };
        let outcome = state
            .authority_commits()
            .historical_producer_signer_key(&event.realm_id, &selector)
            .await?;
        let Some(SignerKeyQueryOutcome::HistoricalResolved {
            selector: actual,
            key,
            ..
        }) = outcome
        else {
            return Err(key_unavailable(
                "imported producer has no exact historical authorization",
            ));
        };
        if actual != selector {
            return Err(signature_refused(
                "imported producer historical selector differs",
            ));
        }
        key.validate().map_err(signature_refused)?;
        arkret_canonical::base64url_decode(key.public_key_b64u.as_str().as_bytes())
            .map_err(signature_refused)?
    } else {
        crate::jws_verify::resolve_ed25519_pubkey_at(
            state,
            producer.verification_method.as_str(),
            event.created_at,
        )
        .await
        .map_err(key_unavailable)?
        .as_bytes()
        .to_vec()
    };
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(refused)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        producer,
        &bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: key_bytes },
        suite,
    )
    .map_err(signature_refused)
}

/// Founding proofs precede the device authorization history they establish.
/// Resolve them from the original signed genesis and verified inception, never
/// from a device's current row or a later authorization.
async fn native_genesis_key(
    state: &AppState,
    full: &arkret_wire::CommittedEventFullView,
    originals: &[arkret_wire::CommittedEventFullView],
) -> ServiceResult<Option<Vec<u8>>> {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizePayload, RealmCreatePayload, RealmPurpose,
    };
    if full.commit.stream_position > 1
        || !matches!(
            full.commit.stream_ref,
            arkret_wire::CommitStreamRef::Realm { .. }
        )
    {
        return Ok(None);
    }
    let Some(create) = originals.iter().find(|item| {
        item.commit.stream_position == 0 && item.commit.stream_ref == full.commit.stream_ref
    }) else {
        return Ok(None);
    };
    let payload: RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&create.event.payload).map_err(refused)?)
            .map_err(refused)?;
    if payload.object.purpose != RealmPurpose::PrincipalControl {
        return Ok(None);
    }
    let Some(authorize) = originals.iter().find(|item| {
        item.commit.stream_position == 1 && item.commit.stream_ref == full.commit.stream_ref
    }) else {
        return Err(key_unavailable(
            "native PCR founding authorization is not imported",
        ));
    };
    let original = if full.commit.stream_position == 0 {
        create
    } else {
        authorize
    };
    if full.commit.commit_id != original.commit.commit_id
        || full.event.event_id != original.event.event_id
    {
        return Err(key_unavailable(
            "native PCR exact founding coordinate is unavailable",
        ));
    }
    arkret_bootstrap::build_pcr_genesis_unit(create.event.clone(), authorize.event.clone())
        .map_err(signature_refused)?;
    let descriptor = payload
        .object
        .founding_device_descriptor
        .as_ref()
        .ok_or_else(|| key_unavailable("native PCR founding descriptor is unavailable"))?;
    let device: DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&authorize.event.payload).map_err(refused)?)
            .map_err(refused)?;
    let suite = create.event.event_id.digest_suite_code().digest_suite();
    let digest = arkret_models_collaboration::events_payloads::device_authorize_payload_digest(
        &serde_json::to_value(&authorize.event.payload).map_err(refused)?,
        suite,
    )
    .map_err(signature_refused)?;
    if descriptor.founding_authorize_payload_digest != digest
        || descriptor.device_id != device.device_id
        || descriptor.device_public_key_did != device.device_public_key_did
        || descriptor.hpke_key != device.hpke_key
        || descriptor.algorithms != device.algorithms
        || authorize.commit.previous_commit_ref.as_ref() != Some(&create.commit.commit_id)
    {
        return Err(signature_refused(
            "native PCR founding source differs from its signed descriptor",
        ));
    }
    let resolution = payload
        .object
        .initial_resolution
        .as_ref()
        .ok_or_else(|| key_unavailable("native PCR inception is unavailable"))?;
    if device.authorization_binding_kind != arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::RegistrationAnchor
        || !matches!(&device.authorized_by, arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::Principal(principal) if principal == create.event.actor_id.signing_principal_id())
        || authorize.event.producer_proof.as_ref().is_none_or(|proof| proof.verification_method.as_str() != format!("{}#{}", resolution.did, descriptor.device_id)) {
        return Err(signature_refused("founding authorization does not bind the native root and device method"));
    }
    let pinned = state
        .dids()
        .resolve_webvh_state_at(&resolution.did, create.event.created_at)
        .await
        .map_err(key_unavailable)?;
    let proof = create
        .event
        .producer_proof
        .as_ref()
        .ok_or_else(|| signature_refused("native PCR root proof is absent"))?;
    let root = proof
        .verification_method
        .as_str()
        .strip_prefix("did:key:")
        .and_then(|method| method.split_once('#'))
        .filter(|(did, fragment)| did == fragment)
        .map(|(did, _)| did);
    if pinned.version_id != resolution.version_id
        || pinned.log_head_digest.as_str() != resolution.method_history_head
        || root.is_none_or(|key| !pinned.update_keys.iter().any(|accepted| accepted == key))
    {
        return Err(signature_refused(
            "native PCR root proof differs from the original verified inception",
        ));
    }
    let method = if full.commit.stream_position == 0 {
        proof.verification_method.to_string()
    } else {
        let human = full
            .event
            .account_device_producer()
            .map_err(signature_refused)?
            .ok_or_else(|| signature_refused("founding authorization has no device producer"))?;
        if human.device_id != descriptor.device_id || full.event.actor_id != create.event.actor_id {
            return Err(signature_refused(
                "founding authorization signer differs from descriptor",
            ));
        }
        let did = descriptor.device_public_key_did.as_str();
        let fragment = did
            .strip_prefix("did:key:")
            .ok_or_else(|| signature_refused("founding device key is not immutable"))?;
        format!("{did}#{fragment}")
    };
    Ok(Some(
        crate::jws_verify::resolve_ed25519_pubkey_at(state, &method, full.event.created_at)
            .await
            .map_err(key_unavailable)?
            .as_bytes()
            .to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_pcr_import_uses_original_producer_keys_and_rejects_tampering() {
        let mut config = coland_test_support::app_config();
        config.notary_signing_key_seed = Some([83; 32]);
        config.seed_demo_data = false;
        let (leased, pool) = coland_test_support::app_state_with_pool(config.clone());
        let state = AppState::new_with_service_identity(
            crate::config::AppConfig {
                public_base_url: config.public_base_url.clone(),
                notary_signing_key_seed: config.notary_signing_key_seed,
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db {
                pool: Some(pool.clone()),
            },
            std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(pool)),
            coland_test_support::fixture_service_identity(&config),
            leased.service_resolution_commitment().as_ref().clone(),
            [83; 32],
        );
        let mut fixture =
            coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        let mut previous = None;
        for (index, transaction) in fixture.unit.transactions.iter_mut().enumerate() {
            let commit = &mut transaction.commit;
            commit.previous_commit_ref = previous;
            commit.commit_id =
                arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    arkret_canonical::canonical_json_bytes(
                        &arkret_canonical::unsigned_value(commit, &["commit_id", "signature"])
                            .unwrap(),
                    )
                    .unwrap(),
                ));
            commit.signature = arkret_signatures::detached_object::sign_detached_object(
                &arkret_canonical::unsigned_value(commit, &["signature"]).unwrap(),
                DetachedSignatureContext::RealmCommit,
                commit.signature.verification_method.clone(),
                commit.committed_at,
                &ed25519_dalek::SigningKey::from_bytes(&[83; 32]),
            )
            .unwrap();
            previous = Some(commit.commit_id.clone());
            fixture.history.commits[index] = commit.clone();
        }
        fixture
            .admit_into(state.test_persistence().as_ref())
            .await
            .expect("real PCR admission");
        let originals = state
            .authority_commits()
            .handoff_originals(&fixture.unit.transactions[0].event.realm_id, 0)
            .await
            .unwrap();
        assert!(!originals.is_empty());
        for full in &originals {
            assert!(full.commit.producer_signer_fact_digest.is_none());
            verify_uninventoried_producer(&state, full, &originals)
                .await
                .expect("original PCR producer proof");
            let mut tampered = full.clone();
            tampered.event.producer_proof.as_mut().unwrap().jws = "invalid".into();
            let error = verify_uninventoried_producer(&state, &tampered, &originals)
                .await
                .unwrap_err();
            assert!(
                matches!(error, ServiceError::Conflict(detail) if detail.starts_with("signature_invalid:"))
            );
            let mut missing = full.clone();
            missing.commit.commit_id = arkret_wire::RealmCommitId::from_digest([249; 32]);
            let error = verify_uninventoried_producer(&state, &missing, &originals)
                .await
                .unwrap_err();
            assert!(
                matches!(error, ServiceError::Conflict(detail) if detail.starts_with("temporarily_unavailable:"))
            );
        }
        // A valid signature from another immutable DID cannot replace the
        // actual producer, even though it binds the declared business actor.
        let root_key = ed25519_dalek::SigningKey::from_bytes(&[211; 32]);
        let root = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            root_key.verifying_key().as_bytes(),
        );
        let proof_method = arkret_wire::DidUrl::new(format!("did:key:{root}#{root}")).unwrap();
        let actor_did = arkret_wire::Did::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                ed25519_dalek::SigningKey::from_bytes(&[210; 32])
                    .verifying_key()
                    .as_bytes()
            )
        ))
        .unwrap();
        let actor =
            arkret_wire::ActorId::service(arkret_wire::project_did_to_core_id(&actor_did).unwrap());
        let raw = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::RealmProfile.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: originals[0].event.realm_id.clone(),
            },
            actor,
            serde_json::json!({"schema":"ak.schema.realm_profile.v1","title":"Wrong producer"}),
            chrono::Utc::now(),
        )
        .unwrap();
        let mut wrong = originals[0].clone();
        wrong.event = coland_test_support::device_authorization_history::sign_event(
            raw,
            proof_method,
            [211; 32],
        );
        wrong.commit.stream_position = 2;
        let error = verify_uninventoried_producer(&state, &wrong, &originals)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ServiceError::Conflict(detail) if detail.starts_with("signature_invalid:") && detail.contains("actual signer"))
        );
    }
}
