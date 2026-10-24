//! Activation of a pre-imported, planned authority migration. The wire body
//! never substitutes for the complete private durable state transfer.

use arkret_models_collaboration::authority_commit::AuthorityRealmAuthorityHandoffRequestBody;
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

// This is an eligibility refusal, never an authority or signature witness.
// Derive it from the complete content-addressed genesis, before the bundle's
// impossible fixed-governor successor is reported as a generic shape failure.
fn require_transferable_genesis(
    genesis: &arkret_wire::Event,
    realm: &arkret_wire::RealmId,
) -> ServiceResult<()> {
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&genesis.payload).map_err(refused)?)
            .map_err(refused)?;
    payload.object.validate().map_err(refused)?;
    genesis
        .verify_event_id_matches_content_with_digest_suite(realm.digest_suite_code().digest_suite())
        .map_err(refused)?;
    if genesis.scope_ref != arkret_wire::ScopeRef::RealmGenesis
        || &genesis.realm_id != realm
        || arkret_wire::RealmId::from_event_id(&genesis.event_id) != *realm
    {
        return Err(refused(
            "the genesis original does not derive the handoff Realm",
        ));
    }
    let governance = arkret_wire::GenesisGovernance::from_genesis(genesis).map_err(refused)?;
    governance
        .require_transferable()
        .map_err(|error| ServiceError::Conflict(format!("failed_precondition: {error}")))?;
    Ok(())
}

fn validate_handoff_admission(
    request: &AuthorityRealmAuthorityHandoffRequestBody,
) -> ServiceResult<()> {
    // Keep absent/invalid mandatory new-admission material a schema failure.
    request.handoff.validate_shape().map_err(refused)?;
    let entries = request
        .historical_signer_facts
        .as_deref()
        .ok_or_else(|| refused("new authority handoff requires the complete signer inventory"))?;
    if request.handoff.historical_signer_facts_digest.as_ref()
        != Some(
            &arkret_models_collaboration::authority_commit::historical_signer_facts_digest(entries)
                .map_err(refused)?,
        )
    {
        return Err(refused(
            "new authority handoff signer inventory digest differs",
        ));
    }
    request
        .management_private_state
        .as_ref()
        .ok_or_else(|| refused("new authority handoff requires the management private manifest"))?
        .validate_handoff(&request.handoff)
        .map_err(refused)?;
    let genesis = &request.authority_bundle.genesis_event;
    request
        .authority_bundle
        .genesis_commit
        .validate_shape()
        .map_err(refused)?;
    if request.authority_bundle.realm_id != request.handoff.realm_id
        || request.authority_bundle.genesis_commit.realm_id != request.handoff.realm_id
        || request.authority_bundle.genesis_commit.event_ref != genesis.event_id
        || request.authority_bundle.genesis_commit.stream_position != 0
        || request
            .authority_bundle
            .genesis_commit
            .governance_generation
            != 0
        || request.authority_bundle.genesis_commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: request.handoff.realm_id.clone(),
            })
        || request.authority_bundle.genesis_commit.authority_ref
            != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone())
    {
        return Err(refused("handoff genesis original and first Commit differ"));
    }
    require_transferable_genesis(genesis, &request.handoff.realm_id)?;
    request.validate_new_handoff().map_err(refused)
}

pub(crate) async fn install(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: AuthorityRealmAuthorityHandoffRequestBody,
) -> ServiceResult<RealmAuthorityHandoff> {
    validate_handoff_admission(&request)?;
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
        &request.authority_bundle,
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
            &request.authority_bundle,
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
            &arkret_wire::RealmAuthorityBundleRequestBody {
                realm_id: request.handoff.realm_id.clone(),
                nonce,
            },
            crate::wire::now(),
        )
        .map_err(key_unavailable)?;
    if local == request.handoff.to_service_id {
        require_imported_mls_public_material(state, &originals).await?;
    }
    drop(originals);
    if local == request.handoff.from_service_id {
        // The accepted chain supplies the new governor's authenticated locator.
        // Install it through ordinary discovery, including Describe binding and
        // rollback checks, before the old Station starts forwarding requests.
        let inline = serde_json::from_value(request.authority_bundle.current_route_record.clone())
            .map_err(refused)?;
        state
            .service_route_resolver()
            .map_err(key_unavailable)?
            .resolve_carrier(
                &arkret_models_identity::ServiceResolutionCarrier::Inline { inline },
                &request.handoff.to_service_id,
                "station",
                crate::wire::now(),
            )
            .await
            .map_err(key_unavailable)?;
    }
    // Storage rechecks the frozen heads, complete current and signer inventory
    // under the same authority lock that every writer takes. Network checks
    // cannot race activation into accepting a different durable cut.
    state.authority_commits().install_handoff(&request).await?;
    Ok(request.handoff)
}

/// Imported rows do not prove the corresponding object bytes are present.
/// Validate every frozen MLS Genesis with the ordinary bounded material reader
/// before enabling the receiving authority. No member private state is read.
async fn require_imported_mls_public_material(
    state: &AppState,
    originals: &[arkret_wire::CommittedEventFullView],
) -> ServiceResult<()> {
    use arkret_models_collaboration::events_payloads::{MlsGenesisEpoch, MlsGenesisPayload};
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;

    for full in originals {
        let event = &full.event;
        if event.kind != arkret_wire::EventKind::MlsGenesis {
            continue;
        }
        let payload: MlsGenesisPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(refused)?)
                .map_err(refused)?;
        payload.validate().map_err(refused)?;
        let request = MlsGroupStateMaterialRequestBody {
            realm_id: event.realm_id.clone(),
            effective_scope: payload.effective_scope().clone(),
            mls_group_id: payload.mls_group_id().map_err(refused)?,
            epoch: MlsGenesisEpoch::try_from(0).map_err(refused)?,
            group_state_event_id: event.event_id.clone(),
            caller_actor_id: None,
            target_commit_event_ref: None,
            target_epoch: None,
            group_info_ref: payload.group_info_ref,
            ratchet_tree_ref: payload.ratchet_tree_ref,
            max_response_bytes: None,
        };
        crate::routing::mls::serve_group_state_material(state, &request, event)
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!(
                    "temporarily_unavailable: handoff MLS public material is incomplete: {}",
                    error.message
                ))
            })?;
    }
    Ok(())
}

/// Native PCR and Agent originals do not carry the Human/Service inventory
/// digest. They still require their original producer proof and historical key.
async fn verify_uninventoried_producer(
    state: &AppState,
    full: &arkret_wire::CommittedEventFullView,
    originals: &[arkret_wire::CommittedEventFullView],
) -> ServiceResult<()> {
    use arkret_models_identity::{
        HistoricalSignerKeyQuerySender, SignerKeyQuerySelector, SignerKeyResolution,
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
        let Some(SignerKeyResolution::HistoricalResolved {
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
        arkret_canonical::base64url_decode(key.public_key_base64url.as_str().as_bytes())
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

    fn governance_genesis(purpose: &str) -> arkret_wire::Event {
        // Local content/shape classification only; never an accepted original
        // or a substitute for the subsequent signature chain verification.
        arkret_wire::test_support::raw_event_at(
            "ak.realm.create",
            arkret_wire::ScopeRef::RealmGenesis,
            "ak:did_core:web:handoff-holder.example".parse().unwrap(),
            "ak:did_core:web:handoff-origin.example".parse().unwrap(),
            serde_json::json!({"object":{
                "schema":"ak.schema.realm_genesis.v1","purpose":purpose,
                "genesis_salt":arkret_canonical::base64url_encode([0xc9;32]),
                "trust_domain":"ak:trust_domain:handoff.example","security_class":"standard",
                "governance_station_id":"ak:did_core:web:handoff-origin.example",
                "initial_join_rule":"closed","initial_history_access":"since_join",
                "initial_discoverability":"invite_only"
            }}),
            crate::wire::now(),
        )
        .unwrap()
    }

    #[test]
    fn direct_handoff_eligibility_is_failed_precondition_without_mutating_original() {
        let genesis = governance_genesis("direct_conversation");
        let original = genesis.clone();
        let error = require_transferable_genesis(&genesis, &genesis.realm_id).unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition)
        );
        assert!(error.to_string().contains("Direct Conversation"));
        assert_eq!(genesis, original);
        let collaboration = governance_genesis("collaboration");
        require_transferable_genesis(&collaboration, &collaboration.realm_id).unwrap();
    }

    #[test]
    fn managed_agent_handoff_eligibility_is_failed_precondition() {
        // Restriction classification only; native accepted provenance is
        // exercised separately by the real PostgreSQL Agent control fixture.
        let mut genesis = governance_genesis("agent_control");
        genesis.payload.get_mut("object").unwrap()["initial_resolution"] = serde_json::json!({
            "did":"did:web:handoff-holder.example",
            "method_history_head":format!("sha256:{}", "12".repeat(32)),
            "version_id":"fixture"
        });
        genesis.executed_by = Some(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:handoff-controller.example"
                .parse()
                .unwrap(),
            "ak:did_core:web:handoff-origin.example".parse().unwrap(),
        )));
        genesis.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new("did:web:handoff-holder.example#controller")
                .unwrap(),
        );
        genesis
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let error = require_transferable_genesis(&genesis, &genesis.realm_id).unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::FailedPrecondition),
            "{error}"
        );
        assert!(error.to_string().contains("Agent PCR"), "{error}");
    }

    #[test]
    fn malformed_direct_handoff_genesis_is_schema_violation() {
        let genesis = governance_genesis("direct_conversation");
        let mut malformed = genesis.clone();
        malformed.payload.remove("object");
        assert!(matches!(
            require_transferable_genesis(&malformed, &genesis.realm_id),
            Err(ServiceError::SchemaViolation(_))
        ));
        let mut wrong_identity = genesis.clone();
        wrong_identity.event_id =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0xca; 32]);
        assert!(matches!(
            require_transferable_genesis(&wrong_identity, &genesis.realm_id),
            Err(ServiceError::SchemaViolation(_))
        ));
        let wrong_realm = arkret_wire::RealmId::from_event_id(&wrong_identity.event_id);
        assert!(matches!(
            require_transferable_genesis(&genesis, &wrong_realm),
            Err(ServiceError::SchemaViolation(_))
        ));
    }

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
