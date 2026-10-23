//! Durable service-identity bootstrap (identity-did.md §3.7).
//!
//! Coland is a class-B Service Identity Provider for its own identity. The
//! database stores the SDK `StoredDidCoreIdentity` plus public WebVH evidence;
//! signing and control secrets remain in a durable SDK `KeyStore`. Configuration
//! never supplies or pins the resulting DID.

pub mod public_base;

use std::sync::Arc;

use arkret_http_client::{Auth, Client, ClientBuilder};
use arkret_identifiers::Did;
use arkret_identity::service_identity::{
    DidCoreIdentityBundle, DidCoreIdentityDiagnostic, DidCoreIdentityKeyRef,
    DidCoreIdentityProviderRef, DidCoreIdentityState, FileIdentityBundleBackend,
    IdentityBundleBackend, IdentityBundleBackendAvailability, LocalDidCoreIdentity,
    StoredDidCoreIdentity,
};
use arkret_keystore::KeyStore;
use arkret_models_identity::service_identity::{
    ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT, CanonicalServiceUrl,
    ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey, ServiceRegistrationOutcome,
    ServiceRegistrationReceipt,
};
use arkret_wire::{PayloadProof, ServiceKind, project_did_to_core_id, proof_kind};
use coland_http::config::{AppConfig, CONFIGURED_SIGNING_KEY_REF, SERVICE_IDENTITY_KEYSTORE_APP};
use coland_http::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
    validate_witness_policy_for_log, verify_log_subject, verify_scid_against_did,
    verify_webvh_log_proof,
};
use coland_services::identity::{
    DidDocumentState as WebvhDocumentRecord, DidLogEvent as WebvhLogRecord,
    ServiceRegistrationCommitResult as ServiceRegistrationCommitOutcome,
};
use coland_services::persistence::PersistenceHandle;
use coland_storage_postgres::{Db, PgPersistenceStore};
use ed25519_dalek::SigningKey;
use rand_chacha::rand_core::SeedableRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Runtime values resolved before AppState is constructed. The service DID is
/// deliberately absent from [`AppConfig`].
pub struct ServiceIdentityBootstrap {
    pub persistence: PersistenceHandle,
    /// The exact KeyStore instance used to prepare or recover this identity.
    /// Waiting/degraded retries must retain it so a timed-out ensure cannot
    /// silently prepare a second control root.
    pub key_store: Option<Arc<dyn KeyStore>>,
    pub state: DidCoreIdentityState,
    /// Stable DID plus the exact current method-history coordinates that
    /// every ServiceDescribe and authenticated DID evidence must share.
    pub resolution_commitment: Option<arkret_models_identity::ResolutionCommitment>,
    /// Signing seed resolved through the verified identity's active KeyRef.
    /// AppState must use this exact seed and must never independently mint or
    /// derive a second runtime signer.
    pub signing_seed: [u8; 32],
}

/// Build the persistence store and resolve or provision the service identity
/// before any signer, clock, or protocol router is built.
pub async fn resolve_and_build_persistence(
    config: &AppConfig,
    db: &Db,
) -> anyhow::Result<ServiceIdentityBootstrap> {
    let pool = db.pool.as_ref().ok_or_else(|| {
        anyhow::anyhow!("DATABASE_URL is required: the Coland runtime persists through PostgreSQL")
    })?;
    let persistence = PersistenceHandle::new(Arc::new(PgPersistenceStore::new(pool.clone())));
    let key_store: Option<Arc<dyn KeyStore>> = config
        .key_store
        .open(SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|error| anyhow::anyhow!("opening service identity KeyStore failed: {error}"))?
        .map(Arc::from);

    retry_service_identity(config, persistence, key_store).await
}

/// Resolve the service identity again while retaining the original storage
/// and key-custody context. This is the only safe retry path after an
/// indeterminate Provider response.
pub async fn retry_service_identity(
    config: &AppConfig,
    persistence: PersistenceHandle,
    key_store: Option<Arc<dyn KeyStore>>,
) -> anyhow::Result<ServiceIdentityBootstrap> {
    let first_provisioning = config.development_mode || config.first_provisioning;
    let bundle_backend = config
        .service_identity_bundle_dir
        .clone()
        .map(FileIdentityBundleBackend::new);

    let state = resolve_service_identity(
        &persistence,
        config,
        key_store.as_deref(),
        bundle_backend
            .as_ref()
            .map(|backend| backend as &dyn IdentityBundleBackend),
        first_provisioning,
    )
    .await?;
    let signing_seed = if let Some(identity) = state.identity() {
        load_signing_seed(
            config,
            key_store.as_deref(),
            &identity.active_signing_key_ref,
        )?
    } else if config.external_webvh_registration_bearer.is_some() {
        let registration_key = registration_key(config)?;
        let provider = external_provider(config)?;
        external_identity_material(
            config,
            key_store.as_deref(),
            &provider,
            &registration_key,
            false,
            None,
        )?
        .signing_seed
    } else {
        anyhow::bail!("service identity bootstrap produced no serving identity")
    };
    let resolution_commitment = persistence
        .stored_service_identity()
        .await
        .map_err(|error| anyhow::anyhow!("reading service resolution commitment failed: {error}"))?
        .map(|stored| arkret_models_identity::ResolutionCommitment {
            did: stored.identity.did.clone(),
            method_history_head: stored.registration_receipt.log_head_digest.clone(),
            version_id: stored.identity.version_id.clone(),
        });
    Ok(ServiceIdentityBootstrap {
        persistence,
        key_store,
        state,
        resolution_commitment,
        signing_seed,
    })
}

async fn resolve_service_identity(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    bundle_backend: Option<&dyn IdentityBundleBackend>,
    first_provisioning: bool,
) -> anyhow::Result<DidCoreIdentityState> {
    let configured_key = registration_key(config)?;
    // A configured Account Authority is a hard startup dependency. Resolve
    // its published signing key before considering any stored identity so a
    // restart cannot silently serve with stale trust merely because the DID
    // was provisioned on an earlier boot.
    let account_authority_key = account_authority_assertion_key(config).await?;
    if config.external_webvh_registration_bearer.is_some() {
        return resolve_external_service_identity(
            persistence,
            config,
            key_store,
            configured_key,
            account_authority_key.as_deref(),
        )
        .await;
    }
    let existing = persistence
        .stored_service_identity()
        .await
        .map_err(|error| anyhow::anyhow!("reading persisted service identity failed: {error}"))?;

    let stored = if let Some(stored) = existing {
        let stored =
            reconcile_pending_local_rotation(persistence, config, key_store, stored).await?;
        // Detect drift BEFORE validating. The stored identity's signing and
        // control keys are bound to the registration key it was minted under,
        // so a deployment pointed at a database from a different public base
        // fails inside validation with a bare "key not found" that reads like a
        // keystore fault. Name the actual cause instead.
        let drifted = stored.identity.registration_key != configured_key;
        validate_stored_service_identity(persistence, config, key_store, &stored)
            .await
            .map_err(|error| {
                if !drifted {
                    return error;
                }
                anyhow::anyhow!(
                    "service_identity_registration_key_drift: the persisted service identity {} was \
                     minted for public base {}, but this process is configured for {}. Its identity \
                     keys are bound to the original registration key, so validation failed with: \
                     {error}. Point this deployment back at its original public base URL, or give a \
                     genuinely new deployment its own database namespace.",
                    stored.identity.service_id,
                    stored.identity.registration_key.public_base_url(),
                    configured_key.public_base_url(),
                )
            })?;
        if drifted {
            tracing::warn!(
                service_id = %stored.identity.service_id,
                stored_public_base = %stored.identity.registration_key.public_base_url(),
                configured_public_base = %configured_key.public_base_url(),
                "service registration key drift detected; retaining the durable service DID and forbidding silent re-registration",
            );
        }
        stored
    } else if let Some(bundle) = load_identity_bundle(bundle_backend, &configured_key)? {
        restore_identity_bundle(
            persistence,
            config,
            key_store,
            configured_key.clone(),
            bundle,
        )
        .await?
    } else if let Some(outcome) = persistence
        .service_registration(&configured_key)
        .await
        .map_err(|error| anyhow::anyhow!("reading local service registration failed: {error}"))?
    {
        let restored =
            stored_identity_from_outcome(config, key_store, configured_key.clone(), outcome)?;
        validate_stored_service_identity(persistence, config, key_store, &restored).await?;
        persist_stored_identity(persistence, restored).await?
    } else {
        if !first_provisioning {
            anyhow::bail!(
                "service_identity_first_provisioning_required: no durable service identity, local \
                 registration, or identity bundle was found; if this is a genuinely new class-B \
                 deployment set COLAND_FIRST_PROVISIONING=1 once, otherwise verify DATABASE_URL \
                 and restore the identity bundle"
            );
        }
        mint_local_service_identity(
            persistence,
            config,
            key_store,
            bundle_backend,
            configured_key.clone(),
            account_authority_key.as_deref(),
        )
        .await?
    };

    // A later successor needs the original receipt. Establish or verify its
    // recoverable bundle before any public head can advance.
    ensure_identity_bundle(persistence, bundle_backend, &stored).await?;

    if stored.identity.registration_key != configured_key {
        return Ok(DidCoreIdentityState::RegistrationKeyDrift {
            stored_key: stored.identity.registration_key.clone(),
            identity: stored.identity,
            computed_key: configured_key,
        });
    }
    let stored = ensure_account_authority_authorization(
        persistence,
        config,
        key_store,
        stored,
        account_authority_key.as_deref(),
    )
    .await?;

    let stored = ensure_service_endpoint(persistence, config, key_store, stored).await?;
    let stored = ensure_service_assertion_signer(persistence, config, key_store, stored).await?;
    ensure_identity_bundle(persistence, bundle_backend, &stored).await?;

    Ok(DidCoreIdentityState::Ready {
        identity: stored.identity,
    })
}

struct ExternalIdentityMaterial {
    signing_seed: [u8; 32],
    signing_key_ref: DidCoreIdentityKeyRef,
    control_key_ref: DidCoreIdentityKeyRef,
    prepared: arkret_signatures::webvh::PreparedInception,
}

async fn resolve_external_service_identity(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    registration_key: ServiceRegistrationKey,
    account_authority_key: Option<&str>,
) -> anyhow::Result<DidCoreIdentityState> {
    let provider = external_provider(config)?;
    let existing = persistence
        .stored_service_identity()
        .await
        .map_err(|error| anyhow::anyhow!("reading persisted service identity failed: {error}"))?;
    let material = external_identity_material(
        config,
        key_store,
        &provider,
        &registration_key,
        existing.is_none(),
        account_authority_key,
    )?;

    if let Some(stored) = existing.as_ref() {
        validate_external_stored_identity(stored, &provider, &material)?;
        if stored.identity.registration_key != registration_key {
            return Ok(DidCoreIdentityState::RegistrationKeyDrift {
                identity: stored.identity.clone(),
                stored_key: stored.identity.registration_key.clone(),
                computed_key: registration_key,
            });
        }
    }

    let client = external_provider_client(config, &provider)?;
    match client.service_registration_get(&registration_key).await {
        Ok(outcome) => {
            accept_external_outcome(
                persistence,
                config,
                &provider,
                &registration_key,
                &material,
                existing.as_ref(),
                account_authority_key,
                outcome,
            )
            .await
        }
        Err(arkret_http_client::Error::Api { status: 404, .. }) if existing.is_none() => {
            let operation = material
                .prepared
                .service_registration_operation()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let request = ServiceRegistrationEnsureRequestBody::new(
                registration_key.clone(),
                operation,
                uuid::Uuid::now_v7().to_string(),
                None,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            match client.service_registration_ensure(&request).await {
                Ok(outcome) => {
                    accept_external_outcome(
                        persistence,
                        config,
                        &provider,
                        &registration_key,
                        &material,
                        None,
                        account_authority_key,
                        outcome,
                    )
                    .await
                }
                Err(error) if provider_unavailable(&error) => {
                    Ok(waiting_provider(registration_key))
                }
                Err(ensure_error) => match client.service_registration_get(&registration_key).await
                {
                    Ok(outcome) => {
                        accept_external_outcome(
                            persistence,
                            config,
                            &provider,
                            &registration_key,
                            &material,
                            None,
                            account_authority_key,
                            outcome,
                        )
                        .await
                    }
                    Err(error) if provider_unavailable(&error) => {
                        Ok(waiting_provider(registration_key))
                    }
                    Err(lookup_error) => Ok(DidCoreIdentityState::Faulted {
                        diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
                        next_action: format!(
                            "verify COLAND_EXTERNAL_WEBVH_PROVIDER_URL, its registration bearer, and the retained KeyStore; Provider rejected ensure ({ensure_error}) and lookup failed ({lookup_error})"
                        ),
                    }),
                },
            }
        }
        Err(error) if provider_unavailable(&error) => match existing {
            Some(stored) => {
                validate_external_account_authority_authorization(
                    config,
                    &stored,
                    account_authority_key,
                )?;
                Ok(DidCoreIdentityState::DegradedStored {
                    identity: stored.identity,
                    retry_at: service_identity_retry_at(),
                    last_error: error.to_string(),
                })
            }
            None => Ok(waiting_provider(registration_key)),
        },
        Err(error) => Ok(DidCoreIdentityState::Faulted {
            diagnostic: DidCoreIdentityDiagnostic::RestoreFailed,
            next_action: format!(
                "verify COLAND_EXTERNAL_WEBVH_PROVIDER_URL, its registration bearer, and the retained KeyStore; Provider lookup failed: {error}"
            ),
        }),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the external identity acceptance boundary keeps provider, retained identity, key material, and outcome inputs explicit"
)]
async fn accept_external_outcome(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    provider: &DidCoreIdentityProviderRef,
    registration_key: &ServiceRegistrationKey,
    material: &ExternalIdentityMaterial,
    prior: Option<&StoredDidCoreIdentity>,
    account_authority_key: Option<&str>,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<DidCoreIdentityState> {
    if let Some(prior) = prior
        && prior.identity.service_id != *outcome.service_id()
    {
        return Ok(DidCoreIdentityState::Conflict {
            stored_service_id: prior.identity.service_id.clone(),
            provider_id: outcome.service_id().clone(),
        });
    }
    let mut stored =
        stored_external_identity_from_outcome(provider, registration_key, material, outcome)?;
    if let Some(prior) = prior {
        retain_prior_signing_key_refs(&prior.identity, &mut stored.identity)?;
        validate_external_stored_identity(&stored, provider, material)?;
    }
    validate_external_account_authority_authorization(config, &stored, account_authority_key)?;
    persist_stored_identity(persistence, stored.clone()).await?;
    Ok(DidCoreIdentityState::Ready {
        identity: stored.identity,
    })
}

fn retain_prior_signing_key_refs(
    prior: &LocalDidCoreIdentity,
    next: &mut LocalDidCoreIdentity,
) -> anyhow::Result<()> {
    prior.validate()?;
    next.validate()?;
    if prior.did != next.did
        || prior.service_id != next.service_id
        || prior.registration_key != next.registration_key
        || prior.provider != next.provider
    {
        anyhow::bail!(
            "service identity refresh cannot transfer retained signing keys across a different complete identity or Provider binding"
        );
    }
    for reference in &prior.signing_key_refs {
        if !next.signing_key_refs.contains(reference) {
            next.signing_key_refs.push(reference.clone());
        }
    }
    next.validate()?;
    Ok(())
}

fn external_provider(config: &AppConfig) -> anyhow::Result<DidCoreIdentityProviderRef> {
    let endpoint = config
        .external_webvh_provider_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("external service identity Provider URL is missing"))?;
    let endpoint = CanonicalServiceUrl::canonicalize(endpoint)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(DidCoreIdentityProviderRef {
        name: "external-webvh".to_owned(),
        endpoint,
    })
}

fn external_provider_client(
    config: &AppConfig,
    provider: &DidCoreIdentityProviderRef,
) -> anyhow::Result<Client> {
    let bearer = config
        .external_webvh_registration_bearer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("external service identity Provider bearer is missing"))?;
    ClientBuilder::new(provider.endpoint.as_url())
        .auth(Auth::Bearer(bearer.clone()))
        .allow_insecure_localhost()
        .build()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn external_identity_material(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    provider: &DidCoreIdentityProviderRef,
    registration_key: &ServiceRegistrationKey,
    allow_create: bool,
    account_authority_key: Option<&str>,
) -> anyhow::Result<ExternalIdentityMaterial> {
    let key_store = required_key_store(key_store)?;
    let suffix = registration_key_ref_suffix(registration_key)?;
    let signing_key_ref = if config.notary_signing_key_seed.is_some() {
        DidCoreIdentityKeyRef::new(CONFIGURED_SIGNING_KEY_REF.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
    } else {
        DidCoreIdentityKeyRef::new(format!("arkret:signer:coland-notary:external:{suffix}"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
    };
    let signing_seed = match config.notary_signing_key_seed {
        Some(seed) => seed,
        None => load_or_create_seed(key_store, &signing_key_ref, allow_create)?,
    };
    let inception_seed_ref = DidCoreIdentityKeyRef::new(format!(
        "arkret:control:coland-webvh:external:{suffix}:inception"
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let inception_seed = load_or_create_seed(key_store, &inception_seed_ref, allow_create)?;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(inception_seed);
    let assertion_keys = account_authority_key
        .map(|key| vec![(ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT, key)])
        .unwrap_or_default();
    let prepared =
        arkret_signatures::webvh::prepare_service_registration_inception_with_assertion_keys(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &provider.endpoint.as_url(),
                registration_key,
                also_known_as: &[],
                version_time: chrono::Utc::now(),
                did_key_fragment: Some("notary-key"),
            },
            &signing_seed,
            &assertion_keys,
        )
        .map_err(|error| anyhow::anyhow!("service DID inception failed: {error}"))?;
    let control_key_ref =
        DidCoreIdentityKeyRef::new(format!("arkret:control:coland-webvh:external:{suffix}:1"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let next_control_key_ref =
        DidCoreIdentityKeyRef::new(format!("arkret:control:coland-webvh:external:{suffix}:2"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    store_or_verify_seed(
        key_store,
        &control_key_ref,
        &prepared.update_key_seed,
        allow_create,
    )?;
    store_or_verify_seed(
        key_store,
        &next_control_key_ref,
        &prepared.next_update_key_seed,
        allow_create,
    )?;
    Ok(ExternalIdentityMaterial {
        signing_seed,
        signing_key_ref,
        control_key_ref,
        prepared,
    })
}

fn stored_external_identity_from_outcome(
    provider: &DidCoreIdentityProviderRef,
    registration_key: &ServiceRegistrationKey,
    material: &ExternalIdentityMaterial,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<StoredDidCoreIdentity> {
    outcome
        .validate_for(registration_key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let stored = StoredDidCoreIdentity {
        identity: LocalDidCoreIdentity {
            service_id: outcome.service_id().clone(),
            did: outcome.did().clone(),
            registration_key: registration_key.clone(),
            provider: Some(provider.clone()),
            signing_key_refs: vec![material.signing_key_ref.clone()],
            active_signing_key_ref: material.signing_key_ref.clone(),
            control_key_ref: material.control_key_ref.clone(),
            version_id: outcome.version_id().to_owned(),
            last_verified_at: now,
        },
        did_document: outcome.did_document,
        registration_receipt: outcome.registration_receipt,
        stored_at: now,
    };
    validate_external_stored_identity(&stored, provider, material)?;
    Ok(stored)
}

fn validate_external_stored_identity(
    stored: &StoredDidCoreIdentity,
    provider: &DidCoreIdentityProviderRef,
    material: &ExternalIdentityMaterial,
) -> anyhow::Result<()> {
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("persisted service identity is invalid: {error}"))?;
    if stored.identity.provider.as_ref() != Some(provider) {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted identity belongs to a different Provider"
        );
    }
    if stored.identity.active_signing_key_ref != material.signing_key_ref
        || !stored
            .identity
            .signing_key_refs
            .iter()
            .any(|key_ref| key_ref == &material.signing_key_ref)
        || stored.identity.control_key_ref != material.control_key_ref
    {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted KeyRefs do not match retained external identity keys"
        );
    }
    validate_service_signing_binding(stored, &material.signing_seed)?;
    let expected_control_digest = material
        .prepared
        .service_registration_operation()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .control_key_digest()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if stored.registration_receipt.control_key_digest != expected_control_digest {
        anyhow::bail!(
            "service_identity_key_mismatch: Provider receipt is bound to different WebVH control keys"
        );
    }
    Ok(())
}

fn validate_external_account_authority_authorization(
    config: &AppConfig,
    stored: &StoredDidCoreIdentity,
    expected_key: Option<&str>,
) -> anyhow::Result<()> {
    if config.account_authority_url.is_none() {
        return Ok(());
    }
    let method_id = format!(
        "{}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}",
        stored.identity.did
    );
    let authorized = stored
        .did_document
        .verification_method
        .iter()
        .find(|method| method.id == method_id)
        .filter(|_| stored.did_document.assertion_method.contains(&method_id));
    match (authorized, expected_key) {
        (Some(method), Some(expected)) if method.public_key_multibase != expected => {
            anyhow::bail!(
                "service_identity_key_mismatch: external Provider identity authorizes a different Account Authority key"
            )
        }
        (Some(_), Some(_)) => Ok(()),
        (Some(_), None) => anyhow::bail!(
            "service_identity_key_mismatch: Account Authority is configured but published no signing key"
        ),
        (None, _) => anyhow::bail!(
            "service_identity_key_mismatch: external Provider identity does not authorize {method_id}; rotate the hosted DID and refresh its registration receipt before starting this deployment"
        ),
    }
}

fn registration_key_ref_suffix(key: &ServiceRegistrationKey) -> anyhow::Result<String> {
    let bytes = arkret_canonical::canonical_json_bytes(key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn load_or_create_seed(
    key_store: &dyn KeyStore,
    key_ref: &DidCoreIdentityKeyRef,
    allow_create: bool,
) -> anyhow::Result<[u8; 32]> {
    match key_store.load(key_ref.as_str()) {
        Ok(bytes) => key_bytes_to_seed(key_ref, bytes.as_slice()),
        Err(error) if error.is_not_found() && allow_create => {
            let mut seed = [0u8; 32];
            coland_http::state::getrandom_seed(&mut seed);
            key_store.store(key_ref.as_str(), &seed).map_err(|error| {
                anyhow::anyhow!("persisting {} failed: {error}", key_ref.as_str())
            })?;
            Ok(seed)
        }
        Err(error) => Err(anyhow::anyhow!(
            "loading service identity key {} failed: {error}",
            key_ref.as_str()
        )),
    }
}

fn store_or_verify_seed(
    key_store: &dyn KeyStore,
    key_ref: &DidCoreIdentityKeyRef,
    expected: &[u8; 32],
    allow_create: bool,
) -> anyhow::Result<()> {
    match key_store.load(key_ref.as_str()) {
        Ok(bytes) if bytes.as_slice() == expected => Ok(()),
        Ok(_) => anyhow::bail!(
            "service_identity_key_mismatch: retained key {} differs from the inception key",
            key_ref.as_str()
        ),
        Err(error) if error.is_not_found() && allow_create => key_store
            .store(key_ref.as_str(), expected)
            .map_err(|error| anyhow::anyhow!("persisting {} failed: {error}", key_ref.as_str())),
        Err(error) => Err(anyhow::anyhow!(
            "loading service identity key {} failed: {error}",
            key_ref.as_str()
        )),
    }
}

fn key_bytes_to_seed(key_ref: &DidCoreIdentityKeyRef, bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes.len() != 32 {
        anyhow::bail!(
            "service identity key {} must be 32 bytes, got {}",
            key_ref.as_str(),
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

fn waiting_provider(registration_key: ServiceRegistrationKey) -> DidCoreIdentityState {
    DidCoreIdentityState::WaitingProvider {
        registration_key,
        retry_at: service_identity_retry_at(),
    }
}

fn service_identity_retry_at() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(5)
}

fn provider_unavailable(error: &arkret_http_client::Error) -> bool {
    matches!(
        error,
        arkret_http_client::Error::Http(_)
            | arkret_http_client::Error::Api {
                status: 429 | 502 | 503 | 504,
                ..
            }
    )
}

async fn ensure_identity_bundle(
    persistence: &PersistenceHandle,
    backend: Option<&dyn IdentityBundleBackend>,
    stored: &StoredDidCoreIdentity,
) -> anyhow::Result<()> {
    let Some(backend) = backend else {
        return Ok(());
    };
    if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
        anyhow::bail!("service identity bundle backend is unavailable: {error}");
    }
    let history = persistence
        .webvh_history(stored.identity.did.as_str())
        .await
        .map_err(|error| anyhow::anyhow!("reading service WebVH history failed: {error}"))?;
    let mut prior_receipts = persistence
        .service_registration_receipts(&stored.identity.service_id)
        .await?;
    let mut visited = Vec::new();
    for entry in history.iter().rev() {
        let document: arkret_models_identity::service_identity::ServiceDidDocument =
            serde_json::from_value(entry.operation["state"].clone())?;
        let endpoint = document
            .service
            .iter()
            .find(|e| e.service_kind == *stored.identity.registration_key.service_kind())
            .ok_or_else(|| anyhow::anyhow!("service history omits its registered endpoint"))?;
        let key = ServiceRegistrationKey::new(
            *stored.identity.registration_key.service_kind(),
            endpoint.service_endpoint.clone(),
        )?;
        if visited.contains(&key) {
            continue;
        }
        visited.push(key.clone());
        if let Some(bundle) = backend.load(&key)? {
            bundle.validate()?;
            validate_bundle_receipt_signatures(&bundle)?;
            if bundle.identity.identity.service_id != stored.identity.service_id {
                anyhow::bail!("prior registration bundle belongs to another service")
            }
            prior_receipts.extend(bundle.receipt_chains);
        }
    }
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut receipts = Vec::with_capacity(history.len());
    for entry in &history {
        let version_id = entry
            .operation
            .get("versionId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("service WebVH entry has no versionId"))?;
        if stored.registration_receipt.version_id == version_id {
            receipts.push(stored.registration_receipt.clone());
            continue;
        }
        // A historical receipt was signed by the assertion key authorized at
        // that entry. Re-signing it with the current key would invent evidence
        // for a past version, especially after assertion signer rotation.
        let receipt = prior_receipts
            .iter()
            .find(|receipt| receipt.version_id == version_id)
            .ok_or_else(|| anyhow::anyhow!(
                "service_identity_historical_receipt_missing: no retained receipt for WebVH version {version_id}"
            ))?;
        receipts.push(receipt.clone());
    }
    let bundle = DidCoreIdentityBundle {
        schema: DidCoreIdentityBundle::SCHEMA.to_owned(),
        identity: stored.clone(),
        webvh_history_entries: history.into_iter().map(|entry| entry.operation).collect(),
        receipt_chains: receipts,
        exported_at: now,
    };
    bundle.validate().map_err(|error| {
        anyhow::anyhow!("refusing to store an invalid identity bundle: {error}")
    })?;
    backend
        .store(&bundle)
        .map_err(|error| anyhow::anyhow!("persisting service identity bundle failed: {error}"))
}

fn load_identity_bundle(
    backend: Option<&dyn IdentityBundleBackend>,
    key: &ServiceRegistrationKey,
) -> anyhow::Result<Option<DidCoreIdentityBundle>> {
    let Some(backend) = backend else {
        return Ok(None);
    };
    if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
        anyhow::bail!("service identity bundle backend is unavailable: {error}");
    }
    backend
        .load(key)
        .map_err(|error| anyhow::anyhow!("loading service identity bundle failed: {error}"))
}

async fn restore_identity_bundle(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    registration_key: ServiceRegistrationKey,
    bundle: DidCoreIdentityBundle,
) -> anyhow::Result<StoredDidCoreIdentity> {
    bundle
        .validate()
        .map_err(|error| anyhow::anyhow!("service identity bundle is invalid: {error}"))?;
    if bundle.identity.identity.registration_key != registration_key {
        anyhow::bail!("service identity bundle registration key does not match this deployment");
    }
    validate_identity_bundle_history(&bundle)?;
    validate_bundle_receipt_signatures(&bundle)?;
    validate_bundle_key_custody(config, key_store, &bundle.identity)?;
    let inception_value = bundle
        .webvh_history_entries
        .first()
        .expect("validated non-empty")
        .clone();
    let inception: arkret_models_identity::service_identity::ServiceWebvhInceptionOperation =
        serde_json::from_value(inception_value.clone())
            .map_err(|error| anyhow::anyhow!("identity bundle inception is malformed: {error}"))?;
    let request = ServiceRegistrationEnsureRequestBody::new(
        bundle.receipt_chains[0].registration_key.clone(),
        inception.clone(),
        uuid::Uuid::now_v7().to_string(),
        None,
    )
    .map_err(|error| anyhow::anyhow!("identity bundle inception is invalid: {error}"))?;
    validate_signed_service_inception(&request)?;
    let inception_receipt = bundle
        .receipt_chains
        .iter()
        .find(|receipt| receipt.version_id == inception.version_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("identity bundle has no inception receipt"))?;
    let outcome = ServiceRegistrationOutcome {
        did_document: inception.state.clone(),
        registration_receipt: inception_receipt,
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(|error| anyhow::anyhow!("identity bundle outcome is invalid: {error}"))?;
    let now = chrono::Utc::now();
    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let document = WebvhDocumentRecord {
        did: inception.state.id.to_string(),
        did_document: serde_json::to_value(&outcome.did_document)?,
        key_log_head: Some(event_digest.clone()),
        seq: 1,
        method_evidence: json!({
            "mode": "service_identity_bundle_restore",
            "operation": arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1,
            "service_kind": registration_key.service_kind().as_str(),
            "public_base_url": registration_key.public_base_url().as_str(),
            "version_id": outcome.version_id(),
        }),
        fetched_at: now,
        expires_at: now,
        updated_at: now,
    };
    let event = WebvhLogRecord {
        event_digest,
        did: inception.state.id.to_string(),
        seq: 1,
        operation: inception_value,
        created_at: now,
    };
    match persistence
        .commit_service_registration(request.registration_key()?, outcome, document, event)
        .await
        .map_err(|error| anyhow::anyhow!("restoring service registration failed: {error}"))?
    {
        ServiceRegistrationCommitOutcome::Created(_)
        | ServiceRegistrationCommitOutcome::Existing(_) => {}
        ServiceRegistrationCommitOutcome::Conflict => {
            anyhow::bail!("service_identity_conflict: identity bundle conflicts with local state")
        }
    }

    let mut previous_digest = event_digest_for_restore(&bundle.webvh_history_entries[0])?;
    for (index, operation) in bundle.webvh_history_entries.iter().enumerate().skip(1) {
        let seq = u64::try_from(index + 1)
            .map_err(|_| anyhow::anyhow!("identity bundle WebVH sequence overflow"))?;
        let event_digest = event_digest_for_restore(operation)?;
        let version_id = operation
            .get("versionId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("identity bundle WebVH entry has no versionId"))?;
        let state = operation.get("state").cloned().ok_or_else(|| {
            anyhow::anyhow!("identity bundle WebVH entry has no DID document state")
        })?;
        let created_at = operation
            .get("versionTime")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("identity bundle WebVH entry has no versionTime"))?
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|error| anyhow::anyhow!("identity bundle versionTime is invalid: {error}"))?;
        let entry_did = state
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("bundle entry omits DID"))?
            .to_owned();
        let document = WebvhDocumentRecord {
            did: entry_did.clone(),
            did_document: state,
            key_log_head: Some(event_digest.clone()),
            seq,
            method_evidence: json!({
                "mode": "service_identity_bundle_restore",
                "version_id": version_id,
            }),
            fetched_at: created_at,
            expires_at: created_at,
            updated_at: created_at,
        };
        let event = WebvhLogRecord {
            event_digest: event_digest.clone(),
            did: entry_did.clone(),
            seq,
            operation: operation.clone(),
            created_at,
        };
        match persistence
            .commit_webvh_log_operation(Some(previous_digest), document, event, None)
            .await
            .map_err(|error| anyhow::anyhow!("replaying service WebVH history failed: {error}"))?
        {
            coland_storage::WebvhLogCommitOutcome::Accepted
            | coland_storage::WebvhLogCommitOutcome::Duplicate => {}
            coland_storage::WebvhLogCommitOutcome::Conflict => anyhow::bail!(
                "service_identity_conflict: identity bundle history conflicts with local state"
            ),
        }
        previous_digest = event_digest;
    }
    validate_stored_service_identity(persistence, config, key_store, &bundle.identity).await?;
    persistence
        .retain_service_registration_receipts(bundle.receipt_chains.clone())
        .await?;
    persist_stored_identity(persistence, bundle.identity).await
}

fn event_digest_for_restore(operation: &Value) -> anyhow::Result<String> {
    arkret_canonical::canonical_sha256(operation)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH digest failed: {error}"))
}

fn validate_identity_bundle_history(bundle: &DidCoreIdentityBundle) -> anyhow::Result<()> {
    let log: Vec<WebvhLogEntry> = bundle
        .webvh_history_entries
        .iter()
        .cloned()
        .map(WebvhLogEntry::new)
        .collect();
    for entry in &log {
        verify_webvh_log_proof(&entry.payload)
            .map_err(|error| anyhow::anyhow!("identity bundle WebVH proof is invalid: {error}"))?;
    }
    validate_log_chain(&log)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH chain is invalid: {error}"))?;
    verify_scid_against_did(bundle.identity.identity.did.as_str(), &log[0])
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH SCID is invalid: {error}"))?;
    verify_log_subject(bundle.identity.identity.did.as_str(), &log)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH subject is invalid: {error}"))?;
    validate_witness_policy_for_log(&log).map_err(|error| {
        anyhow::anyhow!("identity bundle WebVH witness policy is invalid: {error}")
    })?;
    validate_rotation_authorization_for_log(&log).map_err(|error| {
        anyhow::anyhow!("identity bundle WebVH rotation authorization is invalid: {error}")
    })
}

fn validate_bundle_key_custody(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: &StoredDidCoreIdentity,
) -> anyhow::Result<()> {
    let signing_seed =
        load_signing_seed(config, key_store, &stored.identity.active_signing_key_ref)?;
    validate_service_signing_binding(stored, &signing_seed)?;
    validate_registration_receipt_signature(stored)?;
    let key_store = required_key_store(key_store)?;
    load_seed(key_store, &stored.identity.control_key_ref)?;
    load_seed(
        key_store,
        &next_control_key_ref(&stored.identity.control_key_ref)?,
    )?;
    let after_next =
        next_control_key_ref(&next_control_key_ref(&stored.identity.control_key_ref)?)?;
    if key_store.load(after_next.as_str()).is_ok() {
        anyhow::bail!(
            "service_identity_bundle_stale: bundle predates the durable accepted control-key floor"
        );
    }
    Ok(())
}

fn validate_bundle_receipt_signatures(bundle: &DidCoreIdentityBundle) -> anyhow::Result<()> {
    for (entry, receipt) in bundle
        .webvh_history_entries
        .iter()
        .zip(&bundle.receipt_chains)
    {
        if receipt.provider_id != bundle.identity.identity.service_id
            || receipt.proof.verification_method.as_str()
                != format!(
                    "{}#notary-key",
                    entry
                        .pointer("/state/id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("bundle entry omits DID"))?
                )
        {
            anyhow::bail!("identity bundle receipt was issued by an unexpected Provider method");
        }
        let document = entry
            .get("state")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("identity bundle WebVH entry has no state"))?;
        let document = serde_json::from_value(document).map_err(|error| {
            anyhow::anyhow!("identity bundle WebVH entry has an invalid service document: {error}")
        })?;
        arkret_signatures::service_identity::verify_registration_receipt_proof(receipt, &document)
            .map_err(|error| {
                anyhow::anyhow!("identity bundle receipt signature failed: {error}")
            })?;
    }
    Ok(())
}

fn validate_signed_service_inception(
    request: &ServiceRegistrationEnsureRequestBody,
) -> anyhow::Result<()> {
    let operation = serde_json::to_value(&request.inception_operation)?;
    verify_webvh_log_proof(&operation)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH proof is invalid: {error}"))?;
    let log = [WebvhLogEntry::new(operation)];
    validate_log_chain(&log)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH chain is invalid: {error}"))?;
    let did = request.inception_operation.state.id.as_str();
    verify_scid_against_did(did, &log[0])
        .map_err(|error| anyhow::anyhow!("identity bundle SCID is invalid: {error}"))?;
    verify_log_subject(did, &log)
        .map_err(|error| anyhow::anyhow!("identity bundle subject is invalid: {error}"))?;
    validate_witness_policy_for_log(&log)
        .map_err(|error| anyhow::anyhow!("identity bundle witness policy is invalid: {error}"))?;
    validate_rotation_authorization_for_log(&log).map_err(|error| {
        anyhow::anyhow!("identity bundle rotation authorization is invalid: {error}")
    })
}

fn validate_registration_receipt_signature(stored: &StoredDidCoreIdentity) -> anyhow::Result<()> {
    let receipt = &stored.registration_receipt;
    if receipt.provider_id != stored.identity.service_id {
        anyhow::bail!("self-hosted identity bundle receipt was issued by a different service DID");
    }
    let expected_method = format!("{}#notary-key", stored.identity.did);
    if receipt.proof.verification_method.as_str() != expected_method {
        anyhow::bail!("identity bundle receipt uses an unexpected verification method");
    }
    arkret_signatures::service_identity::verify_registration_receipt_proof(
        receipt,
        &stored.did_document,
    )
    .map_err(|error| anyhow::anyhow!("identity bundle receipt signature failed: {error}"))
}

fn registration_key(config: &AppConfig) -> anyhow::Result<ServiceRegistrationKey> {
    let public_base_url = CanonicalServiceUrl::canonicalize(&config.public_base_url)
        .map_err(|error| anyhow::anyhow!("invalid COLAND_PUBLIC_BASE_URL: {error}"))?;
    ServiceRegistrationKey::new(ServiceKind::Station, public_base_url)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

async fn persist_stored_identity(
    persistence: &PersistenceHandle,
    identity: StoredDidCoreIdentity,
) -> anyhow::Result<StoredDidCoreIdentity> {
    identity
        .validate()
        .map_err(|error| anyhow::anyhow!("service identity is invalid: {error}"))?;
    persistence
        .store_service_identity(identity.clone())
        .await
        .map_err(|error| anyhow::anyhow!("persisting service identity failed: {error}"))?;
    Ok(identity)
}

fn stored_identity_from_outcome(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    registration_key: ServiceRegistrationKey,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<StoredDidCoreIdentity> {
    outcome
        .validate_for(&registration_key)
        .map_err(|error| anyhow::anyhow!("stored service registration is invalid: {error}"))?;
    let signing_key_ref = signing_key_ref(config, outcome.did(), key_store)?;
    let generation = webvh_version_number(outcome.version_id())?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let identity = LocalDidCoreIdentity {
        service_id: outcome.service_id().clone(),
        did: outcome.did().clone(),
        registration_key,
        provider: None,
        signing_key_refs: vec![signing_key_ref.clone()],
        active_signing_key_ref: signing_key_ref,
        control_key_ref: control_key_ref(&outcome.did_document.id, generation)?,
        version_id: outcome.version_id().to_owned(),
        last_verified_at: now,
    };
    let stored = StoredDidCoreIdentity {
        identity,
        did_document: outcome.did_document,
        registration_receipt: outcome.registration_receipt,
        stored_at: now,
    };
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("restored service identity is invalid: {error}"))?;
    Ok(stored)
}

async fn validate_stored_service_identity(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: &StoredDidCoreIdentity,
) -> anyhow::Result<()> {
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("persisted service identity is invalid: {error}"))?;
    if stored.identity.did.method() != "webvh" {
        anyhow::bail!(
            "persisted service identity {} is not did:webvh",
            stored.identity.did
        );
    }

    let signing_seed =
        load_signing_seed(config, key_store, &stored.identity.active_signing_key_ref)?;
    validate_service_signing_binding(stored, &signing_seed)?;

    // The Account Authority key is deliberately not checked here.
    // `ensure_account_authority_authorization` owns that comparison and can
    // publish a successor entry when the operator explicitly approves a key
    // rotation. A newly discovered mismatch fails closed instead.

    let log = persistence
        .webvh_history(stored.identity.did.as_str())
        .await
        .map_err(|error| {
            anyhow::anyhow!("reading persisted service WebVH history failed: {error}")
        })?;
    let head = log.last().ok_or_else(|| {
        anyhow::anyhow!("persisted service identity has no authoritative WebVH history")
    })?;
    validate_persisted_webvh_history(stored.identity.did.as_str(), &log)?;
    let head_version_id = head
        .operation
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no versionId"))?;
    if head_version_id != stored.identity.version_id {
        anyhow::bail!(
            "persisted service identity version {} does not match WebVH head {head_version_id}",
            stored.identity.version_id
        );
    }
    validate_control_key_binding(key_store, &stored.identity.control_key_ref, &head.operation)
}

fn validate_persisted_webvh_history(did: &str, history: &[WebvhLogRecord]) -> anyhow::Result<()> {
    let log: Vec<WebvhLogEntry> = history
        .iter()
        .map(|record| WebvhLogEntry::new(record.operation.clone()))
        .collect();
    for entry in &log {
        verify_webvh_log_proof(&entry.payload).map_err(|error| {
            anyhow::anyhow!("persisted service WebVH proof is invalid: {error}")
        })?;
    }
    validate_log_chain(&log)
        .map_err(|error| anyhow::anyhow!("persisted service WebVH chain is invalid: {error}"))?;
    verify_scid_against_did(did, &log[0])
        .map_err(|error| anyhow::anyhow!("persisted service WebVH SCID is invalid: {error}"))?;
    verify_log_subject(did, &log)
        .map_err(|error| anyhow::anyhow!("persisted service WebVH subject is invalid: {error}"))?;
    validate_witness_policy_for_log(&log).map_err(|error| {
        anyhow::anyhow!("persisted service WebVH witness policy is invalid: {error}")
    })?;
    validate_rotation_authorization_for_log(&log).map_err(|error| {
        anyhow::anyhow!("persisted service WebVH rotation authorization is invalid: {error}")
    })
}

fn validate_service_signing_binding(
    stored: &StoredDidCoreIdentity,
    signing_seed: &[u8; 32],
) -> anyhow::Result<()> {
    let expected = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(signing_seed)
            .verifying_key()
            .as_bytes(),
    );
    let published = stored.did_document.signing_key_multibase().ok_or_else(|| {
        anyhow::anyhow!("service DID document has no active assertion signing key")
    })?;
    if published != expected {
        anyhow::bail!(
            "service_identity_key_mismatch: DID assertion key does not match active signing KeyRef {}",
            stored.identity.active_signing_key_ref.as_str()
        );
    }
    Ok(())
}

fn validate_control_key_binding(
    key_store: Option<&dyn KeyStore>,
    current_ref: &DidCoreIdentityKeyRef,
    operation: &Value,
) -> anyhow::Result<()> {
    let key_store = required_key_store(key_store)?;
    let current_seed = load_seed(key_store, current_ref)?;
    let next_ref = next_control_key_ref(current_ref)?;
    let next_seed = load_seed(key_store, &next_ref)?;
    let current_public = seed_public_multibase(&current_seed);
    let next_public = seed_public_multibase(&next_seed);
    let next_hash = arkret_signatures::webvh::webvh_next_key_hash(&next_public)
        .map_err(|error| anyhow::anyhow!("deriving next WebVH control-key hash failed: {error}"))?;
    let update_keys = operation
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no updateKeys"))?;
    let next_key_hashes = operation
        .pointer("/parameters/nextKeyHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no nextKeyHashes"))?;
    if update_keys.as_slice() != [Value::String(current_public)]
        || next_key_hashes.as_slice() != [Value::String(next_hash)]
    {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted WebVH control KeyRefs do not match the authoritative log head"
        );
    }
    Ok(())
}

async fn reconcile_pending_local_rotation(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    mut stored: StoredDidCoreIdentity,
) -> anyhow::Result<StoredDidCoreIdentity> {
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("persisted service identity is invalid: {error}"))?;
    let signing_seed =
        load_signing_seed(config, key_store, &stored.identity.active_signing_key_ref)?;
    validate_service_signing_binding(&stored, &signing_seed)?;
    let history = persistence
        .webvh_history(stored.identity.did.as_str())
        .await
        .map_err(|error| {
            anyhow::anyhow!("reading persisted service WebVH history failed: {error}")
        })?;
    let head = history.last().ok_or_else(|| {
        anyhow::anyhow!("persisted service identity has no authoritative WebVH history")
    })?;
    validate_persisted_webvh_history(stored.identity.did.as_str(), &history)?;
    let head_version = head
        .operation
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no versionId"))?;
    if head_version == stored.identity.version_id {
        // The database cut may have committed before the canonical next-key
        // ref was promoted. Only the candidate matching the committed head
        // may become the next generation's canonical key.
        let next_ref = next_control_key_ref(&stored.identity.control_key_ref)?;
        promote_matching_control_candidate(
            required_key_store(key_store)?,
            &next_ref,
            &head.operation,
        )?;
        return Ok(stored);
    }

    let stored_version = webvh_version_number(&stored.identity.version_id)?;
    let head_number = webvh_version_number(head_version)?;
    if stored_version.checked_add(1) != Some(head_number)
        || history
            .get(history.len().saturating_sub(2))
            .and_then(|entry| entry.operation.get("versionId"))
            .and_then(Value::as_str)
            != Some(stored.identity.version_id.as_str())
    {
        anyhow::bail!(
            "persisted service identity version {} does not match WebVH head {head_version}",
            stored.identity.version_id
        );
    }

    let key_store = required_key_store(key_store)?;
    let previous = &history[history.len() - 2].operation;
    validate_control_key_binding(Some(key_store), &stored.identity.control_key_ref, previous)?;
    let active_control_ref = next_control_key_ref(&stored.identity.control_key_ref)?;
    let active_seed = load_seed(key_store, &active_control_ref)?;
    let active_public = seed_public_multibase(&active_seed);
    if head
        .operation
        .pointer("/parameters/updateKeys/0")
        .and_then(Value::as_str)
        != Some(active_public.as_str())
    {
        anyhow::bail!(
            "service_identity_key_mismatch: retained control key does not match the pending WebVH head"
        );
    }
    let following_control_ref = next_control_key_ref(&active_control_ref)?;
    promote_matching_control_candidate(key_store, &following_control_ref, &head.operation)?;

    let state = head
        .operation
        .get("state")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no DID document state"))?;
    let now = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect("canonical RFC3339 timestamp parses");
    stored.registration_receipt = reissue_registration_receipt(
        &stored,
        head_version,
        &head.event_digest,
        &active_public,
        &signing_seed,
        now,
    )?;
    stored.identity.control_key_ref = active_control_ref;
    stored.identity.version_id = head_version.to_owned();
    stored.identity.last_verified_at = now;
    stored.did_document = serde_json::from_value(state).map_err(|error| {
        anyhow::anyhow!("the recovered Station DID document is invalid: {error}")
    })?;
    stored.stored_at = now;
    tracing::warn!(
        did = %stored.identity.did,
        version_id = %stored.identity.version_id,
        "recovered a committed Station DID rotation after an interrupted identity update"
    );
    persist_stored_identity(persistence, stored).await
}

fn candidate_control_key_ref(
    canonical_ref: &DidCoreIdentityKeyRef,
    seed: &[u8; 32],
) -> anyhow::Result<DidCoreIdentityKeyRef> {
    let digest = Sha256::digest(seed_public_multibase(seed).as_bytes());
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    DidCoreIdentityKeyRef::new(format!("{}:candidate:{suffix}", canonical_ref.as_str()))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn promote_matching_control_candidate(
    key_store: &dyn KeyStore,
    canonical_ref: &DidCoreIdentityKeyRef,
    head: &Value,
) -> anyhow::Result<()> {
    let expected_hash = head
        .pointer("/parameters/nextKeyHashes/0")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no nextKeyHashes"))?;
    if let Ok(seed) = load_seed(key_store, canonical_ref)
        && control_seed_hash(&seed)? == expected_hash
    {
        return Ok(());
    }
    let prefix = format!("{}:candidate:", canonical_ref.as_str());
    for candidate_id in key_store
        .list()
        .map_err(|error| anyhow::anyhow!("listing WebVH control-key candidates failed: {error}"))?
        .into_iter()
        .filter(|id| id.starts_with(&prefix))
    {
        let candidate_ref = DidCoreIdentityKeyRef::new(candidate_id)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let seed = load_seed(key_store, &candidate_ref)?;
        if control_seed_hash(&seed)? == expected_hash {
            return key_store
                .store(canonical_ref.as_str(), &seed)
                .map_err(|error| {
                    anyhow::anyhow!("promoting the next WebVH control key failed: {error}")
                });
        }
    }
    anyhow::bail!(
        "service_identity_key_mismatch: no retained candidate matches the WebVH head's next-key commitment"
    )
}

fn control_seed_hash(seed: &[u8; 32]) -> anyhow::Result<String> {
    arkret_signatures::webvh::webvh_next_key_hash(&seed_public_multibase(seed))
        .map_err(|error| anyhow::anyhow!("deriving next WebVH control-key hash failed: {error}"))
}

fn next_webvh_version_time(head: &Value) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    let previous = head
        .get("versionTime")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no versionTime"))?
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|error| anyhow::anyhow!("service WebVH head versionTime is invalid: {error}"))?;
    let now = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect("canonical RFC3339 timestamp parses");
    Ok(if now <= previous {
        previous + chrono::Duration::seconds(1)
    } else {
        now
    })
}

async fn wait_for_service_webvh_version_time(
    version_time: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
    let deadline = tokio::time::Instant::now() + MAX_WAIT;
    loop {
        let wall_now = chrono::Utc::now();
        if wall_now >= version_time {
            return Ok(());
        }
        let remaining = (version_time - wall_now)
            .to_std()
            .map_err(|error| anyhow::anyhow!("invalid service WebVH versionTime wait: {error}"))?;
        if remaining > MAX_WAIT || tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "service WebVH versionTime is too far ahead of the local clock; refusing to activate the successor"
            );
        }
        tokio::time::sleep(
            remaining.min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }
}

/// JWK `kid` under which an Account Authority publishes its S2S signing key.
///
/// coauth mints this key as `coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID` and
/// serves its public half in the standard OIDC keyset, so this constant is the
/// cross-deployment contract between the two processes.
const ACCOUNT_AUTHORITY_JWK_KID: &str = "coauth-account-authority-v1";

/// The Account Authority signing key to authorize in this deployment's Station
/// DID document, as a `z...` multibase string.
///
/// Two sources, in order:
///
/// 1. `COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE`, used verbatim. An operator who wants to name
///    the exact key still can, and that pin keeps being enforced against the stored DID history on
///    every later boot.
/// 2. Otherwise the Account Authority's own published keyset, read on every startup from the
///    operator-configured `COLAND_ACCOUNT_AUTHORITY_URL`.
///
/// Reading from the service that owns the key removes a transcription step;
/// the URL is operator configuration and TLS authenticates it. Repeating that
/// read on every startup also proves that the Account Authority is online and
/// that its published key still agrees with this Station's durable DID.
///
/// A configured-but-unreachable Account Authority is fatal on every startup.
/// An explicit public-key pin remains an operator override and therefore does
/// not require discovery.
async fn account_authority_assertion_key(config: &AppConfig) -> anyhow::Result<Option<String>> {
    if let Some(pinned) = config.account_authority_public_key_multibase.as_deref() {
        return Ok(Some(pinned.to_owned()));
    }
    let Some(authority_url) = config.account_authority_url.as_deref() else {
        return Ok(None);
    };
    let issuer = url::Url::parse(authority_url)
        .map_err(|error| anyhow::anyhow!("COLAND_ACCOUNT_AUTHORITY_URL is not a URL: {error}"))?;
    // Plain GETs, deliberately not the typed Arkret client: these are the
    // Account Authority's standard OIDC discovery and keyset documents, not
    // Arkret operations, and the typed client rejects any path the operation
    // registry does not name.
    let unreachable = |what: &str, error: String| {
        anyhow::anyhow!(
            "reading the Account Authority {what} at {authority_url} failed: {error}. The \
             Account Authority is a required startup dependency, so Coland stops rather than \
             serving with unverified trust. Start the Account Authority first, or set \
             COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE."
        )
    };
    let fetch = async |url: url::Url, what: &str| -> anyhow::Result<serde_json::Value> {
        // Discovery establishes the initial trust key. Validate each exact URL
        // and certificate against the operator CA store; signing with a fetched
        // key cannot authenticate an otherwise untrusted discovery connection.
        let (url, client) = coland_http::security::validate_http_url_for_egress_with_pinned_client(
            url.as_str(),
            what,
            config.development_mode,
            std::time::Duration::from_secs(10),
        )
        .map_err(|error| unreachable(what, error))?;
        client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| unreachable(what, error.to_string()))?
            .json()
            .await
            .map_err(|error| unreachable(what, error.to_string()))
    };

    // The keyset path is the issuer's to publish, not ours to assume: coauth
    // serves it at `/oauth/keys.json`, another Account Authority may not.
    let discovery_url = issuer
        .join("/.well-known/openid-configuration")
        .map_err(|error| anyhow::anyhow!("Account Authority discovery URL is invalid: {error}"))?;
    let discovery = fetch(discovery_url, "discovery document").await?;
    let keyset_url = discovery
        .get("jwks_uri")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the Account Authority discovery document at {authority_url} publishes no jwks_uri"
            )
        })
        .and_then(|value| {
            url::Url::parse(value)
                .map_err(|error| anyhow::anyhow!("published jwks_uri is not a URL: {error}"))
        })?;
    // A discovery document that points the keyset somewhere else would move
    // the trust decision to a host the operator never named. The issuer origin
    // is what `COLAND_ACCOUNT_AUTHORITY_URL` authorizes, and it is where the
    // key has to come from.
    if keyset_url.origin() != issuer.origin() {
        anyhow::bail!(
            "the Account Authority at {authority_url} publishes its keyset on a different \
             origin ({keyset_url}); the signing key must come from the configured Authority"
        );
    }
    let keyset = fetch(keyset_url, "keyset").await?;
    let multibase = account_authority_key_from_keyset(&keyset).ok_or_else(|| {
        anyhow::anyhow!(
            "the Account Authority keyset at {authority_url} publishes no Ed25519 key with kid              `{ACCOUNT_AUTHORITY_JWK_KID}`"
        )
    })?;
    Ok(Some(multibase))
}

/// Pick the Account Authority Ed25519 key out of a JWKS document and re-encode
/// it the way a DID document verification method carries it.
///
/// Selection is by `kid` rather than by "the only Ed25519 key": a deployment
/// legitimately publishes several keys, and their order is not a contract.
fn account_authority_key_from_keyset(keyset: &serde_json::Value) -> Option<String> {
    use base64::Engine as _;

    let key = keyset.get("keys")?.as_array()?.iter().find(|key| {
        key.get("kid").and_then(serde_json::Value::as_str) == Some(ACCOUNT_AUTHORITY_JWK_KID)
            && key.get("kty").and_then(serde_json::Value::as_str) == Some("OKP")
            && key.get("crv").and_then(serde_json::Value::as_str) == Some("Ed25519")
    })?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key.get("x")?.as_str()?)
        .ok()?;
    let raw: [u8; 32] = raw.try_into().ok()?;
    Some(arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(&raw))
}

/// Bring the Station DID document in line with the deployment's Account
/// Authority, advancing the log when it is behind.
///
/// Two sources of the key are deliberately not equal in authority:
///
/// - `COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE` is the operator naming a key. It authorizes
///   both filling an absent method and replacing one that names a different key, because editing it
///   is a deliberate act.
/// - A key read from the Authority's published keyset only ever fills an *absent* method. Letting a
///   fetched value replace an authorized one would hand whoever answers at that URL the power to
///   re-point this Station's trust at itself.
///
/// A deployment with no Account Authority configured does no work. Otherwise
/// its key was resolved before durable identity handling, even when the stored
/// document is already correct.
async fn ensure_account_authority_authorization(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: StoredDidCoreIdentity,
    resolved_key: Option<&str>,
) -> anyhow::Result<StoredDidCoreIdentity> {
    if config.account_authority_url.is_none() {
        return Ok(stored);
    }
    let method_id = format!(
        "{}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}",
        stored.identity.did
    );
    let authorized = stored
        .did_document
        .verification_method
        .iter()
        .find(|method| method.id == method_id)
        .map(|method| method.public_key_multibase.clone());

    let Some(key) = resolved_key else {
        return Ok(stored);
    };
    if authorized.as_deref() == Some(key) {
        return Ok(stored);
    }
    if authorized.is_some() && config.account_authority_public_key_multibase.is_none() {
        anyhow::bail!(
            "Account Authority published key does not match the key authorized by this Station; \
             refusing automatic replacement. Set \
             COLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE explicitly to approve a key rotation"
        );
    }
    authorize_account_authority_key(persistence, config, key_store, stored, key).await
}

/// Re-issue this deployment's own registration receipt over a successor entry.
///
/// A receipt binds `{registration_key, service_id, did, version_id,
/// log_head_digest, control_key_digest}` and is signed by the Provider. A
/// self-provisioned Station is its own Provider, so advancing its log means
/// re-issuing rather than inheriting a statement about a version that is no
/// longer the head.
fn reissue_registration_receipt(
    stored: &StoredDidCoreIdentity,
    version_id: &str,
    log_head_digest: &str,
    control_key_multibase: &str,
    signing_seed: &[u8; 32],
    issued_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<ServiceRegistrationReceipt> {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
    let mut receipt = stored.registration_receipt.clone();
    receipt.version_id = version_id.to_owned();
    receipt.log_head_digest = log_head_digest.to_owned();
    receipt.control_key_digest = arkret_canonical::sha256_digest(control_key_multibase.as_bytes());
    receipt.issued_at = issued_at;
    receipt.proof.created_at = issued_at;
    receipt.registration_receipt_id = receipt.expected_registration_receipt_id()?;
    receipt.proof.payload_digest = receipt.expected_payload_digest()?;
    receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
        &receipt,
        &SigningKey::from_bytes(signing_seed),
    )?;
    receipt.validate_for(
        &stored.identity.registration_key,
        &stored.identity.service_id,
        &stored.identity.did,
    )?;
    Ok(receipt)
}

/// Authorize the Account Authority signing key in this deployment's own Station
/// DID document, after the DID was already minted.
///
/// Minting is a one-way door: `#account-authority` used to be reachable only as
/// an inception assertion key, so a Station that minted before its Account
/// Authority existed could never verify a single S2S call from it, and the only
/// repair was re-provisioning the identity - which changes the Station DID and
/// orphans every credential and derived id already issued under it.
///
/// `identity-did.md` §3.7 never required that. I-4 defines the pre-rotation
/// discipline for "inception 与每次 rotation", and the Provider paragraph makes
/// rotation, endpoint update and registration-key migration all signed by
/// update keys the service itself holds. So the DID advances by one successor
/// entry, signed by the update key the previous entry pre-committed, publishing
/// a document that differs only by this method.
///
/// The new pre-commitment is persisted under a content-addressed candidate
/// reference before publication, then promoted to the canonical generation
/// reference only after the database cut succeeds. This keeps concurrent boots
/// from overwriting the winning key while retaining enough material to recover
/// if the process stops between the cut and key promotion.
async fn authorize_account_authority_key(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: StoredDidCoreIdentity,
    public_key_multibase: &str,
) -> anyhow::Result<StoredDidCoreIdentity> {
    let did = stored.identity.did.clone();
    let method_id = format!("{did}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}");
    let entries = persistence
        .webvh_history(did.as_str())
        .await
        .map_err(|error| anyhow::anyhow!("reading the Station WebVH history failed: {error}"))?;
    let head = entries.last().ok_or_else(|| {
        anyhow::anyhow!("the stored Station identity has no authoritative WebVH history")
    })?;
    let mut state =
        head.operation.get("state").cloned().ok_or_else(|| {
            anyhow::anyhow!("the Station WebVH head carries no DID document state")
        })?;

    let already_authorized = state
        .get("verificationMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods.iter().any(|method| {
                method["id"] == json!(method_id)
                    && method["publicKeyMultibase"] == json!(public_key_multibase)
            })
        })
        && state
            .get("assertionMethod")
            .and_then(Value::as_array)
            .is_some_and(|methods| methods.contains(&json!(method_id)));
    if already_authorized {
        return Ok(stored);
    }

    // The successor differs from the head document by this method alone. A
    // replacement (the Account Authority rotated its key) drops the superseded
    // entry rather than accumulating two methods under one id.
    let methods = state
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("the Station DID document has no verificationMethod"))?;
    methods.retain(|method| method["id"] != json!(method_id));
    methods.push(json!({
        "id": method_id,
        "type": "Multikey",
        "controller": did.as_str(),
        "publicKeyMultibase": public_key_multibase,
    }));
    let assertions = state
        .get_mut("assertionMethod")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("the Station DID document has no assertionMethod"))?;
    if !assertions.contains(&json!(method_id)) {
        assertions.push(json!(method_id));
    }

    publish_service_document_successor(persistence, config, key_store, stored, state, None).await
}

async fn ensure_service_endpoint(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: StoredDidCoreIdentity,
) -> anyhow::Result<StoredDidCoreIdentity> {
    let desired = CanonicalServiceUrl::canonicalize(&config.public_base_url)?;
    desired.require_https()?;
    let mut document = serde_json::to_value(&stored.did_document)?;
    let services = document
        .get_mut("service")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("service DID omits endpoints"))?;
    let mut entries = services
        .iter_mut()
        .filter(|e| e["type"] == "ArkretService" && e["serviceKind"] == "station");
    let entry = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("service DID omits Station endpoint"))?;
    if entries.next().is_some() {
        anyhow::bail!("ambiguous Station DID endpoints");
    }
    if entry["serviceEndpoint"] == desired.as_str() {
        return Ok(stored);
    }
    entry["serviceEndpoint"] = Value::String(desired.to_string());
    publish_service_document_successor(persistence, config, key_store, stored, document, None).await
}

/// An explicit signing seed is the operator's desired assertion key. The
/// current key remains in KeyStore under its old ref, while the new seed is
/// durably staged under a content-addressed ref before publication.
async fn ensure_service_assertion_signer(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: StoredDidCoreIdentity,
) -> anyhow::Result<StoredDidCoreIdentity> {
    let Some(desired_seed) = config.notary_signing_key_seed else {
        return Ok(stored);
    };
    let current_seed =
        load_signing_seed(config, key_store, &stored.identity.active_signing_key_ref)?;
    if current_seed == desired_seed {
        return Ok(stored);
    }
    let key_store = required_key_store(key_store)?;
    let new_ref = retained_signing_key_ref(&stored.identity.did, &desired_seed)?;
    key_store
        .store(new_ref.as_str(), &desired_seed)
        .map_err(|error| {
            anyhow::anyhow!("staging the next service assertion key failed: {error}")
        })?;
    let mut state = serde_json::to_value(&stored.did_document)?;
    let old_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&current_seed)
            .verifying_key()
            .as_bytes(),
    );
    let new_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&desired_seed)
            .verifying_key()
            .as_bytes(),
    );
    // The runtime uses one seed for both service receipts and federation
    // fanout. Both published assertion methods must move in this successor.
    for fragment in ["notary-key", "federation-fanout-key"] {
        let method_id = format!("{}#{fragment}", stored.identity.did);
        if !state["assertionMethod"]
            .as_array()
            .is_some_and(|methods| methods.contains(&json!(method_id)))
        {
            anyhow::bail!(
                "service DID document does not authorize its {fragment} assertion method"
            );
        }
        let method = state
            .get_mut("verificationMethod")
            .and_then(Value::as_array_mut)
            .and_then(|methods| methods.iter_mut().find(|method| method["id"] == method_id))
            .ok_or_else(|| anyhow::anyhow!("service DID document omits its {fragment} method"))?;
        if method["publicKeyMultibase"] != old_public {
            anyhow::bail!(
                "service DID {fragment} method does not match the retained active signing key"
            );
        }
        method["publicKeyMultibase"] = Value::String(new_public.clone());
    }
    publish_service_document_successor(
        persistence,
        config,
        Some(key_store),
        stored,
        state,
        Some((&new_ref, &desired_seed)),
    )
    .await
}

async fn publish_service_document_successor(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: StoredDidCoreIdentity,
    state: Value,
    signer_successor: Option<(&DidCoreIdentityKeyRef, &[u8; 32])>,
) -> anyhow::Result<StoredDidCoreIdentity> {
    publish_service_document_successor_impl(
        persistence,
        config,
        key_store,
        stored,
        state,
        signer_successor,
        None,
    )
    .await
}

async fn publish_service_document_successor_impl(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: StoredDidCoreIdentity,
    state: Value,
    signer_successor: Option<(&DidCoreIdentityKeyRef, &[u8; 32])>,
    registration_successor: Option<ServiceRegistrationKey>,
) -> anyhow::Result<StoredDidCoreIdentity> {
    let predecessor_did = stored.identity.did.clone();
    let did: Did = state
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("service successor omits DID"))?
        .parse()?;
    let entries = persistence.webvh_history(predecessor_did.as_str()).await?;
    let head = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("service DID has no native history"))?;
    let key_store = required_key_store(key_store)?;
    // The head pre-committed the next generation, so that is the only key
    // allowed to sign this successor.
    let signing_control_ref = next_control_key_ref(&stored.identity.control_key_ref)?;
    let signing_seed = load_seed(key_store, &signing_control_ref)?;
    let following_control_ref = next_control_key_ref(&signing_control_ref)?;
    let mut following_seed = [0u8; 32];
    coland_http::state::getrandom_seed(&mut following_seed);
    let following_candidate_ref =
        candidate_control_key_ref(&following_control_ref, &following_seed)?;
    key_store
        .store(following_candidate_ref.as_str(), &following_seed)
        .map_err(|error| {
            anyhow::anyhow!("persisting the next WebVH control-key candidate failed: {error}")
        })?;
    let following_public_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&following_seed)
            .verifying_key()
            .to_bytes(),
    );

    let previous_entries: Vec<Value> = entries
        .iter()
        .map(|entry| entry.operation.clone())
        .collect();
    let version_time = next_webvh_version_time(&head.operation)?;
    let (log_entry, version_id, current_update_public_key_multibase) = if did == predecessor_did {
        let rotation = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: did.as_str(),
                previous_entries: &previous_entries,
                state: &state,
                current_update_seed: &signing_seed,
                next_update_public_key_multibase: &following_public_key,
                version_time,
            },
        )?;
        (
            rotation.log_entry,
            rotation.version_id,
            rotation.current_update_public_key_multibase,
        )
    } else {
        let relocation = arkret_signatures::webvh::prepare_webvh_relocation(
            &arkret_signatures::webvh::WebvhRelocationInput {
                current_did: predecessor_did.as_str(),
                target_did: did.as_str(),
                previous_entries: &previous_entries,
                state: &state,
                current_update_seed: &signing_seed,
                next_update_public_key_multibase: &following_public_key,
                version_time,
            },
        )?;
        (
            relocation.log_entry,
            relocation.version_id,
            relocation.current_update_public_key_multibase,
        )
    };

    // Re-validate the extended chain with the same checks this deployment
    // applies to a successor submitted by anyone else. A locally built entry
    // gets no shortcut.
    let candidate: Vec<WebvhLogEntry> = previous_entries
        .iter()
        .cloned()
        .chain(std::iter::once(log_entry.clone()))
        .map(WebvhLogEntry::new)
        .collect();
    verify_webvh_log_proof(&log_entry)
        .map_err(|message| anyhow::anyhow!("Station DID successor proof is invalid: {message}"))?;
    validate_log_chain(&candidate)?;
    verify_log_subject(did.as_str(), &candidate)?;
    validate_witness_policy_for_log(&candidate)?;
    validate_rotation_authorization_for_log(&candidate)?;

    let event_digest = arkret_canonical::canonical_sha256(&log_entry)
        .map_err(|error| anyhow::anyhow!("Station DID successor digest failed: {error}"))?;
    let seq = u64::try_from(entries.len())
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("Station WebVH sequence overflow"))?;
    // Historical verifiers select the assertion method at the evidence's real
    // signing instant. A same-second successor may have a versionTime one
    // second ahead of the wall clock; wait before signing its receipt or
    // committing the new active signer, rather than backdating evidence.
    wait_for_service_webvh_version_time(version_time).await?;
    let now = chrono::Utc::now();
    let document = WebvhDocumentRecord {
        did: did.to_string(),
        did_document: state.clone(),
        key_log_head: Some(event_digest.clone()),
        seq,
        method_evidence: json!({
            "mode": "self_hosted_service_rotation",
            "reason": "service_document_update",
            "version_id": version_id,
            "self_provisioned": true,
        }),
        fetched_at: now,
        expires_at: now,
        updated_at: now,
    };
    let mut updated = stored.clone();
    updated.identity.did = did.clone();
    if let Some(key) = registration_successor {
        updated.identity.registration_key = key.clone();
        updated.registration_receipt.registration_key = key;
    }
    updated.registration_receipt.did = did.clone();
    updated.registration_receipt.proof.verification_method =
        arkret_wire::DidUrl::new(format!("{did}#notary-key")).map_err(anyhow::Error::msg)?;

    let signing_seed = if let Some((next_ref, next_seed)) = signer_successor {
        if !updated.identity.signing_key_refs.contains(next_ref) {
            updated.identity.signing_key_refs.push(next_ref.clone());
        }
        updated.identity.active_signing_key_ref = next_ref.clone();
        *next_seed
    } else {
        load_signing_seed(
            config,
            Some(key_store),
            &updated.identity.active_signing_key_ref,
        )?
    };
    updated.registration_receipt = reissue_registration_receipt(
        &updated,
        &version_id,
        &event_digest,
        &current_update_public_key_multibase,
        &signing_seed,
        now,
    )?;
    updated.identity.control_key_ref = signing_control_ref;
    updated.identity.version_id = version_id.clone();
    updated.identity.last_verified_at = now;
    updated.did_document = serde_json::from_value(state).map_err(|error| {
        anyhow::anyhow!("the rotated Station DID document is not a service document: {error}")
    })?;
    updated.stored_at = now;
    validate_service_signing_binding(&updated, &signing_seed)?;
    validate_registration_receipt_signature(&updated)?;
    let event = WebvhLogRecord {
        event_digest,
        did: did.to_string(),
        seq,
        operation: log_entry.clone(),
        created_at: now,
    };
    match persistence
        .commit_webvh_log_operation(
            Some(head.event_digest.clone()),
            document,
            event,
            Some(coland_storage::ServiceIdentitySuccessor {
                expected: stored,
                next: updated.clone(),
            }),
        )
        .await
        .map_err(|error| anyhow::anyhow!("publishing the Station DID successor failed: {error}"))?
    {
        coland_storage::WebvhLogCommitOutcome::Accepted
        | coland_storage::WebvhLogCommitOutcome::Duplicate => {}
        coland_storage::WebvhLogCommitOutcome::Conflict => {
            anyhow::bail!(
                "the Station WebVH head moved while authorizing the Account Authority key"
            )
        }
    }
    promote_matching_control_candidate(key_store, &following_control_ref, &log_entry)?;
    tracing::info!(
        did = %did,
        version_id = %updated.identity.version_id,
        "published a service DID document successor"
    );
    Ok(updated)
}

async fn mint_local_service_identity(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    bundle_backend: Option<&dyn IdentityBundleBackend>,
    registration_key: ServiceRegistrationKey,
    account_authority_key: Option<&str>,
) -> anyhow::Result<StoredDidCoreIdentity> {
    let key_store = required_key_store(key_store)?;
    let provider_endpoint = url::Url::parse(registration_key.public_base_url().as_str())
        .map_err(|error| anyhow::anyhow!("invalid service Provider endpoint: {error}"))?;
    let mut rng_seed = [0u8; 32];
    coland_http::state::getrandom_seed(&mut rng_seed);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rng_seed);
    let service_signing_seed = config.notary_signing_key_seed.unwrap_or_else(|| {
        let mut seed = [0u8; 32];
        coland_http::state::getrandom_seed(&mut seed);
        seed
    });
    let assertion_keys = account_authority_key
        .map(|key| vec![(ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT, key)])
        .unwrap_or_default();
    let prepared =
        arkret_signatures::webvh::prepare_service_registration_inception_with_assertion_keys(
            &mut rng,
            &arkret_signatures::webvh::ServiceRegistrationInceptionInput {
                provider_endpoint: &provider_endpoint,
                registration_key: &registration_key,
                also_known_as: &[],
                version_time: chrono::Utc::now(),
                did_key_fragment: Some("notary-key"),
            },
            &service_signing_seed,
            &assertion_keys,
        )
        .map_err(|error| anyhow::anyhow!("service DID inception failed: {error}"))?;
    let service_did = Did::new(prepared.did.clone())
        .map_err(|error| anyhow::anyhow!("minted service DID is invalid: {error}"))?;
    let signing_ref = signing_key_ref(config, &service_did, Some(key_store))?;
    key_store
        .store(signing_ref.as_str(), &service_signing_seed)
        .map_err(|error| anyhow::anyhow!("persisting service signing key failed: {error}"))?;
    let current_control_ref = control_key_ref(&service_did, 1)?;
    let next_control_ref = next_control_key_ref(&current_control_ref)?;
    key_store
        .store(current_control_ref.as_str(), &prepared.update_key_seed)
        .map_err(|error| anyhow::anyhow!("persisting current WebVH control key failed: {error}"))?;
    key_store
        .store(next_control_ref.as_str(), &prepared.next_update_key_seed)
        .map_err(|error| anyhow::anyhow!("persisting next WebVH control key failed: {error}"))?;

    let inception_operation = serde_json::from_value(prepared.log_entry.clone())
        .map_err(|error| anyhow::anyhow!("decoding SDK service inception failed: {error}"))?;
    let request = ServiceRegistrationEnsureRequestBody::new(
        registration_key.clone(),
        inception_operation,
        uuid::Uuid::now_v7().to_string(),
        None,
    )
    .map_err(|error| anyhow::anyhow!("building service registration failed: {error}"))?;
    let issued_at = chrono::Utc::now();
    let receipt = sign_registration_receipt(
        &registration_key,
        &request,
        &service_did,
        &service_signing_seed,
        issued_at,
    )?;
    let outcome = ServiceRegistrationOutcome {
        did_document: request.inception_operation.state.clone(),
        registration_receipt: receipt,
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(|error| anyhow::anyhow!("self-registration outcome is invalid: {error}"))?;
    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let document = WebvhDocumentRecord {
        did: service_did.to_string(),
        did_document: serde_json::to_value(&outcome.did_document)?,
        key_log_head: Some(event_digest.clone()),
        seq: 1,
        method_evidence: json!({
            "mode": "service_registration_provider",
            "operation": arkret_wire::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE_V1,
            "service_kind": registration_key.service_kind().as_str(),
            "public_base_url": registration_key.public_base_url().as_str(),
            "version_id": outcome.version_id(),
            "self_provisioned": true,
        }),
        fetched_at: issued_at,
        expires_at: issued_at,
        updated_at: issued_at,
    };
    let event = WebvhLogRecord {
        event_digest,
        did: service_did.to_string(),
        seq: 1,
        operation: serde_json::to_value(&request.inception_operation)?,
        created_at: issued_at,
    };
    let committed = persistence
        .commit_service_registration(registration_key.clone(), outcome, document, event)
        .await
        .map_err(|error| {
            anyhow::anyhow!("committing local service registration failed: {error}")
        })?;
    let outcome = match committed {
        ServiceRegistrationCommitOutcome::Created(outcome)
        | ServiceRegistrationCommitOutcome::Existing(outcome) => outcome,
        ServiceRegistrationCommitOutcome::Conflict => {
            anyhow::bail!(
                "service_identity_conflict: the local registration key or service DID is already bound differently"
            )
        }
    };
    let stored = stored_identity_from_outcome(config, Some(key_store), registration_key, outcome)?;
    if let Some(backend) = bundle_backend {
        if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
            anyhow::bail!("service identity bundle backend is unavailable: {error}");
        }
        let bundle = DidCoreIdentityBundle {
            schema: DidCoreIdentityBundle::SCHEMA.to_owned(),
            identity: stored.clone(),
            webvh_history_entries: vec![serde_json::to_value(&request.inception_operation)?],
            receipt_chains: vec![stored.registration_receipt.clone()],
            exported_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        };
        backend.store(&bundle).map_err(|error| {
            anyhow::anyhow!("persisting service identity bundle failed: {error}")
        })?;
    }
    validate_stored_service_identity(persistence, config, Some(key_store), &stored).await?;
    persist_stored_identity(persistence, stored).await
}

fn sign_registration_receipt(
    key: &ServiceRegistrationKey,
    request: &ServiceRegistrationEnsureRequestBody,
    provider_did: &Did,
    signing_seed: &[u8; 32],
    issued_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<ServiceRegistrationReceipt> {
    let issued_at = arkret_canonical::normalize_timestamp_canonical(issued_at);
    let log_head_digest = request.inception_operation.log_head_digest()?;
    let control_key_digest = request.inception_operation.control_key_digest()?;
    let did = request.inception_operation.state.id.clone();
    let service_id = project_did_to_core_id(&did)?;
    let provider_id = project_did_to_core_id(provider_did)?;
    let verification_method = arkret_wire::DidUrl::new(format!("{provider_did}#notary-key"))
        .map_err(|error| {
            anyhow::anyhow!("provider notary verification method is invalid: {error}")
        })?;
    let mut receipt = ServiceRegistrationReceipt {
        registration_receipt_id: arkret_wire::ServiceRegistrationReceiptId::new(format!(
            "ak:service_registration_receipt:{}",
            "0".repeat(64)
        ))?,
        registration_key: key.clone(),
        service_id,
        did,
        version_id: request.inception_operation.version_id.clone(),
        log_head_digest,
        control_key_digest,
        issued_at,
        provider_id,
        proof: PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "placeholder".to_owned(),
        },
    };
    receipt.registration_receipt_id = receipt.expected_registration_receipt_id()?;
    receipt.proof.payload_digest = receipt.expected_payload_digest()?;
    receipt.proof = arkret_signatures::service_identity::sign_registration_receipt_proof(
        &receipt,
        &SigningKey::from_bytes(signing_seed),
    )?;
    receipt.validate_for(key, &receipt.service_id, &receipt.did)?;
    Ok(receipt)
}

fn signing_key_ref(
    config: &AppConfig,
    service_did: &Did,
    key_store: Option<&dyn KeyStore>,
) -> anyhow::Result<DidCoreIdentityKeyRef> {
    required_key_store(key_store)?;
    if let Some(seed) = config.notary_signing_key_seed {
        return retained_signing_key_ref(service_did, &seed);
    }
    DidCoreIdentityKeyRef::new(format!("arkret:signer:coland-notary:{service_did}"))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn retained_signing_key_ref(
    service_did: &Did,
    seed: &[u8; 32],
) -> anyhow::Result<DidCoreIdentityKeyRef> {
    let public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(seed).verifying_key().as_bytes(),
    );
    let digest = Sha256::digest(public.as_bytes());
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    DidCoreIdentityKeyRef::new(format!(
        "arkret:signer:coland-notary:{service_did}:{suffix}"
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn control_key_ref(service_did: &Did, generation: u64) -> anyhow::Result<DidCoreIdentityKeyRef> {
    DidCoreIdentityKeyRef::new(format!(
        "arkret:control:coland-webvh:{service_did}:{generation}"
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn next_control_key_ref(current: &DidCoreIdentityKeyRef) -> anyhow::Result<DidCoreIdentityKeyRef> {
    let (prefix, generation) = current
        .as_str()
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("WebVH control KeyRef has no generation suffix"))?;
    let generation = generation
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("WebVH control KeyRef generation is invalid"))?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("WebVH control KeyRef generation overflow"))?;
    DidCoreIdentityKeyRef::new(format!("{prefix}:{generation}"))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn webvh_version_number(version_id: &str) -> anyhow::Result<u64> {
    version_id
        .split_once('-')
        .and_then(|(number, _)| number.parse().ok())
        .filter(|number| *number > 0)
        .ok_or_else(|| anyhow::anyhow!("service WebVH versionId is invalid: {version_id}"))
}

fn required_key_store(key_store: Option<&dyn KeyStore>) -> anyhow::Result<&dyn KeyStore> {
    key_store.ok_or_else(|| {
        anyhow::anyhow!(
            "service identity requires a durable Secrets/KeyStore backend for WebVH control keys; \
             configure COLAND_KEYSTORE_BACKEND with a durable backend"
        )
    })
}

fn load_signing_seed(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    key_ref: &DidCoreIdentityKeyRef,
) -> anyhow::Result<[u8; 32]> {
    if key_ref.as_str() == CONFIGURED_SIGNING_KEY_REF {
        return config.notary_signing_key_seed.ok_or_else(|| {
            anyhow::anyhow!(
                "service signing KeyRef points to COLAND_NOTARY_SIGNING_KEY but the secret is unavailable"
            )
        });
    }
    load_seed(required_key_store(key_store)?, key_ref)
}

fn load_seed(
    key_store: &dyn KeyStore,
    key_ref: &DidCoreIdentityKeyRef,
) -> anyhow::Result<[u8; 32]> {
    let bytes = key_store.load(key_ref.as_str()).map_err(|error| {
        anyhow::anyhow!(
            "loading service identity key {} failed: {error}",
            key_ref.as_str()
        )
    })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "service identity key {} must be 32 bytes, got {}",
            key_ref.as_str(),
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes.as_slice());
    Ok(seed)
}

fn seed_public_multibase(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(seed).verifying_key().as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
    use coland_storage::{
        DeliveryPolicyStoreRegistry, ResolutionStoreRegistry, ServiceIdentitySuccessor,
        WebvhLogCommitOutcome,
    };
    use coland_storage_postgres::PgPersistenceStore;
    use coland_storage_postgres::test_database::TestDatabase;

    use super::*;
    include!("bootstrap/public_base_tests.rs");

    #[derive(Default)]
    struct TestKeyStore {
        keys: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl KeyStore for TestKeyStore {
        fn load(&self, id: &str) -> std::result::Result<KeyBytes, KeyStoreError> {
            self.keys
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .map(KeyBytes::new)
                .ok_or_else(|| KeyStoreError::not_found(id))
        }

        fn store(&self, id: &str, key: &[u8]) -> std::result::Result<(), KeyStoreError> {
            arkret_keystore::validate_id(id)?;
            self.keys
                .lock()
                .unwrap()
                .insert(id.to_owned(), key.to_vec());
            Ok(())
        }

        fn list(&self) -> std::result::Result<Vec<String>, KeyStoreError> {
            Ok(self.keys.lock().unwrap().keys().cloned().collect())
        }

        fn delete(&self, id: &str) -> std::result::Result<(), KeyStoreError> {
            arkret_keystore::validate_id(id)?;
            self.keys.lock().unwrap().remove(id);
            Ok(())
        }
    }

    /// A durable store on a database leased for the calling test. The lease is
    /// owned by the store, so it lasts exactly as long as the fixture holds it.
    async fn leased_store() -> Arc<PgPersistenceStore> {
        Arc::new(PgPersistenceStore::leased(Arc::new(
            TestDatabase::lease().await,
        )))
    }

    fn bootstrap_config() -> AppConfig {
        AppConfig {
            public_base_url: "https://coland.example/".to_owned(),
            notary_signing_key_seed: Some([0x39u8; 32]),
            ..AppConfig::test_default()
        }
    }

    fn state_did(state: &DidCoreIdentityState) -> String {
        state
            .identity()
            .expect("serving service identity")
            .did
            .to_string()
    }

    /// A Station that minted before its Account Authority existed used to be
    /// stuck: the delegated key could only enter the document at inception, so
    /// the only repair was re-provisioning - a new Station DID, orphaning every
    /// credential and derived id issued under the old one. It now advances its
    /// own log instead.
    #[tokio::test]
    async fn an_account_authority_key_is_authorized_after_the_did_was_minted() {
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();

        // Mint with no Account Authority in sight.
        resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            None,
            true,
        )
        .await
        .expect("first provisioning");
        let minted = persistence_store
            .service_identity()
            .get()
            .await
            .expect("identity lookup")
            .expect("stored identity");
        let method_id = format!(
            "{}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}",
            minted.identity.did
        );
        assert!(
            !minted
                .did_document
                .verification_method
                .iter()
                .any(|method| method.id == method_id),
            "the minted document deliberately carries no delegated key"
        );

        // The operator now names the Account Authority key. Boot authorizes it
        // by publishing one successor entry rather than refusing to start.
        let authority_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[0x5a; 32])
                .verifying_key()
                .to_bytes(),
        );
        let config = AppConfig {
            account_authority_url: Some("https://auth.example".to_owned()),
            account_authority_public_key_multibase: Some(authority_key.clone()),
            ..bootstrap_config()
        };
        resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect("boot authorizes the Account Authority key");

        let rotated = persistence_store
            .service_identity()
            .get()
            .await
            .expect("identity lookup")
            .expect("stored identity");
        assert_eq!(
            rotated.identity.did, minted.identity.did,
            "authorizing a key must not move the Station DID"
        );
        let method = rotated
            .did_document
            .verification_method
            .iter()
            .find(|method| method.id == method_id)
            .expect("the delegated key is authorized");
        assert_eq!(method.public_key_multibase, authority_key);
        assert!(rotated.did_document.assertion_method.contains(&method_id));
        assert_ne!(
            rotated.identity.version_id, minted.identity.version_id,
            "the document changed, so the log advanced"
        );
        assert_ne!(
            rotated.identity.control_key_ref, minted.identity.control_key_ref,
            "the successor consumed the pre-committed update key"
        );

        let history = persistence
            .webvh_history(rotated.identity.did.as_str())
            .await
            .expect("history");
        assert_eq!(history.len(), 2, "exactly one successor was published");
        assert_eq!(
            history[1].operation["parameters"]["scid"], history[0].operation["parameters"]["scid"],
            "the SCID is fixed for the life of the DID"
        );

        // The next boot sees a document that already matches and publishes
        // nothing, so a restart loop cannot walk the log forward.
        resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect("second boot");
        assert_eq!(
            persistence
                .webvh_history(rotated.identity.did.as_str())
                .await
                .expect("history")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn service_document_successor_is_atomic_with_identity_and_cas() {
        let database = Arc::new(TestDatabase::lease().await);
        let persistence_store = Arc::new(PgPersistenceStore::leased(database.clone()));
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();
        resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            None,
            true,
        )
        .await
        .expect("first provisioning");
        let before = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        let first_head = persistence
            .webvh_history(before.identity.did.as_str())
            .await
            .unwrap();
        assert_eq!(first_head.len(), 1);

        let (client, connection) = tokio_postgres::connect(database.url(), tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        client.batch_execute(
            "CREATE FUNCTION fail_service_identity_successor() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'injected service identity write failure'; END $$; \
             CREATE TRIGGER fail_service_identity_successor BEFORE UPDATE ON service_identity \
             FOR EACH ROW EXECUTE FUNCTION fail_service_identity_successor()",
        ).await.unwrap();
        let authority_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[0x5d; 32])
                .verifying_key()
                .to_bytes(),
        );
        let config = AppConfig {
            account_authority_url: Some("https://auth.example".to_owned()),
            account_authority_public_key_multibase: Some(authority_key),
            ..bootstrap_config()
        };
        let failure =
            resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
                .await
                .expect_err("identity write failure must roll back the public successor");
        assert!(
            failure
                .to_string()
                .contains("injected service identity write failure"),
            "{failure}"
        );
        assert_eq!(
            persistence_store.service_identity().get().await.unwrap(),
            Some(before.clone())
        );
        assert_eq!(
            persistence
                .webvh_history(before.identity.did.as_str())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            persistence_store
                .webvh()
                .get_document(before.identity.did.as_str())
                .await
                .unwrap()
                .unwrap()
                .seq,
            1
        );

        client.batch_execute("DROP TRIGGER fail_service_identity_successor ON service_identity; DROP FUNCTION fail_service_identity_successor()").await.unwrap();
        resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect("retry commits the complete successor");
        let next = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        let history = persistence
            .webvh_history(before.identity.did.as_str())
            .await
            .unwrap();
        assert_eq!(history.len(), 2);
        let document = persistence_store
            .webvh()
            .get_document(before.identity.did.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(document.seq, 2);
        assert_eq!(
            next.identity.version_id,
            history[1].operation["versionId"].as_str().unwrap()
        );

        let mut divergent = next.clone();
        divergent.identity.last_verified_at += chrono::TimeDelta::seconds(1);
        let stale = persistence_store
            .webvh()
            .commit_log_operation(
                Some(first_head[0].event_digest.clone()),
                document,
                coland_storage::WebvhLogRecord {
                    event_digest: history[1].event_digest.clone(),
                    did: history[1].did.clone(),
                    seq: history[1].seq,
                    operation: history[1].operation.clone(),
                    created_at: history[1].created_at,
                },
                Some(ServiceIdentitySuccessor {
                    expected: before,
                    next: divergent,
                }),
            )
            .await
            .unwrap();
        assert_eq!(stale, WebvhLogCommitOutcome::Conflict);
        assert_eq!(
            persistence_store.service_identity().get().await.unwrap(),
            Some(next)
        );
        connection_task.abort();
    }

    #[tokio::test]
    async fn concurrent_service_successors_preserve_the_winning_control_key() {
        let database = Arc::new(TestDatabase::lease().await);
        let persistence_store = Arc::new(PgPersistenceStore::leased(database.clone()));
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = Arc::new(TestKeyStore::default());
        resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(key_store.as_ref()),
            None,
            true,
        )
        .await
        .expect("first provisioning");
        let before = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        let core = arkret_wire::project_did_to_core_id(&before.identity.did).unwrap();
        let (client, connection) = tokio_postgres::connect(database.url(), tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .query_one(
                "SELECT pg_advisory_lock(hashtextextended($1, 0))",
                &[&core.as_str()],
            )
            .await
            .unwrap();

        let attempts: Vec<_> = [0x61, 0x62]
            .into_iter()
            .map(|byte| {
                let persistence = persistence.clone();
                let key_store = key_store.clone();
                let authority_key =
                    arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
                        &SigningKey::from_bytes(&[byte; 32])
                            .verifying_key()
                            .to_bytes(),
                    );
                let config = AppConfig {
                    account_authority_url: Some("https://auth.example".to_owned()),
                    account_authority_public_key_multibase: Some(authority_key),
                    ..bootstrap_config()
                };
                tokio::spawn(async move {
                    resolve_service_identity(
                        &persistence,
                        &config,
                        Some(key_store.as_ref()),
                        None,
                        false,
                    )
                    .await
                })
            })
            .collect();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let waiting: i64 = client
                .query_one(
                    "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted \
                     AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting >= 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "both successor proposals must reach the same WebVH CAS"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        client
            .query_one(
                "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
                &[&core.as_str()],
            )
            .await
            .unwrap();
        let mut success_count = 0;
        for attempt in attempts {
            if attempt.await.unwrap().is_ok() {
                success_count += 1;
            }
        }
        assert_eq!(success_count, 1);
        let after = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        let history = persistence
            .webvh_history(after.identity.did.as_str())
            .await
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_ne!(after.identity.version_id, before.identity.version_id);
        validate_stored_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(key_store.as_ref()),
            &after,
        )
        .await
        .expect("the winning candidate remains bound to the committed head");
        connection_task.abort();
    }

    #[tokio::test]
    async fn assertion_signer_successor_retains_old_receipt_and_recovers_after_failure() {
        let database = Arc::new(TestDatabase::lease().await);
        let persistence_store = Arc::new(PgPersistenceStore::leased(database.clone()));
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();
        let bundle_dir = std::env::temp_dir().join(format!(
            "coland-signing-rotation-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let bundle_backend = FileIdentityBundleBackend::new(&bundle_dir);
        let original_config = bootstrap_config();
        resolve_service_identity(
            &persistence,
            &original_config,
            Some(&key_store),
            Some(&bundle_backend),
            true,
        )
        .await
        .expect("initial identity and bundle");
        let before = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        let original_bundle = bundle_backend
            .load(&before.identity.registration_key)
            .unwrap()
            .unwrap();
        let old_ref = before.identity.active_signing_key_ref.clone();
        let new_seed = [0x67; 32];
        let rotated_config = AppConfig {
            notary_signing_key_seed: Some(new_seed),
            ..original_config
        };

        let (client, connection) = tokio_postgres::connect(database.url(), tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        client.batch_execute(
            "DROP TRIGGER IF EXISTS fail_signer_identity_successor ON service_identity; \
             CREATE OR REPLACE FUNCTION fail_signer_identity_successor() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'injected signer identity failure'; END $$; \
             CREATE TRIGGER fail_signer_identity_successor BEFORE UPDATE ON service_identity \
             FOR EACH ROW EXECUTE FUNCTION fail_signer_identity_successor()",
        ).await.unwrap();
        let error = resolve_service_identity(
            &persistence,
            &rotated_config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect_err("identity write failure rolls back signer publication");
        assert!(
            error
                .to_string()
                .contains("injected signer identity failure"),
            "{error}"
        );
        assert_eq!(
            persistence_store.service_identity().get().await.unwrap(),
            Some(before.clone())
        );
        assert_eq!(
            persistence
                .webvh_history(before.identity.did.as_str())
                .await
                .unwrap()
                .len(),
            1
        );
        let still_original = bundle_backend
            .load(&before.identity.registration_key)
            .unwrap()
            .unwrap();
        assert_eq!(still_original.identity, original_bundle.identity);
        assert_eq!(
            still_original.webvh_history_entries,
            original_bundle.webvh_history_entries
        );
        assert_eq!(
            still_original.receipt_chains,
            original_bundle.receipt_chains
        );
        client.batch_execute("DROP TRIGGER fail_signer_identity_successor ON service_identity; DROP FUNCTION fail_signer_identity_successor()")
            .await.unwrap();

        resolve_service_identity(
            &persistence,
            &rotated_config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("retry publishes the assertion signer successor");
        let after = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        for fragment in ["notary-key", "federation-fanout-key"] {
            let method_id = format!("{}#{fragment}", after.identity.did);
            let published = after
                .did_document
                .verification_method
                .iter()
                .find(|method| method.id == method_id)
                .expect("both service assertion methods remain published");
            let old = before
                .did_document
                .verification_method
                .iter()
                .find(|method| method.id == method_id)
                .unwrap();
            assert_ne!(published.public_key_multibase, old.public_key_multibase);
            assert_eq!(
                published.public_key_multibase,
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    SigningKey::from_bytes(&new_seed).verifying_key().as_bytes(),
                )
            );
        }
        assert_ne!(after.identity.active_signing_key_ref, old_ref);
        assert!(after.identity.signing_key_refs.contains(&old_ref));
        assert_eq!(
            key_store.load(old_ref.as_str()).unwrap().as_slice(),
            &[0x39; 32]
        );
        assert_eq!(
            key_store
                .load(after.identity.active_signing_key_ref.as_str())
                .unwrap()
                .as_slice(),
            &new_seed
        );
        let history = persistence
            .webvh_history(after.identity.did.as_str())
            .await
            .unwrap();
        assert_eq!(history.len(), 2);
        let successor_time = history[1].operation["versionTime"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        assert!(
            after.registration_receipt.issued_at >= successor_time,
            "the new receipt must not be signed in the old assertion-key interval"
        );
        assert!(
            chrono::Utc::now() >= successor_time,
            "the runtime must not serve the new signer before its WebVH versionTime"
        );
        let rotated_bundle = bundle_backend
            .load(&after.identity.registration_key)
            .unwrap()
            .unwrap();
        assert_eq!(rotated_bundle.receipt_chains.len(), 2);
        assert_eq!(
            rotated_bundle.receipt_chains[0],
            original_bundle.receipt_chains[0]
        );
        assert_eq!(rotated_bundle.receipt_chains[1], after.registration_receipt);
        arkret_signatures::service_identity::verify_registration_receipt_proof(
            &rotated_bundle.receipt_chains[0],
            &before.did_document,
        )
        .unwrap();
        arkret_signatures::service_identity::verify_registration_receipt_proof(
            &rotated_bundle.receipt_chains[1],
            &after.did_document,
        )
        .unwrap();
        assert!(
            arkret_signatures::service_identity::verify_registration_receipt_proof(
                &rotated_bundle.receipt_chains[0],
                &after.did_document,
            )
            .is_err()
        );
        assert!(
            arkret_signatures::service_identity::verify_registration_receipt_proof(
                &rotated_bundle.receipt_chains[1],
                &before.did_document,
            )
            .is_err()
        );
        resolve_service_identity(
            &persistence,
            &rotated_config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("restart serves the new signer without another successor");
        assert_eq!(
            persistence
                .webvh_history(after.identity.did.as_str())
                .await
                .unwrap()
                .len(),
            2
        );
        std::fs::remove_dir_all(bundle_dir).unwrap();
        connection_task.abort();
    }

    #[tokio::test]
    async fn successor_refuses_version_time_far_ahead_of_local_clock() {
        let future = chrono::Utc::now() + chrono::TimeDelta::seconds(20);
        let started = tokio::time::Instant::now();
        let error = wait_for_service_webvh_version_time(future)
            .await
            .expect_err("an implausible future head must fail closed");
        assert!(error.to_string().contains("too far ahead"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn restart_fails_when_the_configured_account_authority_is_unreachable() {
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store);
        let key_store = TestKeyStore::default();
        resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            None,
            true,
        )
        .await
        .expect("first provisioning without an Account Authority");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unavailable_address = listener.local_addr().unwrap();
        drop(listener);
        let config = AppConfig {
            account_authority_url: Some(format!("http://{unavailable_address}")),
            ..bootstrap_config()
        };
        let error = resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect_err("a stored identity must not bypass Account Authority discovery");

        assert!(
            error
                .to_string()
                .contains("Account Authority is a required startup dependency"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn interrupted_rotation_is_recovered_from_its_candidate_key() {
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();
        resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            None,
            true,
        )
        .await
        .expect("first provisioning");
        let authority_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[0x5b; 32])
                .verifying_key()
                .to_bytes(),
        );
        let config = AppConfig {
            account_authority_url: Some("https://auth.example".to_owned()),
            account_authority_public_key_multibase: Some(authority_key),
            ..bootstrap_config()
        };
        resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect("rotation");
        let committed = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();

        // Model a stop after the atomic database cut but before promotion of
        // the canonical next control key from its retained candidate.
        let canonical_next = next_control_key_ref(&committed.identity.control_key_ref).unwrap();
        key_store.delete(canonical_next.as_str()).unwrap();

        resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect("restart recovers the committed rotation");
        let recovered = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.identity.version_id, committed.identity.version_id);
        assert_eq!(
            recovered.identity.control_key_ref,
            committed.identity.control_key_ref
        );
        assert!(key_store.load(canonical_next.as_str()).is_ok());
    }

    #[tokio::test]
    async fn endpoint_change_advances_native_did_once_and_survives_restart() {
        let store = leased_store().await;
        let persistence = PersistenceHandle::new(store.clone());
        let keys = TestKeyStore::default();
        let first =
            resolve_service_identity(&persistence, &bootstrap_config(), Some(&keys), None, true)
                .await
                .unwrap();
        let original = first.identity().unwrap().clone();
        let first_stored = store.service_identity().get().await.unwrap().unwrap();
        let first_log = persistence
            .webvh_history(original.did.as_str())
            .await
            .unwrap();
        let first_evidence = arkret_identity::build_authenticated_webvh_service_resolution(
            original.service_id.clone(),
            "station".into(),
            serde_json::from_value(serde_json::to_value(&first_stored.did_document).unwrap())
                .unwrap(),
            first_log.into_iter().map(|e| e.operation).collect(),
            vec![],
            chrono::Utc::now(),
        )
        .unwrap();
        let cache_from = |e: &arkret_models_identity::AuthenticatedServiceResolution, at| {
            arkret_models_identity::VerifiedServiceRoute::new(e.projection().unwrap(), at)
        };
        store
            .service_routes()
            .publish_route_cache(
                first_evidence.clone(),
                cache_from(&first_evidence, chrono::Utc::now()),
            )
            .await
            .unwrap();
        let changed = AppConfig {
            public_base_url: "https://relocated.example/station/".into(),
            ..bootstrap_config()
        };
        let drift = resolve_service_identity(&persistence, &changed, Some(&keys), None, false)
            .await
            .unwrap();
        assert!(matches!(
            drift,
            DidCoreIdentityState::RegistrationKeyDrift { .. }
        ));
        assert_eq!(
            persistence
                .webvh_history(original.did.as_str())
                .await
                .unwrap()
                .len(),
            1
        );
        public_base::migrate_with_storage(
            &persistence,
            &bootstrap_config(),
            &keys,
            None,
            &bootstrap_config().public_base_url,
            &changed.public_base_url,
            public_base::MigrationOptions {
                preflight: true,
                preserve_did_host: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            persistence
                .webvh_history(original.did.as_str())
                .await
                .unwrap()
                .len(),
            1
        );
        public_base::migrate_with_storage(
            &persistence,
            &bootstrap_config(),
            &keys,
            None,
            &bootstrap_config().public_base_url,
            &changed.public_base_url,
            public_base::MigrationOptions {
                preflight: false,
                preserve_did_host: false,
            },
        )
        .await
        .unwrap();
        let updated = resolve_service_identity(&persistence, &changed, Some(&keys), None, false)
            .await
            .unwrap();
        assert_eq!(updated.identity().unwrap().service_id, original.service_id);
        assert_ne!(updated.identity().unwrap().did, original.did);
        assert_ne!(updated.identity().unwrap().version_id, original.version_id);
        let stored = store.service_identity().get().await.unwrap().unwrap();
        let doc = serde_json::to_value(&stored.did_document).unwrap();
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            changed.public_base_url
        );
        let log = persistence
            .webvh_history(original.did.as_str())
            .await
            .unwrap();
        assert_eq!(log.len(), 2);
        resolve_service_identity(&persistence, &changed, Some(&keys), None, false)
            .await
            .unwrap();
        assert_eq!(
            persistence
                .webvh_history(original.did.as_str())
                .await
                .unwrap()
                .len(),
            2,
            "same DID and endpoint must not create refresh versions"
        );
        let next = AppConfig {
            public_base_url: "https://final.example/".into(),
            ..bootstrap_config()
        };
        public_base::migrate_with_storage(
            &persistence,
            &changed,
            &keys,
            None,
            &changed.public_base_url,
            &next.public_base_url,
            public_base::MigrationOptions {
                preflight: false,
                preserve_did_host: false,
            },
        )
        .await
        .unwrap();
        resolve_service_identity(&persistence, &next, Some(&keys), None, false)
            .await
            .unwrap();
        let latest = store.service_identity().get().await.unwrap().unwrap();
        let logs = persistence
            .webvh_history(original.did.as_str())
            .await
            .unwrap();
        assert_eq!(logs.len(), 3);
        let latest = arkret_identity::build_authenticated_webvh_service_resolution(
            original.service_id.clone(),
            "station".into(),
            serde_json::from_value(serde_json::to_value(&latest.did_document).unwrap()).unwrap(),
            logs.into_iter().map(|e| e.operation).collect(),
            vec![],
            chrono::Utc::now(),
        )
        .unwrap();
        assert!(matches!(
            store
                .service_routes()
                .publish_route_cache(latest.clone(), cache_from(&latest, chrono::Utc::now()))
                .await
                .unwrap(),
            coland_storage::MonotonicRouteWrite::Applied
        ));
        let retained = store
            .service_routes()
            .route_cache(&original.service_id, "station")
            .await
            .unwrap()
            .unwrap();
        let earlier = retained.verified_at - chrono::Duration::nanoseconds(1);
        assert!(
            matches!(
                store
                    .service_routes()
                    .publish_route_cache(latest.clone(), cache_from(&latest, earlier))
                    .await
                    .unwrap(),
                coland_storage::MonotonicRouteWrite::Replay
            ),
            "an identical authenticated route finishing later replays without rollback"
        );
        assert_eq!(
            store
                .service_routes()
                .route_cache(&original.service_id, "station")
                .await
                .unwrap()
                .unwrap(),
            retained
        );
        store
            .service_routes()
            .evict_route_cache(&original.service_id, "station")
            .await
            .unwrap();
        assert!(matches!(
            store
                .service_routes()
                .publish_route_cache(
                    first_evidence.clone(),
                    cache_from(
                        &first_evidence,
                        chrono::Utc::now() + chrono::Duration::minutes(15)
                    )
                )
                .await
                .unwrap(),
            coland_storage::MonotonicRouteWrite::Stale
        ));
        assert_eq!(
            store
                .service_routes()
                .method_state(&original.service_id, "station")
                .await
                .unwrap()
                .unwrap()
                .version_id,
            latest.projection().unwrap().version_id
        );
    }

    #[tokio::test]
    async fn portable_bundle_restore_preserves_each_native_entry_did() {
        let config = bootstrap_config();
        let source = leased_store().await;
        let persistence = PersistenceHandle::new(source.clone());
        let keys = TestKeyStore::default();
        resolve_service_identity(&persistence, &config, Some(&keys), None, true)
            .await
            .unwrap();
        let first = source.service_identity().get().await.unwrap().unwrap();
        let old_did = first.identity.did.to_string();
        let scid = old_did.split(':').nth(2).unwrap();
        let new_did = format!("did:webvh:{scid}:moved.example:webvh:service");
        let mut logs = persistence
            .webvh_history(&old_did)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.operation)
            .collect::<Vec<_>>();
        let mut state: Value = serde_json::from_str(
            &serde_json::to_string(&logs[0]["state"])
                .unwrap()
                .replace(&old_did, &new_did),
        )
        .unwrap();
        state["alsoKnownAs"] = json!([old_did]);
        let active = next_control_key_ref(&first.identity.control_key_ref).unwrap();
        let seed = load_seed(&keys, &active).unwrap();
        let following = next_control_key_ref(&active).unwrap();
        let following_seed = [0x77; 32];
        keys.store(following.as_str(), &following_seed).unwrap();
        let moved = arkret_signatures::webvh::prepare_webvh_relocation(
            &arkret_signatures::webvh::WebvhRelocationInput {
                current_did: &old_did,
                target_did: &new_did,
                previous_entries: &logs,
                version_time: next_webvh_version_time(&logs[0]).unwrap(),
                current_update_seed: &seed,
                next_update_public_key_multibase: &seed_public_multibase(&following_seed),
                state: &state,
            },
        )
        .unwrap();
        let head = event_digest_for_restore(&moved.log_entry).unwrap();
        logs.push(moved.log_entry.clone());
        let mut latest = first.clone();
        latest.identity.did = Did::new(&new_did).unwrap();
        latest.identity.version_id = moved.version_id.clone();
        latest.identity.control_key_ref = active;
        latest.did_document = serde_json::from_value(state).unwrap();
        latest.registration_receipt.did = latest.identity.did.clone();
        latest.registration_receipt.proof.verification_method =
            arkret_wire::DidUrl::new(format!("{new_did}#notary-key")).unwrap();
        latest.registration_receipt = reissue_registration_receipt(
            &latest,
            &moved.version_id,
            &head,
            &seed_public_multibase(&seed),
            &config.notary_signing_key_seed.unwrap(),
            chrono::Utc::now(),
        )
        .unwrap();
        let bundle = DidCoreIdentityBundle {
            schema: DidCoreIdentityBundle::SCHEMA.into(),
            identity: latest.clone(),
            webvh_history_entries: logs,
            receipt_chains: vec![
                first.registration_receipt,
                latest.registration_receipt.clone(),
            ],
            exported_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        };
        let destination = leased_store().await;
        let restored_persistence = PersistenceHandle::new(destination.clone());
        restore_identity_bundle(
            &restored_persistence,
            &config,
            Some(&keys),
            latest.identity.registration_key.clone(),
            bundle,
        )
        .await
        .unwrap();
        let history = restored_persistence.webvh_history(&new_did).await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].did, old_did);
        assert_eq!(history[1].did, new_did);
        assert_eq!(
            destination
                .service_identity()
                .get()
                .await
                .unwrap()
                .unwrap()
                .identity
                .service_id,
            latest.identity.service_id
        );
        validate_stored_service_identity(&restored_persistence, &config, Some(&keys), &latest)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn runtime_bootstrap_rejects_missing_postgres_pool() {
        let error = resolve_and_build_persistence(&bootstrap_config(), &Db { pool: None })
            .await
            .err()
            .expect("runtime bootstrap must reject memory persistence");

        assert!(
            error.to_string().contains("DATABASE_URL is required"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn first_provisioning_persists_sdk_identity_and_both_control_keys() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();

        let state = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");

        let stored = persistence_store
            .service_identity()
            .get()
            .await
            .expect("identity lookup")
            .expect("stored identity");
        assert_eq!(stored.identity.did.method(), "webvh");
        let historical_ref = DidCoreIdentityKeyRef::new("contact-retained-historical-key").unwrap();
        key_store
            .store(historical_ref.as_str(), &[91_u8; 32])
            .unwrap();
        let mut prior = stored.identity.clone();
        prior.signing_key_refs.push(historical_ref.clone());
        let mut refreshed = stored.identity.clone();
        retain_prior_signing_key_refs(&prior, &mut refreshed).unwrap();
        assert!(refreshed.signing_key_refs.contains(&historical_ref));
        assert_eq!(
            refreshed.active_signing_key_ref,
            stored.identity.active_signing_key_ref
        );
        assert_eq!(refreshed.control_key_ref, stored.identity.control_key_ref);
        let retained = refreshed.signing_key_refs.clone();
        retain_prior_signing_key_refs(&prior, &mut refreshed).unwrap();
        assert_eq!(refreshed.signing_key_refs, retained);
        let mut other_provider = refreshed.clone();
        other_provider.provider = Some(DidCoreIdentityProviderRef {
            name: "other-provider".into(),
            endpoint: CanonicalServiceUrl::canonicalize("https://other-provider.example/").unwrap(),
        });
        assert!(retain_prior_signing_key_refs(&prior, &mut other_provider).is_err());
        let mut relocated = refreshed.clone();
        relocated.did = arkret_wire::Did::new(format!("{}:different-location", prior.did)).unwrap();
        assert!(retain_prior_signing_key_refs(&prior, &mut relocated).is_err());
        assert_ne!(
            stored.identity.did.as_str(),
            stored.identity.service_id.as_str(),
            "the WebVH store key is the complete DID, not its stable core projection"
        );
        assert_eq!(
            stored.identity.registration_key,
            registration_key(&config).unwrap()
        );
        assert_eq!(
            stored.identity.active_signing_key_ref.as_str(),
            retained_signing_key_ref(
                &stored.identity.did,
                &config.notary_signing_key_seed.unwrap()
            )
            .unwrap()
            .as_str()
        );
        assert!(
            key_store
                .load(stored.identity.active_signing_key_ref.as_str())
                .is_ok()
        );
        assert!(
            key_store
                .load(stored.identity.control_key_ref.as_str())
                .is_ok()
        );
        assert!(
            key_store
                .load(
                    next_control_key_ref(&stored.identity.control_key_ref)
                        .unwrap()
                        .as_str()
                )
                .is_ok()
        );
        assert_eq!(state_did(&state), stored.identity.did.as_str());
    }

    #[tokio::test]
    async fn restart_reuses_identity_and_rejects_missing_control_key() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();
        let state = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");
        let first_did = state_did(&state);

        let restarted = bootstrap_config();
        let restarted_state =
            resolve_service_identity(&persistence, &restarted, Some(&key_store), None, false)
                .await
                .expect("durable restart");
        assert_eq!(state_did(&restarted_state), first_did);

        let stored = persistence_store
            .service_identity()
            .get()
            .await
            .unwrap()
            .unwrap();
        key_store
            .delete(stored.identity.control_key_ref.as_str())
            .unwrap();
        let error = resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            None,
            false,
        )
        .await
        .expect_err("missing control key must fail closed");
        assert!(error.to_string().contains("loading service identity key"));
    }

    #[tokio::test]
    async fn keystore_backed_key_authorization_event_survives_restart() {
        let config = AppConfig {
            public_base_url: "https://coland.example/".to_owned(),
            notary_signing_key_seed: None,
            key_store: coland_http::config::KeyStoreConfig::Platform,
            ..AppConfig::test_default()
        };
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store);
        let key_store = TestKeyStore::default();

        let first = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");
        let first_identity = first.identity().expect("serving identity");
        let first_seed = load_signing_seed(
            &config,
            Some(&key_store),
            &first_identity.active_signing_key_ref,
        )
        .expect("first active signing key");

        let restarted =
            resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
                .await
                .expect("restart");
        let restarted_identity = restarted.identity().expect("restarted serving identity");
        let restarted_seed = load_signing_seed(
            &config,
            Some(&key_store),
            &restarted_identity.active_signing_key_ref,
        )
        .expect("restarted active signing key");

        assert_eq!(restarted_identity.service_id, first_identity.service_id);
        assert_eq!(
            restarted_identity.active_signing_key_ref,
            first_identity.active_signing_key_ref
        );
        assert_eq!(restarted_seed, first_seed);
        assert_eq!(
            restarted_identity.active_signing_key_ref.as_str(),
            format!("arkret:signer:coland-notary:{}", restarted_identity.did)
        );
    }

    #[tokio::test]
    async fn database_row_loss_recovers_from_local_registration_without_reminting() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = TestKeyStore::default();
        let state = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");
        let first_did = state_did(&state);

        let replacement_identity_store = leased_store().await;
        let replacement_persistence = PersistenceHandle::new(replacement_identity_store.clone());
        let key = registration_key(&config).unwrap();
        let outcome = persistence_store
            .webvh()
            .get_service_registration(&key)
            .await
            .unwrap()
            .unwrap();
        let events = persistence_store
            .webvh()
            .list_log_events(&first_did)
            .await
            .unwrap();
        let document = persistence_store
            .webvh()
            .get_document(&first_did)
            .await
            .unwrap()
            .unwrap();
        replacement_identity_store
            .webvh()
            .commit_service_registration(key, outcome, document, events.into_iter().next().unwrap())
            .await
            .unwrap();

        let restarted = bootstrap_config();
        let restarted_state = resolve_service_identity(
            &replacement_persistence,
            &restarted,
            Some(&key_store),
            None,
            false,
        )
        .await
        .expect("local registration restores singleton row");
        assert_eq!(state_did(&restarted_state), first_did);
    }

    #[tokio::test]
    async fn empty_database_restores_verified_identity_bundle() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store);
        let key_store = TestKeyStore::default();
        let bundle_dir = std::env::temp_dir().join(format!(
            "coland-service-identity-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let bundle_backend = FileIdentityBundleBackend::new(&bundle_dir);
        let state = resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            true,
        )
        .await
        .expect("first provisioning with bundle");
        let first_did = state_did(&state);

        let empty_database = leased_store().await;
        let empty_persistence = PersistenceHandle::new(empty_database.clone());
        let restored_config = bootstrap_config();
        let restored_state = resolve_service_identity(
            &empty_persistence,
            &restored_config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("verified bundle restores the same identity");
        assert_eq!(state_did(&restored_state), first_did);
        assert!(
            empty_database
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(bundle_dir).unwrap();
    }

    #[tokio::test]
    async fn rotated_identity_bundle_replays_the_complete_history() {
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store);
        let key_store = TestKeyStore::default();
        let bundle_dir = std::env::temp_dir().join(format!(
            "coland-rotated-identity-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let bundle_backend = FileIdentityBundleBackend::new(&bundle_dir);
        resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            Some(&bundle_backend),
            true,
        )
        .await
        .expect("first provisioning");
        let authority_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[0x5c; 32])
                .verifying_key()
                .to_bytes(),
        );
        let config = AppConfig {
            account_authority_url: Some("https://auth.example".to_owned()),
            account_authority_public_key_multibase: Some(authority_key),
            ..bootstrap_config()
        };
        let rotated = resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("rotation updates the bundle");

        let empty_database = leased_store().await;
        let empty_persistence = PersistenceHandle::new(empty_database);
        let restored = resolve_service_identity(
            &empty_persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("rotated bundle restores");
        assert_eq!(state_did(&restored), state_did(&rotated));
        let identity = restored.identity().unwrap();
        assert_eq!(
            empty_persistence
                .webvh_history(identity.did.as_str())
                .await
                .unwrap()
                .len(),
            2
        );

        let valid_bundle = bundle_backend
            .load(&registration_key(&config).unwrap())
            .unwrap()
            .unwrap();
        let mut forged_bundle = valid_bundle.clone();
        let signature = &mut forged_bundle.receipt_chains[0].proof.jws;
        let replacement = if signature.ends_with('1') { '2' } else { '1' };
        signature.pop();
        signature.push(replacement);
        bundle_backend.store(&forged_bundle).unwrap();
        let forged_history = resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect_err("a forged historical receipt cannot be retained");
        assert!(
            forged_history.to_string().contains("receipt signature"),
            "{forged_history}"
        );
        bundle_backend.store(&valid_bundle).unwrap();

        bundle_backend
            .delete(&registration_key(&config).unwrap())
            .unwrap();
        resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("durable accepted receipts rebuild a missing bundle");
        let rebuilt = bundle_backend
            .load(&registration_key(&config).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(rebuilt.receipt_chains, valid_bundle.receipt_chains);
        std::fs::remove_dir_all(bundle_dir).unwrap();
    }

    #[tokio::test]
    async fn bundle_restore_rejects_a_forged_provider_receipt() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store);
        let key_store = TestKeyStore::default();
        let bundle_dir = std::env::temp_dir().join(format!(
            "coland-forged-identity-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let bundle_backend = FileIdentityBundleBackend::new(&bundle_dir);
        resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            true,
        )
        .await
        .expect("first provisioning with bundle");
        let key = registration_key(&config).unwrap();
        let mut forged = bundle_backend.load(&key).unwrap().unwrap();
        let mut jws = forged.identity.registration_receipt.proof.jws.clone();
        let replacement = if jws.ends_with('1') { '2' } else { '1' };
        jws.pop();
        jws.push(replacement);
        forged.identity.registration_receipt.proof.jws = jws;
        forged.receipt_chains[0] = forged.identity.registration_receipt.clone();
        bundle_backend.store(&forged).unwrap();

        let empty_database = leased_store().await;
        let empty_persistence = PersistenceHandle::new(empty_database);
        let error = resolve_service_identity(
            &empty_persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect_err("forged receipt must not restore an identity");
        assert!(error.to_string().contains("receipt signature"), "{error}");
        std::fs::remove_dir_all(bundle_dir).unwrap();
    }

    #[tokio::test]
    async fn production_without_first_provisioning_fails_closed() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store);
        let key_store = TestKeyStore::default();
        let error = resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect_err("empty durable state must require the explicit signal");
        assert!(
            error
                .to_string()
                .contains("service_identity_first_provisioning_required")
        );
    }

    #[tokio::test]
    async fn external_provider_outage_waits_without_first_provisioning_or_minting() {
        let config = AppConfig {
            external_webvh_provider_url: Some("http://127.0.0.1:9/".to_owned()),
            external_webvh_registration_bearer: Some("test-registration-bearer".to_owned()),
            ..bootstrap_config()
        };
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let key_store = Arc::new(TestKeyStore::default());

        let first = retry_service_identity(&config, persistence.clone(), Some(key_store.clone()))
            .await
            .expect("an external outage is a lifecycle state, not a startup error");
        assert!(matches!(
            first.state,
            DidCoreIdentityState::WaitingProvider { .. }
        ));
        assert!(
            persistence_store
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_none()
        );
        let retained_key_ids = key_store.list().unwrap();
        assert_eq!(retained_key_ids.len(), 3);

        let retried = retry_service_identity(&config, persistence.clone(), Some(key_store.clone()))
            .await
            .expect("retry remains fail-closed while the Provider is unavailable");
        assert!(matches!(
            retried.state,
            DidCoreIdentityState::WaitingProvider { .. }
        ));
        assert_eq!(key_store.list().unwrap(), retained_key_ids);
        assert!(
            persistence_store
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn external_provider_inception_authorizes_the_account_authority_key() {
        let config = AppConfig {
            external_webvh_provider_url: Some("https://identity.example/".to_owned()),
            external_webvh_registration_bearer: Some("test-registration-bearer".to_owned()),
            ..bootstrap_config()
        };
        let provider = external_provider(&config).unwrap();
        let key_store = TestKeyStore::default();
        let authority_key = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &SigningKey::from_bytes(&[0x5d; 32])
                .verifying_key()
                .to_bytes(),
        );
        let material = external_identity_material(
            &config,
            Some(&key_store),
            &provider,
            &registration_key(&config).unwrap(),
            true,
            Some(&authority_key),
        )
        .unwrap();
        let method_id = format!(
            "{}#{ACCOUNT_AUTHORITY_ASSERTION_METHOD_FRAGMENT}",
            material.prepared.did
        );
        let state = &material.prepared.log_entry["state"];
        assert!(
            state["verificationMethod"]
                .as_array()
                .unwrap()
                .iter()
                .any(|method| {
                    method["id"] == method_id && method["publicKeyMultibase"] == authority_key
                })
        );
        assert!(
            state["assertionMethod"]
                .as_array()
                .unwrap()
                .contains(&json!(method_id))
        );
    }

    #[tokio::test]
    async fn provisioning_without_durable_control_store_is_rejected() {
        let config = bootstrap_config();
        let persistence_store = leased_store().await;
        let persistence = PersistenceHandle::new(persistence_store.clone());
        let error = resolve_service_identity(&persistence, &config, None, None, true)
            .await
            .expect_err("plaintext database fallback must not exist");
        assert!(
            error
                .to_string()
                .contains("durable Secrets/KeyStore backend")
        );
        assert!(
            persistence_store
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod account_authority_keyset_tests {
    use super::*;

    /// Uses the canonical run-scoped TLS fixture and actual operator CA input.
    /// The development network policy permits loopback, but never disables
    /// certificate identity verification. No global environment is mutated.
    #[tokio::test]
    async fn authority_discovery_uses_operator_ca_and_rejects_wrong_certificate_identity() {
        use std::io::{Read, Write};
        use std::sync::Arc;

        coland_test_support::native_tls::require_trust_store();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let authority = format!("https://127.0.0.1:{port}");
        let discovery = serde_json::json!({"jwks_uri": format!("{authority}/keys")}).to_string();
        let raw = [7u8; 32];
        use base64::Engine as _;
        let keyset = serde_json::json!({"keys": [{
            "kid": ACCOUNT_AUTHORITY_JWK_KID, "kty": "OKP", "crv": "Ed25519",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        }]})
        .to_string();
        let tls = Arc::new(coland_test_support::native_tls::server_config());
        // First connection has the wrong DNS identity and must fail its TLS
        // handshake; the next two are real discovery and keyset HTTP reads.
        let peer = std::thread::spawn(move || {
            for (index, body) in [String::new(), discovery, keyset].into_iter().enumerate() {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(tls.clone()).unwrap(),
                    socket,
                );
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if index == 0 {
                    assert!(
                        request.is_empty(),
                        "wrong certificate identity reached HTTP"
                    );
                    continue;
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(if index == 1 {
                    "GET /.well-known/openid-configuration "
                } else {
                    "GET /keys "
                }));
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let mut config = AppConfig {
            development_mode: true,
            account_authority_url: Some(format!("https://localhost:{port}")),
            ..coland_test_support::app_config()
        };
        assert!(account_authority_assertion_key(&config).await.is_err());
        config.account_authority_url = Some(authority);
        assert_eq!(
            account_authority_assertion_key(&config).await.unwrap(),
            Some(arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(&raw))
        );
        peer.join().unwrap();
    }

    #[test]
    fn keyset_selection_is_by_kid_and_round_trips_to_the_did_document_encoding() {
        let raw = [7u8; 32];
        let x = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        };
        let expected = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(&raw);

        // A real keyset carries several keys and their order is not a
        // contract, so selection is by kid, not by "the only Ed25519 key".
        let keyset = serde_json::json!({
            "keys": [
                {"kid": "coauth-service-identity-v1", "kty": "OKP", "crv": "Ed25519", "x": x},
                {"kid": "some-rsa", "kty": "RSA", "n": "...", "e": "AQAB"},
                {"kid": ACCOUNT_AUTHORITY_JWK_KID, "kty": "OKP", "crv": "Ed25519", "x": x},
            ]
        });
        let picked = account_authority_key_from_keyset(&keyset).expect("kid is present");
        assert_eq!(picked, expected);
        // What comes back is exactly what the DID document decoder accepts.
        assert_eq!(
            arkret_canonical::multibase::decode_ed25519_multibase(&picked).unwrap(),
            raw
        );

        // Right kid, wrong key type: not a signer this deployment can authorize.
        let wrong_type = serde_json::json!({
            "keys": [{"kid": ACCOUNT_AUTHORITY_JWK_KID, "kty": "EC", "crv": "P-256", "x": x}]
        });
        assert!(account_authority_key_from_keyset(&wrong_type).is_none());

        // Absent entirely, and a malformed `x`, both decline rather than guess.
        assert!(account_authority_key_from_keyset(&serde_json::json!({"keys": []})).is_none());
        let short = serde_json::json!({
            "keys": [{"kid": ACCOUNT_AUTHORITY_JWK_KID, "kty": "OKP", "crv": "Ed25519", "x": "AAAA"}]
        });
        assert!(account_authority_key_from_keyset(&short).is_none());
    }
}
