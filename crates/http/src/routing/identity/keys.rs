//! E2EE key surfaces.
//!
//! Surfaces:
//! - `POST /_arkret/self/keys/upload` - upload one-time / fallback prekeys with the current device
//!   signature.
//! - `POST /_arkret/self/keys/query` - fetch device key bundles for a peer set.
//! - `POST /_arkret/self/keys/claim` - claim one-time keys, draining the per-device pool.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::{DeviceIdentity, FindDeviceQuery, SaveDeviceCommand};
use ed25519_dalek::Signature;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{bearer_token, now, sha256_hex};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    AuthorizedDeviceSigningKey, DeviceSigningKeyDirectoryOutcome,
    DeviceSigningKeyDirectoryQueryRequestBody, DeviceStatus, KeysClaimOutcome,
    KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody, KeysUploadOutcome,
    KeysUploadRequestBody, KeysUploadUnsignedRequest, PeerQueryDeviceRecord, QueryDeviceRecord,
};

pub(crate) fn peer_router() -> Router {
    Router::with_path("keys/query").post(peer_keys_query)
}

pub(super) fn router() -> Router {
    Router::new()
        .push(Router::with_path("keys/upload").post(keys_upload))
        .push(Router::with_path("keys/query").post(keys_query))
        .push(Router::with_path("keys/claim").post(keys_claim))
}

/// Product-surface (`/_coland/gate/account/...`) router carrying the
/// server-to-server device signing-key directory read used by the Account Authority process
/// (coauth) to verify device holder proofs. Mounted under `_coland`, not the
/// `/_arkret` protocol root: it is a deployment-local integration read, not a
/// spec operation.
pub(super) fn product_router() -> Router {
    Router::with_path("gate/account/device-signing-keys/query").post(device_signing_keys_query)
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.upload.create", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.upload.create.v1"))]
async fn keys_upload(
    aa: AuthArgs,
    body: JsonBody<KeysUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysUploadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    // Session admission already required the device to be `active` at the
    // PCR status cut; the device mirror is not a revocation authority.
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    let unsigned = body.unsigned();
    let device_id = body.device_id.as_str().to_owned();
    if device_id.as_str() != session.require_human_device_id() {
        return Err(AppError::capability_denied(
            "session device does not match upload device",
        ));
    }
    let current_device = state
        .identities()
        .find_device(FindDeviceQuery {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let current_facet =
        crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
            state,
            &session.actor,
            &device_id,
        )
        .await;
    if !matches!(current_facet.status, DeviceStatus::Active) {
        return Err(crate::app_error!(
            DeviceGenerationFenced,
            "device is revoked, unverified, or fenced by the current generation",
        ));
    }
    verify_keys_upload_device_signature(
        &session.actor,
        current_device.as_ref(),
        &unsigned,
        &body.device_signature,
    )?;

    let original_device = current_device
        .as_ref()
        .ok_or_else(|| AppError::capability_denied("device authorization unavailable"))?;
    let (authorization_event_id, _generation) =
        super::device_generation::verified_device_authorization_binding(original_device)
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| AppError::capability_denied("device authorization unavailable"))?;
    // Freeze the accepted authorization instance whose key verified this
    // upload. Storage rechecks its Commit ref under the device lock.
    let authorization = super::device_generation::active_device_revocation_gate_selector(
        state,
        &session.actor,
        &device_id,
    )
    .await
    .map_err(|error| AppError::capability_denied(error.to_string()))?;
    if authorization.authorization_ref.event_id != authorization_event_id {
        return Err(AppError::capability_denied(
            "device authorization changed during key upload",
        ));
    }

    let one_time_key_count = body.one_time_keys.len() as u64;
    let mut one_time_key_alg_counts = BTreeMap::new();
    for key_id in body.one_time_keys.keys() {
        let algorithm = key_id.as_str().split(':').next().unwrap_or(key_id.as_str());
        *one_time_key_alg_counts
            .entry(
                arkret_wire::NonEmptyString::new(algorithm.to_owned()).map_err(|error| {
                    AppError::param_invalid(format!("one-time key algorithm is invalid: {error}"))
                })?,
            )
            .or_insert(0) += 1;
    }
    let one_time_keys = body.one_time_keys;
    let fallback_keys = body.fallback_keys;
    let key_payload = json!({
        "device_id": device_id.clone(),
        "one_time_keys": one_time_keys.clone(),
        "fallback_keys": fallback_keys.clone(),
        "device_signature": body.device_signature.clone(),
        "updated_at": now(),
    });
    state
        .key_material()
        .save_bundle(&authorization, key_payload)
        .await
        .map_err(|error| AppError::internal(format!("persist device keys: {error}")))?;

    let updated_at = now();
    let mut device = original_device.clone();
    device.updated_at = updated_at;
    if let Some(payload) = device.payload.as_object_mut() {
        payload.insert("last_key_upload_at".into(), json!(updated_at));
    }
    state
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: session.actor.clone(),
            device_id: device_id.clone(),
            display_name: device.display_name.clone(),
            device,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    state
        .key_material()
        .save_one_time_keys(
            &authorization,
            one_time_keys
                .into_values()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| AppError::internal(format!("serialize one-time key: {error}")))?,
        )
        .await
        .map_err(|error| AppError::internal(format!("persist one-time keys: {error}")))?;

    one_time_key_alg_counts.insert(
        arkret_wire::NonEmptyString::new("total").expect("total is non-empty"),
        one_time_key_count,
    );
    json_ok(KeysUploadOutcome {
        one_time_key_counts: one_time_key_alg_counts,
        fallback_keys,
    })
}

fn directory_evidence_service_error(error: coland_services::ServiceError) -> AppError {
    if error.conflict_code() == Some(coland_storage::ConflictCode::TemporarilyUnavailable) {
        crate::app_error!(
            TemporarilyUnavailable,
            "current account-device evidence is temporarily unavailable",
        )
    } else {
        AppError::internal(error.to_string())
    }
}

/// Build one complete, origin-Station-attested device row when its current
/// signer-evidence provider is available.
///
/// This is the **origin** shape of `device-lifecycle.md` §8.2: the signed
/// `device_projection_attestation` plus the `signer_evidence_ref` that locates
/// the immutable `account_device` evidence retaining it. It is what the
/// Station-to-Station surface (§8.2.1) returns verbatim; it is **never**
/// handed to a client. The client-facing row is produced from a *verified*
/// attestation by [`PeerQueryDeviceRecord::project_verified_row`].
///
/// Returns `None` when the device is not currently usable. §8.2 makes that the
/// only two outcomes: the surface returns a fully attested row, or it returns
/// nothing for that `(principal_id, device_id)` — which is also the
/// anti-enumeration shape, since an omission is indistinguishable from "no
/// relationship" and from "no such device".
pub(crate) async fn attested_device_record(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    device_id: &arkret_wire::DeviceId,
    facet: crate::routing::identity::device_signing::DeviceSigningDirectoryFacet,
    algorithms: arkret_models_crypto::AlgorithmKeyRecords,
) -> Result<Option<PeerQueryDeviceRecord>, AppError> {
    use arkret_wire::NonEmptyString;

    let Some((evidence, signer_evidence_ref)) =
        issue_current_account_device_signer_evidence(state, account_id, device_id, &facet)
            .await
            .map_err(directory_evidence_service_error)?
    else {
        return Ok(None);
    };
    let trust_algorithms = facet
        .trust_algorithms
        .unwrap_or_default()
        .into_iter()
        .map(NonEmptyString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(Some(PeerQueryDeviceRecord {
        signer_evidence_ref,
        algorithms,
        trust_algorithms,
        device_projection_attestation: evidence.device_projection_attestation,
    }))
}

/// Sign a fresh `account_device_signer_evidence` for one local device and
/// retain the complete object and its ref before returning either.
///
/// The attestation is signed from the current accepted authorization, and the
/// retention transaction re-proves the same PCR status and authority cut at
/// `attested_at`, refusing with the device's registered code when it is no
/// longer active. The keys/query row and the `producer_device_evidence` of
/// every `authority_forward` attempt (device-lifecycle §8.2.2) are issued
/// here; neither reuses an earlier object. `None` means the current device
/// material is not available at all.
pub(crate) async fn issue_current_account_device_signer_evidence(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    device_id: &arkret_wire::DeviceId,
    facet: &crate::routing::identity::device_signing::DeviceSigningDirectoryFacet,
) -> coland_services::ServiceResult<
    Option<(
        arkret_models_identity::AccountDeviceSignerEvidence,
        arkret_wire::SignerEvidenceRef,
    )>,
> {
    let Some((evidence, authorization_ref)) =
        prepare_current_account_device_signer_evidence(state, account_id, device_id, facet).await?
    else {
        return Ok(None);
    };
    let reference = state
        .persistence()
        .retain_current_account_device_signer_evidence(&evidence, &authorization_ref)
        .await?;
    Ok(Some((evidence, reference)))
}

/// Prepare the original root without a pre-admission durable side effect.
/// Local Event acceptance retains it with its Commit under the same PCR cut;
/// explicit keys/query and forwarded evidence issuance use the wrapper above.
pub(crate) async fn prepare_current_account_device_signer_evidence(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    device_id: &arkret_wire::DeviceId,
    facet: &crate::routing::identity::device_signing::DeviceSigningDirectoryFacet,
) -> coland_services::ServiceResult<
    Option<(
        arkret_models_identity::AccountDeviceSignerEvidence,
        arkret_wire::CommittedEventRef,
    )>,
> {
    use arkret_models_crypto::{DeviceAuthorizationWindow, DeviceProjectionAttestationCore};
    use arkret_models_identity::AccountDeviceSignerEvidence;
    use arkret_wire::{ActorId, DidKey};
    use coland_services::ServiceError;

    if account_id.station_id != state.service_core_id() || facet.status != DeviceStatus::Active {
        return Ok(None);
    }
    let actor = ActorId::account(account_id.clone());
    let Some(authorization) =
        super::device_signing::current_device_authorization(state, &actor, device_id, facet)
            .await?
    else {
        return Ok(None);
    };
    let selector = super::device_generation::active_device_revocation_gate_selector(
        state,
        account_id.principal_id.as_str(),
        device_id.as_str(),
    )
    .await?;
    let (Some(facet_event), Some(facet_generation)) = (
        facet.device_authorize_event_id.as_ref(),
        facet.authorized_generation_ref,
    ) else {
        return Ok(None);
    };
    if &selector.authorization_ref.event_id != facet_event
        || authorization.authorized_generation_ref != facet_generation
        || facet.signing_key_did.as_deref() != Some(authorization.device_public_key_did.as_str())
        || facet.hpke_key.as_deref() != Some(authorization.hpke_key.as_str())
    {
        return Ok(None);
    }
    let attested_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        crate::wire::now().timestamp_millis(),
    )
    .ok_or_else(|| ServiceError::internal("current attestation time is invalid"))?;
    let expires_at = (attested_at + chrono::Duration::minutes(5)).min(
        authorization
            .expires_at
            .flatten()
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    if expires_at <= attested_at {
        return Ok(None);
    }
    let service_resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|error| {
                ServiceError::Conflict(format!(
                    "{}: current Service resolution is unavailable: {}",
                    coland_storage::ConflictCode::TemporarilyUnavailable,
                    error.message
                ))
            })?;
    let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
        DeviceProjectionAttestationCore {
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            device_signing_key_did: DidKey::new(authorization.device_public_key_did.to_string())
                .map_err(|error| ServiceError::internal(error.to_string()))?,
            hpke_key: authorization.hpke_key.clone(),
            device_authorize_event_id: selector.authorization_ref.event_id.clone(),
            authorized_generation_ref: authorization.authorized_generation_ref,
            device_status: DeviceStatus::Active,
            authorization_window: DeviceAuthorizationWindow {
                not_before: authorization.not_before,
                expires_at: authorization.expires_at.flatten(),
            },
            attested_at,
            expires_at,
        },
        state
            .service_verification_method("notary-key")
            .map_err(|error| ServiceError::internal(error.to_string()))?,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| ServiceError::internal(error.to_string()))?;
    let evidence = AccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution,
    };
    Ok(Some((evidence, selector.authorization_ref)))
}

/// `device-lifecycle.md` §8.2 check 3 / check 4 applied to one attested row
/// against the `device_generations` entry that travels in the same response.
///
/// Kept separate from the proof check so both the local-origin and the remote
/// path run byte-identical generation and status rules.
fn attested_row_is_current(
    record: &PeerQueryDeviceRecord,
    generation: &arkret_models_crypto::AccountDeviceGenerationEntry,
) -> bool {
    let attested = &record.device_projection_attestation.attestation;
    attested.device_status == DeviceStatus::Active
        && attested.authorized_generation_ref
            == generation.generation_state.current_device_generation_ref
}

/// Verify one **remote** origin row, then project it onto the client-facing
/// shape.
///
/// `device-lifecycle.md` §8.2: this Station MUST verify the origin
/// attestation's proof, its issuer/assertion authority, the complete AccountId
/// and device map key, the generation and the validity window *before* the row
/// may become a client result, and it MUST NOT turn an unverified peer row into
/// a verified one by dropping its proof. Only after all of that does
/// `project_verified_row` copy the already-signed values verbatim — `expires_at`
/// included, never extended — and forward the very same `signer_evidence_ref`.
async fn verified_remote_device_projection(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
    device_id: &arkret_wire::DeviceId,
    record: &PeerQueryDeviceRecord,
    generation: &arkret_models_crypto::AccountDeviceGenerationEntry,
) -> Option<QueryDeviceRecord> {
    if record
        .validate_attestation_binding(account_id, device_id)
        .is_err()
        || !attested_row_is_current(record, generation)
    {
        return None;
    }
    let attestation = &record.device_projection_attestation;
    let document =
        super::current_signer_evidence::current_device_projection_document(state, attestation)
            .await
            .ok()?;
    super::current_signer_evidence::verify_current_device_projection(
        attestation,
        &document,
        chrono::Utc::now(),
    )
    .ok()?;
    record.project_verified_row(account_id, device_id).ok()
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.read.lookup", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.read.lookup.v1"))]
async fn keys_query(
    aa: AuthArgs,
    body: JsonBody<KeysQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let mut result = Vec::new();
    let mut device_generations = Vec::new();
    let mut failures = Vec::new();
    let requester = super::session_actor::validated_session_actor(state, &session).await?;
    let requester_account = requester
        .as_account_id()
        .ok_or_else(|| AppError::capability_denied("keys query requires an Account requester"))?
        .clone();
    let mut local = Vec::new();
    let mut remote = BTreeMap::<arkret_wire::DidCoreId, Vec<_>>::new();
    for selector in body.device_keys {
        if selector.account_id.station_id == state.service_core_id() {
            local.push(selector);
        } else {
            remote
                .entry(selector.account_id.station_id.clone())
                .or_default()
                .push(selector);
        }
    }
    for selector in local {
        let account_id = selector.account_id;
        // This directory only attests accounts owned by this Station. A foreign
        // selector must never borrow the local account's same-principal devices.
        if account_id.station_id != state.service_core_id() {
            continue;
        }
        let actor_core = &account_id.principal_id;
        let devices = selector.device_ids;
        if state
            .identities()
            .account(&account_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .is_none()
        {
            continue;
        }
        let target = arkret_wire::ActorId::account(account_id.clone());
        if !keys_query_actor_visible_to_requester(
            &state.projections().snapshot(),
            &requester,
            &target,
        ) {
            continue;
        }
        let generation_entry =
            crate::routing::identity::device_generation::current_device_generation(
                state,
                actor_core.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .map(
                |generation| arkret_models_crypto::AccountDeviceGenerationEntry {
                    account_id: account_id.clone(),
                    generation_state: arkret_models_crypto::keys::DeviceGenerationState {
                        current_device_generation_ref: generation.current_ref,
                    },
                },
            );
        if let Some(entry) = generation_entry.clone() {
            device_generations.push(entry);
        }
        let mut actor_keys = BTreeMap::new();
        for device_id in devices {
            let device_record = state
                .identities()
                .find_device(FindDeviceQuery {
                    actor_id: actor_core.as_str().to_owned(),
                    device_id: device_id.as_str().to_owned(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if device_record.is_none() {
                continue;
            }
            // Carry the opaque uploaded prekey blob under `algorithms`. The demo
            // upload stores one payload object per device, so it is surfaced as a
            // single `algorithms` map (key→value) rather than per-algorithm
            // key_records; the directory facet below is the real signing-key data.
            let algorithms = match state
                .key_material()
                .bundle(actor_core.as_str(), device_id.as_str())
                .await
            {
                Ok(Some(value)) => value
                    .get("one_time_keys")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default(),
                _ => BTreeMap::new(),
            };
            // Signing-key directory facet from the authoritative devices-table
            // `payload.device_public_key_did`: returns the verify key only for a
            // verified, non-revoked device. Shared with the recovery receipt
            // predicate via `resolve_device_signing_directory_facet`.
            let facet =
                crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                    state,
                    actor_core.as_str(),
                    device_id.as_str(),
                )
                .await;
            // `device-lifecycle.md` §8.2: a row is complete and attested or it
            // is not returned. A revoked, unverified or fenced
            // device is omitted entirely rather than degraded into a partial
            // row, so its prekey bundle is never surfaced, no signing key
            // leaks, and a caller can never mistake an incomplete row for a
            // usable one.
            let Some(record) =
                attested_device_record(state, &account_id, &device_id, facet, algorithms).await?
            else {
                continue;
            };
            // Local accounts take the same "verified, then projected" path as
            // remote ones, so the self surface has exactly one row type. Here
            // this Station *is* the origin: the attested values were derived
            // from its own durable device projection inside this request and
            // signed above, so the verification step is the origin derivation
            // itself plus the §8.2 generation / status rules — it deliberately
            // does not re-resolve its own DID Document to check a signature it
            // just produced. The projection itself is the same verbatim copy
            // the remote path performs; the attestation and its proof stay on
            // the origin side and never reach the client.
            let Some(generation) = generation_entry.as_ref() else {
                continue;
            };
            if !attested_row_is_current(&record, generation) {
                continue;
            }
            let Ok(projected) = record.project_verified_row(&account_id, &device_id) else {
                continue;
            };
            actor_keys.insert(device_id, projected);
        }
        result.push(arkret_models_crypto::QueryAccountDeviceEntry {
            account_id,
            device_keys: actor_keys,
        });
    }
    for (destination, selectors) in remote {
        let mut by_basis =
            BTreeMap::<String, (arkret_models_crypto::PeerKeysRelationshipBasis, Vec<_>)>::new();
        for selector in selectors {
            let target = arkret_wire::ActorId::account(selector.account_id.clone());
            if let Some(basis) =
                peer_relationship_basis_for_target(state, &requester, &target).await?
            {
                let key = serde_json::to_string(&basis)
                    .map_err(|error| AppError::internal(error.to_string()))?;
                by_basis
                    .entry(key)
                    .or_insert_with(|| (basis, Vec::new()))
                    .1
                    .push(selector);
            }
        }
        for (_, (relationship_basis, selectors)) in by_basis {
            let peer_request = arkret_models_crypto::PeerKeysQueryRequestBody {
                request_id: arkret_wire::RequestId::new(format!(
                    "ak:request:{}",
                    uuid::Uuid::now_v7()
                ))
                .map_err(|error| AppError::internal(error.to_string()))?,
                requester_account_id: requester_account.clone(),
                purpose: arkret_models_crypto::PeerKeysQueryPurpose::E2eeMessageEncryption,
                relationship_basis,
                device_keys: selectors.clone(),
            };
            match proxy_peer_keys_query(state, &peer_request, &destination).await {
                Ok(outcome) => {
                    let arkret_models_crypto::PeerKeysQueryOutcome {
                        device_keys: peer_entries,
                        device_generations: peer_generations,
                        failures: peer_failures,
                        ..
                    } = outcome;
                    failures.extend(peer_failures);
                    for entry in peer_entries {
                        let generation = peer_generations
                            .iter()
                            .find(|generation| generation.account_id == entry.account_id);
                        let Some(generation) = generation else {
                            failures.extend(entry.device_keys.keys().cloned().map(|device_id| {
                                arkret_models_crypto::QueryFailure {
                                    account_id: Some(entry.account_id.clone()),
                                    device_id: Some(device_id),
                                    reason_code: arkret_models_crypto::QueryFailureReason::DeviceDirectoryUnavailable,
                                    retry_after_ms: None,
                                }
                            }));
                            continue;
                        };
                        let mut verified = BTreeMap::new();
                        for (device_id, record) in entry.device_keys {
                            // §8.2: verify the origin attestation first, then
                            // hand the client the pruned projection. The peer
                            // row — attestation and proof included — stops here.
                            let projected = verified_remote_device_projection(
                                state,
                                &entry.account_id,
                                &device_id,
                                &record,
                                generation,
                            )
                            .await;
                            if let Some(projected) = projected {
                                verified.insert(device_id, projected);
                            } else {
                                failures.push(arkret_models_crypto::QueryFailure {
                                    account_id: Some(entry.account_id.clone()),
                                    device_id: Some(device_id),
                                    reason_code: arkret_models_crypto::QueryFailureReason::DeviceDirectoryUnavailable,
                                    retry_after_ms: None,
                                });
                            }
                        }
                        if !verified.is_empty() {
                            result.push(arkret_models_crypto::QueryAccountDeviceEntry {
                                account_id: entry.account_id,
                                device_keys: verified,
                            });
                            device_generations.push(generation.clone());
                        }
                    }
                }
                Err(_) => {
                    for selector in selectors {
                        for device_id in selector.device_ids {
                            failures.push(arkret_models_crypto::QueryFailure {
                                account_id: Some(selector.account_id.clone()),
                                device_id: Some(device_id),
                                reason_code: arkret_models_crypto::QueryFailureReason::DeviceDirectoryUnavailable,
                                retry_after_ms: None,
                            });
                        }
                    }
                }
            }
        }
    }
    json_ok(KeysQueryOutcome {
        device_keys: result,
        failures,
        device_generations,
    })
}

async fn peer_relationship_basis_for_target(
    state: &AppState,
    requester: &arkret_wire::ActorId,
    target: &arkret_wire::ActorId,
) -> Result<Option<arkret_models_crypto::PeerKeysRelationshipBasis>, AppError> {
    let projection = state.projections().snapshot();
    if let Some(((realm_id, _), _)) =
        projection
            .members
            .iter()
            .find(|((realm_id, actor), membership)| {
                actor == &requester.to_string()
                    && membership.state == "join"
                    && projection
                        .member(realm_id, &target.to_string())
                        .is_some_and(|row| row.state == "join")
            })
    {
        return Ok(Some(
            arkret_models_crypto::PeerKeysRelationshipBasis::RealmMembership {
                realm_id: arkret_wire::RealmId::new(realm_id.clone())
                    .map_err(|error| AppError::internal(error.to_string()))?,
            },
        ));
    }
    let contact = state
        .contacts()
        .contact_any(requester, target)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(contact
        .filter(|contact| contact.status == "accepted")
        .map(|_| arkret_models_crypto::PeerKeysRelationshipBasis::Contact {}))
}

async fn proxy_peer_keys_query(
    state: &AppState,
    request: &arkret_models_crypto::PeerKeysQueryRequestBody,
    destination: &arkret_wire::DidCoreId,
) -> Result<arkret_models_crypto::PeerKeysQueryOutcome, AppError> {
    let route = crate::routing::federation::resolved_peer_target(
        state,
        destination.as_str(),
        "station",
        false,
    )
    .await
    .map_err(|_| AppError::not_found("peer device directory is unavailable"))?;
    let target = format!(
        "{}/_arkret/peer/keys/query",
        route.base_url.trim_end_matches('/')
    );
    let body = arkret_canonical::canonical_json_bytes(request)
        .map_err(|error| AppError::internal(format!("canonical peer keys request: {error}")))?;
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "peer keys query",
        state.config().development_mode,
        std::time::Duration::from_secs(10),
    )
    .map_err(|_| AppError::not_found("peer device directory is unavailable"))?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    for (name, value) in [
        (
            "content-digest",
            crate::routing::federation::outbox::content_digest_header_value(&body),
        ),
        ("source-service-id", state.service_id().to_owned()),
        ("destination-service-id", destination.to_string()),
        (
            "source-trust-domain",
            state.config().trust_domain.to_string(),
        ),
        ("destination-trust-domain", route.trust_domain),
        ("arkret-operation", "ak.peer.keys.read.lookup.v1".to_owned()),
    ] {
        crate::routing::federation::outbox::insert_header_if_valid(&mut headers, name, &value);
    }
    let headers = crate::routing::federation::outbox::rfc9421_sign(state, headers, "POST", &target);
    let mut response = client
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| AppError::not_found("peer device directory is unavailable"))?;
    if !response.status().is_success() {
        return Err(AppError::not_found("peer device directory is unavailable"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::not_found("peer device directory is unavailable"))?
    {
        if bytes.len().saturating_add(chunk.len()) > 512 * 1024 {
            return Err(AppError::from_rejection(
                arkret_wire::ErrorCode::LimitExceeded,
                "peer device directory response exceeds budget",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome: arkret_models_crypto::PeerKeysQueryOutcome = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::not_found("peer device directory is unavailable"))?;
    outcome
        .validate_for_request(request)
        .map_err(|_| AppError::not_found("peer device directory is unavailable"))?;
    Ok(outcome)
}

/// Reuse the exact-device directory gate for the query-local signer surface.
pub(crate) async fn current_device_projection_for_signer(
    state: &AppState,
    recipient: &arkret_wire::AccountId,
    realm: &arkret_wire::RealmId,
    account: &arkret_wire::AccountId,
    device: &arkret_wire::DeviceId,
) -> Option<QueryDeviceRecord> {
    if account.station_id == state.service_core_id() {
        let facet = super::device_signing::resolve_device_signing_directory_facet(
            state,
            account.principal_id.as_str(),
            device.as_str(),
        )
        .await;
        let record = attested_device_record(state, account, device, facet, BTreeMap::new())
            .await
            .ok()??;
        let generation = super::device_generation::current_device_generation(
            state,
            account.principal_id.as_str(),
        )
        .await
        .ok()??;
        let generation = arkret_models_crypto::AccountDeviceGenerationEntry {
            account_id: account.clone(),
            generation_state: arkret_models_crypto::keys::DeviceGenerationState {
                current_device_generation_ref: generation.current_ref,
            },
        };
        if !attested_row_is_current(&record, &generation) {
            return None;
        }
        return record.project_verified_row(account, device).ok();
    }
    let request = arkret_models_crypto::PeerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64),
        requester_account_id: recipient.clone(),
        purpose: arkret_models_crypto::PeerKeysQueryPurpose::E2eeMessageEncryption,
        relationship_basis: arkret_models_crypto::PeerKeysRelationshipBasis::RealmMembership {
            realm_id: realm.clone(),
        },
        device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
            account_id: account.clone(),
            device_ids: vec![device.clone()],
        }],
    };
    let outcome = proxy_peer_keys_query(state, &request, &account.station_id)
        .await
        .ok()?;
    let generation = outcome
        .device_generations
        .iter()
        .find(|entry| entry.account_id == *account)?;
    let entry = outcome
        .device_keys
        .iter()
        .find(|entry| entry.account_id == *account)?;
    let record = entry.device_keys.get(device)?;
    verified_remote_device_projection(state, account, device, record, generation).await
}

/// `device-lifecycle.md` §8.2.1 — the Station-to-Station surface. It returns
/// the origin-signed `peer_query_device_record`, never the client-facing
/// projection: the requesting Station is the party that verifies the
/// attestation, and it is the one that prunes the row afterwards.
#[salvo::oapi::endpoint(operation_id = "ak.peer.keys.read.lookup", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.keys.read.lookup.v1"))]
async fn peer_keys_query(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_crypto::PeerKeysQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    crate::routing::federation::verify_inbound_peer_http_signature(state, req, true).await?;
    let source_service_id = req
        .headers()
        .get("source-service-id")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::unauthenticated("peer keys query source is missing"))?
        .to_owned();
    let body = req
        .parse_json::<arkret_models_crypto::PeerKeysQueryRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer keys query body"))?;
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let destination = body
        .destination_station_id()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if body.requester_account_id.station_id.as_str() != source_service_id
        || destination != &state.service_core_id()
    {
        return Err(AppError::unauthenticated(
            "peer keys query service binding is invalid",
        ));
    }
    let requester = arkret_wire::ActorId::account(body.requester_account_id.clone());
    let mut device_keys = Vec::new();
    let mut device_generations = Vec::new();
    for selector in &body.device_keys {
        let target = arkret_wire::ActorId::account(selector.account_id.clone());
        if !peer_keys_relationship_authorized(state, &body, &requester, &target).await? {
            continue;
        }
        if state
            .identities()
            .account(&selector.account_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .is_none()
        {
            continue;
        }
        if let Some(generation) =
            crate::routing::identity::device_generation::current_device_generation(
                state,
                selector.account_id.principal_id.as_str(),
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            device_generations.push(arkret_models_crypto::AccountDeviceGenerationEntry {
                account_id: selector.account_id.clone(),
                generation_state: arkret_models_crypto::keys::DeviceGenerationState {
                    current_device_generation_ref: generation.current_ref,
                },
            });
        }
        let mut rows = BTreeMap::new();
        for device_id in &selector.device_ids {
            let algorithms = state
                .key_material()
                .bundle(
                    selector.account_id.principal_id.as_str(),
                    device_id.as_str(),
                )
                .await
                .ok()
                .flatten()
                .and_then(|value| value.get("one_time_keys").cloned())
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or_default();
            let facet =
                crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                    state,
                    selector.account_id.principal_id.as_str(),
                    device_id.as_str(),
                )
                .await;
            if let Some(record) =
                attested_device_record(state, &selector.account_id, device_id, facet, algorithms)
                    .await?
            {
                rows.insert(device_id.clone(), record);
            }
        }
        if !rows.is_empty() {
            device_keys.push(arkret_models_crypto::PeerQueryAccountDeviceEntry {
                account_id: selector.account_id.clone(),
                device_keys: rows,
            });
        }
    }
    let outcome = arkret_models_crypto::PeerKeysQueryOutcome {
        request_id: body.request_id.clone(),
        requester_account_id: body.requester_account_id.clone(),
        device_keys,
        device_generations,
        failures: Vec::new(),
    };
    outcome
        .validate_for_request(&body)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

async fn peer_keys_relationship_authorized(
    state: &AppState,
    request: &arkret_models_crypto::PeerKeysQueryRequestBody,
    requester: &arkret_wire::ActorId,
    target: &arkret_wire::ActorId,
) -> Result<bool, AppError> {
    match &request.relationship_basis {
        arkret_models_crypto::PeerKeysRelationshipBasis::RealmMembership { realm_id } => {
            let current = state.authority_commits();
            let requester_joined = current
                .accepted_current_member_joined(realm_id, requester)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            let target_joined = current
                .accepted_current_member_joined(realm_id, target)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            Ok(requester_joined && target_joined)
        }
        arkret_models_crypto::PeerKeysRelationshipBasis::Contact {} => {
            let Some(contact) = state
                .contacts()
                .contact_any(requester, target)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                return Ok(false);
            };
            if contact.status != "accepted" {
                return Ok(false);
            }
            let scopes = if contact.requester_id == *requester {
                &contact.granted_to_requester_scopes
            } else if contact.target_id == *requester {
                &contact.granted_to_target_scopes
            } else {
                return Ok(false);
            };
            Ok(match request.purpose {
                arkret_models_crypto::PeerKeysQueryPurpose::E2eeMessageEncryption => {
                    scopes.iter().any(|scope| scope == "direct_message")
                }
                arkret_models_crypto::PeerKeysQueryPurpose::MlsGroupAdmission => {
                    scopes.iter().any(|scope| scope == "invite")
                }
                arkret_models_crypto::PeerKeysQueryPurpose::CallMedia => scopes
                    .iter()
                    .any(|scope| matches!(scope.as_str(), "voice_call" | "video_call")),
            })
        }
    }
}

fn keys_query_actor_visible_to_requester(
    projection: &coland_domain::reducer::ProjectionState,
    requester: &arkret_wire::ActorId,
    actor: &arkret_wire::ActorId,
) -> bool {
    if requester == actor {
        return true;
    }
    let requester = requester.to_string();
    let actor = actor.to_string();
    projection
        .members
        .iter()
        .any(|((realm_id, member_actor), membership)| {
            if member_actor != &requester || membership.state != "join" {
                return false;
            }
            projection
                .member(realm_id, &actor)
                .is_some_and(|membership| {
                    matches!(membership.state.as_str(), "join" | "leave" | "ban")
                })
        })
}

fn verification_method_controller(verification_method: &str) -> &str {
    let no_query = verification_method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(verification_method);
    no_query
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(no_query)
}

pub(crate) fn device_signature_kid_points_to_device_key(
    kid: &str,
    actor: &str,
    device_public_key: &str,
) -> bool {
    let expected_principal_id_key = device_public_key
        .strip_prefix("did:key:")
        .map_or_else(|| format!("did:key:{device_public_key}"), str::to_owned);
    kid == expected_principal_id_key
        || kid
            .strip_prefix(&expected_principal_id_key)
            .is_some_and(|rest| rest.starts_with('#') || rest.starts_with('?'))
        || verification_method_controller(kid) == actor
        || arkret_wire::Did::new(verification_method_controller(kid).to_owned())
            .and_then(|controller| arkret_wire::project_did_to_core_id(&controller))
            .is_ok_and(|controller| controller.as_str() == actor)
}

fn verify_keys_upload_device_signature(
    actor: &str,
    current_device: Option<&DeviceIdentity>,
    unsigned: &KeysUploadUnsignedRequest,
    device_signature: &arkret_models_crypto::artifacts_keys::KeyOperationSignature,
) -> Result<(), AppError> {
    let record = current_device.ok_or_else(|| {
        AppError::param_invalid("keys/upload requires an authorized device_public_key")
    })?;
    if record.verification_state != "verified" || record.revoked_at.is_some() {
        return Err(AppError::param_invalid(
            "keys/upload requires a verified, non-revoked device",
        ));
    }
    let device_public_key = record
        .payload
        .get("device_public_key_did")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::param_invalid("keys/upload requires authoritative device_public_key")
        })?;
    let signature_algorithm = device_signature
        .signature_algorithm
        .as_ref()
        .map(arkret_wire::NonEmptyString::as_str)
        .unwrap_or_default();
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(
            "keys/upload device_signature.signature_algorithm must be Ed25519",
        ));
    }
    let kid = device_signature.kid.as_str();
    if !device_signature_kid_points_to_device_key(kid, actor, device_public_key) {
        return Err(AppError::param_invalid(
            "keys/upload device_signature.kid does not point to the authorized device key",
        ));
    }
    let signing_input = arkret_models_crypto::keys_upload_signing_input(unsigned)
        .map_err(|error| AppError::param_invalid(format!("keys/upload canonicalize: {error}")))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(device_signature.sig.as_bytes())
        .map_err(|_| AppError::param_invalid("keys/upload signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AppError::param_invalid("keys/upload signature must be 64 bytes"))?;
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|error| AppError::param_invalid(format!("device signing key is invalid: {error}")))?;
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|_| AppError::param_invalid("keys/upload signature verification failed"))
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.command.claim", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.command.claim.v1"))]
async fn keys_claim(
    aa: AuthArgs,
    body: JsonBody<KeysClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let requester = super::session_actor::validated_session_actor(state, &session).await?;

    let body = body.into_inner();
    let mut claimed = Vec::new();
    for entry in body.one_time_keys {
        let account_id = entry.account_id;
        if account_id.station_id != state.service_core_id() {
            continue;
        }
        let actor_core = &account_id.principal_id;
        let devices = entry.device_algorithms;
        if state
            .identities()
            .account(&account_id)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .is_none()
        {
            continue;
        }
        let target = arkret_wire::ActorId::account(account_id.clone());
        if !keys_query_actor_visible_to_requester(
            &state.projections().snapshot(),
            &requester,
            &target,
        ) {
            continue;
        }
        let mut device_map = BTreeMap::new();
        for (device_id, algorithm) in devices {
            let facet =
                crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                    state,
                    actor_core.as_str(),
                    device_id.as_str(),
                )
                .await;
            if !matches!(facet.status, DeviceStatus::Active) {
                continue;
            }
            if let Ok(Some(key)) = state
                .key_material()
                .claim_one_time_key(actor_core.as_str(), device_id.as_str())
                .await
            {
                let key = serde_json::from_value(key).map_err(|error| {
                    AppError::internal(format!("stored one-time key is invalid: {error}"))
                })?;
                device_map.insert(device_id, BTreeMap::from([(algorithm, key)]));
            }
        }
        claimed.push(arkret_models_crypto::AccountDeviceKeyEntry {
            account_id,
            device_keys: device_map,
        });
    }
    json_ok(KeysClaimOutcome {
        one_time_keys: claimed,
        failures: Vec::new(),
    })
}

/// Server-to-server bearer gate for the device signing-key directory read.
///
/// Reuses the deployment's `COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER`: the Auth
/// Server (coauth) already holds this static bearer for the same Station (it registers embedded
/// `did:webvh` records with it), so the directory read it issues while verifying a device holder
/// proof rides the same trust edge without minting a second credential. Compared in constant-ish
/// form via SHA-256 digests of both sides.
fn require_device_directory_bearer(state: &AppState, req: &Request) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "device signing-key directory read requires COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        ));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "device signing-key directory read requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid device signing-key directory bearer",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.gate.account.device_signing_keys.query",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.gate.account.device_signing_keys.query")
)]
async fn device_signing_keys_query(
    body: JsonBody<DeviceSigningKeyDirectoryQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DeviceSigningKeyDirectoryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_device_directory_bearer(state, req)?;

    let body = body.into_inner();
    let principal_id = body.principal_id;

    // Resolve the target device-id set. An explicit, non-empty `device_ids`
    // restricts the lookup; otherwise enumerate the principal's directory
    // (revoked devices are dropped below by the facet predicate either way).
    let device_ids: Vec<String> = if body.device_ids.is_empty() {
        state
            .identities()
            .devices_for_actor(principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .into_iter()
            .map(|record| record.device_id)
            .collect()
    } else {
        body.device_ids
            .into_iter()
            .map(|device_id| device_id.as_str().to_owned())
            .collect()
    };

    let mut devices = Vec::new();
    for device_id in device_ids {
        // Single source of truth: the same verified + non-revoked predicate the
        // `keys/query` directory facet applies (device-lifecycle.md §8.2). A
        // revoked / unverified device yields no `signing_key_did`, so it never
        // surfaces here.
        let facet =
            crate::routing::identity::device_signing::resolve_device_signing_directory_facet(
                state,
                principal_id.as_str(),
                &device_id,
            )
            .await;
        if !matches!(facet.status, DeviceStatus::Active) {
            continue;
        }
        let Some(device_signing_key_did) = facet.signing_key_did else {
            continue;
        };
        let Ok(typed_device_id) = arkret_identifiers::DeviceId::new(device_id.clone()) else {
            continue;
        };
        devices.push(AuthorizedDeviceSigningKey {
            device_id: typed_device_id,
            device_signing_key_did,
            device_status: DeviceStatus::Active,
            device_authorize_event_id: facet.device_authorize_event_id,
        });
    }

    json_ok(DeviceSigningKeyDirectoryOutcome {
        principal_id,
        devices,
    })
}

#[cfg(test)]
mod tests {
    use super::{device_signature_kid_points_to_device_key, keys_query_actor_visible_to_requester};

    #[test]
    fn directory_evidence_cut_race_preserves_registered_retryable_error() {
        let error =
            super::directory_evidence_service_error(coland_services::ServiceError::Conflict(
                "temporarily_unavailable: current evidence retention lost its cut".into(),
            ));
        assert_eq!(error.code, arkret_wire::ErrorCode::TemporarilyUnavailable);
        assert_eq!(
            error.http_status(),
            salvo::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let database = super::directory_evidence_service_error(
            coland_services::ServiceError::Database("connection failure".into()),
        );
        assert_eq!(database.code, arkret_wire::ErrorCode::InternalError);
    }
    #[test]
    fn key_visibility_requires_exact_actor_membership_not_a_shared_principal() {
        use arkret_wire::{AccountId, ActorId, DidCoreId};
        let actor = |principal: &str, station: &str| {
            ActorId::account(AccountId::new(
                DidCoreId::new(principal).unwrap(),
                DidCoreId::new(station).unwrap(),
            ))
        };
        let alice = actor(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let other_alice = actor(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:other.example",
        );
        let bob = actor(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        let mut projection = coland_domain::reducer::ProjectionState::default();
        assert!(keys_query_actor_visible_to_requester(
            &projection,
            &alice,
            &alice
        ));
        assert!(!keys_query_actor_visible_to_requester(
            &projection,
            &other_alice,
            &alice
        ));
        for member in [&alice, &bob] {
            let member = member.to_string();
            projection.members.insert(
                ("realm".into(), member.clone()),
                coland_domain::reducer::ColandMembershipState {
                    member,
                    realm_id: "realm".into(),
                    state: "join".into(),
                    role: "member".into(),
                    membership_event_ref: None,
                    invited_at: None,
                    joined_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    reason: None,
                },
            );
        }
        assert!(keys_query_actor_visible_to_requester(
            &projection,
            &alice,
            &bob
        ));
        assert!(!keys_query_actor_visible_to_requester(
            &projection,
            &other_alice,
            &bob
        ));
        assert!(!keys_query_actor_visible_to_requester(
            &projection,
            &bob,
            &other_alice
        ));
    }

    #[test]
    fn device_signature_kid_projects_did_controller_to_core_actor() {
        assert!(device_signature_kid_points_to_device_key(
            "did:web:alice.example#ak:device:primary",
            "ak:did_core:web:alice.example",
            "z6MkAuthorizedDeviceKey",
        ));
        assert!(!device_signature_kid_points_to_device_key(
            "did:web:mallory.example#ak:device:primary",
            "ak:did_core:web:alice.example",
            "z6MkAuthorizedDeviceKey",
        ));
    }
}
