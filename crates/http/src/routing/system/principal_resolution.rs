use arkret_models_identity::{
    DidDocument, PrincipalResolutionProjection, PrincipalResolutionProjectionAttestationCore,
    PublicPrincipalResolution, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionDidBindingMethodProofKind, ResolutionMethodEvidenceBoundary,
    ResolutionMethodHistoryEvidence,
};
use arkret_wire::{AccountId, Did, DidCoreId, Hash};
use coland_http::error::AppError;
use coland_services::identity::PinnedDidVersionStatus;
use salvo::oapi::extract::{PathParam, QueryParam};
use salvo::prelude::*;

use crate::state::AppState;
use crate::{JsonResult, json_ok};

pub(super) fn open_router() -> Router {
    Router::with_path("principals/{principal_id}/resolution").get(open_principal_resolution)
}

/// Freshness window of the projection attestation.
///
/// A consumer performing a security-sensitive action refetches at or after
/// `expires_at`; a cache never extends it. This is first-contact identity
/// resolution, not an issuance fence, so it is not the 30-second bound the
/// device-revocation gate receipt uses.
const PROJECTION_ATTESTATION_TTL_SECONDS: i64 = 600;

#[salvo::oapi::endpoint(operation_id = "ak.open.identity.read.resolution", tags("identity"))]
async fn open_principal_resolution(
    principal_id: PathParam<String>,
    station_id: QueryParam<String, true>,
    depot: &mut Depot,
) -> JsonResult<PublicPrincipalResolution> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let principal_id = DidCoreId::new(principal_id.into_inner())
        .map_err(|_| AppError::not_found("principal resolution not found"))?;
    let station_id = DidCoreId::new(station_id.into_inner())
        .map_err(|_| AppError::param_invalid("invalid station_id"))?;
    let authority = AccountId::new(principal_id.clone(), station_id);
    let (evidence, _) = current_public_principal_resolution(state, &authority).await?;
    json_ok(evidence)
}

pub(crate) async fn current_public_principal_resolution(
    state: &AppState,
    authority: &AccountId,
) -> Result<(PublicPrincipalResolution, DidDocument), AppError> {
    let record = state
        .persistence()
        .principal_resolution_by_account_id(authority)
        .await
        .map_err(|error| AppError::internal(format!("principal resolution store failed: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution not found"))?;
    if &record.account_id != authority {
        return Err(AppError::not_found("principal resolution not found"));
    }

    let (method_history_evidence, normalized_did_document) =
        principal_method_history_evidence(state, &record.projection, true).await?;
    let issued_at = chrono::Utc::now();
    let method_history_evidence_digest = Hash::new(
        arkret_canonical::canonical_sha256(&method_history_evidence).map_err(|error| {
            AppError::internal(format!("method history evidence digest failed: {error}"))
        })?,
    )
    .map_err(|error| AppError::internal(format!("method history digest is invalid: {error}")))?;
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(AppError::internal)?;
    let projection_attestation =
        arkret_signatures::service_resolution::sign_principal_resolution_projection_attestation(
            PrincipalResolutionProjectionAttestationCore {
                account_id: authority.clone(),
                resolution_projection: record.projection.clone(),
                method_history_evidence_digest,
                issued_at,
                expires_at: issued_at
                    + chrono::Duration::seconds(PROJECTION_ATTESTATION_TTL_SECONDS),
            },
            verification_method,
            state.notary_signing_key().as_ref(),
        )
        .map_err(|error| {
            AppError::internal(format!("principal resolution attestation failed: {error}"))
        })?;
    let evidence = PublicPrincipalResolution {
        account_id: authority.clone(),
        resolution_projection: record.projection,
        method_history_evidence,
        projection_attestation,
    };
    evidence.validate_attestation_binding().map_err(|error| {
        AppError::internal(format!(
            "principal resolution attestation binding is invalid: {error}"
        ))
    })?;
    let response_bytes = arkret_canonical::canonical_json_bytes(&evidence).map_err(|error| {
        AppError::internal(format!("principal resolution encoding failed: {error}"))
    })?;
    if response_bytes.len() > 1_048_576 {
        return Err(crate::app_error!(
            LimitExceeded,
            "principal resolution evidence exceeds 1 MiB",
        ));
    }
    Ok((evidence, normalized_did_document))
}

pub(crate) async fn principal_method_history_evidence(
    state: &AppState,
    projection: &PrincipalResolutionProjection,
    require_current: bool,
) -> Result<(ResolutionMethodHistoryEvidence, DidDocument), AppError> {
    let did = Did::new(projection.did.to_string())
        .map_err(|error| AppError::internal(format!("stored principal did is invalid: {error}")))?;
    let boundary = ResolutionMethodEvidenceBoundary {
        from_method_history_head: projection.method_history_head.clone(),
        from_version_id: projection.version_id.clone(),
        to_method_history_head: projection.method_history_head.clone(),
        to_version_id: projection.version_id.clone(),
    };
    match did.method() {
        "webvh" => {
            let history_head =
                Hash::new(projection.method_history_head.clone()).map_err(|error| {
                    AppError::internal(format!(
                        "stored did:webvh method-history head is invalid: {error}"
                    ))
                })?;
            let pinned = state
                .dids()
                .resolve_pinned_webvh_state(&did, &projection.version_id, &history_head)
                .await
                .map_err(|error| {
                    crate::app_error!(
                        TemporarilyUnavailable,
                        format!("current principal did:webvh history is unverifiable: {error}"),
                    )
                })?;
            if require_current && pinned.status != PinnedDidVersionStatus::Current {
                return Err(crate::app_error!(
                    TemporarilyUnavailable,
                    "principal did:webvh commitment is not the current verified method head",
                ));
            }
            let document: DidDocument =
                serde_json::from_value(pinned.document).map_err(|error| {
                    AppError::internal(format!(
                        "resolved principal DID document is invalid: {error}"
                    ))
                })?;
            let document_digest = canonical_document_digest(&document)?;
            let mut events = state
                .dids()
                .log_events(did.as_str())
                .await
                .map_err(|error| {
                    crate::app_error!(
                        TemporarilyUnavailable,
                        format!("durable principal WebVH history unavailable: {error}"),
                    )
                })?;
            events.sort_by(|left, right| {
                (left.sequence, left.event_digest.as_str())
                    .cmp(&(right.sequence, right.event_digest.as_str()))
            });
            let terminal = events
                .iter()
                .position(|event| {
                    event.event_digest == projection.method_history_head
                        && event
                            .operation
                            .get("versionId")
                            .and_then(serde_json::Value::as_str)
                            == Some(projection.version_id.as_str())
                })
                .ok_or_else(|| {
                    crate::app_error!(
                        TemporarilyUnavailable,
                        "durable principal WebVH history does not contain the projected head",
                    )
                })?;
            let log_entries = events
                .into_iter()
                .take(terminal + 1)
                .map(|event| event.operation)
                .collect::<Vec<_>>();
            for entry in &log_entries {
                let parameters = entry.get("parameters").ok_or_else(|| {
                    crate::app_error!(
                        TemporarilyUnavailable,
                        "durable principal WebVH history has invalid parameters",
                    )
                })?;
                if arkret_identity::parse_did_webvh_witness_policy(parameters)
                    .map_err(|error| {
                        crate::app_error!(
                            TemporarilyUnavailable,
                            format!("principal WebVH witness policy is invalid: {error}"),
                        )
                    })?
                    .is_some()
                {
                    return Err(crate::app_error!(
                        TemporarilyUnavailable,
                        "principal WebVH witness records are unavailable",
                    ));
                }
            }
            let witness_proofs_digest = canonical_digest(&Vec::<serde_json::Value>::new())?;
            Ok((
                ResolutionMethodHistoryEvidence::WebvhLog {
                    boundary,
                    evidence: ResolutionDidBindingEvidenceReceipt {
                        kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                        method: "webvh".to_owned(),
                        document_digest,
                        method_proofs: vec![ResolutionDidBindingMethodProof {
                            kind: ResolutionDidBindingMethodProofKind::WebvhLog,
                            history_head: projection.method_history_head.clone(),
                            witnesses: Vec::new(),
                            witness_proofs_digest,
                        }],
                    },
                    log_entries,
                    witness_records: Vec::new(),
                },
                document,
            ))
        }
        "web" | "key" => {
            let resolved = state.dids().resolve_did(&did).await.map_err(|error| {
                crate::app_error!(
                    TemporarilyUnavailable,
                    format!("current principal DID document is unverifiable: {error}"),
                )
            })?;
            let document: DidDocument =
                serde_json::from_value(serde_json::to_value(resolved).map_err(|error| {
                    AppError::internal(format!("resolved principal DID encode failed: {error}"))
                })?)
                .map_err(|error| {
                    AppError::internal(format!(
                        "resolved principal DID document is invalid: {error}"
                    ))
                })?;
            let document_digest = canonical_document_digest(&document)?;
            let evidence = ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: did.method().to_owned(),
                document_digest,
                method_proofs: Vec::new(),
            };
            if did.method() == "web" {
                validate_did_web_coordinates(projection, &evidence.document_digest)?;
                Ok((
                    ResolutionMethodHistoryEvidence::DidWebDocument { boundary, evidence },
                    document,
                ))
            } else {
                validate_did_key_coordinates(projection, &projection.did)?;
                Ok((
                    ResolutionMethodHistoryEvidence::DidKeyExpansion { boundary, evidence },
                    document,
                ))
            }
        }
        method => Err(crate::app_error!(
            TemporarilyUnavailable,
            format!("principal DID method {method:?} has no active resolution evidence adapter"),
        )),
    }
}

fn canonical_document_digest(document: &DidDocument) -> Result<Hash, AppError> {
    arkret_identity::document_canonical_digest(document)
        .map_err(|error| AppError::internal(format!("DID document digest failed: {error}")))
}

fn canonical_digest(value: &impl serde::Serialize) -> Result<Hash, AppError> {
    let digest = crate::util::canonical_digest(value)?;
    Hash::new(digest)
        .map_err(|error| AppError::internal(format!("canonical digest is invalid: {error}")))
}

fn validate_did_web_coordinates(
    projection: &PrincipalResolutionProjection,
    document_digest: &Hash,
) -> Result<(), AppError> {
    validate_synthetic_coordinates(
        projection,
        document_digest,
        "synthetic-jcs-sha256:",
        "did:web",
    )
}

fn validate_did_key_coordinates(
    projection: &PrincipalResolutionProjection,
    did: &Did,
) -> Result<(), AppError> {
    let digest = Hash::new(arkret_canonical::sha256_digest(did.as_str().as_bytes()))
        .map_err(|error| AppError::internal(format!("did:key digest is invalid: {error}")))?;
    validate_synthetic_coordinates(projection, &digest, "synthetic-did-sha256:", "did:key")
}

fn validate_synthetic_coordinates(
    projection: &PrincipalResolutionProjection,
    digest: &Hash,
    version_prefix: &str,
    method: &str,
) -> Result<(), AppError> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| AppError::internal("canonical SHA-256 digest lost its suite prefix"))?;
    if projection.method_history_head != digest.as_str()
        || projection.version_id != format!("{version_prefix}{hex}")
    {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            format!("stored {method} commitment does not match the active adapter"),
        ));
    }
    Ok(())
}
