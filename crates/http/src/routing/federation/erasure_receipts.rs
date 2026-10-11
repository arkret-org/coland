use arkret_models_collaboration::governance::erasure::{
    ErasureReceiptAcceptance, ErasureReceiptAcceptanceStatus, ErasureReceiptPackage,
    ErasureReceiptResource, ErasureReceiptSubmitOutcome, ErasureReceiptSubmitRequestBody,
};
use arkret_wire::ProtocolSignature;
use chrono::{Duration, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::jobs::IdempotencyState;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;

use super::signature::verify_inbound_peer_http_signature;
use crate::state::AppState;

pub(crate) fn router() -> Router {
    Router::with_path("erasure-receipts")
        .post(submit)
        .push(Router::with_path("{receipt_id}").get(get))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.erasure_receipt.command.submit",
    tags("federation")
)]
async fn submit(
    body: JsonBody<ErasureReceiptSubmitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ErasureReceiptSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    verify_inbound_peer_http_signature(state, req, true).await?;
    let source = required_header(req, "source-service-id")?;
    let source_id = arkret_wire::DidCoreId::new(source.clone())
        .map_err(|error| AppError::param_invalid(format!("Source-Service-ID invalid: {error}")))?;
    let key = required_header(req, "idempotency-key")?;
    let body = body.into_inner();
    let raw: serde_json::Value = serde_json::from_slice(
        req.payload()
            .await
            .map_err(|error| AppError::json_invalid(error.to_string()))?,
    )
    .map_err(|error| AppError::json_invalid(error.to_string()))?;
    let raw_stub = raw
        .get("package")
        .and_then(|package| package.get("retained_stub"))
        .ok_or_else(|| AppError::param_invalid("receipt package has no retained stub"))?;
    let raw_stub_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(raw_stub)
            .map_err(|error| AppError::param_invalid(error.to_string()))?,
    )
    .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if raw_stub_digest != body.package.receipt.retained_stub_digest {
        return Err(
            AppError::param_invalid("exact retained stub digest differs")
                .with_reason_code("erasure_receipt_stub_digest_mismatch"),
        );
    }
    if body.package.receipt.issuer_id.as_str() != source {
        return Err(AppError::capability_denied(
            "erasure receipt issuer must equal Source-Service-ID",
        )
        .with_reason_code("erasure_receipt_authority_invalid"));
    }
    body.package.validate_bindings().map_err(|error| {
        AppError::param_invalid(format!("invalid erasure receipt package: {error}"))
            .with_reason_code("erasure_receipt_stub_binding_mismatch")
    })?;
    let receipt_digest = body
        .package
        .computed_receipt_digest()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let proof_input = body
        .package
        .receipt
        .canonical_proof_input()
        .map_err(|error| {
            AppError::param_invalid(format!("invalid erasure receipt proof input: {error}"))
                .with_reason_code("erasure_receipt_proof_invalid")
        })?;
    body.package
        .receipt
        .validate_proof_payload_digests()
        .map_err(|error| {
            AppError::param_invalid(format!("invalid erasure receipt proof digest: {error}"))
                .with_reason_code("erasure_receipt_proof_invalid")
        })?;
    // `identity/account-lifecycle.md` requires every `proofs[]` entry to verify
    // and at least one of them to come from the issuer's currently valid
    // verification method. An erasure receipt is issued by a peer Station, so each proof is
    // verified against the DID document its own verification method resolves to; a proof from a
    // co-signing party is still verified, but only an issuer-controlled one satisfies the
    // authority requirement.
    let mut issuer_signed = false;
    for proof in &body.package.receipt.proofs {
        let proof_signer = arkret_identity::verification_method_did(
            proof.verification_method.as_str(),
        )
        .map_err(|error| {
            AppError::param_invalid(format!("erasure receipt proof method is invalid: {error}"))
                .with_reason_code("erasure_receipt_proof_invalid")
        })?;
        crate::jws_verify::validate_verification_method_controller(
            proof_signer.as_str(),
            proof.verification_method.as_str(),
        )
        .map_err(|error| {
            AppError::param_invalid(error).with_reason_code("erasure_receipt_authority_invalid")
        })?;
        let proof_key = crate::jws_verify::resolve_ed25519_pubkey_at(
            state,
            proof.verification_method.as_str(),
            body.package
                .receipt
                .issued_at
                .unwrap_or(body.package.receipt.completed_at),
        )
        .await
        .map_err(|error| {
            AppError::param_invalid(error).with_reason_code("erasure_receipt_authority_invalid")
        })?;
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &proof.signature,
                &proof_input,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: proof_key.to_bytes().to_vec(),
                },
            )
            .map_err(|reason| {
                AppError::param_invalid(format!(
                    "erasure receipt proof verification failed: {reason}"
                ))
                .with_reason_code("erasure_receipt_proof_invalid")
            })?;
        issuer_signed |= crate::jws_verify::validate_verification_method_controller(
            body.package.receipt.issuer_id.as_str(),
            proof.verification_method.as_str(),
        )
        .is_ok();
    }
    if !issuer_signed {
        return Err(AppError::param_invalid(
            "erasure receipt has no proof signed by the issuer's verification method",
        )
        .with_reason_code("erasure_receipt_authority_invalid"));
    }

    let request_hash = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(format!("erasure receipt request digest: {error}")))?;
    if let Some(stored) = state
        .jobs()
        .scoped_idempotency_record(
            &arkret_wire::ActorId::service(source_id.clone()),
            arkret_wire::ServiceOperationId::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT_V1,
            &key,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        if stored.request_hash != request_hash {
            return Err(
                AppError::conflict("Idempotency-Key reused with another receipt package")
                    .with_wire_code("duplicate_conflict"),
            );
        }
        let outcome = serde_json::from_value(stored.response_body)
            .map_err(|error| AppError::internal(format!("stored erasure outcome: {error}")))?;
        return json_ok(outcome);
    }

    let lookup_key = format!("erasure-receipt:lookup:{}", body.package.receipt.receipt_id);
    let existing = state
        .jobs()
        .idempotency_record(&state.service_core_id(), &lookup_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let acceptance = if let Some(existing) = existing {
        let stored: StoredReceipt = serde_json::from_value(existing.response_body)
            .map_err(|error| AppError::internal(format!("stored erasure package: {error}")))?;
        if stored
            .package
            .computed_receipt_digest()
            .map_err(|error| AppError::internal(error.to_string()))?
            != receipt_digest
        {
            return Err(
                AppError::conflict("receipt_id resolves to another receipt digest")
                    .with_wire_code("duplicate_conflict"),
            );
        }
        signed_acceptance(
            state,
            &body.package,
            ErasureReceiptAcceptanceStatus::Duplicate,
            stored.acceptance.accepted_at,
        )
        .await?
    } else {
        signed_acceptance(
            state,
            &body.package,
            ErasureReceiptAcceptanceStatus::Accepted,
            Utc::now(),
        )
        .await?
    };
    let outcome = ErasureReceiptSubmitOutcome::Accepted(acceptance);
    let now = Utc::now();
    let response_record = IdempotencyState {
        authenticated_actor: arkret_wire::ActorId::service(source_id),
        operation_id: arkret_wire::ServiceOperationId::PEER_ERASURE_RECEIPT_COMMAND_SUBMIT_V1
            .to_owned(),
        idempotency_key: key,
        request_hash,
        response_status: StatusCode::OK.as_u16() as i32,
        response_body: serde_json::to_value(&outcome)
            .map_err(|error| AppError::internal(error.to_string()))?,
        created_at: now,
        expires_at: now + Duration::days(3650),
    };
    let ErasureReceiptSubmitOutcome::Accepted(acceptance) = &outcome else {
        unreachable!()
    };
    let lookup = IdempotencyState {
        authenticated_actor: arkret_wire::ActorId::service(state.service_core_id()),
        operation_id: coland_services::jobs::INTERNAL_IDEMPOTENCY_OPERATION.to_owned(),
        idempotency_key: lookup_key,
        request_hash: receipt_digest.to_string(),
        response_status: StatusCode::OK.as_u16() as i32,
        response_body: serde_json::to_value(StoredReceipt {
            package: body.package,
            acceptance: acceptance.clone(),
            authorized_requester_id: None,
        })
        .map_err(|error| AppError::internal(error.to_string()))?,
        created_at: now,
        expires_at: now + Duration::days(3650),
    };
    let landed = state
        .persistence()
        .idempotency_keys()
        .record_with_lookup(&response_record, &lookup)
        .await
        .map_err(|error| {
            if error.conflict_code() == Some(coland_storage::ConflictCode::DuplicateConflict) {
                AppError::conflict(error.to_string()).with_wire_code("duplicate_conflict")
            } else {
                AppError::internal(error.to_string())
            }
        })?;
    json_ok(
        serde_json::from_value(landed.response_body).map_err(|error| {
            AppError::internal(format!("landed erasure acknowledgement: {error}"))
        })?,
    )
}

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.erasure_receipt.resource.get",
    tags("federation")
)]
async fn get(
    receipt_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ErasureReceiptResource> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    verify_inbound_peer_http_signature(state, req, false).await?;
    let source = required_header(req, "source-service-id")?;
    let lookup_key = format!("erasure-receipt:lookup:{}", receipt_id.into_inner());
    let stored = state
        .jobs()
        .idempotency_record(&state.service_core_id(), &lookup_key)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("erasure receipt not found"))?;
    let stored: StoredReceipt = serde_json::from_value(stored.response_body)
        .map_err(|error| AppError::internal(format!("stored erasure package: {error}")))?;
    if source != stored.package.receipt.issuer_id.as_str()
        && source != stored.acceptance.receiver_id.as_str()
        && stored
            .authorized_requester_id
            .as_ref()
            .map(|id| id.as_str())
            != Some(source.as_str())
    {
        return Err(AppError::not_found("erasure receipt not found"));
    }
    json_ok(ErasureReceiptResource {
        package: stored.package,
    })
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StoredReceipt {
    package: ErasureReceiptPackage,
    acceptance: ErasureReceiptAcceptance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized_requester_id: Option<arkret_wire::DidCoreId>,
}

async fn persist_lookup(
    state: &AppState,
    package: &ErasureReceiptPackage,
    outcome: &ErasureReceiptSubmitOutcome,
    authorized_requester_id: Option<&arkret_wire::DidCoreId>,
) -> Result<(), AppError> {
    let ErasureReceiptSubmitOutcome::Accepted(acceptance) = outcome else {
        return Ok(());
    };
    let lookup_key = format!("erasure-receipt:lookup:{}", package.receipt.receipt_id);
    let now = Utc::now();
    state
        .jobs()
        .store_idempotency_record(IdempotencyState {
            authenticated_actor: arkret_wire::ActorId::service(state.service_core_id()),
            operation_id: coland_services::jobs::INTERNAL_IDEMPOTENCY_OPERATION.to_owned(),
            idempotency_key: lookup_key,
            request_hash: package
                .computed_receipt_digest()
                .map_err(|error| AppError::internal(error.to_string()))?
                .to_string(),
            response_status: StatusCode::OK.as_u16() as i32,
            response_body: serde_json::to_value(StoredReceipt {
                package: package.clone(),
                acceptance: acceptance.clone(),
                authorized_requester_id: authorized_requester_id.cloned(),
            })
            .map_err(|error| AppError::internal(error.to_string()))?,
            created_at: now,
            expires_at: now + Duration::days(3650),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

pub(crate) async fn persist_issued_package(
    state: &AppState,
    package: &ErasureReceiptPackage,
    authorized_requester_id: &arkret_wire::DidCoreId,
) -> Result<(), AppError> {
    if package.receipt.issuer_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "issued erasure receipt belongs to another Station",
        ));
    }
    package
        .validate_bindings()
        .map_err(|error| AppError::internal(format!("issued erasure package invalid: {error}")))?;
    let acceptance = signed_acceptance(
        state,
        package,
        ErasureReceiptAcceptanceStatus::Accepted,
        Utc::now(),
    )
    .await?;
    persist_lookup(
        state,
        package,
        &ErasureReceiptSubmitOutcome::Accepted(acceptance),
        Some(authorized_requester_id),
    )
    .await
}

async fn signed_acceptance(
    state: &AppState,
    package: &ErasureReceiptPackage,
    status: ErasureReceiptAcceptanceStatus,
    accepted_at: chrono::DateTime<Utc>,
) -> Result<ErasureReceiptAcceptance, AppError> {
    let (_, verification_method) = state
        .current_service_receipt_binding()
        .await
        .map_err(|error| AppError::internal(format!("service receipt binding: {error}")))?;
    let mut acceptance = ErasureReceiptAcceptance {
        status,
        receipt_id: package.receipt.receipt_id.clone(),
        receipt_digest: package
            .computed_receipt_digest()
            .map_err(|error| AppError::internal(error.to_string()))?,
        issuer_id: package.receipt.issuer_id.clone(),
        receiver_id: arkret_identifiers::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(error.to_string()))?,
        accepted_at,
        proof: ProtocolSignature {
            verification_method,
            created_at: accepted_at,
            jws: String::new(),
        },
    };
    let input = acceptance
        .signing_input_bytes()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let jws = arkret_signatures::jws::sign_jws_ed25519(&input, state.notary_signing_key().as_ref())
        .map_err(AppError::internal)?;
    acceptance.proof.jws = jws;
    Ok(acceptance)
}

/// A successful HTTP response is not evidence of receipt acceptance.
pub(crate) async fn verify_acceptance(
    state: &AppState,
    package: &ErasureReceiptPackage,
    destination: &arkret_wire::DidCoreId,
    response: &str,
) -> Result<ErasureReceiptAcceptance, String> {
    let outcome: ErasureReceiptSubmitOutcome = serde_json::from_str(response)
        .map_err(|error| format!("erasure acknowledgement shape: {error}"))?;
    let ErasureReceiptSubmitOutcome::Accepted(acceptance) = outcome else {
        return Err("erasure receipt was rejected".into());
    };
    if acceptance.receipt_id != package.receipt.receipt_id
        || acceptance.receipt_digest
            != package
                .computed_receipt_digest()
                .map_err(|error| error.to_string())?
        || acceptance.issuer_id != package.receipt.issuer_id
        || &acceptance.receiver_id != destination
    {
        return Err("erasure acknowledgement differs from the frozen receipt/destination".into());
    }
    crate::jws_verify::validate_verification_method_controller(
        destination.as_str(),
        acceptance.proof.verification_method.as_str(),
    )?;
    let key = crate::jws_verify::resolve_ed25519_pubkey_at(
        state,
        acceptance.proof.verification_method.as_str(),
        acceptance.accepted_at,
    )
    .await?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &acceptance.proof.jws,
            &acceptance
                .signing_input_bytes()
                .map_err(|error| error.to_string())?,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_bytes().to_vec(),
            },
        )
        .map_err(|error| format!("erasure acknowledgement signature: {error}"))?;
    Ok(acceptance)
}

/// Delivery progress is derived from the durable rail, never from today's
/// membership or by mutating the original signed package sent on retries.
pub(crate) async fn fanout_progress(
    state: &AppState,
    receipt_id: &str,
) -> Result<
    (
        arkret_models_collaboration::governance::erasure::ErasureFanoutStatus,
        Vec<arkret_models_collaboration::governance::erasure::ErasurePeerReceipt>,
    ),
    AppError,
> {
    use arkret_models_collaboration::governance::erasure::{
        ErasureFanoutStatus, ErasureOutcome, ErasurePeerReceipt, ErasurePeerStatus,
    };
    let rows = state
        .persistence()
        .federation_outbox()
        .erasure_receipt_deliveries(receipt_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(first) = rows.first() else {
        return Ok((ErasureFanoutStatus::Complete, Vec::new()));
    };
    let body: ErasureReceiptSubmitRequestBody = serde_json::from_str(&first.payload_json)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let feedback = state
        .persistence()
        .federation_outbox()
        .erasure_receipt_feedback(&body.package.receipt)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut status = ErasureFanoutStatus::Complete;
    let peers = rows
        .into_iter()
        .map(|row| {
            let received = feedback
                .iter()
                .filter(|(package, _)| package.receipt.issuer_id == row.peer_id)
                .max_by_key(|(package, _)| package.receipt.completed_at);
            let timed_out = received.is_none()
                && Utc::now().timestamp()
                    >= row
                        .created_at
                        .saturating_add(super::outbox::ERASURE_PROPAGATION_WINDOW_SECS);
            if timed_out {
                status = ErasureFanoutStatus::Incomplete;
            } else if received.is_none() && status != ErasureFanoutStatus::Incomplete {
                status = ErasureFanoutStatus::Pending;
            }
            ErasurePeerReceipt {
                peer_id: row.peer_id,
                status: if let Some((package, _)) = received {
                    if package.receipt.outcome == ErasureOutcome::Completed {
                        ErasurePeerStatus::Acknowledged
                    } else {
                        ErasurePeerStatus::Failed
                    }
                } else if timed_out {
                    ErasurePeerStatus::TimedOut
                } else {
                    ErasurePeerStatus::Pending
                },
                receipt_id: received.map(|(package, _)| package.receipt.receipt_id.clone()),
                acknowledged_at: received.map(|(_, at)| *at),
            }
        })
        .collect();
    Ok((status, peers))
}

fn required_header(req: &Request, name: &str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AppError::param_invalid(format!("missing {name} header")))
}
