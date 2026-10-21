use salvo::oapi::endpoint;

use super::*;

#[endpoint(operation_id = "org.arkret.coland.interop.mimi.protocol_directory")]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.interop.mimi.protocol_directory")
)]
pub(super) async fn mimi_protocol_directory(
    depot: &mut Depot,
) -> JsonResult<arkret_models_collaboration::objects::interop::ProviderDirectory> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(mimi_provider_directory_value(state)?)
}

#[endpoint(operation_id = "ak.open.mimi.read.provider_directory")]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.read.provider_directory.v1"))]
pub(super) async fn mimi_provider_directory(
    depot: &mut Depot,
) -> JsonResult<arkret_models_collaboration::objects::interop::ProviderDirectory> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    json_ok(mimi_provider_directory_value(state)?)
}

#[endpoint(
    operation_id = "ak.open.mimi.exchange.request_key_material",
    summary = "Request MIMI key material",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.exchange.request_key_material.v1"))]
pub(super) async fn mimi_key_material(
    body: JsonBody<MimiKeyMaterialRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiKeyMaterialOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let typed = body.into_inner();
    let body = typed_body_value(&typed, "mimi key material")?;
    let source_provider = verify_mimi_source_service_signature(state, req, None).await?;
    if typed.requester_id.as_str() != source_provider {
        return Err(AppError::capability_denied(
            "MIMI key-material requester must be the attested source service",
        ));
    }
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    verify_mimi_key_material_request_proofs(state, &typed).await?;
    let target = typed.strand_id.as_str();
    let realm_id = typed.realm_id.as_ref().ok_or_else(|| {
        AppError::param_invalid("MIMI key-material claim requires realm_id")
            .with_wire_code("claim_failed")
    })?;
    let group_id = typed.mls_group_id.as_deref().ok_or_else(|| {
        AppError::param_invalid("MIMI key-material claim requires mls_group_id")
            .with_wire_code("claim_failed")
    })?;
    let claimed = crate::routing::mls::claim_mimi_keypackage(
        state,
        &typed.requester_id,
        &typed.device_id,
        realm_id.as_str(),
        group_id,
    )
    .await?
    .ok_or_else(|| crate::app_error!(ClaimFailed, "KeyPackage claim failed"))?;
    let claimed_device = claimed
        .device_id
        .as_deref()
        .ok_or_else(|| AppError::internal("claimed MIMI KeyPackage does not carry a device_id"))?;
    let keypackage = MimiKeyPackage {
        device_id: arkret_wire::DeviceId::new(claimed_device.to_owned())
            .map_err(|error| AppError::internal(format!("claimed device_id: {error}")))?,
        keypackage_ref: Some(
            arkret_wire::NonEmptyString::new(claimed.keypackage_ref.clone())
                .map_err(|error| AppError::internal(format!("claimed KeyPackage ref: {error}")))?,
        ),
        mls_keypackage: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            &claimed.key_package_bytes,
        ))
        .map_err(|error| AppError::internal(format!("claimed KeyPackage bytes: {error}")))?,
    };
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL_V1,
        &body,
        json!({
            "target": target,
            "keypackage_claim_lifecycle": "single_use_required",
            "keypackage_ref": claimed.keypackage_ref,
        }),
    );
    json_ok(MimiKeyMaterialOutcome {
        keypackages: Some(vec![keypackage]),
        group_info: None,
        failures: None,
        signature: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.update_room",
    summary = "Update a MIMI room",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.update_room.v1"))]
pub(super) async fn mimi_room_update(
    strand_id: PathParam<String>,
    body: JsonBody<MimiRoomUpdateRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRoomUpdateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi room update")?;
    let room_uri = mimi_room_uri(state, &room_id)?;
    verify_mimi_source_service_signature(state, req, Some(room_uri.as_str())).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::param_invalid("invalid MIMI room id"));
    }
    // If the update carries a `room_binding` block, persist it as a
    // `ak.mimi.room_binding` projection event so the Arkret
    // timeline observes the binding. Updates without a binding block
    // fall through to the receipt-only response. A binding block that
    // omits both `binding_scope.realm_id` and a top-level `realm_id`
    // is rejected; we never implicitly route to a default Realm.
    let update_payload = decode_mimi_update_payload(&body)?;
    let declared_update_kind = body
        .pointer("/update/kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::param_invalid("MIMI room update requires update.kind")
                .with_wire_code("mimi_room_binding_event_invalid")
        })?;
    let decoded_update_kind = update_payload
        .as_ref()
        .and_then(|payload| payload.get("kind"))
        .and_then(Value::as_str);
    if decoded_update_kind.is_some_and(|kind| kind != declared_update_kind) {
        return Err(AppError::param_invalid(
            "declared MIMI update kind does not match the decoded payload",
        )
        .with_wire_code("mimi_room_binding_event_invalid"));
    }
    let binding_event_id = match declared_update_kind {
        arkret_wire::event_kind_str::MIMI_ROOM_BINDING => {
            let binding = update_payload
                .as_ref()
                .and_then(mimi_room_binding_payload)
                .filter(|binding| binding.is_object())
                .ok_or_else(|| {
                    AppError::param_invalid(
                        "room binding branch requires a decoded room binding payload",
                    )
                    .with_wire_code("mimi_room_binding_event_invalid")
                })?;
            let submission = body.get("room_binding_event").cloned().ok_or_else(|| {
                AppError::param_invalid(
                    "room_binding update requires a caller-authored room_binding_event",
                )
                .with_wire_code("mimi_room_binding_event_invalid")
            })?;
            Some(admit_mimi_room_binding_event(state, &room_id, &body, binding, submission).await?)
        }
        _ => {
            if body.get("room_binding_event").is_some() {
                return Err(AppError::param_invalid(
                    "room_binding_event is only valid for a room binding update",
                )
                .with_wire_code("mimi_room_binding_event_invalid"));
            }
            None
        }
    };

    let room_state_ref = binding_event_id
        .as_deref()
        .map(EventId::new)
        .transpose()
        .map_err(|error| AppError::internal(format!("MIMI room state ref: {error}")))?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM_V1,
        &body,
        json!({
            "mimi_room_uri": mimi_room_uri(state, &room_id)?,
            "truth_source": "arkret_signed_event_reducer",
            "status": "projected",
            "binding_emitted": binding_event_id.is_some(),
        }),
    );
    json_ok(MimiRoomUpdateOutcome {
        accepted: true,
        room_state_ref,
        rejections: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.notify",
    summary = "MIMI notify",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.notify.v1"))]
pub(super) async fn mimi_notify(
    strand_id: PathParam<String>,
    body: JsonBody<MimiNotifyRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiNotifyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = typed_body_value(body.into_inner(), "mimi notify")?;
    let room_uri = mimi_room_uri(state, &room_id)?;
    verify_mimi_source_service_signature(state, req, Some(room_uri.as_str())).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::param_invalid("invalid MIMI room id"));
    }
    // Notify is an ephemeral MIMI control signal, not an Arkret Event. It must
    // not mint an Event id or enter the canonical projection timeline.
    let _realm_id = mimi_bound_realm_id(state, &room_id).await?.ok_or_else(|| {
        AppError::not_found("MIMI room is not bound to any Arkret Realm")
            .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
    })?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY_V1,
        &body,
        json!({
            "delivery": "queued",
            "mimi_room_uri": mimi_room_uri(state, &room_id)?,
            "broadcast_emitted": false,
        }),
    );
    json_ok(MimiNotifyOutcome {
        accepted: true,
        retry_after_ms: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.submit_message",
    summary = "Submit a MIMI message",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.submit_message.v1"))]
pub(super) async fn mimi_room_message(
    strand_id: PathParam<String>,
    body: JsonBody<MimiSubmitMessageRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiSubmitMessageOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let room_id = strand_id.into_inner();
    let body = body.into_inner();
    let room_uri = mimi_room_uri(state, &room_id)?;
    let source_provider =
        verify_mimi_source_service_signature(state, req, Some(room_uri.as_str())).await?;
    if !valid_mimi_room_id(&room_id) {
        return Err(AppError::param_invalid("invalid MIMI room id"));
    }
    let room_binding = latest_mimi_room_binding(state, &room_id)
        .await?
        .ok_or_else(|| {
            AppError::not_found("MIMI room is not bound to any Arkret Realm")
                .with_reason_code(arkret_wire::ReasonCode::MIMI_GOVERNANCE_BINDING_MISSING)
        })?;
    enforce_mimi_writable_binding(&room_binding.binding)?;
    let message = decode_mimi_ciphertext_payload(&body.ciphertext)?;
    let associated_data = decode_mimi_associated_data(body.associated_data.as_ref())?;
    let source_format = body.ciphertext.content_type.as_str().to_owned();
    if !valid_mimi_content_type(&source_format) {
        return Err(AppError::param_invalid("unsupported MIMI content type"));
    }
    enforce_mimi_submit_binding(
        state,
        &source_provider,
        &room_binding,
        &body,
        &message,
        associated_data.as_ref(),
    )
    .await?;
    let operation_id = ids::generate_operation_id();
    let mimi_message_id = message
        .get("mimi_message_id")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "mimi-msg-{}",
                operation_id.trim_start_matches("ak:operation:")
            )
        });
    let body_bytes = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|error| AppError::internal(format!("MIMI request canonicalization: {error}")))?;
    let original_hash = arkret_canonical::sha256_digest(&body_bytes);

    // Map the MIMI message into the canonical Arkret timeline.
    // Append a MessageRecord + a `ak.message.create` projection event so
    // the message shows up in `QUERY /_arkret/self/events`. The
    // MIMI provenance is bound in the closed top-level payload branch so
    // admission and audit consumers can verify service authorship separately
    // from external sender attribution.
    let realm_id = room_binding.realm_id.clone();
    let sender = body.sender_actor_id.to_string();
    let mapped_content = map_mimi_message_content(&message, &source_format)?;
    let thread_id = message
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| crate::routing::events::strand::strand_id_from_realm_id(&realm_id))
        .ok_or_else(|| AppError::param_invalid("MIMI binding carries a non-canonical realm_id"))?;
    let mut event_payload = json!({
        "strand_id": thread_id.clone(),
        "track_name": "discussion",
        "content": mapped_content.content.clone(),
        "metadata": {
            "mimi_policy": mapped_content.policy.clone(),
            "quarantine": mapped_content.quarantine.clone(),
        },
        "mimi_provenance": {
            "provenance": "mimi_facade",
            "source_provider_id": source_provider,
            "attributed_sender_actor_id": body.sender_actor_id,
            "attributed_sender_device_id": body.device_id,
            "source_envelope_digest": original_hash,
            "room_binding_ref": room_binding.event_id.clone(),
        },
    });
    if let Some(encrypted) = message.get("encrypted_content") {
        let object = event_payload
            .as_object_mut()
            .expect("message payload object");
        object.remove("content");
        object.remove("metadata");
        object.insert("encrypted_content".into(), encrypted.clone());
        if let Some(metadata) = message.get("encrypted_metadata") {
            object.insert("encrypted_metadata".into(), metadata.clone());
        }
    }
    let event_payload = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::message::MessageCreatePayload,
    >(event_payload)
    .map_err(|error| {
        mimi_admission_error(coland_services::ServiceError::SchemaViolation(
            error.to_string(),
        ))
    })?;
    let event_id = persist_mimi_canonical_message_event(
        state,
        &realm_id,
        room_uri,
        EventId::new(room_binding.event_id.clone())
            .map_err(|e| AppError::internal(e.to_string()))?,
        arkret_wire::DidCoreId::new(source_provider)
            .map_err(|e| AppError::internal(e.to_string()))?,
        &body,
        event_payload,
    )
    .await?;

    append_audit_log(
        state,
        Some(&sender),
        "mimi.submit_message",
        json!({
            "room_id": room_id,
            "realm_id": realm_id,
            "operation_id": operation_id,
            "event_id": event_id,
            "source_format": source_format,
            "mimi_message_id": mimi_message_id,
            "mimi_policy": mapped_content.policy,
            "quarantine": mapped_content.quarantine,
        }),
        mapped_content.status,
    )
    .await;
    let event_ref = EventId::new(event_id)
        .map_err(|error| AppError::internal(format!("MIMI mapped event ref: {error}")))?;
    json_ok(MimiSubmitMessageOutcome {
        event_ref: Some(event_ref),
        delivery: MimiDelivery {
            status: MimiDeliveryStatus::Accepted,
            delivered_to_ids: Vec::new(),
        },
        rejections: Vec::new(),
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.request_consent",
    summary = "Request MIMI consent",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.request_consent.v1"))]
pub(super) async fn mimi_consent_request(
    aa: AuthArgs,
    body: JsonBody<MimiRequestConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiRequestConsentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let body_value = typed_body_value(body.clone(), "mimi consent request")?;
    if let Some(message) = unsupported_mimi_draft(&body_value) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    let (source_id, session) =
        verify_mimi_consent_write_authority(state, req, aa, &body.requester_actor_id).await?;
    verify_mimi_request_consent_proofs(state, &body, session.as_ref()).await?;
    let consent_id = ids::generate("consent");
    let consent_id = arkret_identifiers::ConsentId::new(consent_id)
        .map_err(|error| AppError::internal(format!("generated consent id is invalid: {error}")))?;
    state
        .consents()
        .save_mimi_correlation(MimiConsentCorrelation {
            consent_id: consent_id.to_string(),
            requester_actor_id: canonical_identity_json(&body.requester_actor_id)?,
            holder_account_id: canonical_identity_json(&body.holder_account_id)?,
            purpose: mimi_consent_purpose(body.purpose).to_owned(),
            strand_id: body.strand_id.as_ref().map(ToString::to_string),
            source_id,
            created_at: now(),
            expires_at: body.expires_at,
        })
        .await
        .map_err(|error| {
            AppError::internal(format!("persist MIMI consent correlation: {error}"))
        })?;
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1,
        &body_value,
        json!({
            "consent_grants_space_capability": false,
            "privacy_state": "holder_private",
            "holder_private_materialized": false,
            "identifier_mapping": "pending_invite_or_pairwise"
        }),
    );
    json_ok(MimiRequestConsentOutcome {
        consent_id,
        challenge: None,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.update_consent",
    summary = "Update MIMI consent",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.update_consent.v1"))]
pub(super) async fn mimi_consent_update(
    aa: AuthArgs,
    body: JsonBody<MimiUpdateConsentRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiUpdateConsentOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let body_value = typed_body_value(body.clone(), "mimi consent update")?;
    if let Some(message) = unsupported_mimi_draft(&body_value) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    body.validate_consent_event().map_err(|error| {
        AppError::schema_violation(format!("MIMI consent Event binding is invalid: {error}"))
    })?;
    // mimi-interop.md section 5: a carried Event id that is not the
    // re-derived content address is refused before any holder state is read.
    body.consent_event
        .event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| {
            AppError::schema_violation(format!("MIMI consent Event identity: {error}"))
                .with_reason_code(arkret_wire::ReasonCode::EVENT_ID_DIGEST_MISMATCH)
        })?;
    let (_session, source_id) = verify_mimi_consent_update_authority(state, req, aa, &body).await?;
    verify_mimi_consent_correlation(state, &body, source_id.as_deref()).await?;
    // Recheck the current caller and correlation disclosure before returning a
    // retained outcome. Native producer verification belongs to the accepting PCR.
    if let Some(outcome) = state
        .persistence()
        .mimi_consent_update_outcome(&body)
        .await
        .map_err(|error| {
            AppError::internal(format!("MIMI original outcome persistence: {error}"))
        })?
    {
        return json_ok(outcome);
    }
    crate::state::authority_consent::submit_mimi_forward(state, &body.consent_event)
        .await
        .map_err(|error| mimi_consent_admission_error(body.decision, error))?;
    let outcome = MimiUpdateConsentOutcome {
        consent_id: body.consent_id.clone(),
        decision: body.decision,
        updated_at: body.consent_event.event.created_at,
        event_ref: body.consent_event.event.event_id.clone(),
    };
    state
        .persistence()
        .complete_mimi_consent_update(&body, &outcome)
        .await
        .map_err(|error| {
            AppError::internal(format!("MIMI original outcome persistence: {error}"))
        })?;
    json_ok(outcome)
}

pub(super) async fn verify_mimi_consent_write_authority(
    state: &AppState,
    req: &mut Request,
    aa: AuthArgs,
    expected_actor: &arkret_wire::ActorId,
) -> Result<
    (
        Option<String>,
        Option<coland_services::identity::SessionIdentityState>,
    ),
    AppError,
> {
    let source_id = verify_mimi_source_service_signature(state, req, None).await?;
    if request_has_bearer_session(req) {
        let session = aa.authenticated_session(state, req).await?;
        if crate::routing::identity::session_actor::validated_session_actor(state, &session).await?
            != *expected_actor
        {
            return Err(AppError::capability_denied(
                "MIMI consent user session must match the consent actor",
            ));
        }
        return Ok((Some(source_id), Some(session)));
    }
    Ok((Some(source_id), None))
}

const MIMI_OPERATION_PROOF_WINDOW_SECONDS: i64 = 300;

/// Signer identity an inbound MIMI operation proof has to resolve to.
///
/// The two arms are not interchangeable: `PrincipalDevice` requires an
/// accepted device authorization inside this deployment's Principal Control
/// Realm, while `DidController` only requires the proof method to be
/// controlled by the DID the request names as its originator.
enum MimiProofSigner<'a> {
    /// A device of a principal whose account authority lives on this service.
    /// Both consent families use the exact account's accepted device authority.
    PrincipalDevice {
        authority: arkret_wire::AccountId,
        device_id: arkret_identifiers::DeviceId,
    },
    /// A verification method controlled by the originator DID carried on the
    /// wire. Only service-originated families use this authority source.
    DidController(&'a str),
    /// A current Agent runtime key selected from the accepted Agent PCR/key
    /// authorization state. The request never supplies this key material.
    AgentRuntime { public_key: &'a [u8; 32] },
}

/// Destination, replay-window and signature checks shared by every inbound
/// MIMI operation proof.
///
/// There is deliberately no context argument. The proof context is baked into
/// `binding` by the request body family's own SDK `proof_binding_bytes`
/// helper, so which context applies falls out of which body type the caller
/// held; a signature produced under one family's context can never verify
/// here under another's. The SDK helper has already enforced
/// `PayloadProof::validate_production`, the absent `proof_purpose`, the
/// `payload_digest` match and the presence of `domain`/`audience`. This
/// function adds only the checks that need deployment state.
async fn verify_mimi_operation_proof(
    state: &AppState,
    binding: &[u8],
    proof: &arkret_wire::PayloadProof,
    signer: MimiProofSigner<'_>,
    label: &str,
) -> Result<(), AppError> {
    if proof.domain.as_deref() != Some(state.config().trust_domain.as_str()) {
        return Err(AppError::param_invalid(format!(
            "{label} proof domain does not match the destination trust domain"
        ))
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID));
    }
    let audience_matches = match proof.audience.as_ref() {
        Some(Audience::Single(value)) => value == state.service_id(),
        Some(Audience::Multiple(values)) => values.iter().any(|value| value == state.service_id()),
        None => false,
    };
    if !audience_matches {
        return Err(AppError::param_invalid(format!(
            "{label} proof audience does not cover the destination service"
        ))
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID));
    }
    let age_seconds = now()
        .signed_duration_since(proof.created_at)
        .num_seconds()
        .unsigned_abs();
    if age_seconds > MIMI_OPERATION_PROOF_WINDOW_SECONDS as u64 {
        return Err(AppError::param_invalid(format!(
            "{label} proof created_at is outside the accepted replay window"
        ))
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID));
    }
    let verified = match signer {
        MimiProofSigner::PrincipalDevice {
            authority,
            device_id,
        } => {
            if proof
                .verification_method
                .as_str()
                .rsplit_once('#')
                .map(|(_, fragment)| fragment)
                != Some(device_id.as_str())
            {
                Err("MIMI proof does not name the expected device".to_owned())
            } else {
                // Projection freshness alone does not prove the accepted PCR
                // device is still active or admitted by its durable revoke gate.
                crate::state::verify_account_device_payload_proof(state, &authority, proof, binding)
                    .await
                    .map_err(|error| error.to_string())
            }
        }
        MimiProofSigner::DidController(issuer) => {
            crate::jws_verify::verify_did_controlled_jws_async(
                binding,
                &proof.jws,
                proof.verification_method.as_str(),
                issuer,
                state,
            )
            .await
        }
        MimiProofSigner::AgentRuntime { public_key } => {
            arkret_signatures::verify_ed25519_detached_jws_payload_proof(
                proof,
                binding,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: public_key.to_vec(),
                },
            )
            .map_err(|error| error.to_string())
        }
    };
    verified.map_err(|reason| {
        tracing::warn!(
            %reason,
            %label,
            verification_method = %proof.verification_method,
            "MIMI operation proof verification failed"
        );
        AppError::param_invalid(format!("{label} proof JWS verification failed"))
            .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
    })
}

/// Verify every proof carried by a MIMI key-material request.
///
/// `proofs` is `#[serde(default)]` on the wire, so an empty vector is a valid
/// request and this is a no-op for it. The originator is the mandatory
/// `requester_id` field.
async fn verify_mimi_key_material_request_proofs(
    state: &AppState,
    body: &MimiKeyMaterialRequestBody,
) -> Result<(), AppError> {
    let issuer = body.requester_id.to_string();
    for proof in &body.proofs {
        let binding = body.proof_binding_bytes(proof).map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI key material request proof binding is invalid: {error}"
            ))
            .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
        })?;
        verify_mimi_operation_proof(
            state,
            &binding,
            proof,
            MimiProofSigner::DidController(issuer.as_str()),
            "MIMI key material request",
        )
        .await?;
    }
    Ok(())
}

/// Verify every proof carried by a MIMI consent request.
///
/// The originator is the mandatory `requester_actor_id` field, and the proof
/// issuer is that complete Actor rather than its signing principal: the
/// correlation is only as strong as the identity the signature froze. Ruling
/// `arkret-spec/spec/v1/zh/extensions/mimi-interop.md section 10`.
async fn verify_mimi_request_consent_proofs(
    state: &AppState,
    body: &MimiRequestConsentRequestBody,
    session: Option<&coland_services::identity::SessionIdentityState>,
) -> Result<(), AppError> {
    if body.proofs.is_empty() {
        return Err(mimi_consent_proof_invalid());
    }
    for proof in &body.proofs {
        let binding = body.proof_binding_bytes(proof).map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI consent request proof binding is invalid: {error}"
            ))
            .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
        })?;
        verify_mimi_consent_requester_proof(
            state,
            &binding,
            proof,
            &body.requester_actor_id,
            session,
        )
        .await?;
    }
    Ok(())
}

fn mimi_consent_proof_invalid() -> AppError {
    AppError::param_invalid("MIMI consent requester authority is unavailable")
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

async fn verify_mimi_consent_requester_proof(
    state: &AppState,
    binding: &[u8],
    proof: &arkret_wire::PayloadProof,
    actor: &arkret_wire::ActorId,
    session: Option<&coland_services::identity::SessionIdentityState>,
) -> Result<(), AppError> {
    // This operation has no authorized remote PCR disclosure carrier. Check
    // the exact Station before any local principal or private PCR lookup.
    if crate::routing::actor_delivery_station(state, &actor).await? != state.service_core_id() {
        return Err(mimi_consent_proof_invalid());
    }
    let agent = crate::routing::identity::agent_pcr::agent_record_for_actor(state, actor)
        .await
        .map_err(|_| mimi_consent_proof_invalid())?;
    if let Some(record) = agent {
        let session = session.ok_or_else(mimi_consent_proof_invalid)?;
        let grant = session
            .session_grant
            .as_ref()
            .ok_or_else(mimi_consent_proof_invalid)?;
        let arkret_models_identity::SessionGrantHolderBinding::AgentRuntime {
            agent_id,
            agent_key_authorization_ref,
            verification_method,
            ..
        } = &grant.holder_binding
        else {
            return Err(mimi_consent_proof_invalid());
        };
        let key = record
            .authorized_key_event
            .as_ref()
            .ok_or_else(mimi_consent_proof_invalid)?;
        let key =
            arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
                key,
            )
            .map_err(|_| mimi_consent_proof_invalid())?;
        if actor.as_account_id() != Some(&grant.account_id)
            || agent_id != actor.signing_principal_id()
            || session.agent_session().is_none_or(|agent| {
                !agent.granted_scope.iter().any(|scope| {
                    scope == arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1
                })
            })
            || record.state
                != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            || record.authorized_event_ref.as_deref() != Some(agent_key_authorization_ref.as_str())
            || record.authorized_verification_method.as_deref()
                != Some(proof.verification_method.as_str())
            || verification_method != &proof.verification_method
            || key.agent_id != *agent_id
            || key.verification_method != *verification_method
            || key.agent_key_authorize_event_id != *agent_key_authorization_ref
            || record.authorized_public_key_digest.as_deref()
                != Some(key.public_key_digest.as_str())
        {
            return Err(mimi_consent_proof_invalid());
        }
        crate::routing::identity::agent_pcr::validate_agent_controller_binding(
            state,
            &record,
            now(),
        )
        .await
        .map_err(|_| mimi_consent_proof_invalid())?;
        if !crate::routing::mls::current_agent_key_authorization_matches_method(
            state,
            agent_id,
            agent_key_authorization_ref.as_str(),
            verification_method.as_str(),
        )
        .await
            || arkret_wire::Hash::new(arkret_canonical::canonical::sha256_digest(
                &arkret_canonical::base64url_decode(key.public_key.key.as_str())
                    .map_err(|_| mimi_consent_proof_invalid())?,
            ))
            .map_err(|_| mimi_consent_proof_invalid())?
                != key.public_key_digest
        {
            return Err(mimi_consent_proof_invalid());
        }
        let public_key: [u8; 32] = arkret_canonical::base64url_decode(key.public_key.key.as_str())
            .map_err(|_| mimi_consent_proof_invalid())?
            .try_into()
            .map_err(|_| mimi_consent_proof_invalid())?;
        return verify_mimi_operation_proof(
            state,
            binding,
            proof,
            MimiProofSigner::AgentRuntime {
                public_key: &public_key,
            },
            "MIMI consent request",
        )
        .await;
    }
    let authority = actor
        .as_account_id()
        .cloned()
        .ok_or_else(mimi_consent_proof_invalid)?;
    let device_id = proof
        .verification_method
        .as_str()
        .rsplit_once('#')
        .and_then(|(_, fragment)| arkret_identifiers::DeviceId::new(fragment.to_owned()).ok())
        .ok_or_else(mimi_consent_proof_invalid)?;
    verify_mimi_operation_proof(
        state,
        binding,
        proof,
        MimiProofSigner::PrincipalDevice {
            authority,
            device_id,
        },
        "MIMI consent request",
    )
    .await
}

/// Verify every proof carried by a MIMI identifier query.
///
/// `proofs` is `#[serde(default)]` on the wire; an empty vector stays valid.
/// This family's `requester_id` is optional and the SDK transcript then omits
/// `issuer` entirely, so when it is absent the only originator the request
/// carries is the transport-authenticated source service and the proof must
/// be signed by that service.
async fn verify_mimi_identifier_query_proofs(
    state: &AppState,
    body: &MimiIdentifierQueryRequestBody,
    source_id: &str,
) -> Result<(), AppError> {
    let issuer = body
        .requester_id
        .as_ref()
        .map_or_else(|| source_id.to_owned(), ToString::to_string);
    for proof in &body.proofs {
        let binding = body.proof_binding_bytes(proof).map_err(|error| {
            AppError::param_invalid(format!(
                "MIMI identifier query proof binding is invalid: {error}"
            ))
            .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
        })?;
        verify_mimi_operation_proof(
            state,
            &binding,
            proof,
            MimiProofSigner::DidController(issuer.as_str()),
            "MIMI identifier query",
        )
        .await?;
    }
    Ok(())
}

async fn verify_mimi_consent_update_authority(
    state: &AppState,
    req: &mut Request,
    aa: AuthArgs,
    body: &MimiUpdateConsentRequestBody,
) -> Result<
    (
        Option<coland_services::identity::SessionIdentityState>,
        Option<String>,
    ),
    AppError,
> {
    let (source_id, session) =
        verify_mimi_consent_write_authority(state, req, aa, &body.actor_id).await?;
    verify_mimi_consent_actor_proof(state, body).await?;
    Ok((session, source_id))
}

fn mimi_consent_purpose(purpose: MimiConsentPurpose) -> &'static str {
    match purpose {
        MimiConsentPurpose::Invite => "invite",
        MimiConsentPurpose::VoiceCall => "voice_call",
        MimiConsentPurpose::VideoCall => "video_call",
        MimiConsentPurpose::Presence => "presence",
    }
}

fn mimi_consent_correlation_unavailable() -> AppError {
    AppError::not_found("MIMI consent correlation is unavailable")
}

fn mimi_consent_admission_error(
    decision: arkret_models_collaboration::mimi_operations::MimiConsentDecision,
    error: coland_services::ServiceError,
) -> AppError {
    use coland_storage::ConflictCode;
    let _ = decision;
    if matches!(
        error.conflict_code(),
        Some(ConflictCode::CasConflict | ConflictCode::FailedPrecondition)
    ) {
        mimi_consent_correlation_unavailable()
    } else {
        crate::routing::identity::consent::consent_error(error)
    }
}

/// Decode the exact Actor frozen by the original requester signature.
/// Correlation never re-resolves a principal into a locally hosted account.
fn mimi_correlation_peer(correlation_requester_actor_id: &str) -> Option<ConsentPeer> {
    let actor_id: arkret_wire::ActorId =
        serde_json::from_str(correlation_requester_actor_id).ok()?;
    Some(ConsentPeer::Actor { actor_id })
}

/// Canonical JSON for an identity frozen into the private correlation.
///
/// The correlation stores exactly what the requester signed, so the later
/// comparison is a byte comparison over canonical bytes rather than a
/// structural re-derivation.
fn canonical_identity_json<T: serde::Serialize>(value: &T) -> Result<String, AppError> {
    let value = serde_json::to_value(value).map_err(|error| {
        AppError::internal(format!("serialize MIMI correlation identity: {error}"))
    })?;
    let bytes = arkret_wire::canonical::canonical_json_bytes(&value).map_err(|error| {
        AppError::internal(format!("canonicalize MIMI correlation identity: {error}"))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        AppError::internal(format!(
            "canonical MIMI correlation identity is not UTF-8: {error}"
        ))
    })
}

async fn verify_mimi_consent_correlation(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
    source_id: Option<&str>,
) -> Result<(), AppError> {
    let correlation = state
        .consents()
        .mimi_correlation(body.consent_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("read MIMI consent correlation: {error}")))?
        .ok_or_else(mimi_consent_correlation_unavailable)?;

    if correlation
        .expires_at
        .is_some_and(|expires_at| expires_at <= now())
        || correlation.source_id.as_deref() != source_id
    {
        return Err(mimi_consent_correlation_unavailable());
    }

    // The holder is compared as a complete AccountId. Comparing the principal
    // core here let the same principal's account on another Station accept a
    // consent addressed to this one; section 6.1.1.2 keys the holder dimension
    // on the complete AccountId. Ruling
    // arkret-spec/spec/v1/zh/extensions/mimi-interop.md section 10.
    let Some(body_holder_account_id) = body.actor_id.as_account_id() else {
        return Err(mimi_consent_correlation_unavailable());
    };
    if canonical_identity_json(body_holder_account_id)? != correlation.holder_account_id {
        return Err(mimi_consent_correlation_unavailable());
    }

    let correlation_peer = mimi_correlation_peer(&correlation.requester_actor_id);

    match state
        .persistence()
        .mimi_consent_update_binding(body)
        .await
        .map_err(|_| mimi_consent_correlation_unavailable())?
    {
        Some(true) => return Ok(()),
        Some(false) => return Err(mimi_consent_correlation_unavailable()),
        None => {}
    }
    use arkret_models_collaboration::events_payloads::consent::{
        ConsentExpectedCurrent, ConsentReplacePayload,
    };
    let payload: ConsentReplacePayload = serde_json::from_value(
        serde_json::to_value(&body.consent_event.event.payload)
            .map_err(|_| mimi_consent_correlation_unavailable())?,
    )
    .map_err(|_| mimi_consent_correlation_unavailable())?;
    let peer = correlation_peer.ok_or_else(mimi_consent_correlation_unavailable)?;
    if payload.peer != peer {
        return Err(mimi_consent_correlation_unavailable());
    }
    let previous = match &payload.expected_current {
        ConsentExpectedCurrent::NeverWritten => None,
        ConsentExpectedCurrent::Present { revision } => {
            let basis = state
                .persistence()
                .consent_historical_basis(body_holder_account_id, peer.actor_id(), revision)
                .await
                .map_err(|_| mimi_consent_correlation_unavailable())?;
            if let Some(basis) = basis {
                let replacement: ConsentReplacePayload = serde_json::from_value(
                    serde_json::to_value(&basis.event.payload)
                        .map_err(|_| mimi_consent_correlation_unavailable())?,
                )
                .map_err(|_| mimi_consent_correlation_unavailable())?;
                if replacement.peer != peer {
                    return Err(mimi_consent_correlation_unavailable());
                }
                Some(arkret_models_collaboration::consent_operations::ConsentCurrentRow {
                    selector: arkret_models_collaboration::consent_operations::ConsentCurrentSelector {
                        kind: arkret_models_collaboration::consent_operations::ConsentCurrentSelectorKind::Consent,
                        peer_id: peer.actor_id().clone(),
                    },
                    source_stream_ref: basis.commit.stream_ref,
                    revision: revision.clone(),
                    value: arkret_models_collaboration::consent_operations::ConsentValue { permissions: replacement.permissions },
                })
            } else {
                let read = arkret_models_collaboration::consent_operations::ConsentCurrentReadRequestBody {
                    holder_account_id: body_holder_account_id.clone(), peer: peer.clone(),
                    audience_actor_id: arkret_wire::ActorId::service(body_holder_account_id.station_id.clone()),
                    nonce: crate::routing::call_admission::nonce(),
                };
                let current = crate::routing::call_admission::verified_holder_current(state, &read)
                    .await
                    .map_err(|_| mimi_consent_correlation_unavailable())?;
                match current.current {
                    arkret_models_collaboration::consent_operations::ConsentCurrentState::Present { result }
                        if result.revision == *revision => Some(result),
                    _ => return Err(mimi_consent_correlation_unavailable()),
                }
            }
        }
    };
    let scope = correlation
        .purpose
        .parse::<arkret_wire::ConsentScope>()
        .map_err(|_| mimi_consent_correlation_unavailable())?;
    body.validate_replacement_for(peer.actor_id(), scope, previous.as_ref())
        .map_err(|_| mimi_consent_correlation_unavailable())?;

    state
        .persistence()
        .freeze_mimi_consent_update(body)
        .await
        .map_err(|_| mimi_consent_correlation_unavailable())?;
    Ok(())
}

async fn verify_mimi_consent_actor_proof(
    state: &AppState,
    body: &MimiUpdateConsentRequestBody,
) -> Result<(), AppError> {
    body.validate_consent_event().map_err(|error| {
        AppError::param_invalid(format!("MIMI consent Event carrier is invalid: {error}"))
            .with_internal_reason("invalid_consent_event")
    })?;
    let proof = &body.signature;
    let binding = body.signature_binding_bytes().map_err(|error| {
        AppError::param_invalid(format!("MIMI consent proof binding is invalid: {error}"))
            .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
    })?;
    let device_id = proof
        .verification_method
        .as_str()
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| {
            AppError::param_invalid("MIMI consent proof method has no device fragment")
                .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
        })?;
    let device_id = arkret_identifiers::DeviceId::new(device_id.to_owned()).map_err(|error| {
        AppError::param_invalid(format!(
            "MIMI consent proof method device fragment is invalid: {error}"
        ))
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
    })?;
    let authority = body
        .consent_event
        .event
        .actor_id
        .as_account_id()
        .cloned()
        .ok_or_else(|| {
            AppError::param_invalid("MIMI consent actor must be an account")
                .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
        })?;
    verify_mimi_operation_proof(
        state,
        &binding,
        proof,
        MimiProofSigner::PrincipalDevice {
            authority,
            device_id,
        },
        "MIMI consent",
    )
    .await
}

pub(super) fn request_has_bearer_session(req: &Request) -> bool {
    req.headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().to_ascii_lowercase().starts_with("bearer "))
}

#[endpoint(
    operation_id = "ak.open.mimi.read.identifiers",
    summary = "Query MIMI identifiers",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.read.identifiers.v1"))]
pub(super) async fn mimi_identifiers_query(
    body: JsonBody<MimiIdentifierQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiIdentifierQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let typed = body.into_inner();
    let body = typed_body_value(&typed, "mimi identifiers query")?;
    let source_id = verify_mimi_source_service_signature(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    verify_mimi_identifier_query_proofs(state, &typed, &source_id).await?;
    let identifiers = body
        .get("identifiers")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| AppError::param_missing("identifiers is required"))?;
    let mut matches = Vec::with_capacity(identifiers.len());
    for identifier in identifiers {
        let kind = identifier
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::param_invalid("identifier entries require kind"))?;
        if !matches!(
            kind,
            "mimi_uri" | "did" | "handle" | "phone" | "email" | "opaque"
        ) {
            return Err(AppError::param_invalid("identifier kind is unsupported"));
        }
        let commitment = identifier
            .get("identifier_commitment")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::param_invalid("identifier entries require identifier_commitment")
            })?;
        Hash::new(commitment.to_owned())
            .map_err(|_| AppError::param_invalid("identifier_commitment must be a hash"))?;
        matches.push(MimiIdentifierMatch {
            identifier_commitment: Hash::new(commitment.to_owned())
                .map_err(|_| AppError::param_invalid("identifier_commitment must be a hash"))?,
            matched: false,
            mimi_uri: None,
            subject_id: None,
        });
    }
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1,
        &body,
        json!({
            "contact_graph_exposed": false,
            "connection_identifier_separated": true,
            "reachability_proof_returned": false,
            "mapping_policy": "opaque_fail_closed"
        }),
    );
    json_ok(MimiIdentifierQueryOutcome {
        matches,
        proofs: Vec::new(),
        has_more: false,
    })
}

#[endpoint(
    operation_id = "ak.open.mimi.command.report_abuse",
    summary = "Report MIMI abuse",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.report_abuse.v1"))]
pub(super) async fn mimi_report_abuse(
    body: JsonBody<MimiReportAbuseRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiReportAbuseOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    body.validate()
        .map_err(|_| mimi_reporter_resolution_required())?;
    let source = verify_mimi_source_service_signature(state, req, None).await?;
    let provider_uri = mimi_required_header(req, "provider-id")?;
    let binding = current_mimi_room_binding_for_event_id(
        state,
        &body.reporter_authority.room_binding_ref.event_id,
    )
    .await?
    .ok_or_else(mimi_reporter_resolution_required)?;
    enforce_mimi_writable_binding(&binding.binding)?;
    let authenticated_actor = arkret_wire::ActorId::service(
        arkret_wire::DidCoreId::new(source.clone())
            .map_err(|_| mimi_reporter_resolution_required())?,
    );
    let operation = arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE_V1;
    let canonical_body = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|_| mimi_reporter_resolution_required())?;
    let request_hash = arkret_canonical::sha256_digest(&canonical_body);
    let key = arkret_canonical::sha256_digest(
        &arkret_canonical::canonical_json_bytes(
            &json!({"provider_id":provider_uri,"request_hash":request_hash}),
        )
        .map_err(|e| AppError::internal(e.to_string()))?,
    );
    if let Some(record) = state
        .jobs()
        .scoped_idempotency_record(&authenticated_actor, operation, &key)
        .await
        .map_err(mimi_report_admission_error)?
    {
        return json_ok(
            serde_json::from_value(record.response_body)
                .map_err(|e| AppError::internal(e.to_string()))?,
        );
    }
    let selector = crate::state::mimi_reporter_device_guard(state, &body)
        .await
        .map_err(|_| mimi_reporter_resolution_required())?;
    let claim = &body.report_claim;
    let reason = serde_json::to_value(claim.report_reason_code)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let mut payload = json!({
        "realm_id":claim.realm_id,"effective_scope":claim.scope_ref,"target_ref":claim.target_ref,
        "report_reason_code":reason,"reporter_id":body.reporter_authority.actor_id.signing_principal_id(),
        "provenance":"mimi_facade","source_provider_id":source,
    });
    let object = payload.as_object_mut().expect("report object");
    for (field, value) in [
        ("description", serde_json::to_value(&claim.description)),
        (
            "evidence_package",
            serde_json::to_value(&claim.evidence_package),
        ),
        (
            "franking_proof",
            serde_json::to_value(&claim.franking_proof),
        ),
    ] {
        let value = value.map_err(|e| AppError::internal(e.to_string()))?;
        if !value.is_null() {
            object.insert(field.into(), value);
        }
    }
    if !claim.evidence_refs.is_empty() {
        object.insert(
            "evidence_refs".into(),
            serde_json::to_value(&claim.evidence_refs)
                .map_err(|e| AppError::internal(e.to_string()))?,
        );
    }
    let payload = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload,
    >(payload)
    .map_err(|e| {
        mimi_report_admission_error(coland_services::ServiceError::SchemaViolation(
            e.to_string(),
        ))
    })?;
    let event = crate::state::author_mimi_event::<arkret_wire::event_spec::SelfModerationReport>(
        state,
        claim.scope_ref.clone(),
        payload,
    )
    .await
    .map_err(mimi_report_admission_error)?;
    let response = MimiReportAbuseOutcome {
        report_id: arkret_wire::ReportId::from_event_id(&event.event_id),
        routed_to_ids: Vec::new(),
    };
    let at = chrono::Utc::now();
    let guard = coland_storage::SelfProducerCommitGuard::MimiFacade {
        service_id: state.service_core_id(),
        verification_method: event
            .producer_proof
            .as_ref()
            .expect("authored proof")
            .verification_method
            .clone(),
        room_uri: MimiRoomUri::new(
            binding
                .binding
                .get("mimi_room_uri")
                .and_then(Value::as_str)
                .ok_or_else(mimi_reporter_resolution_required)?
                .to_owned(),
        )
        .map_err(|_| mimi_reporter_resolution_required())?,
        binding_event_id: body.reporter_authority.room_binding_ref.event_id.clone(),
        attributed_actor: body.reporter_authority.actor_id.clone(),
        source_provider_id: arkret_wire::DidCoreId::new(source)
            .map_err(|_| mimi_reporter_resolution_required())?,
        reporter_authority: Some(
            serde_json::to_value(&body).map_err(|e| AppError::internal(e.to_string()))?,
        ),
        submit_request: None,
        mapping_receipt: None,
        reporter_device_guard: Some(Box::new(selector)),
    };
    let idempotency = coland_services::events::IdempotentResponse {
        authenticated_actor: authenticated_actor.clone(),
        operation_id: operation.into(),
        key: key.clone(),
        request_hash,
        status: 200,
        body: serde_json::to_value(&response).map_err(|e| AppError::internal(e.to_string()))?,
        created_at: at,
        expires_at: at + chrono::Duration::days(30),
    };
    if let Err(error) =
        crate::state::commit_mimi_event(state, event, guard, Some(idempotency)).await
    {
        if let Some(record) = state
            .jobs()
            .scoped_idempotency_record(&authenticated_actor, operation, &key)
            .await
            .map_err(mimi_report_admission_error)?
        {
            return json_ok(
                serde_json::from_value(record.response_body)
                    .map_err(|e| AppError::internal(e.to_string()))?,
            );
        }
        return Err(mimi_report_admission_error(error));
    }
    json_ok(response)
}

// Admission conflicts carry private current/visibility diagnostics. Only
// infrastructure failures retain the generic server-error classification.
fn mimi_report_admission_error(error: coland_services::ServiceError) -> AppError {
    if error.is_conflict_kind() || error.is_not_found() {
        tracing::debug!(error = %error, "MIMI reporter admission refused");
        mimi_reporter_resolution_required()
    } else {
        mimi_admission_error(error)
    }
}

fn mimi_reporter_resolution_required() -> AppError {
    AppError::capability_denied("MIMI reporter authority admission is unavailable")
        .with_internal_reason("mimi_reporter_resolution_required")
}
#[endpoint(
    operation_id = "ak.open.mimi.command.proxy_download",
    summary = "Proxy a MIMI download",
    tags("mimi")
)]
#[tracing::instrument(skip_all, fields(op = "ak.open.mimi.command.proxy_download.v1"))]
pub(super) async fn mimi_proxy_download(
    body: JsonBody<MimiProxyDownloadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MimiProxyDownloadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = typed_body_value(body.into_inner(), "mimi proxy download")?;
    verify_mimi_source_service_signature(state, req, None).await?;
    if let Some(message) = unsupported_mimi_draft(&body) {
        return Err(AppError::param_invalid(message).with_reason_code("mimi_draft_unsupported"));
    }
    let asset_ref = body
        .get("asset_ref")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::param_missing("asset_ref is required"))?;
    enforce_mimi_proxy_download_egress_policy(state, asset_ref)?;
    let asset_policy = body
        .get("asset_privacy_policy")
        .and_then(|value| value.as_str())
        .unwrap_or("provider_proxy");
    let blob = state.deliveries().blob(asset_ref).await.ok().flatten();
    let proxy_required = matches!(asset_policy, "provider_proxy" | "ohttp_relay");
    let download_ref = if proxy_required {
        mimi_proxy_download_ref(state, asset_ref)?
    } else {
        asset_ref.to_owned()
    };
    let download_ref = arkret_wire::NonEmptyString::new(download_ref)
        .map_err(|_| AppError::internal("MIMI proxy download reference is empty"))?;
    let mut headers = BTreeMap::new();
    if let Some(blob) = blob.as_ref() {
        headers.insert(
            "content-type".to_owned(),
            arkret_wire::NonEmptyString::new(blob.media_type.clone())
                .map_err(|_| AppError::internal("MIMI proxy media type is empty"))?,
        );
        headers.insert(
            "content-length".to_owned(),
            arkret_wire::NonEmptyString::new(blob.size_bytes.to_string())
                .map_err(|_| AppError::internal("MIMI proxy content length is empty"))?,
        );
    }
    let _receipt = mimi_receipt(
        state,
        arkret_wire::ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD_V1,
        &body,
        json!({
            "asset_privacy_policy": asset_policy,
            "direct_object_store_url_returned": false,
            "client_must_verify_content_hash": true
        }),
    );
    json_ok(MimiProxyDownloadOutcome {
        download_ref,
        headers,
        expires_at: Some(now() + Duration::minutes(5)),
    })
}

pub(super) fn mimi_proxy_download_ref(
    state: &AppState,
    asset_ref: &str,
) -> Result<String, AppError> {
    let mut url = reqwest::Url::parse(&format!("{}/proxy-download", mimi_base_url(state)))
        .map_err(|error| AppError::internal(format!("MIMI proxy download URL invalid: {error}")))?;
    url.query_pairs_mut().append_pair("asset_ref", asset_ref);
    Ok(url.to_string())
}

pub(super) fn enforce_mimi_proxy_download_egress_policy(
    state: &AppState,
    asset_ref: &str,
) -> Result<(), AppError> {
    if asset_ref.trim() != asset_ref || asset_ref.is_empty() {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: asset_ref must be a non-empty canonical reference",
        ));
    }
    let asset_ref = asset_ref.trim();
    // The in-protocol branch is the typed blob reference. A string that merely
    // opens with `ak:blob:` is not one, and must fall through to the URL /
    // scheme rules below rather than being waved past egress policy.
    if asset_ref.starts_with("ak:blob:") && arkret_identifiers::BlobRef::new(asset_ref).is_ok() {
        return Ok(());
    }
    if asset_ref.starts_with("//") || asset_ref.contains('\\') {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: URL-like asset_ref is not allowed without an explicit http(s) scheme",
        ));
    }
    if asset_ref.contains("://") {
        return crate::security::validate_http_url_for_egress(
            asset_ref,
            "mimi proxy download",
            state.config().development_mode,
        )
        .map(|_| ())
        .map_err(mimi_proxy_download_egress_denied);
    }
    if asset_ref.contains(':') {
        return Err(mimi_proxy_download_egress_denied(
            "mimi proxy download: non-blob URI scheme is not allowed",
        ));
    }
    Ok(())
}

pub(super) fn mimi_proxy_download_egress_denied(error: impl Into<String>) -> AppError {
    AppError::capability_denied("MIMI proxy download asset_ref is denied by egress policy")
        .with_reason_code("egress_policy_denied")
        .with_reason_detail(error)
}

#[cfg(test)]
mod consent_proof_tests {
    use arkret_identifiers::{ConsentId, DeviceId, Did, DidCoreId, Hash, Hlc, RealmId, StrandId};
    use arkret_models_collaboration::mimi_operations::MimiConsentDecision;
    use arkret_models_collaboration::objects::mimi::{MimiIdentifier, MimiIdentifierKind};
    use arkret_wire::{
        Audience, EventAdmissionSubmission, EventKind, PayloadProof, ScopeRef, proof_kind,
    };
    use coland_http::error::ErrorCode;
    use coland_storage_postgres::Db;

    use super::*;

    fn state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        AppState::new(config, Db { pool: None })
    }

    fn request(state: &AppState) -> MimiUpdateConsentRequestBody {
        let actor_did = Did::new("did:web:mimi-proof-test.invalid".to_owned()).unwrap();
        let actor_id = arkret_wire::project_did_to_core_id(&actor_did).unwrap();
        let verification_method =
            format!("{actor_did}#ak:device:01964137-0000-7000-8000-000000000777");
        let consent_id =
            ConsentId::new("ak:consent:01964137-0000-7000-8000-000000000777".to_owned()).unwrap();
        let realm_id =
            RealmId::new("ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned())
                .unwrap();
        let mut consent_event = crate::test_event::raw_event_at(
            EventKind::ConsentReplace.as_str(),
            ScopeRef::Realm { realm_id },
            crate::test_actor_id(&actor_did),
            1,
            Hlc::new(state.hlc().now()).unwrap(),
            json!({
                "peer": {
                    "kind": "actor",
                    "actor_id": {
                        "kind": "account",
                        "account_id": {
                            "principal_id": "ak:did_core:web:mimi-peer-test.invalid",
                            "station_id": state.service_core_id(),
                        },
                    },
                },
                "expected_current":{"state":"never_written"},"permissions":[{"consent_scope":"voice_call"}]
            }),
            now(),
        )
        .unwrap();
        consent_event.actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.clone(),
            state.service_core_id(),
        ));
        consent_event = coland_test_support::device_authorization_history::sign_event(
            consent_event,
            arkret_wire::DidUrl::new(verification_method.clone()).unwrap(),
            arkret_test_kit::keys::development_signing_key(&verification_method).to_bytes(),
        );
        let mut request = MimiUpdateConsentRequestBody {
            consent_id,
            decision: MimiConsentDecision::Accept,
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                actor_id,
                state.service_core_id().clone(),
            )),
            consent_event: EventAdmissionSubmission::new(consent_event),
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new(verification_method.clone()).unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: now(),
                domain: Some(state.config().trust_domain.to_string()),
                audience: Some(Audience::Single(state.service_id().to_owned())),
                proof_purpose: None,
                jws: String::new(),
            },
            reason: None,
            expires_at: None,
        };
        request.signature.payload_digest = request.payload_digest().unwrap();
        let binding = request
            .unsigned_signature_binding_bytes(&request.signature.unsigned())
            .unwrap();
        let signing_key = arkret_test_kit::keys::development_signing_key(&verification_method);
        request.signature.jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, &signing_key).unwrap();
        request
    }

    fn canonical_json<T: serde::Serialize>(value: &T) -> String {
        let value = serde_json::to_value(value).unwrap();
        String::from_utf8(arkret_wire::canonical::canonical_json_bytes(&value).unwrap()).unwrap()
    }

    /// The peer the update payload names, so the correlation and the grant
    /// agree in the positive cases.
    fn test_requester_actor(state: &AppState) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:mimi-peer-test.invalid").unwrap(),
            state.service_core_id(),
        ))
    }

    async fn install_correlation(
        state: &AppState,
        request: &MimiUpdateConsentRequestBody,
        holder_account_id: &arkret_wire::AccountId,
    ) {
        state
            .consents()
            .save_mimi_correlation(MimiConsentCorrelation {
                consent_id: request.consent_id.to_string(),
                requester_actor_id: canonical_json(&test_requester_actor(state)),
                holder_account_id: canonical_json(holder_account_id),
                purpose: "voice_call".to_owned(),
                strand_id: None,
                source_id: None,
                created_at: now(),
                expires_at: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn consent_correlation_binds_target_peer_and_scope() {
        let state = state();
        let request = request(&state);
        let holder_account_id = request
            .actor_id
            .as_account_id()
            .expect("holder actor is an account")
            .clone();
        install_correlation(&state, &request, &holder_account_id).await;

        verify_mimi_consent_correlation(&state, &request, None)
            .await
            .expect("matching private correlation");

        let mut mismatched = request.clone();
        mismatched
            .consent_event
            .event
            .payload
            .insert("peer".to_owned(), json!("did:web:other-peer-test.invalid"));
        let error = verify_mimi_consent_correlation(&state, &mismatched, None)
            .await
            .expect_err("mismatched private correlation must fail closed");
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    /// Ruling:
    ///
    /// arkret-spec/spec/v1/zh/extensions/mimi-interop.md section 10
    ///
    /// The holder is
    /// compared as a complete AccountId. Before it, the correlation stored a principal core
    /// and this update -- from the same principal's account on a *different*
    /// Station -- was accepted.
    #[tokio::test]
    async fn consent_correlation_rejects_same_principal_on_another_station() {
        let state = state();
        let request = request(&state);
        let holder = request
            .actor_id
            .as_account_id()
            .expect("holder actor is an account")
            .clone();
        let other_station_holder = arkret_wire::AccountId::new(
            holder.principal_id.clone(),
            DidCoreId::new("ak:did_core:web:other-holder-station.invalid").unwrap(),
        );
        assert_eq!(
            other_station_holder.principal_id, holder.principal_id,
            "the negative is only meaningful while the principal cores match"
        );
        install_correlation(&state, &request, &other_station_holder).await;

        let error = verify_mimi_consent_correlation(&state, &request, None)
            .await
            .expect_err("same principal on another Station is a different holder");
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn unknown_and_invisible_consent_correlations_are_indistinguishable() {
        let state = state();
        let request = request(&state);
        let another_holder = arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:another-holder.invalid").unwrap(),
            DidCoreId::new("ak:did_core:web:another-holder-station.invalid").unwrap(),
        );
        install_correlation(&state, &request, &another_holder).await;

        let invisible = verify_mimi_consent_correlation(&state, &request, None)
            .await
            .expect_err("another holder's correlation must be unavailable");

        let mut unknown = request.clone();
        unknown.consent_id =
            ConsentId::new("ak:consent:01964137-0000-7000-8000-000000000778".to_owned()).unwrap();
        let unknown = verify_mimi_consent_correlation(&state, &unknown, None)
            .await
            .expect_err("unknown correlation must be unavailable");

        assert_eq!(invisible.code, ErrorCode::NotFound);
        assert_eq!(unknown.code, invisible.code);
        assert_eq!(unknown.message, invisible.message);
    }

    #[tokio::test]
    async fn consent_deny_and_revoke_use_exact_current_and_preserve_accepted_retry() {
        use coland_storage::ConsentAdmissionOutcome;
        use coland_test_support::AppStateTestExt as _;
        async fn footprint(pool: &coland_storage_postgres::PgPool) -> Value {
            use diesel_async::RunQueryDsl;
            #[derive(diesel::QueryableByName)]
            struct Row {
                #[diesel(sql_type = diesel::sql_types::Jsonb)]
                value: Value,
            }
            let mut conn = pool.get().await.unwrap();
            diesel::sql_query("SELECT jsonb_build_array((SELECT count(*) FROM canonical_events),(SELECT count(*) FROM realm_commits),(SELECT jsonb_agg(to_jsonb(r) ORDER BY peer_id) FROM consent_current_results r),(SELECT count(*) FROM consent_result_versions),(SELECT count(*) FROM account_data_changes)) AS value")
                .get_result::<Row>(&mut conn).await.unwrap().value
        }
        for (decision, scope) in [
            (MimiConsentDecision::Deny, "voice_call"),
            (MimiConsentDecision::Revoke, "voice_call"),
            (MimiConsentDecision::Revoke, "video_call"),
        ] {
            let (external, pool) =
                coland_test_support::app_state_with_pool(coland_test_support::app_config());
            let persistence = external.test_persistence();
            let mut config = crate::config::AppConfig::test_default();
            config.development_mode = true;
            config.public_base_url = external.config().public_base_url.clone();
            // Unit tests compile another instance of this crate. Share the
            // seeded PG/Service fixture, keeping this crate's local AppState.
            let state = AppState::new_with_service_identity(
                config,
                Db { pool: None },
                persistence.clone(),
                external.service_identity_state().as_ref().clone(),
                external.service_resolution_commitment().as_ref().clone(),
                external.notary_signing_key().to_bytes(),
            );
            let fixture =
                coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
            fixture.admit_into(persistence.as_ref()).await.unwrap();
            let mut body = request(&state);
            body.actor_id = arkret_wire::ActorId::account(fixture.history.account.clone());
            let signed_event = |kind: EventKind, payload: Value| {
                let mut event = arkret_wire::test_support::raw_event_at(
                    kind.as_str(),
                    fixture.unit.transactions[1].event.scope_ref.clone(),
                    fixture.history.account.principal_id.clone(),
                    fixture.history.account.station_id.clone(),
                    payload,
                    now(),
                )
                .unwrap();
                event.authorization_ref =
                    Some(fixture.unit.transactions[0].event.event_id.clone().into());
                coland_test_support::device_authorization_history::sign_event(
                    event,
                    fixture.history.device_verification_method.clone(),
                    fixture.history.founding_device_signing_seed,
                )
            };
            body.consent_event = EventAdmissionSubmission::new(signed_event(
                EventKind::ConsentReplace,
                json!({
                    "peer": {"kind": "actor", "actor_id": test_requester_actor(&state)},
                    "expected_current":{"state":"never_written"},"permissions":[{"consent_scope":scope}]
                }),
            ));
            install_correlation(&state, &body, &fixture.history.account).await;
            if scope == "voice_call" {
                verify_mimi_consent_correlation(&state, &body, None)
                    .await
                    .unwrap();
            }
            let ConsentAdmissionOutcome::Committed(granted) =
                crate::state::authority_consent::submit_mimi(&state, &body.consent_event)
                    .await
                    .unwrap()
            else {
                panic!("first grant must commit")
            };
            body.decision = decision;
            body.consent_id = ConsentId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64);
            install_correlation(&state, &body, &fixture.history.account).await;
            body.consent_event = EventAdmissionSubmission::new(signed_event(
                EventKind::ConsentReplace,
                json!({
                    "peer":{"kind":"actor","actor_id":test_requester_actor(&state)},"expected_current":{"state":"present","revision":granted.view().revision},"permissions":[]
                }),
            ));
            body.validate_consent_event().unwrap();
            // A native grant can exist with a different scope from the
            // immutable MIMI correlation. The facade cannot revoke it.
            if scope != "voice_call" {
                let before = footprint(&pool).await;
                assert_eq!(
                    verify_mimi_consent_correlation(&state, &body, None)
                        .await
                        .unwrap_err()
                        .code,
                    ErrorCode::NotFound
                );
                assert_eq!(footprint(&pool).await, before);
                continue;
            }
            verify_mimi_consent_correlation(&state, &body, None)
                .await
                .unwrap();

            let before = footprint(&pool).await;
            let mut stale = body.clone();
            let mut stale_revision = granted.view().revision;
            stale_revision.stream_position -= 1;
            stale.consent_event = EventAdmissionSubmission::new(signed_event(
                EventKind::ConsentReplace,
                json!({
                    "peer":{"kind":"actor","actor_id":test_requester_actor(&state)},"expected_current":{"state":"present","revision":stale_revision},"permissions":[]
                }),
            ));
            stale.validate_consent_event().unwrap();
            let error = verify_mimi_consent_correlation(&state, &stale, None)
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::NotFound);
            let raced = crate::state::authority_consent::submit_mimi(&state, &stale.consent_event)
                .await
                .unwrap_err();
            assert_eq!(
                mimi_consent_admission_error(decision, raced).code,
                ErrorCode::NotFound
            );
            assert_eq!(footprint(&pool).await, before);

            let ConsentAdmissionOutcome::Committed(revoked) =
                crate::state::authority_consent::submit_mimi(&state, &body.consent_event)
                    .await
                    .unwrap()
            else {
                panic!("first revoke must commit")
            };
            assert!(revoked.value.permissions.is_empty());
            assert!(revoked.commit.stream_position > granted.commit.stream_position);
            let after = footprint(&pool).await;
            verify_mimi_consent_correlation(&state, &body, None)
                .await
                .unwrap();
            let ConsentAdmissionOutcome::Duplicate(replayed) =
                crate::state::authority_consent::submit_mimi(&state, &body.consent_event)
                    .await
                    .unwrap()
            else {
                panic!("exact revoke must replay")
            };
            assert_eq!(replayed.view(), revoked.view());
            assert_eq!(replayed.event, revoked.event);

            let mut another_revoke = body.clone();
            another_revoke.consent_event = EventAdmissionSubmission::new(signed_event(
                EventKind::ConsentReplace,
                json!({
                    "peer":{"kind":"actor","actor_id":test_requester_actor(&state)},"expected_current":{"state":"present","revision":granted.view().revision},"permissions":[]
                }),
            ));
            assert_eq!(
                verify_mimi_consent_correlation(&state, &another_revoke, None)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::NotFound
            );
            assert_eq!(footprint(&pool).await, after);
            let refused = mimi_consent_correlation_unavailable();
            let error =
                crate::state::authority_consent::submit_mimi(&state, &another_revoke.consent_event)
                    .await
                    .unwrap_err();
            let raced = mimi_consent_admission_error(decision, error);
            assert_eq!(raced.code, refused.code);
            assert_eq!(raced.message, refused.message);
            let current = state
                .persistence()
                .consent_current(&fixture.history.account)
                .await
                .unwrap();
            assert_eq!(current.len(), 1);
            assert_eq!(current[0].view(), revoked.view());
            assert_eq!(footprint(&pool).await, after);
        }
    }

    /// A `did:key` originator. `did:key` documents are self-describing, so the
    /// production DID-controlled verification path resolves them without any
    /// deployment-local device or account state.
    fn did_key_originator(
        seed: &str,
    ) -> (ed25519_dalek::SigningKey, DidCoreId, arkret_wire::DidUrl) {
        let signing_key = arkret_test_kit::keys::development_signing_key(seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let core_id = DidCoreId::new(format!("ak:did_core:key:{multibase}")).unwrap();
        let method = arkret_wire::DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap();
        (signing_key, core_id, method)
    }

    fn unsigned_request_proof(state: &AppState, method: &arkret_wire::DidUrl) -> PayloadProof {
        PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: now(),
            domain: Some(state.config().trust_domain.to_string()),
            audience: Some(Audience::Single(state.service_id().to_owned())),
            proof_purpose: None,
            jws: String::new(),
        }
    }

    fn fixture_strand_id() -> StrandId {
        let event_id =
            EventId::new("ak:event:AY_KsmK6yLixEOrtHaJQKVPxqvToAwftLv3kDhf3WwDk".to_owned())
                .unwrap();
        StrandId::from_event_id(&event_id)
    }

    fn key_material_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
    ) -> MimiKeyMaterialRequestBody {
        MimiKeyMaterialRequestBody {
            requester_id: requester_id.clone(),
            strand_id: fixture_strand_id(),
            device_id: DeviceId::new("ak:device:01964137-0000-7000-8000-000000000901".to_owned())
                .unwrap(),
            mimi_room_uri: None,
            realm_id: None,
            mls_group_id: None,
            epoch: None,
            proofs: vec![unsigned_request_proof(state, method)],
        }
    }

    fn signed_key_material_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MimiKeyMaterialRequestBody {
        let mut body = key_material_request(state, requester_id, method);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body
            .unsigned_proof_binding_bytes(&proof.unsigned())
            .unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key).unwrap();
        body
    }

    fn request_consent_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
    ) -> MimiRequestConsentRequestBody {
        MimiRequestConsentRequestBody {
            requester_actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                requester_id.clone(),
                DidCoreId::new("ak:did_core:web:mimi-requester-station.invalid").unwrap(),
            )),
            holder_account_id: arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:mimi-holder-test.invalid").unwrap(),
                DidCoreId::new("ak:did_core:web:mimi-holder-station.invalid").unwrap(),
            ),
            purpose: MimiConsentPurpose::VoiceCall,
            strand_id: None,
            expires_at: None,
            proofs: vec![unsigned_request_proof(state, method)],
        }
    }

    fn signed_request_consent_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MimiRequestConsentRequestBody {
        let mut body = request_consent_request(state, requester_id, method);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body
            .unsigned_proof_binding_bytes(&proof.unsigned())
            .unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key).unwrap();
        body
    }

    fn identifier_query_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
    ) -> MimiIdentifierQueryRequestBody {
        MimiIdentifierQueryRequestBody {
            identifiers: vec![MimiIdentifier {
                kind: MimiIdentifierKind::Handle,
                identifier_commitment: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            }],
            requester_id: Some(requester_id.clone()),
            privacy_profile: None,
            proofs: vec![unsigned_request_proof(state, method)],
        }
    }

    fn signed_identifier_query_request(
        state: &AppState,
        requester_id: &DidCoreId,
        method: &arkret_wire::DidUrl,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> MimiIdentifierQueryRequestBody {
        let mut body = identifier_query_request(state, requester_id, method);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body
            .unsigned_proof_binding_bytes(&proof.unsigned())
            .unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, signing_key).unwrap();
        body
    }

    fn binding_context(binding: &[u8]) -> String {
        serde_json::from_slice::<Value>(binding)
            .unwrap()
            .get("context")
            .and_then(Value::as_str)
            .expect("MIMI binding transcript carries a context")
            .to_owned()
    }

    fn assert_rejected_proof(error: &AppError) {
        assert_eq!(error.code, ErrorCode::ParamInvalid);
        assert_eq!(
            error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::PROOF_INVALID)
        );
    }

    #[tokio::test]
    async fn principal_device_operation_proof_rechecks_the_durable_revocation_gate() {
        use coland_test_support::AppStateTestExt as _;
        let (external, pool) =
            coland_test_support::app_state_with_pool(coland_test_support::app_config());
        let persistence = external.test_persistence();
        let mut config = crate::config::AppConfig::test_default();
        config.development_mode = true;
        config.public_base_url = external.config().public_base_url.clone();
        let state = AppState::new_with_service_identity(
            config,
            Db { pool: Some(pool) },
            persistence.clone(),
            external.service_identity_state().as_ref().clone(),
            external.service_resolution_commitment().as_ref().clone(),
            external.notary_signing_key().to_bytes(),
        );
        let fixture = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        let selector = fixture
            .admit_founding_device(persistence.as_ref())
            .await
            .unwrap();
        let binding = b"MIMI current device proof revocation regression";
        let mut proof = unsigned_request_proof(&state, &fixture.history.device_verification_method);
        proof.payload_digest = Hash::new(arkret_canonical::sha256_digest(binding)).unwrap();
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            binding,
            &ed25519_dalek::SigningKey::from_bytes(&fixture.history.founding_device_signing_seed),
        )
        .unwrap();
        let signer = || MimiProofSigner::PrincipalDevice {
            authority: fixture.history.account.clone(),
            device_id: fixture.history.founding_device_id.clone(),
        };
        verify_mimi_operation_proof(&state, binding, &proof, signer(), "MIMI test")
            .await
            .unwrap();
        // Exercise the real durable terminal gate. The complete SecurityRotation
        // ceremony is independently covered by its owner, not simulated here.
        persistence
            .device_revocations()
            .commit_revocation(&coland_storage::DeviceRevocationTransition {
                selector: selector.clone(),
                revoke_ref: arkret_wire::CommittedEventRef {
                    event_id: EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x70; 32],
                    ),
                    commit_id: arkret_wire::RealmCommitId::from_digest([0x71; 32]),
                    stream_ref: selector.authorization_ref.stream_ref.clone(),
                    stream_position: selector.authorization_ref.stream_position + 1,
                },
                committed_at: now(),
            })
            .await
            .unwrap();
        let error = verify_mimi_operation_proof(&state, binding, &proof, signer(), "MIMI test")
            .await
            .unwrap_err();
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn request_family_proofs_verify_under_their_own_context() {
        let state = state();
        let (signing_key, requester_id, method) =
            did_key_originator("mimi-request-family-positive");

        verify_mimi_key_material_request_proofs(
            &state,
            &signed_key_material_request(&state, &requester_id, &method, &signing_key),
        )
        .await
        .expect("key material request proof");
        verify_mimi_request_consent_proofs(
            &state,
            &signed_request_consent_request(&state, &requester_id, &method, &signing_key),
            None,
        )
        .await
        .expect_err("DID key control cannot authorize an unproven remote Account");
        verify_mimi_identifier_query_proofs(
            &state,
            &signed_identifier_query_request(&state, &requester_id, &method, &signing_key),
            requester_id.as_str(),
        )
        .await
        .expect("identifier query proof");
    }

    #[tokio::test]
    async fn request_families_bind_distinct_proof_contexts() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-context-separation");
        let key_material =
            signed_key_material_request(&state, &requester_id, &method, &signing_key);
        let consent = signed_request_consent_request(&state, &requester_id, &method, &signing_key);
        let query = signed_identifier_query_request(&state, &requester_id, &method, &signing_key);

        let contexts = [
            binding_context(
                &key_material
                    .proof_binding_bytes(&key_material.proofs[0])
                    .unwrap(),
            ),
            binding_context(&consent.proof_binding_bytes(&consent.proofs[0]).unwrap()),
            binding_context(&query.proof_binding_bytes(&query.proofs[0]).unwrap()),
        ];
        let distinct: std::collections::BTreeSet<&String> = contexts.iter().collect();
        assert_eq!(
            distinct.len(),
            contexts.len(),
            "each MIMI request family must sign under its own registered context"
        );
    }

    // Cross-family replay: the transplanted proof keeps the same signer, the
    // same destination binding and the same freshness, and its
    // `payload_digest` is re-pointed at the destination body so the SDK digest
    // check cannot be what rejects it. The only remaining difference is the
    // per-family context baked into the signed transcript.
    #[tokio::test]
    async fn key_material_rejects_a_consent_request_context_proof() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-cross-family-consent");
        let consent = signed_request_consent_request(&state, &requester_id, &method, &signing_key);

        let mut key_material = key_material_request(&state, &requester_id, &method);
        let mut replayed = consent.proofs[0].clone();
        replayed.payload_digest = key_material.payload_digest().unwrap();
        key_material.proofs = vec![replayed];

        let error = verify_mimi_key_material_request_proofs(&state, &key_material)
            .await
            .expect_err("a consent-request context proof must not verify as key material");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn request_consent_rejects_an_identifier_query_context_proof() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-cross-family-query");
        let query = signed_identifier_query_request(&state, &requester_id, &method, &signing_key);

        let mut consent = request_consent_request(&state, &requester_id, &method);
        let mut replayed = query.proofs[0].clone();
        replayed.payload_digest = consent.payload_digest().unwrap();
        consent.proofs = vec![replayed];

        let error = verify_mimi_request_consent_proofs(&state, &consent, None)
            .await
            .expect_err("an identifier-query context proof must not verify as a consent request");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn identifier_query_rejects_a_key_material_context_proof() {
        let state = state();
        let (signing_key, requester_id, method) =
            did_key_originator("mimi-cross-family-key-material");
        let key_material =
            signed_key_material_request(&state, &requester_id, &method, &signing_key);

        let mut query = identifier_query_request(&state, &requester_id, &method);
        let mut replayed = key_material.proofs[0].clone();
        replayed.payload_digest = query.payload_digest().unwrap();
        query.proofs = vec![replayed];

        let error = verify_mimi_identifier_query_proofs(&state, &query, requester_id.as_str())
            .await
            .expect_err("a key-material context proof must not verify as an identifier query");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn key_material_rejects_a_proof_outside_the_replay_window() {
        let state = state();
        let (signing_key, requester_id, method) = did_key_originator("mimi-replay-window");
        let mut body = key_material_request(&state, &requester_id, &method);
        body.proofs[0].created_at =
            now() - Duration::seconds(MIMI_OPERATION_PROOF_WINDOW_SECONDS + 1);
        body.proofs[0].payload_digest = body.payload_digest().unwrap();
        let proof = body.proofs[0].clone();
        let binding = body
            .unsigned_proof_binding_bytes(&proof.unsigned())
            .unwrap();
        body.proofs[0].jws =
            arkret_signatures::jws::sign_jws_ed25519(&binding, &signing_key).unwrap();

        let error = verify_mimi_key_material_request_proofs(&state, &body)
            .await
            .expect_err("a proof older than the replay window must fail closed");
        assert_rejected_proof(&error);
    }

    #[tokio::test]
    async fn request_family_proofs_stay_optional_on_the_wire() {
        let state = state();
        let (_signing_key, requester_id, method) = did_key_originator("mimi-optional-proofs");
        let mut key_material = key_material_request(&state, &requester_id, &method);
        key_material.proofs.clear();
        let mut query = identifier_query_request(&state, &requester_id, &method);
        query.proofs.clear();

        verify_mimi_key_material_request_proofs(&state, &key_material)
            .await
            .expect("key material proofs are serde-default and may be absent");
        verify_mimi_identifier_query_proofs(&state, &query, requester_id.as_str())
            .await
            .expect("identifier query proofs are serde-default and may be absent");
    }

    // Only a typed blob reference takes the in-protocol branch. A string that
    // merely opens with `ak:blob:` is not one and must be judged by the URL /
    // scheme rules, which fail closed on a bare `ak:` scheme.
    #[test]
    fn proxy_download_admits_only_typed_blob_references() {
        let state = state();
        enforce_mimi_proxy_download_egress_policy(
            &state,
            &format!("ak:blob:sha256:{}", "a".repeat(64)),
        )
        .expect("a content-addressed blob reference stays in-protocol");
        enforce_mimi_proxy_download_egress_policy(
            &state,
            "ak:blob:01964137-0000-7000-8000-000000000777",
        )
        .expect_err("a Blob metadata id does not address downloadable bytes");
        enforce_mimi_proxy_download_egress_policy(&state, "ak:blob:abc")
            .expect_err("a non-canonical blob payload is not a blob reference");
        enforce_mimi_proxy_download_egress_policy(&state, &format!("sha256:{}", "a".repeat(64)))
            .expect_err("a bare digest carries no kind segment");
    }
}
