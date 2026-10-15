//! Verify the compact media binding against its exact enclosing roster tuple.

use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_models_collaboration::objects::media::CallMediaParticipantBinding;
use arkret_signatures::media::{ParticipantBindingContext, participant_binding_signing_input};
use arkret_wire::{CallId, DeviceId, DidCoreId};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::state::AppState;

pub(crate) fn verify_binding_signature(
    context: &ParticipantBindingContext<'_>,
    sig: &str,
    verifying_key: &VerifyingKey,
) -> bool {
    let Ok(bytes) = arkret_canonical::base64url_decode(sig) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    let Ok(input) = participant_binding_signing_input(context) else {
        return false;
    };
    verifying_key.verify_strict(&input, &signature).is_ok()
}

fn required_string<'a>(object: &'a Value, field: &str) -> Result<&'a str, &'static str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("participant_binding_invalid: enclosing carrier lacks a required tuple field")
}

pub(crate) fn verify_call_state_participant_bindings(
    state: &AppState,
    operation: &Operation,
) -> Result<(), &'static str> {
    let payload = &operation.payload;
    let Some(participant) = payload
        .get("roster_delta")
        .filter(|delta| delta.get("op").and_then(Value::as_str) == Some("join"))
        .and_then(|delta| delta.get("participant"))
    else {
        return Ok(());
    };
    let Some(binding_value) = participant.get("participant_binding") else {
        return Ok(());
    };
    let binding: CallMediaParticipantBinding = serde_json::from_value(binding_value.clone())
        .map_err(
            |_| "participant_binding_invalid: binding must have exactly the registered fields",
        )?;
    let call_id = CallId::new(required_string(payload, "call_id")?)
        .map_err(|_| "participant_binding_invalid: enclosing call_id is invalid")?;
    let actor_id: DidCoreId = serde_json::from_value(
        participant
            .get("actor_id")
            .cloned()
            .ok_or("participant_binding_invalid: enclosing actor_id is missing")?,
    )
    .map_err(|_| "participant_binding_invalid: enclosing actor_id is invalid")?;
    let device_id = DeviceId::new(required_string(participant, "device_id")?)
        .map_err(|_| "participant_binding_invalid: enclosing device_id is invalid")?;
    let participant_id = required_string(participant, "participant_id")?;
    let focus_id = required_string(participant, "focus_id")?;
    let focus_facet = coland_domain::reducer::FacetRef::new(
        coland_domain::reducer::facet::CALL_FOCUS,
        call_id.as_str(),
    );
    let projection = state.projections().snapshot();
    let current_focus = projection
        .facet_value(operation.realm_id.as_str(), &focus_facet)
        .and_then(|focus| focus.get("session_focus"))
        .and_then(Value::as_str);
    let selected_focus = current_focus.or_else(|| {
        payload
            .get("focus")
            .and_then(|focus| focus.get("session_focus"))
            .and_then(Value::as_str)
    });
    if selected_focus != Some(focus_id) {
        return Err("participant_binding_invalid: roster focus does not equal the selected focus");
    }
    let media = projection
        .realm_facet_value(
            operation.realm_id.as_str(),
            coland_domain::reducer::facet::REALM_MEDIA_SERVICE,
        )
        .ok_or("token_issuer_unauthorised: current media service is missing")?;
    let service_id = DidCoreId::new(
        media
            .get("service_id")
            .and_then(Value::as_str)
            .ok_or("token_issuer_unauthorised: current media service id is missing")?,
    )
    .map_err(|_| "token_issuer_unauthorised: current media service id is invalid")?;
    let issuer_did = arkret_identity::verification_method_did(binding.issuer_kid.as_str())
        .map_err(|_| "token_issuer_unauthorised: issuer is not a verification method")?;
    if arkret_wire::project_did_to_core_id(&issuer_did)
        .ok()
        .as_ref()
        != Some(&service_id)
    {
        return Err("token_issuer_unauthorised: issuer is outside the current media service");
    }
    let key = if crate::jws_verify::is_local_service_notary_method(
        state,
        &issuer_did,
        binding.issuer_kid.as_str(),
    ) {
        state.notary_verifying_key()
    } else {
        crate::jws_verify::resolve_ed25519_pubkey(state, binding.issuer_kid.as_str())
            .map_err(|_| "token_issuer_unauthorised: exact issuer key is unavailable")?
    };
    if binding.expires_at <= operation.created_at {
        return Err("participant_binding_invalid: binding is expired at event creation");
    }
    let context = ParticipantBindingContext {
        actor_id: &actor_id,
        call_id: &call_id,
        device_id: &device_id,
        expires_at: binding.expires_at,
        focus_id,
        participant_id,
        realm_id: &operation.realm_id,
        issuer_kid: binding.issuer_kid.as_str(),
        subject_binding_digest: &binding.subject_binding_digest,
        media: serde_json::from_value(
            participant
                .get("media")
                .cloned()
                .ok_or("participant_binding_invalid: media range is absent")?,
        )
        .map_err(|_| "participant_binding_invalid: media range is not the closed issued range")?,
    };
    if !verify_binding_signature(&context, &binding.sig, &key) {
        return Err("participant_binding_invalid: signature does not cover the enclosing tuple");
    }
    Ok(())
}
