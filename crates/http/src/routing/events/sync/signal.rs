//! Signal Extension rail (`zh/sync/signal.md`).
//!
//! Two local client surfaces:
//! - `POST /_arkret/self/signal`           — `ak.self.signal.command.send.v1`
//! - `GET  /_arkret/self/signal/subscribe` — `ak.self.signal.stream.subscribe.v1`
//!
//! Cross-service recipients are reached through the separate authenticated
//! single-hop `POST /_arkret/peer/signal` federation binding.
//!
//! A Signal is not a durable Event: admitting one mints no Event id, advances
//! no authority Commit, enters no durable Event stream and produces no current state. The
//! only server-visible product classification is `signal_class`; the payload
//! type, the Strand / Message / Call / receipt target and the sender sequence
//! all live inside the ciphertext and are never reconstructible here.
//!
//! There is no plaintext branch (§3).

use std::collections::{BTreeMap, BTreeSet};

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::SignalStreamFrame;
use arkret_models_collaboration::signal_operations::SignalSubmitResponseBody;
use arkret_wire::{SignalEnvelope, SignalRelayRequestBody};
use coland_http::error::AppError;
use coland_services::identity::SessionIdentityState;
use futures_util::stream::StreamExt;
use salvo::prelude::*;

use super::events_query::ndjson_line;
use super::subscribe::account_subscribe_session_or_render;
use crate::state::{AppState, EventNotification};

#[cfg(feature = "conformance-harness")]
mod emission_probe;

/// Default lifetime of one cursorless Signal connection. Reconnection may lose frames;
/// the relay never promises catch-up or delivery.
const SIGNAL_SUBSCRIBE_DEFAULT_WAIT_MS: u64 = 30_000;
/// Idle keepalive so an intermediary does not reap a quiet connection.
const SIGNAL_SUBSCRIBE_DEFAULT_HEARTBEAT_MS: u64 = 15_000;
/// A cursorless Signal rail cannot catch up across a reconnect gap. Keep the
/// normal bounded-response rollover below the product's five-second live
/// presence recovery target instead of inheriting the durable subscribe
/// surfaces' ten-second cooldown.
const SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 250;
/// How often the stream re-polls the relay. Signals are short-lived and are
/// not carried on the durable event broadcast, so the live rail polls.
const SIGNAL_SUBSCRIBE_POLL_MS: u64 = 250;

/// `ak.self.signal.command.send.v1`.
///
/// The body is an `ak.schema.signal_envelope.v1` [`SignalEnvelope`].
#[endpoint(operation_id = "ak.self.signal.command.send")]
#[tracing::instrument(skip_all, fields(op = "ak.self.signal.command.send.v1"))]
pub(super) async fn submit_signal(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::JsonResult<SignalSubmitResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SIGNAL_COMMAND_SEND_V1,
    )?;

    let envelope: SignalEnvelope = req.parse_json().await.map_err(|error| {
        AppError::json_invalid(format!(
            "signal envelope does not match ak.schema.signal_envelope.v1: {error}"
        ))
    })?;

    admit_signal(state, &session, &envelope).await?;
    let sender_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;

    let scope_authority = verify_signal_scope_authority(state, &envelope, &sender_actor).await?;

    let envelope_digest = envelope
        .envelope_digest()
        .map_err(|error| signal_invalid(format!("signal envelope digest: {error}")))?
        .as_str()
        .to_owned();
    let realm_id = envelope.realm_id.clone();

    // §2 — the server does short-term replay suppression on the complete
    // envelope digest only. A repeat inside the retention window is answered
    // as accepted without a second relay append: a Signal has no durable
    // receipt to reissue, so the only observable difference must be that it is
    // not delivered twice.
    let record = coland_storage::SignalRelayRecord {
        realm_id: realm_id.as_str().to_owned(),
        scope_ref: envelope.scope_ref.clone(),
        sender_actor_id: sender_actor.to_string(),
        sender_device_id: envelope.sender_device_id.as_ref().map(ToString::to_string),
        signal_class: envelope.signal_class,
        envelope_digest: envelope_digest.clone(),
        sent_at: envelope.sent_at,
        expires_at: envelope.expires_at,
        envelope: envelope.clone(),
        position: 0,
    };
    let appended = state
        .deliveries()
        .append_signal(record)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to append signal to the live relay");
            signal_rail_unavailable("append the signal to the live relay")
        })?;
    let mut dispatched_recipient_count = None;
    if appended {
        dispatched_recipient_count = Some(
            scope_authority
                .recipient_actors
                .iter()
                .filter(|actor| *actor != &sender_actor)
                .count() as u64,
        );
        let _ = state.publish_event_notification(EventNotification::signal(
            realm_id.as_str().to_owned(),
            envelope.signal_class,
        ));
        relay_signal_to_remote_services(state, &envelope, &scope_authority.recipient_actors).await;
    }

    coland_http::result::json_ok(SignalSubmitResponseBody {
        accepted: true,
        realm_id,
        envelope_digest: arkret_wire::Hash::new(envelope_digest)
            .map_err(|error| signal_invalid(format!("signal envelope digest: {error}")))?,
        dispatched_recipient_count,
        server_received_at: Some(chrono::Utc::now()),
    })
}

/// Fan one admitted local Signal out to each eligible remote recipient service.
///
/// The protocol deliberately gives this path no durable outbox, retry, or
/// acknowledgement semantics. Each destination is attempted once in a
/// detached task; failure is diagnostic-only and never changes the sender's
/// opaque accepted outcome.
async fn relay_signal_to_remote_services(
    state: &AppState,
    envelope: &SignalEnvelope,
    recipients: &[arkret_wire::ActorId],
) {
    let Ok(destinations) = remote_recipient_services(state, recipients).await else {
        return;
    };
    for destination_id in destinations {
        let state = state.clone();
        let request = SignalRelayRequestBody {
            realm_id: envelope.realm_id.clone(),
            signals: vec![envelope.clone()],
        };
        tokio::spawn(async move {
            if let Err(error) = crate::routing::federation::outbox::relay_signal_once(
                &state,
                &destination_id,
                &request,
            )
            .await
            {
                tracing::debug!(
                    %error,
                    %destination_id,
                    realm = %request.realm_id,
                    "single-attempt Signal peer relay failed"
                );
            }
        });
    }
}

async fn remote_recipient_services(
    state: &AppState,
    recipients: &[arkret_wire::ActorId],
) -> Result<BTreeSet<String>, AppError> {
    let mut destinations = BTreeSet::new();
    for actor in recipients {
        let station = crate::routing::actor_delivery_station(state, actor).await?;
        if station != state.service_core_id() {
            destinations.insert(station.to_string());
        }
    }
    Ok(destinations)
}

pub(crate) async fn admit_signal(
    state: &AppState,
    session: &SessionIdentityState,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    // (1) + (4, partly) — `scope_ref.realm_id == realm_id`, the E2EE profile
    // constants, the AAD binding, the signed outer `sent_at`, the envelope
    // digest and the per-class TTL ceilings.
    envelope.validate_structural().map_err(structural_error)?;
    require_signal_content_mapping(state, session, &envelope.realm_id).await?;
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(signal_invalid("signal envelope is already expired"));
    }

    // The complete sender actor is always the authenticated one. Endpoint
    // authority is checked by the selected closed branch below.
    let authenticated_actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    if envelope.sender_actor_id != authenticated_actor {
        return Err(AppError::capability_denied(
            "signal sender_actor_id must match the bearer session actor",
        ));
    }

    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)?;

    // The source-selected basis must resolve to an accepted Event and its exact
    // covering RealmCommit before any live eligibility decision is made.

    // (2, continued) + (3) — require authority-committed membership and
    // class action at both the declared Commit and the current accepted head.
    verify_signal_scope_authority(state, envelope, &actor).await?;
    // Resolve eligibility before reporting a stale MLS basis, so a sender
    // excluded at the current cut receives the closed class denial.

    match (&envelope.sender_device_id, session.agent_session()) {
        (Some(device_id), None) if device_id.as_str() == session.require_human_device_id() => {
            verify_signal_device_proof(state, envelope, &actor).await
        }
        (None, Some(_)) => verify_signal_agent_proof(state, session, envelope, &actor).await,
        (Some(_), Some(_)) => Err(signal_proof_invalid(
            "Agent Signal sender must omit sender_device_id",
        )),
        (None, None) => Err(signal_proof_invalid(
            "ordinary Signal sender must carry sender_device_id",
        )),
        (Some(_), None) => Err(AppError::capability_denied(
            "signal sender_device_id must match the bearer session device",
        )),
    }
}

/// Resolve both declared and current accepted governance cuts in one read transaction.
pub(crate) async fn verify_signal_scope_authority(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<coland_storage::SignalScopeAuthority, AppError> {
    verify_signal_scope_authority_with_product(state, envelope, actor, false, None).await
}

async fn verify_signal_scope_authority_with_product(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
    include_product_authority: bool,
    product_agent: Option<(
        &arkret_wire::AccountId,
        &arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    )>,
) -> Result<coland_storage::SignalScopeAuthority, AppError> {
    let authority = state
        .authority_commits()
        .signal_scope_authority(coland_storage::SignalScopeAuthorityQuery {
            include_product_authority,
            product_agent,

            scope: &envelope.scope_ref,
            authority_commit_id: &envelope.authority_commit_id,
            parent_realm_authority_commit_id: envelope.parent_realm_authority_commit_id.as_ref(),
            sender: actor,
            signal_class: envelope.signal_class,
            sent_at: envelope.sent_at,
            at: chrono::Utc::now(),
        })
        .await
        .map_err(|error| {
            tracing::warn!(%error,"verified Signal governance is unavailable");
            signal_rail_unavailable("resolve historical and current Signal scope authority")
        })?
        .ok_or_else(|| {
            crate::app_error!(
                SignalClassDenied,
                "Signal class is not eligible in this scope"
            )
        })?;
    if !mls_ciphersuite_is_active(&envelope.encrypted_payload.aead_profile)
        || authority.current_mls.epoch != envelope.encrypted_payload.epoch
        || authority.current_mls.current_mls_commit_event_ref.as_str()
            != envelope.encrypted_payload.key_ref.group_state_ref
        || authority.historical_mls_event_ref.as_str()
            != envelope.encrypted_payload.key_ref.group_state_ref
        || authority.cipher_suite != envelope.encrypted_payload.aead_profile
    {
        return Err(signal_invalid(
            "Signal MLS basis does not match the accepted cuts",
        ));
    }
    Ok(authority)
}

async fn verify_signal_device_proof(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    resolve_local_signal_device_key(state, envelope, actor)
        .await
        .map(|_| ())
}

/// Resolve a delivery key only after the full current local device and producer gate.
async fn resolve_local_signal_device_key(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<arkret_wire::StationSigningKey, AppError> {
    let sender_device_id = envelope.sender_device_id.as_ref().ok_or_else(|| {
        signal_proof_invalid("ordinary Signal sender must carry sender_device_id")
    })?;
    // This identity adapter owns only this Station's account device directory.
    // A peer's account must not borrow a local same-principal device record.
    require_local_signal_device_account(actor, state.service_id())?;
    // Account shape alone does not distinguish an Agent. Accepted local
    // provisioning must never be downgraded into an ordinary device lookup.
    if state
        .projections()
        .snapshot()
        .agent_membership_binding(envelope.realm_id.as_str(), &actor.to_string())
        .is_some()
        || crate::routing::identity::agent_pcr::agent_record_for_actor(state, actor)
            .await
            .map_err(|_| signal_rail_unavailable("resolve the Signal sender provisioning"))?
            .is_some()
    {
        return Err(signal_proof_invalid(
            "Signal has no registered Agent sender carrier",
        ));
    }
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            envelope.sender_actor_id.signing_principal_id().as_str(),
            sender_device_id.as_str(),
        )
        .await
        .map_err(|error| {
            tracing::error!(
                %error,
                actor = %envelope.sender_actor_id,
                device = %sender_device_id,
                "failed to resolve the signal sender device signing key"
            );
            signal_rail_unavailable("resolve the device signing directory")
        })?;
    if !matches!(
        facet.status,
        arkret_models_crypto::keys::DeviceStatus::Active
    ) || facet.device_authorize_event_id.is_none()
        || !facet
            .authorized_generation_ref
            .is_some_and(|generation| generation >= 1)
    {
        return Err(signal_proof_invalid(
            "signal sender device is not active and authorized",
        ));
    }
    // Current authorization includes the exact accepted Event/generation,
    // pending revocation, and the original authorization's time window.
    if crate::routing::identity::device_signing::current_device_authorization(
        state,
        actor,
        sender_device_id,
        &facet,
    )
    .await
    .map_err(|_| signal_rail_unavailable("resolve current device authorization"))?
    .is_none()
    {
        return Err(signal_proof_invalid(
            "signal device authorization is not currently effective",
        ));
    }
    // §1 — `verification_method` is the directory lookup key and the SDK's
    // shared structural contract already binds its principal and device.
    // That structural binding is never
    // the authorization: the key material verified against comes from the
    // accepted device directory row (`signing_key_did`), not from anything the
    // envelope carries.
    let multibase = facet
        .signing_key_did
        .as_deref()
        .and_then(|value| value.strip_prefix("did:key:"))
        .ok_or_else(|| signal_proof_invalid("signal sender device signing key is unavailable"))?;
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    // `signal.md` §3 — the Signal transcript is the SDK's, not this crate's: it
    // commits to `envelope_digest` (the envelope with `proof` removed) and names
    // the sending device, so a signature can never be replayed across the Event
    // rail. The state-dependent admission checks §3 also requires — that the
    // method resolves to this device's active signing key, and that the device
    // may send into this scope — ran above.
    arkret_signatures::verify_ed25519_signal_proof(envelope, &public_key).map_err(|error| {
        tracing::warn!(
            %error,
            actor = %envelope.sender_actor_id,
            device = %sender_device_id,
            "signal device proof verification failed"
        );
        signal_proof_invalid("signal device proof verification failed")
    })?;
    let raw_key = public_key
        .ed25519_bytes()
        .map_err(|_| signal_proof_invalid("Signal device key encoding is invalid"))?;
    Ok(arkret_wire::StationSigningKey {
        actor: actor.clone(),
        verification_method: envelope.proof.verification_method.clone(),
        public_key_base64url: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(raw_key),
        )
        .map_err(|_| signal_proof_invalid("Signal device key encoding is invalid"))?,
        authorization_ref: facet
            .device_authorize_event_id
            .ok_or_else(|| signal_proof_invalid("Signal device authorization is missing"))?,
    })
}

/// Recipient admission resolves remote exact-account authority through the
/// registered peer keys surface, with the same verified attestation gate as
/// self signer lookup. Peer relay itself never enters this device gate.
pub(crate) async fn resolve_signal_delivery_device_key(
    state: &AppState,
    recipient: &arkret_wire::AccountId,
    envelope: &SignalEnvelope,
) -> Result<arkret_wire::StationSigningKey, AppError> {
    let actor = &envelope.sender_actor_id;
    let account = actor
        .as_account_id()
        .ok_or_else(|| signal_proof_invalid("ordinary sender requires an account"))?;
    if account.station_id == state.service_core_id() {
        return resolve_local_signal_device_key(state, envelope, actor).await;
    }
    let device = envelope
        .sender_device_id
        .as_ref()
        .ok_or_else(|| signal_proof_invalid("ordinary sender requires a device"))?;
    let record = crate::routing::identity::keys::current_device_projection_for_signer(
        state,
        recipient,
        &envelope.realm_id,
        account,
        device,
    )
    .await
    .ok_or_else(|| {
        signal_rail_unavailable("verify current remote exact-account device authority")
    })?;
    let projection = record.device_projection;
    let multibase = projection
        .device_signing_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| signal_proof_invalid("remote device key is unavailable"))?;
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    arkret_signatures::verify_ed25519_signal_proof(envelope, &public)
        .map_err(|_| signal_proof_invalid("remote Signal producer proof is invalid"))?;
    let raw = public
        .ed25519_bytes()
        .map_err(|_| signal_proof_invalid("remote device key encoding is invalid"))?;
    Ok(arkret_wire::StationSigningKey {
        actor: actor.clone(),
        verification_method: envelope.proof.verification_method.clone(),
        public_key_base64url: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(raw),
        )
        .map_err(|_| signal_proof_invalid("remote device key encoding is invalid"))?,
        authorization_ref: projection.device_authorize_event_id,
    })
}

async fn verify_signal_agent_proof(
    state: &AppState,
    session: &SessionIdentityState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
) -> Result<(), AppError> {
    let agent_session = session
        .agent_session()
        .filter(|agent| agent.freshness_state == arkret_wire::FreshnessState::Fresh)
        .ok_or_else(|| signal_proof_invalid("Agent Signal requires a fresh Agent session"))?;
    let _ = agent_session;
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        signal_proof_invalid("Agent Signal requires a typed session-grant authority binding")
    })?;
    let arkret_models_identity::session_credential::SessionGrantHolderBinding::AgentRuntime {
        agent_id,
        agent_key_authorization_ref,
        verification_method,
    } = &grant.holder_binding
    else {
        return Err(signal_proof_invalid(
            "Agent Signal cannot use a human-device session grant",
        ));
    };
    if agent_id != actor.signing_principal_id()
        || verification_method != &envelope.proof.verification_method
    {
        return Err(signal_proof_invalid(
            "Agent Signal does not match its typed session-grant key binding",
        ));
    }

    verify_signal_agent_current_authority(
        state,
        envelope,
        actor,
        Some((agent_key_authorization_ref, verification_method)),
    )
    .await
}

pub(crate) async fn invitation_agent_key(
    state: &AppState,
    envelope: &SignalEnvelope,
) -> Result<arkret_signatures::PublicKeyMaterial, AppError> {
    verify_signal_agent_current_authority(state, envelope, &envelope.sender_actor_id, None).await?;
    let record = crate::routing::identity::agent_pcr::agent_record_for_actor(
        state,
        &envelope.sender_actor_id,
    )
    .await
    .map_err(|_| signal_rail_unavailable("resolve accepted Agent invitation key"))?
    .ok_or_else(|| signal_proof_invalid("Agent is unavailable"))?;
    let runtime = record
        .runtime_bindings()
        .map_err(|_| signal_proof_invalid("Agent runtime binding is inconsistent"))?
        .active_binding
        .ok_or_else(|| signal_proof_invalid("Agent runtime binding is absent"))?;
    let key = arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
        &runtime.key_authorization_event,
    )
    .map_err(|_| signal_proof_invalid("Agent invitation key is invalid"))?;
    agent_runtime_signal_public_key(&key.public_key, &runtime.public_key_digest)
}

async fn verify_signal_agent_current_authority(
    state: &AppState,
    envelope: &SignalEnvelope,
    actor: &arkret_wire::ActorId,
    session_binding: Option<(&arkret_wire::EventId, &arkret_wire::DidUrl)>,
) -> Result<(), AppError> {
    let agent_id = actor.signing_principal_id();
    let agent_record = crate::routing::identity::agent_pcr::agent_record_for_actor(state, actor)
        .await
        .map_err(|_| signal_rail_unavailable("resolve the Signal Agent provisioning"))?
        .ok_or_else(|| signal_proof_invalid("Signal sender is not an accepted Agent"))?;
    if agent_record.state
        != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    {
        return Err(signal_proof_invalid("Signal Agent is not active"));
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &agent_record,
        chrono::Utc::now(),
    )
    .await?;
    let controller_account =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &agent_record).await?;
    let owner_direct = if let Some(account) = actor.as_account_id() {
        state
            .authority_commits()
            .agent_owner_direct_scope(&envelope.realm_id, account, &controller_account)
            .await
            .map_err(|_| signal_rail_unavailable("resolve Signal private scope"))?
    } else {
        false
    };
    if !matches!(envelope.scope_ref, arkret_wire::ScopeRef::Sidecar { .. }) && !owner_direct {
        let account = actor
            .as_account_id()
            .ok_or_else(|| signal_proof_invalid("Signal authority is unavailable"))?;
        let mode = state
            .authority_commits()
            .current_agent_result(
                &envelope.realm_id,
                &arkret_wire::CurrentSelector::AgentInteraction {
                    agent_account_id: account.clone(),
                },
            )
            .await
            .map_err(|_| signal_rail_unavailable("resolve Signal authority"))?;
        if !matches!(mode, Some(arkret_wire::CurrentState::Value { value, .. }) if serde_json::from_value::<arkret_models_collaboration::agent_interaction::AgentInteractionCurrentValue>(value.clone()).is_ok_and(|v| v.controller_account_id == controller_account && v.interaction_mode == arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public))
        {
            return Err(signal_proof_invalid("Signal authority is unavailable"));
        }
    }
    let controller_actor = arkret_wire::ActorId::account(controller_account);
    let controller_realms = state
        .authority_commits()
        .signal_recipient_realms(&controller_actor)
        .await
        .map_err(|_| signal_rail_unavailable("resolve the Signal Agent controller membership"))?;
    if !controller_realms.contains(&envelope.realm_id) {
        return Err(signal_proof_invalid(
            "Signal Agent controller is not a current Realm member",
        ));
    }
    let runtime = agent_record
        .runtime_bindings()
        .map_err(|_| signal_proof_invalid("Signal Agent runtime binding is inconsistent"))?
        .active_binding
        .ok_or_else(|| signal_proof_invalid("Signal Agent has no active runtime binding"))?;
    if runtime.verification_method != envelope.proof.verification_method {
        return Err(signal_proof_invalid(
            "Signal Agent proof method differs from the active runtime binding",
        ));
    }
    if let Some((agent_key_authorization_ref, verification_method)) = &session_binding
        && (runtime.authorized_event_ref != **agent_key_authorization_ref
            || runtime.verification_method != **verification_method)
    {
        return Err(signal_proof_invalid(
            "Signal Agent session names a stale runtime authorization",
        ));
    }

    let active_authorizations =
        crate::routing::identity::agents::accepted_active_agent_key_authorizations(
            state,
            &agent_record,
        )
        .await
        .map_err(|_| signal_rail_unavailable("resolve accepted Agent key state"))?;
    if active_authorizations.is_empty() {
        return Err(signal_proof_invalid(
            "Signal Agent has no current accepted key authorization",
        ));
    }
    for (key_id, authorization_ref) in active_authorizations {
        let authorization = state
            .event_queries()
            .canonical_event(&authorization_ref)
            .await
            .map_err(|_| signal_rail_unavailable("resolve Agent key authorization"))?
            .ok_or_else(|| signal_proof_invalid("Agent key authorization is unavailable"))?;
        let event: arkret_wire::Event = serde_json::from_value(authorization.envelope)
            .map_err(|_| signal_proof_invalid("Agent authorization Event is invalid"))?;
        let key =
            arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
                &event,
            )
            .map_err(|_| signal_proof_invalid("Agent authorization key is invalid"))?;
        if key.agent_id != *agent_id
            || key.agent_key_id.as_str() != key_id
            || key.verification_method != runtime.verification_method
            || key.public_key_digest != runtime.public_key_digest
        {
            return Err(signal_proof_invalid(
                "Agent has conflicting current runtime key authorizations",
            ));
        }
    }

    // The authenticated grant binds the runtime authorization, while its
    // session public key authenticates HTTP DPoP only. Signal producers sign
    // with the independently accepted Agent runtime key (signal.md section 1).
    let authorized_key =
        arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
            &runtime.key_authorization_event,
        )
        .map_err(|_| signal_proof_invalid("Agent authorization Event key is invalid"))?;
    let public_key =
        agent_runtime_signal_public_key(&authorized_key.public_key, &runtime.public_key_digest)?;
    arkret_signatures::verify_ed25519_signal_proof(envelope, &public_key).map_err(|error| {
        tracing::warn!(
            %error,
            actor = %envelope.sender_actor_id,
            "signal Agent proof verification failed"
        );
        signal_proof_invalid("signal Agent proof verification failed")
    })
}

fn agent_runtime_signal_public_key(
    key: &arkret_models_identity::agent_signer_evidence::AgentSigningPublicKey,
    expected_digest: &arkret_wire::Hash,
) -> Result<arkret_signatures::PublicKeyMaterial, AppError> {
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(key.key.as_str())
            .map_err(|_| signal_proof_invalid("Agent runtime public key is invalid"))?,
    };
    if public_key
        .raw_ed25519_digest()
        .map_err(|_| signal_proof_invalid("Agent runtime public key is invalid"))?
        != *expected_digest
    {
        return Err(signal_proof_invalid(
            "Agent runtime public key differs from its accepted binding",
        ));
    }
    Ok(public_key)
}

fn require_local_signal_device_account(
    actor: &arkret_wire::ActorId,
    station_id: &str,
) -> Result<(), AppError> {
    if actor
        .as_account_id()
        .is_some_and(|account| account.station_id.as_str() == station_id)
    {
        Ok(())
    } else {
        Err(signal_proof_invalid(
            "the exact Signal account has no accepted device directory here",
        ))
    }
}

/// Admit one item from an authenticated single-hop peer relay.
///
/// Every item-level failure is returned only to the caller for audit logging;
/// the HTTP handler deliberately converts it to the same opaque accepted
/// outcome. Request authentication and request-shape failures are handled
/// before this function is entered.
pub(crate) async fn accept_peer_signal(
    state: &AppState,
    source_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    admit_signal_outer(state, source_id, envelope).await?;
    // The authenticated source Station owns current ordinary-device admission.
    // Destination transport admission cannot authenticate a foreign producer
    // using a local same-principal directory or an MLS public-tree lookup.
    // Recipients still authenticate the original proof before consuming it.
    let sender_actor = &envelope.sender_actor_id;
    let authority = verify_signal_scope_authority(state, envelope, sender_actor).await?;
    let has_local_recipient = authority.recipient_actors.iter().any(|actor| {
        actor != sender_actor
            && actor
                .as_account_id()
                .is_some_and(|account| account.station_id.as_str() == state.service_id().as_str())
    });
    if !has_local_recipient {
        return Ok(());
    }

    let envelope_digest = envelope
        .envelope_digest()
        .map_err(|error| signal_invalid(format!("signal envelope digest: {error}")))?
        .as_str()
        .to_owned();
    let appended = state
        .deliveries()
        .append_signal(coland_storage::SignalRelayRecord {
            realm_id: envelope.realm_id.as_str().to_owned(),
            scope_ref: envelope.scope_ref.clone(),
            sender_actor_id: sender_actor.to_string(),
            sender_device_id: envelope.sender_device_id.as_ref().map(ToString::to_string),
            signal_class: envelope.signal_class,
            envelope_digest,
            sent_at: envelope.sent_at,
            expires_at: envelope.expires_at,
            envelope: envelope.clone(),
            position: 0,
        })
        .await
        .map_err(|_| signal_rail_unavailable("append peer signal to the live relay"))?;
    if appended {
        let _ = state.publish_event_notification(EventNotification::signal(
            envelope.realm_id.as_str().to_owned(),
            envelope.signal_class,
        ));
    }
    Ok(())
}

/// Revalidate current source authority immediately before signing a peer request.
pub(crate) async fn admit_outbound_signal(
    state: &AppState,
    destination_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    let actor = &envelope.sender_actor_id;
    admit_signal_outer(state, state.service_id(), envelope).await?;
    let authority = verify_signal_scope_authority(state, envelope, actor).await?;
    if !remote_recipient_services(state, &authority.recipient_actors)
        .await?
        .contains(destination_id)
    {
        return Err(signal_invalid(
            "Signal destination has no current eligible member",
        ));
    }
    match envelope.sender_device_id.as_ref() {
        Some(_) => verify_signal_device_proof(state, envelope, actor).await,
        None => verify_signal_agent_current_authority(state, envelope, actor, None).await,
    }
}

#[cfg(feature = "test-support")]
impl AppState {
    #[doc(hidden)]
    pub async fn test_admit_outbound_signal(
        &self,
        destination_id: &str,
        envelope: &SignalEnvelope,
    ) -> Result<(), AppError> {
        admit_outbound_signal(self, destination_id, envelope).await
    }
}

/// Server-visible checks shared by source dispatch and destination admission.
pub(crate) async fn admit_signal_outer(
    state: &AppState,
    source_id: &str,
    envelope: &SignalEnvelope,
) -> Result<(), AppError> {
    envelope.validate_structural().map_err(structural_error)?;
    if envelope.sender_actor_id.as_account_id().is_none() {
        return Err(signal_proof_invalid(
            "Signal requires an account-backed ordinary or Agent sender",
        ));
    }
    arkret_signatures::proof::validate_ed25519_detached_jws_shape(&envelope.proof.jws)
        .map_err(|_| signal_proof_invalid("signal producer proof encoding is invalid"))?;
    if envelope.expires_at <= chrono::Utc::now() {
        return Err(signal_invalid("signal envelope is already expired"));
    }
    let sender_actor = envelope.sender_actor_id.clone();
    if sender_actor
        .as_account_id()
        .map(|account| account.station_id.as_str())
        != Some(source_id)
    {
        return Err(signal_invalid(
            "Signal sender route does not match the authenticated source Station",
        ));
    }
    verify_signal_scope_authority(state, envelope, &sender_actor).await?;
    Ok(())
}

fn mls_ciphersuite_is_active(canonical_id: &str) -> bool {
    arkret_wire::MLS_CIPHERSUITES
        .iter()
        .any(|suite| suite.canonical_id == canonical_id && suite.status == "active")
}

/// Map the SDK's structural rejection onto the registered wire code. The TTL
/// and byte ceilings retain their registered codes; other violations are
/// malformed envelopes.
fn structural_error(error: arkret_wire::WireError) -> AppError {
    let error_code = error.error_code();
    let message = error.to_string();
    if error_code == Some(arkret_wire::ErrorCode::SignalTtlOutOfRange) {
        return crate::app_error!(SignalTtlOutOfRange, message);
    }
    if error_code == Some(arkret_wire::ErrorCode::PayloadTooLarge) {
        return crate::app_error!(PayloadTooLarge, message);
    }
    signal_invalid(message)
}

fn signal_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(ParamInvalid, message)
}

fn signal_proof_invalid(message: impl Into<String>) -> AppError {
    crate::app_error!(ParamInvalid, message)
        .with_reason_code(arkret_wire::ReasonCode::PROOF_INVALID)
}

fn signal_rail_unavailable(what: &str) -> AppError {
    crate::app_error!(
        SignalRailUnavailable,
        format!("the signal rail could not {what}"),
    )
}

/// `ak.self.signal.stream.subscribe.v1` at `GET /_arkret/self/signal/subscribe`.
///
/// NDJSON of the verbatim admitted [`SignalEnvelope`], so a receiver verifies
/// `proof` over the exact canonical bytes the sender signed. §4 forbids a new
/// stream frame kind or server-visible selector per payload type, and the
/// binding table gives this operation no request body and no durable cursor:
/// the stream therefore takes no scope selector and no `after` token. It emits
/// envelope lines plus bounded transport control frames only.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.signal.stream.subscribe.v1"))]
pub(super) async fn signal_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot
        .get_typed::<AppState>()
        .expect("state injected")
        .clone();
    let session = match account_subscribe_session_or_render(&state, req, res).await {
        Some(session) => session,
        None => return,
    };
    let grant = super::subscribe::stream_grant(req);
    if let Err(error) = super::super::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_SIGNAL_STREAM_SUBSCRIBE_V1,
    ) {
        coland_http::error::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
        return;
    }

    let max_duration_ms = super::query_param(req, "max_duration_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SIGNAL_SUBSCRIBE_DEFAULT_WAIT_MS)
        .min(600_000);
    let heartbeat_ms = super::query_param(req, "heartbeat_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SIGNAL_SUBSCRIBE_DEFAULT_HEARTBEAT_MS)
        .max(100);

    signal_response(
        state,
        session,
        grant,
        res,
        Some(max_duration_ms),
        heartbeat_ms,
    );
}

pub(super) fn signal_response(
    state: AppState,
    session: SessionIdentityState,
    grant: Option<String>,
    res: &mut Response,
    max_duration_ms: Option<u64>,
    heartbeat_ms: u64,
) {
    let body_stream = async_stream::stream! {
        let Ok(mut live_starts) = signal_subscription_start(&state, &session).await else {
            yield Ok::<bytes::Bytes,std::io::Error>(ndjson_line(&SignalStreamFrame::Unauthorized { reason:None }));
            return;
        };
        yield Ok::<bytes::Bytes,std::io::Error>(ndjson_line(&SignalStreamFrame::HEARTBEAT));
        let deadline = max_duration_ms.map(|ms|tokio::time::Instant::now()+std::time::Duration::from_millis(ms));
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(heartbeat_ms));
        heartbeat.tick().await;
        let mut poll = tokio::time::interval(std::time::Duration::from_millis(
            SIGNAL_SUBSCRIBE_POLL_MS,
        ));
        loop {
            tokio::select! {
                _ = async { match deadline { Some(deadline)=>tokio::time::sleep_until(deadline).await,None=>std::future::pending().await } } => {
                    let frame = SignalStreamFrame::Drain {
                        reconnect_after_ms: Some(SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS),
                        reason: None,
                    };
                    yield Ok::<bytes::Bytes, std::io::Error>(ndjson_line(&frame));
                    break;
                }
                _ = poll.tick() => {
                    if !super::subscribe::stream_session_current(&state, &session, grant.as_deref()).await {
                        yield Ok::<bytes::Bytes,std::io::Error>(ndjson_line(&SignalStreamFrame::Unauthorized { reason:None }));
                        break;
                    }
                    for envelope in pending_signals_for_subscriber(&state, &session, &mut live_starts).await {
                        match admitted_signal_frame(&state, &session, envelope).await {
                            Ok(frame) => yield Ok(ndjson_line(&frame)),
                            Err(error) => {
                                #[cfg(feature = "conformance-harness")]
                                tracing::warn!(code=error.wire_code(), %error, "conformance Signal frame refused by the production emission gate");
                                #[cfg(not(feature = "conformance-harness"))]
                                let _ = error;
                            }
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    yield Ok(ndjson_line(&SignalStreamFrame::HEARTBEAT));
                }
            }
        }
    };

    let _ = res.add_header("content-type", "application/x-ndjson", true);
    res.stream(body_stream.boxed());
}

/// Fresh current admission belongs to the recipient authenticated self boundary,
/// separately from peer relay. Never return a frame if current authority is unknown.
pub(crate) async fn admitted_signal_frame(
    state: &AppState,
    session: &SessionIdentityState,
    envelope: SignalEnvelope,
) -> Result<SignalStreamFrame, AppError> {
    use arkret_models_identity::{
        CurrentSignerKeyQuerySender, SignerKeyQuerySelector, SignerKeyResolution,
        SignerKeysQueryRequestBody,
    };
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let recipient = actor
        .as_account_id()
        .cloned()
        .ok_or_else(|| signal_invalid("recipient is not an account"))?;
    admit_signal_outer(
        state,
        envelope
            .sender_actor_id
            .as_account_id()
            .ok_or_else(|| signal_invalid("Signal requires an Account sender"))?
            .station_id
            .as_str(),
        &envelope,
    )
    .await?;
    // Agent and ordinary devices retain their distinct current authority gates.
    let agent_key = if envelope.sender_device_id.is_none() {
        let selector = SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::Agent {
                actor: envelope.sender_actor_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
            },
        };
        let request = SignerKeysQueryRequestBody {
            request_id: arkret_wire::RequestId::new_v7_at(
                chrono::Utc::now().timestamp_millis() as u64
            ),
            realm_id: envelope.realm_id.clone(),
            recipient_account_id: Some(recipient.clone()),
            recipient_actor_id: None,
            queries: vec![selector],
        };
        let outcome = crate::routing::identity::current_signer_evidence::resolve_self_signer_keys(
            state, session, &request,
        )
        .await?;
        outcome
            .validate_for_request(&request)
            .map_err(structural_error)?;
        let Some(SignerKeyResolution::CurrentResolved { selector, key }) =
            outcome.resolutions.into_iter().next()
        else {
            return Err(signal_rail_unavailable("verify current sender authority"));
        };
        Some(arkret_wire::StationSigningKey {
            actor: selector.actor().clone(),
            verification_method: selector.verification_method().clone(),
            public_key_base64url: key.public_key_base64url,
            authorization_ref: key.authorization_ref.event_id,
        })
    } else {
        None
    };
    // Re-check time/scope after a possible remote round trip and before emitting this frame.
    admit_signal_outer(
        state,
        envelope
            .sender_actor_id
            .as_account_id()
            .ok_or_else(|| signal_invalid("Signal requires an Account sender"))?
            .station_id
            .as_str(),
        &envelope,
    )
    .await?;
    crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let recipient_actor = arkret_wire::ActorId::account(recipient.clone());
    let scope_authority =
        verify_signal_scope_authority(state, &envelope, &envelope.sender_actor_id).await?;
    if !scope_authority.recipient_actors.contains(&recipient_actor) {
        return Err(signal_rail_unavailable("verify current recipient scope"));
    }
    let key = match agent_key {
        Some(key) => {
            verify_signal_agent_current_authority(
                state,
                &envelope,
                &envelope.sender_actor_id,
                Some((&key.authorization_ref, &key.verification_method)),
            )
            .await?;
            key
        }
        None => resolve_signal_delivery_device_key(state, &recipient, &envelope).await?,
    };
    let mut authority = arkret_models_collaboration::SignalDeliveryAuthority {
        product_authority: None,
        call_invitation: None,
        recipient_account_id: recipient,
        key,
    };
    authority
        .validate_for_envelope(&envelope)
        .map_err(structural_error)?;
    // A remote directory lookup may have crossed a membership or TTL change.
    // Repeat the session and governance gates at the actual frame boundary.
    #[cfg(feature = "conformance-harness")]
    let probe = emission_probe::pause(state, &envelope, &authority.recipient_account_id).await?;
    require_signal_content_mapping(state, session, &envelope.realm_id).await?;
    let decision = async {
        let current_actor =
            crate::routing::identity::session_actor::validated_session_actor(state, session)
                .await?;
        admit_signal_outer(
            state,
            envelope
                .sender_actor_id
                .as_account_id()
                .ok_or_else(|| signal_invalid("Signal requires an Account sender"))?
                .station_id
                .as_str(),
            &envelope,
        )
        .await?;
        if envelope.sender_device_id.is_none() {
            verify_signal_agent_current_authority(
                state,
                &envelope,
                &envelope.sender_actor_id,
                Some((
                    &authority.key.authorization_ref,
                    &authority.key.verification_method,
                )),
            )
            .await?;
        } else {
            let current_key = resolve_signal_delivery_device_key(
                state,
                &authority.recipient_account_id,
                &envelope,
            )
            .await?;
            if current_key != authority.key {
                return Err(signal_proof_invalid(
                    "Signal signer authorization changed before emission",
                ));
            }
        }
        let product_agent = signal_product_agent(state, &envelope, &authority.key).await?;
        let current = verify_signal_scope_authority_with_product(
            state,
            &envelope,
            &envelope.sender_actor_id,
            true,
            product_agent
                .as_ref()
                .map(|(controller, scope)| (controller, scope)),
        )
        .await?;
        if current_actor.as_account_id() != Some(&authority.recipient_account_id)
            || !current.recipient_actors.contains(&current_actor)
        {
            return Err(crate::app_error!(
                SignalClassDenied,
                "Signal recipient is no longer eligible"
            ));
        }
        if envelope.expires_at <= chrono::Utc::now() {
            return Err(signal_invalid("Signal expired before emission"));
        }
        authority.product_authority = current.product_authority;
        authority.call_invitation = if let Some(device) = session.human_device_id() {
            crate::routing::call_admission::delivery_for_device(
                state,
                &envelope,
                &authority.recipient_account_id,
                &arkret_wire::DeviceId::new(device)
                    .map_err(|e| AppError::param_invalid(e.to_string()))?,
            )
            .await?
        } else {
            None
        };
        authority
            .validate_for_envelope(&envelope)
            .map_err(structural_error)?;
        Ok(())
    }
    .await;
    #[cfg(feature = "conformance-harness")]
    emission_probe::record(
        probe.as_deref(),
        &envelope,
        &decision,
        authority.call_invitation.is_some(),
    )?;
    decision?;
    Ok(SignalStreamFrame::signal(envelope, authority))
}

/// Project the accepted public key ceiling into this Realm, without leaking
/// another Realm or private controller participation preference to recipients.
async fn signal_product_agent(
    state: &AppState,
    envelope: &SignalEnvelope,
    key: &arkret_wire::StationSigningKey,
) -> Result<
    Option<(
        arkret_wire::AccountId,
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    )>,
    AppError,
> {
    if envelope.sender_device_id.is_some() {
        return Ok(None);
    }
    let record = crate::routing::identity::agent_pcr::agent_record_for_actor(
        state,
        &envelope.sender_actor_id,
    )
    .await
    .map_err(|_| signal_rail_unavailable("resolve accepted Agent product ceiling"))?
    .ok_or_else(|| signal_proof_invalid("Agent product authorization is unavailable"))?;
    let controller =
        crate::routing::identity::agent_pcr::agent_controller_account(state, &record).await?;
    let binding = record
        .runtime_bindings()
        .map_err(|_| signal_proof_invalid("Agent product runtime is inconsistent"))?
        .active_binding
        .ok_or_else(|| signal_proof_invalid("Agent product runtime is unavailable"))?;
    if binding.authorized_event_ref != key.authorization_ref
        || binding.verification_method != key.verification_method
    {
        return Err(signal_proof_invalid(
            "Agent product key authorization changed",
        ));
    }
    let mut scope = binding
        .key_authorization_event
        .as_agent_key_authorize()
        .map_err(|_| signal_proof_invalid("Agent product key ceiling is invalid"))?
        .agent_key_scope;
    scope.actions.retain(|action| {
        matches!(
            action.as_str(),
            arkret_wire::CapabilityActionId::MESSAGE_STREAM_SEND
                | arkret_wire::CapabilityActionId::MESSAGE_CREATE
                | arkret_wire::CapabilityActionId::TYPING_BROADCAST
        )
    });
    let mut projected = Vec::new();
    let mut has_content_selector = false;
    for mut resource in scope.resources {
        let selector = arkret_policy::agent_content_ceiling::key_scope_content_selector(&resource)
            .map_err(|_| signal_proof_invalid("Agent product resource ceiling is invalid"))?;
        let Some(selector) = selector else {
            continue;
        };
        has_content_selector = true;
        if selector
            .realm_id
            .as_ref()
            .is_some_and(|realm| realm != &envelope.realm_id)
        {
            continue;
        }
        if !matches!(
            selector.kind,
            arkret_wire::ResourceSelectorKind::Realm | arkret_wire::ResourceSelectorKind::Strand
        ) {
            continue;
        }
        resource.realm_id = Some(envelope.realm_id.clone());
        projected.push(resource);
    }
    if !has_content_selector && !scope.actions.is_empty() {
        projected.push(arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResource {
            kind: arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind::Realm,
            realm_id: Some(envelope.realm_id.clone()), resource_ref: None, schema_ref: None, operation: None, service_id: None,
        });
    }
    scope.resources = projected;
    Ok(Some((controller, scope)))
}

async fn require_signal_content_mapping(
    state: &AppState,
    session: &SessionIdentityState,
    realm: &arkret_wire::RealmId,
) -> Result<(), AppError> {
    // The encrypted Signal rail has no registered durable content-action
    // mapping. Independent Direct/control authority keeps its own contract.
    if session.agent_session().is_some() {
        let actor =
            crate::routing::identity::session_actor::validated_session_actor(state, session)
                .await?;
        if let Some(account) = actor.as_account_id()
            && let Some(agent) =
                crate::routing::identity::agent_pcr::agent_record_for_actor(state, &actor)
                    .await
                    .map_err(|_| signal_rail_unavailable("resolve Signal independent scope"))?
        {
            let controller =
                crate::routing::identity::agent_pcr::agent_controller_account(state, &agent)
                    .await?;
            if state
                .authority_commits()
                .agent_owner_direct_scope(realm, account, &controller)
                .await
                .map_err(|_| signal_rail_unavailable("resolve Signal independent scope"))?
            {
                // This selects the existing participant rail, not a durable
                // content read. Every caller still checks current scope, MLS,
                // runtime key, lifecycle, proof and TTL at its Signal boundary.
                return Ok(());
            }
        }
    }
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![realm.clone()],
        unresolved_content_realms: vec![realm.clone()],
        ..Default::default()
    };
    if let Some(guard) = super::content_delivery_guard(state, session, &input).await? {
        guard
            .finish()
            .await
            .map_err(|_| signal_rail_unavailable("release its current delivery cut"))?;
        return Err(AppError::capability_denied(
            "Signal content-action mapping is unavailable",
        ));
    }
    Ok(())
}

async fn signal_subscription_start(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<BTreeMap<String, u64>, AppError> {
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, session).await?;
    let realms = state
        .authority_commits()
        .signal_recipient_realms(&actor)
        .await
        .map_err(|_| signal_rail_unavailable("establish live recipient cut"))?;
    let mut starts = BTreeMap::new();
    for realm in realms {
        let records = state
            .deliveries()
            .signals_for_realm(realm.as_str())
            .await
            .map_err(|_| signal_rail_unavailable("establish live relay cut"))?;
        starts.insert(
            realm.to_string(),
            records.iter().map(|row| row.position).max().unwrap_or(0),
        );
    }
    Ok(starts)
}

/// Every unexpired Signal this live connection is eligible for and has not already been
/// handed, ascending by relay position. The watermark is advanced as the batch
/// is taken, so the same envelope is not re-emitted on the next poll or on a
/// reconnect inside the TTL window.
pub(crate) async fn pending_signals_for_subscriber(
    state: &AppState,
    session: &SessionIdentityState,
    live_starts: &mut BTreeMap<String, u64>,
) -> Vec<SignalEnvelope> {
    let now = chrono::Utc::now();
    let mut delivered = Vec::new();
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return delivered;
    };
    let actor_key = actor.to_string();
    let Ok(member_realms) = state
        .authority_commits()
        .signal_recipient_realms(&actor)
        .await
    else {
        return delivered;
    };
    for realm in member_realms {
        let realm_id = realm.to_string();
        let Ok(watermark) = state
            .deliveries()
            .signal_watermark(&actor_key, session.require_human_device_id(), &realm_id)
            .await
        else {
            continue;
        };
        let Ok(records) = state.deliveries().signals_for_realm(&realm_id).await else {
            continue;
        };
        // A newly eligible Realm starts live here, never at its retained backlog.
        let start = live_starts
            .entry(realm_id.clone())
            .or_insert_with(|| records.iter().map(|row| row.position).max().unwrap_or(0));
        let watermark = watermark.max(*start);
        let mut highest = watermark;
        for record in records {
            highest = highest.max(record.position);
            if record.position <= watermark || record.expires_at <= now {
                continue;
            }
            // A device never receives its own Signal back.
            if record.sender_actor_id == actor_key
                && record.sender_device_id.as_deref()
                    == Some(session.require_human_device_id().as_str())
            {
                continue;
            }
            if !signal_visible_to_subscriber(state, &record, &actor).await {
                continue;
            }
            delivered.push(record.envelope);
        }
        if highest > watermark {
            let _ = state
                .deliveries()
                .advance_signal_watermark(
                    &actor_key,
                    session.require_human_device_id(),
                    &realm_id,
                    highest,
                )
                .await;
        }
    }
    delivered
}

/// Every frame re-observes sender authority and exact current recipient eligibility.
async fn signal_visible_to_subscriber(
    state: &AppState,
    record: &coland_storage::SignalRelayRecord,
    actor: &arkret_wire::ActorId,
) -> bool {
    verify_signal_scope_authority(state, &record.envelope, &record.envelope.sender_actor_id)
        .await
        .is_ok_and(|authority| authority.recipient_actors.contains(actor))
}

#[cfg(test)]
mod tests {
    use salvo::http::StatusCode;

    use super::*;

    #[test]
    fn agent_signal_key_comes_from_runtime_authorization_independently_of_session_key() {
        use arkret_signatures::PublicKeyMaterial;
        let runtime_bytes = [0x73; 32];
        let session_bytes = [0x74; 32];
        let runtime_digest = PublicKeyMaterial::Ed25519Raw {
            bytes: runtime_bytes.to_vec(),
        }
        .raw_ed25519_digest()
        .unwrap();
        let session_digest = PublicKeyMaterial::Ed25519Raw {
            bytes: session_bytes.to_vec(),
        }
        .raw_ed25519_digest()
        .unwrap();
        assert_ne!(runtime_digest, session_digest);
        let runtime_key = serde_json::from_value(serde_json::json!({
            "kty": "OKP", "algorithm": "Ed25519",
            "key": arkret_canonical::base64url_encode(runtime_bytes),
        }))
        .unwrap();
        let selected = agent_runtime_signal_public_key(&runtime_key, &runtime_digest).unwrap();
        assert_eq!(selected.raw_ed25519_digest().unwrap(), runtime_digest);
        assert!(agent_runtime_signal_public_key(&runtime_key, &session_digest).is_err());
    }

    #[test]
    fn signal_device_directory_never_substitutes_a_same_principal_local_account() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let local = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            station.clone(),
        ));
        let foreign = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        let service = arkret_wire::ActorId::service(principal);
        assert!(require_local_signal_device_account(&local, station.as_str()).is_ok());
        assert!(require_local_signal_device_account(&foreign, station.as_str()).is_err());
        assert!(require_local_signal_device_account(&service, station.as_str()).is_err());
    }

    #[test]
    fn only_active_registry_ciphersuites_are_accepted() {
        assert!(mls_ciphersuite_is_active(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        ));
        // Reserved rows fail closed until their profile is activated.
        assert!(!mls_ciphersuite_is_active(
            "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"
        ));
        assert!(!mls_ciphersuite_is_active("AES128GCM"));
    }

    #[test]
    fn ttl_overrun_surfaces_the_registered_wire_code() {
        let error = structural_error(arkret_wire::WireError::ProtocolCode {
            code: arkret_wire::ErrorCode::SignalTtlOutOfRange,
            message: "signal TTL 90s exceeds the Session class ceiling of 30s".to_owned(),
        });
        assert_eq!(error.wire_code(), "signal_ttl_out_of_range");
        assert_eq!(error.http_status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn other_structural_rejections_stay_on_the_generic_param_code() {
        let error = structural_error(arkret_wire::WireError::Protocol(
            "signal expires_at must be strictly after sent_at".to_owned(),
        ));
        assert_eq!(error.wire_code(), "param_invalid");
    }

    #[test]
    fn signal_byte_overflow_retains_the_registered_wire_code() {
        let error = structural_error(arkret_wire::WireError::ProtocolCode {
            code: arkret_wire::ErrorCode::PayloadTooLarge,
            message: "signal envelope exceeds 65536 canonical bytes".to_owned(),
        });
        assert_eq!(error.wire_code(), "payload_too_large");
        assert_eq!(error.http_status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn cursorless_signal_rollover_does_not_inherit_durable_stream_cooldown() {
        assert_eq!(
            SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS,
            SIGNAL_SUBSCRIBE_POLL_MS
        );
        const {
            assert!(
                SIGNAL_SUBSCRIBE_RECONNECT_AFTER_MS < super::super::SUBSCRIBE_RECONNECT_AFTER_MS
            );
        }
    }
}
