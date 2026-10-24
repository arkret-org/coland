//! RTC media handlers.
//!
//! Surfaces:
//! - `POST /_arkret/self/rtc/ice-config` (TURN / STUN list)
//! - `POST /_arkret/self/rtc/token` (media token exchange, AKP-0010)
//!
//! These are the only spec-registered media surfaces. Both are stateless with
//! respect to any ephemeral signaling session: the media token issuer reads the
//! independent durable focus and moderation cells; ICE
//! config is a transport-layer
//! discovery surface bound to the authenticated `(actor, device)`. STUN/TURN
//! URLs, credential TTLs, and the optional TURN shared secret are
//! operator-configurable via `AppConfig::ice`.

#[cfg(feature = "conformance-harness")]
mod release_probe;

use arkret_identifiers::{CallId, DeviceId, RealmId};
#[cfg(test)]
use arkret_models_collaboration::events_payloads::RealmMediaServicePayload;
use arkret_models_collaboration::events_payloads::RealmMediaServiceValue;
use arkret_models_collaboration::objects::media::{
    ArkretNativeMediaBackendToken, ArkretNativeMediaPermissions,
    ArkretNativeMediaSignatureAlgorithm, ArkretNativeMediaTokenPayload, MediaBackendKind,
    MediaBackendToken, MediaIceConfigurationRequestBody, MediaIceConfigurationResponseBody,
    MediaIceConfigurationSignature, MediaIceCredentialType, MediaIceMode, MediaIceServer,
    MediaIceSignatureAlgorithm,
};
use arkret_wire::{CapabilityActionId, DidUrl, XExtensionMap};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::identity::SessionIdentityState as SessionRecord;
use ed25519_dalek::Signer as _;
use salvo::http::HeaderValue;
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::{Value, json};

use super::{hmac_sha256, now, sha256_hex, validate_device_id};
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{
    CallMediaParticipantBinding, CallMediaTokenExchangeRequestBody,
    CallMediaTokenExchangeResponseBody,
};

/// Spec-canonical RTC media surface. Mounted under the `self` trust segment by
/// `interop::router()` so the only spec-registered media paths resolve at
/// `/_arkret/self/rtc/ice-config` and `/_arkret/self/rtc/token` (see
/// `contract-registry.json` / the OpenAPI binding). Call signalling travels
/// encrypted inside the Signal Extension; the durable call model is the
/// composite call-cell state model. Token/ICE authz and focus/ban read the
/// independent durable cells directly.
pub(super) fn protocol_router() -> Router {
    Router::new()
        // Spec-canonical signed ICE config (`/_arkret/self/rtc/ice-config`).
        .push(Router::with_path("rtc/ice-config").post(arkret_ice_config))
        // AKP-0010 — media token exchange (`/_arkret/self/rtc/token`).
        .push(Router::with_path("rtc/token").post(arkret_rtc_token))
}

#[derive(Clone, Debug)]
struct IceConfigRequestContext {
    pub realm_id: RealmId,
    pub call_id: String,
    pub actor_id: arkret_wire::ActorId,
    pub device_id: DeviceId,
    pub turn_required: bool,
}

#[endpoint(
    operation_id = "ak.self.media.read.ice_config",
    summary = "Get media ICE configuration",
    tags("media")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.media.read.ice_config.v1"))]
async fn arkret_ice_config(
    aa: AuthArgs,
    body: JsonBody<MediaIceConfigurationRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> JsonResult<MediaIceConfigurationResponseBody> {
    set_ice_config_cache_headers(res);
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    issue_ice_config(
        state,
        &session,
        IceConfigRequestContext {
            realm_id: body.realm_id,
            call_id: body.call_id,
            actor_id: body.actor_id,
            device_id: body.device_id,
            turn_required: matches!(body.mode, MediaIceMode::Turn),
        },
    )
    .await
}

async fn issue_ice_config(
    state: &AppState,
    session: &SessionRecord,
    body: IceConfigRequestContext,
) -> JsonResult<MediaIceConfigurationResponseBody> {
    let realm_id = body.realm_id.as_str();
    let call_id = body.call_id.as_str();
    if call_id.is_empty() {
        return Err(AppError::param_missing("call_id is required"));
    }
    let device_id = body.device_id.as_str();

    if !is_valid_webrtc_session_id(call_id) {
        return Err(AppError::param_invalid("invalid call_id"));
    }
    if body.actor_id
        != crate::routing::identity::session_actor::session_actor_from_credential(state, session)?
    {
        return Err(AppError::param_invalid(
            "actor_id must match the authenticated actor",
        ));
    }
    if validate_device_id(device_id).is_err() || device_id != session.require_human_device_id() {
        return Err(AppError::param_invalid(
            "device_id must match the authenticated device",
        ));
    }
    // `webrtc-signaling.md` §4 — ICE config is a transport-layer discovery
    // surface bound to the authenticated `(actor, device)`. It precedes the
    // `ak.call.state` roster (a caller fetches TURN/STUN before it has
    // committed its participant row, and the callee fetches it while the call
    // is still ringing), so call existence MUST NOT be enforced here. The only
    // authorization gate is realm membership; the per-call ban gate lives on
    // the media token issuer, not on ICE discovery.
    if !state
        .authority_commits()
        .accepted_current_member_joined(&body.realm_id, &body.actor_id)
        .await
        .map_err(|error| {
            crate::app_error!(
                TemporarilyUnavailable,
                format!("membership cut unavailable: {error}")
            )
        })?
    {
        return Err(AppError::capability_denied(
            "actor is not a joined member of the realm",
        ));
    }

    let issued_at = now();
    let ttl_seconds: u32 = state.config().ice.ttl_seconds;
    // `webrtc-signaling.md` §4.2 — `refresh_lead_seconds` MUST be strictly less
    // than `ttl_seconds`; a server MUST NOT issue `lead >= ttl` or the client
    // would judge the credential stale at issuance and storm refresh. The env
    // value is operator-configurable, so clamp it at the signing point: cap to
    // `ttl_seconds - 1` and keep the schema floor (>= 10) when `ttl` is large
    // enough to admit it.
    let refresh_lead_seconds: u32 =
        clamp_refresh_lead_seconds(state.config().ice.refresh_lead_seconds, ttl_seconds);
    let credential_expires_at = issued_at
        .checked_add_signed(Duration::seconds(i64::from(ttl_seconds)))
        .ok_or_else(|| AppError::internal("ICE credential expiry overflow"))?;
    // `webrtc-signaling.md` §4.1 — the TURN pseudonym binds the fixed v1
    // `ice_bucket(issued_at)`. The bucket is derived from the signed issuance
    // time and is never repeated on wire.
    let ice_bucket = ice_bucket(issued_at);
    let turn_required = body.turn_required;
    // `webrtc-signaling.md` §4.1 — REST-style (draft-uberti) TURN credential.
    // Each issuance has fresh private random input, including concurrent
    // refreshes within the same signed time bucket.
    let pseudonym = pairwise_turn_username(
        state,
        realm_id,
        call_id,
        &body.actor_id,
        device_id,
        ice_bucket,
    )?;
    let turn_username = format!("{}:{}", credential_expires_at.timestamp(), pseudonym);
    // credential = base64( HMAC-SHA256(turn_shared_secret, username) ) — the
    // HMAC is taken over the full REST-style username (SHA256, never SHA1).
    let turn_credential = turn_rest_credential(state, &turn_username);
    let turn_server = MediaIceServer {
        urls: state.config().ice.turn_urls.clone(),
        username: Some(turn_username.clone()),
        credential: Some(turn_credential),
        credential_type: Some(MediaIceCredentialType::Password),
    };
    let mut ice_servers = vec![MediaIceServer {
        urls: state.config().ice.stun_urls.clone(),
        username: None,
        credential: None,
        credential_type: None,
    }];
    ice_servers.push(turn_server.clone());
    if turn_required {
        ice_servers = vec![turn_server.clone()];
    }
    let mut response = MediaIceConfigurationResponseBody {
        realm_id: body.realm_id,
        call_id: call_id.to_owned(),
        actor_id: body.actor_id,
        device_id: body.device_id,
        ice_servers,
        ttl_seconds,
        refresh_lead_seconds,
        issued_at,
        turn_required,
        constraints: None,
        next_retry_at: None,
        signature: MediaIceConfigurationSignature {
            kid: format!("{}#notary-key", state.service_did()),
            signature_algorithm: MediaIceSignatureAlgorithm::Ed25519,
            signature: String::new(),
        },
        extensions: XExtensionMap::default(),
    };
    sign_ice_config_outcome(state, &mut response)?;
    json_ok(response)
}

fn set_ice_config_cache_headers(res: &mut Response) {
    res.headers_mut().insert(
        "cache-control",
        HeaderValue::from_static("private, no-store"),
    );
    res.headers_mut()
        .insert("pragma", HeaderValue::from_static("no-cache"));
}

/// `webrtc-signaling.md` §4.1 — v1 fixes the TURN pseudonym bucket at 300s.
const ICE_PSEUDONYM_BUCKET_SECONDS: u32 = 300;

/// Schema-aligned floor for `refresh_lead_seconds`
/// (`media-ice-configuration-response-body.schema.json`: `minimum: 10`).
const ICE_REFRESH_LEAD_FLOOR_SECONDS: u32 = 10;

/// `webrtc-signaling.md` §4.2 — server-side guarantee that
/// `refresh_lead_seconds < ttl_seconds`. The operator-configured lead is
/// clamped at issuance so the response always satisfies the MUST: the lead is
/// capped to `ttl_seconds - 1`. When `ttl_seconds` is large enough that the
/// schema floor (10s) still leaves `floor < ttl`, the result is also held at or
/// above that floor; for very small `ttl` the cap to `ttl - 1` wins so the
/// strict-inequality invariant holds even below the floor.
fn clamp_refresh_lead_seconds(configured: u32, ttl_seconds: u32) -> u32 {
    let ceiling = ttl_seconds.saturating_sub(1);
    let clamped = configured.min(ceiling);
    if ttl_seconds > ICE_REFRESH_LEAD_FLOOR_SECONDS {
        clamped.max(ICE_REFRESH_LEAD_FLOOR_SECONDS)
    } else {
        clamped
    }
}

/// Fixed v1 `ice_bucket(t) = floor(unix_seconds(t) / 300) * 300`.
fn ice_bucket(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    let bucket = i64::from(ICE_PSEUDONYM_BUCKET_SECONDS);
    let floored = timestamp.timestamp().div_euclid(bucket) * bucket;
    DateTime::<Utc>::from_timestamp(floored, 0).unwrap_or(timestamp)
}

/// Issuer-private pairwise tag with a fresh 256-bit CSPRNG nonce per issuance.
/// The full Actor includes its Station; neither the nonce nor input is exposed.
fn pairwise_turn_username(
    state: &AppState,
    realm_id: &str,
    call_id: &str,
    actor_id: &arkret_wire::ActorId,
    device_id: &str,
    ice_bucket: DateTime<Utc>,
) -> Result<String, AppError> {
    let secret = hmac_sha256(
        &state.notary_signing_key().to_bytes(),
        b"ak.media.turn_pseudonym.v1",
    );
    let nonce = rand::random::<[u8; 32]>();
    let input = json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "actor_id": actor_id,
        "device_id": device_id,
        "ice_bucket": ice_bucket,
        "media_service_id": state.service_id(),
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
    });
    let canonical = arkret_canonical::canonical_json_bytes(&input)
        .map_err(|error| AppError::internal(format!("TURN pseudonym canonicalization: {error}")))?;
    let tag = hmac_sha256(&secret, &canonical);
    Ok(format!(
        "ak_pseudonym_call_{}",
        URL_SAFE_NO_PAD.encode(&tag[..16])
    ))
}

/// `webrtc-signaling.md` §4.1 — REST-style (draft-uberti) TURN credential:
/// `credential = base64( HMAC-SHA256(turn_shared_secret, username) )`. The
/// HMAC is over the full `<expiry-unix>:<pseudonym>` username and uses SHA256
/// The credential is standard base64 (with padding),
/// matching what an external coturn expects.
///
/// `turn_shared_secret` comes from `state.config().ice.turn_shared_secret`
/// (`COLAND_TURN_SHARED_SECRET`, W1). When unset, a deployment-stable fallback
/// key is derived from the notary signing seed so credentials stay
/// self-consistent across issue/refresh within this deployment; production
/// deployments fronting an external coturn MUST set `COLAND_TURN_SHARED_SECRET`
/// to the same secret coturn is configured with.
fn turn_rest_credential(state: &AppState, username: &str) -> String {
    let configured = state.config().ice.turn_shared_secret.as_deref();
    let fallback;
    let secret: &[u8] = match configured {
        Some(secret) => secret.as_bytes(),
        None => {
            fallback = hmac_sha256(
                &state.notary_signing_key().to_bytes(),
                b"coland-turn-shared-secret-fallback-v1",
            );
            &fallback
        }
    };
    base64::engine::general_purpose::STANDARD.encode(hmac_sha256(secret, username.as_bytes()))
}

/// Sign the typed SDK response using its single protocol-owned canonical
/// payload and domain-separated transcript implementation.
fn sign_ice_config_outcome(
    state: &AppState,
    outcome: &mut MediaIceConfigurationResponseBody,
) -> Result<(), AppError> {
    let signing_input = outcome
        .signature_input()
        .map_err(|error| AppError::internal(format!("ICE config transcript: {error}")))?;
    let signature = state.notary_signing_key().sign(&signing_input);
    outcome.signature.signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(())
}

// ── AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — media
// token exchange. Issues a backend_token + ParticipantBinding for a
// caller that already has a committed `ak.component.call.focus.v1` value.
//
// Wire-level checks implemented here:
//   - `focus_id` must equal the call's committed session_focus → `focus_mismatch` (MEDIA-2,
//     REDU-3).
//   - Focus selection is oldest-membership-wins; until the session_focus cell is wired through the
//     reducer, the handler derives the focus from the call participants and their latest
//     `foci_preferred[]` signal.
//   - Token TTL ≤ `MEDIA_TOKEN_TTL_MAX_SECS` (600s); default `MEDIA_TOKEN_TTL_SHOULD_SECS` (300s)
//     (MEDIA-1).
//   - `participant_binding.issuer_kid` resolves to the current `ak.realm.media_service.service_id`
//     epoch → `token_issuer_unauthorised` (MEDIA-1).

/// The `foci[].focus_kind` values this deployment can actually issue a token for.
///
/// `media-service-binding.md` §4 gives v1 a normative binding for `livekit` and
/// `arkret_native` only; `mediasoup`, `janus` and `moq_relay` are reserved
/// placeholders, and an unsupported type MUST fail closed with
/// `unknown_focus_type` rather than be handed to an invented envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaProviderKind {
    ArkretNative,
    LiveKit,
}

impl MediaProviderKind {
    fn parse(value: &str) -> Result<Self, AppError> {
        match value.trim() {
            "arkret_native" => Ok(Self::ArkretNative),
            "livekit" => Ok(Self::LiveKit),
            _ => Err(crate::app_error!(
                ParamInvalid,
                format!("media focus provider `{value}` has no normative v1 binding"),
            )
            .with_reason_code(arkret_wire::ReasonCode::UNKNOWN_FOCUS_TYPE)),
        }
    }

    fn backend_kind(self) -> MediaBackendKind {
        match self {
            Self::ArkretNative => MediaBackendKind::ArkretNative,
            Self::LiveKit => MediaBackendKind::Livekit,
        }
    }
}

impl TryFrom<MediaBackendKind> for MediaProviderKind {
    type Error = AppError;

    fn try_from(value: MediaBackendKind) -> Result<Self, Self::Error> {
        match value {
            MediaBackendKind::ArkretNative => Ok(Self::ArkretNative),
            MediaBackendKind::Livekit => Ok(Self::LiveKit),
            MediaBackendKind::Mediasoup => Self::parse("mediasoup"),
            MediaBackendKind::Janus => Self::parse("janus"),
            MediaBackendKind::MoqRelay => Self::parse("moq_relay"),
        }
    }
}

#[derive(Clone, Debug)]
struct MediaProviderConfig {
    provider: MediaProviderKind,
    focus_id: String,
    token_endpoint: String,
    connect_url: String,
}

#[derive(Clone, Debug)]
pub(crate) struct MediaServiceEpoch {
    pub(crate) service_id: String,
    foci: Vec<MediaProviderConfig>,
}

impl MediaServiceEpoch {
    fn focus(&self, focus_id: &str) -> Option<&MediaProviderConfig> {
        self.foci.iter().find(|focus| focus.focus_id == focus_id)
    }

    fn focus_ids(&self) -> Vec<String> {
        self.foci
            .iter()
            .map(|focus| focus.focus_id.clone())
            .collect()
    }
}

struct MediaTokenIssueRequestBody<'a> {
    focus: &'a MediaProviderConfig,
    /// Deployment-configured signing key DID URL of this media service. It is
    /// not a cell field: `media-service-binding.md` §3 anchors it by requiring
    /// its bare controller to equal a current-epoch `service_id`, which is
    /// checked before issuance.
    issuer_kid: &'a str,
    realm_id: &'a str,
    call_id: &'a str,
    // The backend token deliberately carries no long-term actor identity:
    // `media-service-binding.md` §3 keeps the SFU's view to
    // `participant_id`, a per-exchange pseudonym. The `(actor, device)`
    // pair is bound by the signed `participant_binding` the Arkret side
    // verifies, not by anything the backend receives.
    participant_id: &'a str,
    /// Publish intent derived from the request `desired_media` (LiveKit
    /// `video.canPublishSources`). `(audio, video, screen)`.
    desired_media: (bool, bool, bool),
    /// Whether the caller carries `ak.call.screen_share` (gates the
    /// `screen_share` publish source per `bindings/livekit.md` §5).
    allow_screen_share: bool,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

struct IssuedMediaToken {
    backend_token: MediaBackendToken,
    connect_url: String,
}

/// Per-provider signing material handed to a [`MediaTokenIssuer`]. The
/// ed25519 notary key signs the `arkret_native` / `mediasoup` envelopes;
/// LiveKit needs the deployment's API Key/Secret to emit a real LiveKit
/// JWT (`bindings/livekit.md` §2).
struct MediaTokenSigningContext<'a> {
    notary_signing_key: &'a ed25519_dalek::SigningKey,
    livekit: &'a crate::config::LiveKitConfig,
}

trait MediaTokenIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError>;
}

struct ArkretNativeMediaIssuer;
struct LiveKitMediaIssuer;

impl MediaTokenIssuer for ArkretNativeMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError> {
        issue_arkret_native_backend_token(request, ctx.notary_signing_key)
    }
}

impl MediaTokenIssuer for LiveKitMediaIssuer {
    fn issue(
        &self,
        request: &MediaTokenIssueRequestBody<'_>,
        ctx: &MediaTokenSigningContext<'_>,
    ) -> Result<IssuedMediaToken, AppError> {
        issue_livekit_backend_token(request, ctx.livekit)
    }
}

async fn handle_rtc_token_with_original(
    state: &AppState,
    session: &SessionRecord,
    body: CallMediaTokenExchangeRequestBody,
    original: Option<Value>,
) -> JsonResult<CallMediaTokenExchangeResponseBody> {
    // The request body is the SDK typed shape: `realm_id`/`call_id`/`actor_id`/
    // `device_id` retain their exact complete ActorId and typed DeviceId shapes,
    // and the response binding carries the same typed ids — so the wire outcome
    // reuses `arkret_models_collaboration::objects::media::CallMediaTokenExchangeResponseBody`
    // directly instead of a stringly coland mirror.
    let realm_id = body.realm_id.clone();
    if !is_valid_webrtc_session_id(body.call_id.as_str()) {
        return Err(AppError::param_invalid("invalid call_id"));
    }
    let call_id = body.call_id.clone();
    if body.actor_id
        != crate::routing::identity::session_actor::session_actor_from_credential(state, session)?
    {
        return Err(AppError::param_invalid(
            "actor_id must match the authenticated actor",
        ));
    }
    let actor_id = body.actor_id.clone();
    if session.human_device_id().map(String::as_str) != Some(body.device_id.as_str()) {
        return Err(AppError::param_invalid(
            "device_id must match the authenticated device",
        ));
    }
    let device_id = body.device_id.clone();
    if body.focus_id.trim().is_empty() {
        return Err(AppError::param_invalid("focus_id is required"));
    }
    // Authz (`media-service-binding.md` §6 commit ordering) — the token issuer does NOT
    // depend on any ephemeral signaling session. Per `media-service-binding.md`
    // the client redeems the media token BEFORE it joins the durable
    // `ak.component.call.roster.v1` OR-Set (the initiator may exchange a token
    // when no call cell exists yet), so a roster-membership
    // / session-not-found gate would be wrong. Authorization is the conjunction
    // of: (1) realm membership, (2) the `ak.call.join` capability, (3) not under
    // an actor-wide ban in the durable call moderation OR-Set.
    //
    // Membership and permission resources come from the accepted exact Call
    // scope. The final release rechecks this durable cut in its transaction.
    let call_cells = CallMediaCells::load(
        state,
        body.realm_id.as_str(),
        body.call_id.as_str(),
        &body.actor_id,
    )
    .await?;

    let call_scope = &call_cells
        .accepted
        .as_ref()
        .ok_or_else(|| {
            crate::app_error!(TemporarilyUnavailable, "accepted Call scope is unavailable")
        })?
        .scope_ref;
    let resource = match call_scope {
        arkret_wire::ScopeRef::Circle { circle_id, .. } => circle_id.as_str(),
        _ => body.realm_id.as_str(),
    };
    if !crate::authz::authorize(
        state,
        body.realm_id.as_str(),
        &body.actor_id,
        &[CapabilityActionId::CALL_JOIN],
        resource,
        now(),
    )
    .await?
    .allowed()
    {
        return Err(AppError::capability_denied(
            "actor lacks current Call join capability in the accepted scope",
        ));
    }
    // (3) `webrtc-signaling.md` §3a — a banned actor MUST NOT re-issue a join
    // token for this call's lifetime. The ban set is the durable
    // call moderation effective OR-Set; an absent cell carries
    // no bans (everyone passes).
    if call_cells.actor_is_banned(&body.actor_id) {
        return Err(crate::app_error!(
            FailedPrecondition,
            "actor was removed from the call (ban) and cannot re-issue a join token",
        )
        .with_reason_code(arkret_wire::ReasonCode::CALL_PARTICIPANT_REMOVED));
    }
    let media_epoch = media_service_epoch_for_realm(state, body.realm_id.as_str()).await?;

    // MEDIA-2 — focus selection. A committed
    // `ak.component.call.focus.v1` value wins when present and `focus_id`
    // MUST match it (`focus_mismatch`). Absent a committed focus, the issuer
    // admits the requested `focus_id` as long as it is a legal focus within the
    // realm media_service epoch (oldest-membership-wins reduces to "any epoch
    // focus" once the ephemeral foci_preferred[] session is gone; the durable
    // committed focus remains the binding decision).
    let session_focus = session_focus_for_call(&call_cells, &media_epoch, body.focus_id.as_str())?;
    if body.focus_id != session_focus {
        return Err(crate::app_error!(
            FailedPrecondition,
            format!(
                "focus_id `{}` does not match committed session_focus `{}`",
                body.focus_id, session_focus
            ),
        )
        .with_reason_code(arkret_wire::ReasonCode::FOCUS_MISMATCH));
    }
    let focus = media_epoch.focus(&session_focus).ok_or_else(|| {
        focus_unavailable_error("selected focus is not present in media_service epoch")
    })?;
    // `media-service-binding.md` §3 — this deployment may only mint a token for
    // a focus whose declared `token_endpoint` is this service. The endpoint is
    // the §2.1 trust root a client anchors on, so issuing for a focus that
    // names somebody else would hand out a binding no client should accept.
    let issuer_kid = configured_media_issuer_kid(state);
    if !issuer_kid_belongs_to_service(&issuer_kid, &media_epoch.service_id) {
        return Err(token_issuer_unauthorised(format!(
            "configured media issuer_kid `{issuer_kid}` is not a key of media_service service_id `{}`",
            media_epoch.service_id
        )));
    }
    if !token_endpoint_is_local(&focus.token_endpoint, state) {
        return Err(token_issuer_unauthorised(format!(
            "focus `{}` declares token_endpoint `{}`, which is not this service",
            focus.focus_id, focus.token_endpoint
        )));
    }
    // MEDIA-1 — token TTL comes from deployment configuration, defaults to
    // 300s and is capped at the spec ceiling.
    let ttl_secs = state
        .config()
        .media
        .token_ttl_seconds
        .clamp(1, arkret_wire::MEDIA_TOKEN_TTL_MAX_SECS);
    let issued_at = now();
    let expires_at = issued_at + Duration::seconds(ttl_secs as i64);

    // `media-service-binding.md` §3 — participant_id is an SFU-local
    // handle that MUST NOT be a deterministic function of the public principal
    // tuple. Mint a fresh random `ak:rtc_participant:<uuidv7>` per token
    // exchange so the SFU cannot be linked back to (realm, call, actor, device)
    // by recomputing the id, and the wire form matches the schema pattern
    // `^ak:rtc_participant:<uuidv7>$`.
    let refresh =
        validate_token_join_context(state, session, &body, &call_cells, original.as_ref()).await?;
    let participant_id =
        refresh.unwrap_or_else(|| arkret_identifiers::new_prefixed_uuid7("ak:rtc_participant:"));
    let signing_key = state.notary_signing_key();
    // `bindings/livekit.md` §2/§5 — publish grants are derived from the
    // caller's `desired_media`. Absent the field we default to audio+video
    // (no screen): screen capture is an opt-in source gated by
    // `ak.call.screen_share`. Moderator force mute is unavailable in v1.
    let desired_media = body
        .desired_media
        .as_ref()
        .map(|media| {
            (
                media.audio.unwrap_or(true),
                media.video.unwrap_or(true),
                media.screen.unwrap_or(false),
            )
        })
        .unwrap_or((true, true, false));
    // `bindings/livekit.md` §5 — the `screen_share` publish source is gated by
    // a real `ak.call.screen_share` capability, not merely the presence of any
    // `capability_refs`. Resolve it against the projected grants so an actor
    // without the capability never receives a screen-share publish grant.
    let allow_screen_share = crate::authz::authorize(
        state,
        body.realm_id.as_str(),
        &body.actor_id,
        &[CapabilityActionId::CALL_SCREEN_SHARE],
        resource,
        now(),
    )
    .await?
    .allowed();
    if desired_media.2 && !allow_screen_share {
        return Err(AppError::capability_denied(
            "screen publish requires its current capability",
        ));
    }
    let issue_request = MediaTokenIssueRequestBody {
        focus,
        issuer_kid: &issuer_kid,
        realm_id: body.realm_id.as_str(),
        call_id: body.call_id.as_str(),
        participant_id: &participant_id,
        desired_media,
        allow_screen_share,
        issued_at,
        expires_at,
    };
    let signing_ctx = MediaTokenSigningContext {
        notary_signing_key: &signing_key,
        livekit: &state.config().livekit,
    };
    let issued_token =
        media_token_issuer_for(focus.provider).issue(&issue_request, &signing_ctx)?;

    let issuer_kid = DidUrl::new(issuer_kid).map_err(|error| {
        token_issuer_unauthorised(format!(
            "configured media issuer_kid is not a verification-method DID URL: {error}"
        ))
    })?;
    let mut outcome = CallMediaTokenExchangeResponseBody {
        focus_id: body.focus_id.clone(),
        backend_kind: focus.provider.backend_kind(),
        connect_url: issued_token.connect_url,
        backend_token: issued_token.backend_token,
        participant_id: participant_id.clone(),
        participant_binding: CallMediaParticipantBinding {
            expires_at,
            issuer_kid,
            signature: String::new(),
        },
        expires_at,
        realm_id,
        call_id,
        actor_id: actor_id.clone(),
        device_id: device_id.clone(),
        media: arkret_models_collaboration::call_invitation::CallInvitationMedia {
            audio: desired_media.0,
            video: desired_media.1,
            screen: desired_media.2,
        },
    };
    let signing_input = arkret_signatures::media::participant_binding_signing_input(
        &arkret_signatures::media::ParticipantBindingContext::from_outcome(&outcome),
    )
    .map_err(|e| AppError::internal(e.to_string()))?;
    outcome.participant_binding.signature =
        URL_SAFE_NO_PAD.encode(signing_key.sign(&signing_input).to_bytes());
    // The token is prepared privately. This is its final, outstanding release cut.
    #[cfg(feature = "conformance-harness")]
    release_probe::pause(state, &body).await?;
    final_invitation_token_cut(state, &body, &call_cells, desired_media).await?;
    let facet =
        crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
            state,
            body.actor_id.signing_principal_id().as_str(),
            body.device_id.as_str(),
        )
        .await
        .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?;
    crate::routing::identity::device_signing::current_device_authorization(
        state,
        &body.actor_id,
        &body.device_id,
        &facet,
    )
    .await
    .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?
    .ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "device authority changed before token release"
        )
    })?;
    if !state
        .authority_commits()
        .check_call_media_release(&body, &state.service_core_id())
        .await
        .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "media permission or accepted leg changed before token release"
        ));
    }
    json_ok(outcome)
}

async fn validate_token_join_context(
    state: &AppState,
    _session: &SessionRecord,
    body: &CallMediaTokenExchangeRequestBody,
    cells: &CallMediaCells,
    original: Option<&Value>,
) -> Result<Option<String>, AppError> {
    use arkret_models_collaboration::call_invitation::*;
    let invalid = |message: &str| crate::app_error!(FailedPrecondition, message.to_owned());
    let current = cells
        .accepted
        .as_ref()
        .ok_or_else(|| invalid("accepted Call cut is unavailable"))?;
    let media = body
        .desired_media
        .as_ref()
        .map(|m| CallInvitationMedia {
            audio: m.audio.unwrap_or(true),
            video: m.video.unwrap_or(true),
            screen: m.screen.unwrap_or(false),
        })
        .unwrap_or(CallInvitationMedia {
            audio: true,
            video: true,
            screen: false,
        });
    match &body.join_context {
        CallMediaJoinContext::Invitation(context) => {
            context
                .invitation
                .validate_for_envelope(&context.envelope)
                .map_err(|e| AppError::param_invalid(e.to_string()))?;
            if context.invitation.holder_account_id
                != *body
                    .actor_id
                    .as_account_id()
                    .ok_or_else(|| invalid("invited subject is not an Account"))?
                || context.invitation.call_id != body.call_id
                || context.invitation.scope_ref != current.scope_ref
                || !media.is_subset_of(&context.invitation.media)
                || context.invitation.expires_at <= Utc::now()
            {
                return Err(invalid(
                    "invitation is not this exact first-contact request",
                ));
            }
            Ok(None)
        }
        CallMediaJoinContext::Voluntary(intent) => {
            let now = Utc::now();
            if intent.created_at > now
                || intent.expires_at <= now
                || intent.expires_at > intent.created_at + Duration::seconds(60)
                || !valid_nonce(&intent.nonce)
            {
                return Err(invalid("voluntary join intent is stale"));
            }
            let method = DidUrl::new(intent.proof.verification_method.clone())
                .map_err(|e| AppError::param_invalid(e.to_string()))?;
            let did = arkret_identity::verification_method_did(method.as_str())
                .map_err(|e| AppError::param_invalid(e.to_string()))?;
            if arkret_wire::project_did_to_core_id(&did).ok().as_ref()
                != Some(body.actor_id.signing_principal_id())
                || method
                    .as_str()
                    .rsplit_once('#')
                    .map(|(_, fragment)| fragment)
                    != Some(body.device_id.as_str())
            {
                return Err(invalid("voluntary signer is not exact request device"));
            }
            let facet=crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(state,body.actor_id.signing_principal_id().as_str(),body.device_id.as_str()).await.map_err(|e| crate::app_error!(TemporarilyUnavailable,e.to_string()))?;
            if crate::routing::identity::device_signing::current_device_authorization(
                state,
                &body.actor_id,
                &body.device_id,
                &facet,
            )
            .await
            .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?
            .is_none()
            {
                return Err(invalid("voluntary device is not currently authorized"));
            }
            let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                value: facet
                    .signing_key_did
                    .as_deref()
                    .and_then(|v| v.strip_prefix("did:key:"))
                    .ok_or_else(|| invalid("current device key is unavailable"))?
                    .to_owned(),
            };
            let value = original.cloned().unwrap_or(
                serde_json::to_value(body).map_err(|e| AppError::internal(e.to_string()))?,
            );
            let bytes = voluntary_join_signing_input_from_value(&value)
                .map_err(|e| AppError::param_invalid(e.to_string()))?;
            arkret_signatures::proof::Ed25519DetachedJwsVerifier::new()
                .verify_detached_jws(&intent.proof.jws, &bytes, &key)
                .map_err(|_| invalid("voluntary intent signature is invalid"))?;
            Ok(None)
        }
        CallMediaJoinContext::Refresh(context) => {
            let (participant, commit) = current
                .participants
                .iter()
                .find(|(p, _)| {
                    p.actor_id == body.actor_id
                        && p.device_id == body.device_id.as_str()
                        && p.participant_id.as_deref() == Some(context.participant_id.as_str())
                        && p.focus_id.as_deref() == Some(body.focus_id.as_str())
                })
                .ok_or_else(|| {
                    invalid(
                        "refresh has no active accepted participant for this exact actor/device",
                    )
                })?;
            let binding = participant
                .participant_binding
                .as_ref()
                .ok_or_else(|| invalid("accepted leg has no participant binding"))?;
            if !media.is_subset_of(
                &participant
                    .signed_media()
                    .map_err(|e| AppError::param_invalid(e.to_string()))?,
            ) {
                return Err(invalid("refresh exceeds the accepted signed media range"));
            }
            let did = arkret_identity::verification_method_did(binding.issuer_kid.as_str())
                .map_err(|e| AppError::param_invalid(e.to_string()))?;
            let key = if did.method() == "key" {
                let doc = state
                    .dids()
                    .resolve_did(&did)
                    .await
                    .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?;
                let value = doc
                    .verification_methods
                    .get(binding.issuer_kid.as_str())
                    .ok_or_else(|| invalid("historical issuer method is unavailable"))?;
                arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                    value: value.clone(),
                }
            } else {
                let point = state
                    .dids()
                    .resolve_webvh_state_at(&did, commit.committed_at)
                    .await
                    .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?;
                let doc: arkret_models_identity::service_identity::ServiceDidDocument =
                    serde_json::from_value(point.document)
                        .map_err(|e| AppError::internal(e.to_string()))?;
                let method = doc
                    .verification_method
                    .iter()
                    .find(|m| {
                        m.id == binding.issuer_kid.as_str()
                            && m.controller == did
                            && doc.assertion_method.contains(&m.id)
                    })
                    .ok_or_else(|| {
                        invalid("issuer was not an assertion method at accepted join")
                    })?;
                arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                    value: method.public_key_multibase.clone(),
                }
            };
            let public = arkret_signatures::media::ParticipantBindingContext {
                actor_id: &participant.actor_id,
                call_id: &body.call_id,
                device_id: &body.device_id,
                expires_at: binding.expires_at,
                focus_id: &body.focus_id,
                participant_id: &context.participant_id,
                realm_id: &body.realm_id,
                issuer_kid: binding.issuer_kid.as_str(),
                media: participant
                    .signed_media()
                    .map_err(|e| AppError::param_invalid(e.to_string()))?,
            };
            if !arkret_signatures::proof::verify_detached_ed25519_signature(
                &key,
                &arkret_signatures::media::participant_binding_signing_input(&public)
                    .map_err(|e| AppError::internal(e.to_string()))?,
                &binding.signature,
            ) {
                return Err(invalid("accepted participant binding is invalid"));
            }
            Ok(Some(context.participant_id.clone()))
        }
    }
}

async fn final_invitation_token_cut(
    state: &AppState,
    body: &CallMediaTokenExchangeRequestBody,
    cells: &CallMediaCells,
    media: (bool, bool, bool),
) -> Result<(), AppError> {
    use arkret_models_collaboration::call_invitation::*;
    if let CallMediaJoinContext::Invitation(context) = &body.join_context {
        let scope = &cells
            .accepted
            .as_ref()
            .ok_or_else(|| AppError::internal("accepted Call cut is unavailable"))?
            .scope_ref;
        if &context.invitation.scope_ref != scope {
            return Err(AppError::capability_denied("invitation scope changed"));
        }
        let request = CallInvitationAdmissionRequestBody {
            invitation: context.invitation.clone(),
            envelope: context.envelope.clone(),
            admission_phase: CallInvitationAdmissionPhase::MediaToken,
            audience_actor_id: arkret_wire::ActorId::service(state.service_core_id()),
            subject_actor_id: body.actor_id.clone(),
            subject_device_id: body.device_id.clone(),
            nonce: crate::routing::call_admission::nonce(),
            focus_id: Some(body.focus_id.clone()),
            desired_media: Some(CallInvitationMedia {
                audio: media.0,
                video: media.1,
                screen: media.2,
            }),
        };
        let outcome = crate::routing::call_admission::fresh_admission(state, &request).await?;
        if !outcome.admitted {
            return Err(AppError::capability_denied(
                "first-contact media admission was refused",
            ));
        }
    }
    Ok(())
}

/// MEDIA-2 focus selection against `ak.component.call.focus.v1`.
///
/// - A committed `session_focus` is the binding decision: it is returned verbatim provided it is
///   still a legal focus within the current realm media_service epoch (the caller compares it
///   against the request `focus_id` and surfaces `focus_mismatch` on a disagreement).
/// - Absent a committed focus (a brand-new call whose focus cell is still bottom), the issuer
///   admits the `requested_focus_id` as long as it names a legal focus in the epoch. This replaces
///   the old ephemeral oldest-membership-wins derivation that read `foci_preferred[]` off a
///   signaling session: the durable committed focus is the source of truth, and until it is
///   committed any epoch-legal focus the caller asks for is acceptable (the first committer's focus
///   then pins it for everyone via the cell's write-once `session_focus`).
fn session_focus_for_call(
    call_cells: &CallMediaCells,
    media_epoch: &MediaServiceEpoch,
    requested_focus_id: &str,
) -> Result<String, AppError> {
    if let Some(focus) = call_cells.session_focus() {
        if media_epoch.focus(focus).is_some() {
            return Ok(focus.to_owned());
        }
        return Err(focus_unavailable_error(
            "committed session_focus is not present in current media_service epoch",
        ));
    }

    let requested = requested_focus_id.trim();
    if !requested.is_empty() && media_epoch.focus(requested).is_some() {
        return Ok(requested.to_owned());
    }
    // No committed focus and the request did not name a legal epoch focus: fall
    // back to a deterministic default so the issuer can still mint a token for a
    // well-formed epoch (the mismatch against `requested_focus_id` is then
    // surfaced as `focus_mismatch` by the caller).
    if let Some(focus_id) = media_epoch.focus_ids().into_iter().next() {
        return Ok(focus_id);
    }
    Err(focus_unavailable_error(
        "realm media_service epoch has no available foci",
    ))
}

/// Read-only view of the committed focus and moderation facets consumed by
/// the media token issuer.
struct CallMediaCells {
    focus: Option<Value>,
    moderation: Option<Value>,
    accepted: Option<coland_storage::CallCurrentCut>,
}

impl CallMediaCells {
    async fn load(
        state: &AppState,
        realm_id: &str,
        call_id: &str,
        actor: &arkret_wire::ActorId,
    ) -> Result<Self, AppError> {
        let accepted = state
            .authority_commits()
            .call_current_cut(
                &RealmId::new(realm_id.to_owned())
                    .map_err(|e| AppError::param_invalid(e.to_string()))?,
                &CallId::new(call_id.to_owned())
                    .map_err(|e| AppError::param_invalid(e.to_string()))?,
                actor,
            )
            .await
            .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?
            .ok_or_else(|| AppError::capability_denied("Call has no visible accepted source"))?;
        if matches!(
            accepted.lifecycle,
            arkret_models_collaboration::events_payloads::call::CallLifecycleState::Ended
                | arkret_models_collaboration::events_payloads::call::CallLifecycleState::Failed
                | arkret_models_collaboration::events_payloads::call::CallLifecycleState::Missed
                | arkret_models_collaboration::events_payloads::call::CallLifecycleState::Cancelled
        ) {
            return Err(crate::app_error!(FailedPrecondition, "Call is terminal")
                .with_reason_code(arkret_wire::ReasonCode::CALL_STATE_TERMINAL));
        }
        Ok(Self {
            focus: accepted
                .focus
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| AppError::internal(e.to_string()))?,
            moderation: Some(Value::Array(
                accepted
                    .moderation
                    .iter()
                    .map(|value| json!({"value":value}))
                    .collect(),
            )),
            accepted: Some(accepted),
        })
    }

    /// The committed `ak.component.call.focus.v1` value, if any.
    fn session_focus(&self) -> Option<&str> {
        self.focus
            .as_ref()?
            .get("session_focus")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|focus| !focus.is_empty())
    }

    /// Whether `actor_id` is under an actor-wide ban in the moderation
    /// effective OR-Set. A ban value omits `device_id`.
    /// An absent cell carries no bans.
    fn actor_is_banned(&self, actor_id: &arkret_wire::ActorId) -> bool {
        let Some(rows) = self.moderation.as_ref().and_then(Value::as_array) else {
            return false;
        };
        rows.iter().any(|entry| {
            if entry.get("removed").and_then(Value::as_bool) == Some(true) {
                return false;
            }
            let row = entry.get("value").unwrap_or(&Value::Null);
            row.get("action").and_then(Value::as_str) == Some("ban")
                && row
                    .get("actor_id")
                    .and_then(|value| {
                        serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()
                    })
                    .as_ref()
                    == Some(actor_id)
        })
    }
}

pub(crate) async fn media_service_epoch_for_realm(
    state: &AppState,
    realm_id: &str,
) -> Result<MediaServiceEpoch, AppError> {
    let descriptor = state
        .authority_commits()
        .realm_media_service_current(
            &RealmId::new(realm_id.to_owned())
                .map_err(|e| AppError::param_invalid(e.to_string()))?,
        )
        .await
        .map_err(|e| crate::app_error!(TemporarilyUnavailable, e.to_string()))?
        .ok_or_else(|| {
            token_issuer_unauthorised(format!(
                "realm `{realm_id}` has no projected ak.realm.media_service epoch"
            ))
        })?;
    media_service_epoch_from_descriptor(descriptor)
}

pub(crate) async fn prepare_verified_roster_participant(
    state: &AppState,
    event: &arkret_wire::Event,
) -> coland_services::ServiceResult<Option<arkret_signatures::media::VerifiedCallParticipant>> {
    if event.kind != arkret_wire::EventKind::CallState {
        return Ok(None);
    }
    let payload: arkret_models_collaboration::events_payloads::call::CallStatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload)
                .map_err(|e| coland_services::ServiceError::SchemaViolation(e.to_string()))?,
        )
        .map_err(|e| coland_services::ServiceError::SchemaViolation(e.to_string()))?;
    let Some(arkret_models_collaboration::events_payloads::call::CallRosterDelta::Join {
        participant,
    }) = payload.roster_delta
    else {
        return Ok(None);
    };
    let Some(binding) = participant.participant_binding else {
        return Ok(None);
    };
    let descriptor = state
        .authority_commits()
        .realm_media_service_current(&event.realm_id)
        .await?
        .ok_or_else(|| {
            coland_services::ServiceError::Conflict(
                "media service current is unavailable".to_owned(),
            )
        })?;
    let (_, keys, history) =
        crate::routing::media_service_binding::resolve_issuer(state, &descriptor).await?;
    let key = keys
        .iter()
        .find(|key| key.verification_method == binding.issuer_kid)
        .ok_or_else(|| {
            coland_services::ServiceError::Conflict(
                "current anchored media issuer key is unavailable".to_owned(),
            )
        })?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(&key.public_key_base64url)
            .map_err(|e| coland_services::ServiceError::SchemaViolation(e.to_string()))?,
    };
    arkret_signatures::media::VerifiedCallParticipant::verify(event, &descriptor.service_id, &key)
        .map(|verified| verified.map(|verified| verified.with_issuer_history(history)))
        .map_err(|e| coland_services::ServiceError::Conflict(e.to_string()))
}

#[cfg(test)]
fn decode_media_service_descriptor(value: Value) -> Result<RealmMediaServiceValue, AppError> {
    let payload = serde_json::from_value::<RealmMediaServicePayload>(value).map_err(|error| {
        focus_unavailable_error(format!(
            "projected realm media_service epoch is malformed: {error}"
        ))
    })?;
    let descriptor = payload.value;
    descriptor.validate().map_err(|error| {
        focus_unavailable_error(format!(
            "projected realm media_service epoch is malformed: {error}"
        ))
    })?;
    Ok(descriptor)
}

fn media_service_epoch_from_descriptor(
    descriptor: RealmMediaServiceValue,
) -> Result<MediaServiceEpoch, AppError> {
    let RealmMediaServiceValue {
        service_id,
        foci: focus_descriptors,
        ..
    } = descriptor;

    let mut foci = Vec::with_capacity(focus_descriptors.len());
    for focus in focus_descriptors {
        let provider = MediaProviderKind::try_from(focus.focus_kind)?;
        foci.push(MediaProviderConfig {
            provider,
            focus_id: focus.focus_id.into_string(),
            token_endpoint: focus.token_endpoint,
            connect_url: focus.connect_url,
        });
    }
    Ok(MediaServiceEpoch {
        service_id: service_id.to_string(),
        foci,
    })
}

/// Whether a focus `token_endpoint` addresses this deployment.
///
/// Compared on origin, not on the full path: the path is fixed by the spec
/// binding while the origin is what identifies the issuing service.
/// This deployment's media signing key DID URL.
///
/// Falls back to `<service DID>#media-1` so a single-key deployment needs no
/// extra environment variable; the anchoring check against the current-epoch
/// `service_id` runs either way, so a misconfigured value fails closed rather
/// than minting a token nobody will accept.
fn configured_media_issuer_kid(state: &AppState) -> String {
    let configured = state.config().media.issuer_kid.trim();
    if !configured.is_empty() {
        return configured.to_owned();
    }
    format!("{}#notary-key", state.service_did())
}

fn token_endpoint_is_local(token_endpoint: &str, state: &AppState) -> bool {
    fn origin(url: &str) -> Option<String> {
        let (scheme, rest) = url.split_once("://")?;
        let authority = rest.split(['/', '?', '#']).next()?;
        (!authority.is_empty()).then(|| format!("{}://{authority}", scheme.to_ascii_lowercase()))
    }
    match (
        origin(token_endpoint),
        origin(state.config().public_base_url.as_str()),
    ) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(&right),
        _ => false,
    }
}

fn media_token_issuer_for(provider: MediaProviderKind) -> Box<dyn MediaTokenIssuer> {
    match provider {
        MediaProviderKind::ArkretNative => Box::new(ArkretNativeMediaIssuer),
        MediaProviderKind::LiveKit => Box::new(LiveKitMediaIssuer),
    }
}

/// Arkret-native `backend_token` (`bindings/arkret-native.md` §2).
///
/// The wire form is the binding's own object — `{kid, payload, signature,
/// signature_algorithm}` with the payload carrying exactly `call_id`,
/// `focus_id`, `participant_id`, `issued_at`, `expires_at` and `media`.
/// It is not a private envelope: an arkret-native SFU validates this token
/// before each SDP negotiation, so a locally invented shape would only be
/// readable by this deployment's own SFU.
fn issue_arkret_native_backend_token(
    request: &MediaTokenIssueRequestBody<'_>,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<IssuedMediaToken, AppError> {
    let (audio, video, screen) = token_media_permissions(request);
    let payload = ArkretNativeMediaTokenPayload {
        call_id: CallId::new(request.call_id.to_owned()).map_err(|error| {
            AppError::internal(format!("validated media call_id became invalid: {error}"))
        })?,
        focus_id: request.focus.focus_id.clone(),
        participant_id: request.participant_id.to_owned(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        media: ArkretNativeMediaPermissions {
            audio,
            video,
            screen,
        },
    };
    let payload_bytes = arkret_canonical::canonical_json_bytes(&payload).map_err(|error| {
        AppError::internal(format!(
            "arkret-native backend token canonicalization: {error}"
        ))
    })?;
    let signature = signing_key.sign(&payload_bytes);
    let token = ArkretNativeMediaBackendToken {
        kid: DidUrl::new(request.issuer_kid.to_owned()).map_err(|error| {
            AppError::internal(format!(
                "validated media issuer_kid became invalid: {error}"
            ))
        })?,
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        signature_algorithm: ArkretNativeMediaSignatureAlgorithm::Ed25519,
    };
    Ok(IssuedMediaToken {
        backend_token: MediaBackendToken::ArkretNative(token),
        connect_url: request.focus.connect_url.clone(),
    })
}

fn token_media_permissions(request: &MediaTokenIssueRequestBody<'_>) -> (bool, bool, bool) {
    let (audio, video, screen) = request.desired_media;
    (audio, video, screen && request.allow_screen_share)
}

/// LiveKit backend token (`bindings/livekit.md` §2). Emits a **standard
/// LiveKit JWT** — `base64url(header).base64url(payload).base64url(signature)`
/// with header `{"alg":"HS256","typ":"JWT"}` and signature
/// `HMAC-SHA256(API Secret, header.payload)` — so a real LiveKit
/// deployment validates it.
///
/// The deployment LiveKit API Key/Secret come from
/// [`crate::config::LiveKitConfig`]. The API Key is the JWT `iss` (§2 mapping)
/// and is deployment configuration, never a Realm cell field: the media
/// descriptor is signed Realm policy, and a backend API credential has no
/// business living there. v1 carries a single API Key/Secret pair.
fn issue_livekit_backend_token(
    request: &MediaTokenIssueRequestBody<'_>,
    livekit: &crate::config::LiveKitConfig,
) -> Result<IssuedMediaToken, AppError> {
    let api_key = livekit.api_key.as_deref().filter(|key| !key.is_empty());
    let api_secret = livekit
        .api_secret
        .as_deref()
        .filter(|secret| !secret.is_empty());
    let (Some(api_key), Some(api_secret)) = (api_key, api_secret) else {
        return Err(focus_unavailable_error(
            "livekit focus selected but COLAND_LIVEKIT_API_KEY / COLAND_LIVEKIT_API_SECRET are not configured",
        ));
    };
    let (audio, video, screen) = token_media_permissions(request);
    let mut can_publish_sources = Vec::new();
    if audio {
        can_publish_sources.push("microphone");
    }
    if video {
        can_publish_sources.push("camera");
    }
    if screen {
        can_publish_sources.push("screen_share");
    }
    let can_publish = !can_publish_sources.is_empty();
    // LiveKit room name MUST NOT leak the raw Realm/call id into LiveKit logs.
    // Derive a stable opaque backend room handle from the full media tuple.
    let room_material = format!(
        "{}\0{}\0{}",
        request.realm_id, request.call_id, request.focus.focus_id
    );
    let room = format!("ak_call_{}", &sha256_hex(room_material.as_bytes())[..16]);
    // LiveKit JWT registered claims (`iat`/`nbf`/`exp`) are NumericDate —
    // seconds since the Unix epoch — not RFC3339 strings.
    let iat = request.issued_at.timestamp();
    let nbf = iat;
    let exp = request.expires_at.timestamp();
    let token_payload = json!({
        "iss": api_key,
        "sub": request.participant_id,
        // §2: `name` MUST NOT carry actor identity; participant_id is
        // already a pairwise pseudonym, so reuse it as the display label.
        "name": request.participant_id,
        "nbf": nbf,
        "iat": iat,
        "exp": exp,
        "video": {
            "room": room,
            "roomJoin": true,
            "canPublish": can_publish,
            "canPublishSources": can_publish_sources,
            "canSubscribe": true,
            "hidden": false,
            "recorder": false,
        },
    });

    let header = json!({"alg": "HS256", "typ": "JWT"});
    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap_or_else(|_| header.to_string().into_bytes()));
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&token_payload)
            .unwrap_or_else(|_| token_payload.to_string().into_bytes()),
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature_b64 =
        URL_SAFE_NO_PAD.encode(hmac_sha256(api_secret.as_bytes(), signing_input.as_bytes()));
    Ok(IssuedMediaToken {
        backend_token: MediaBackendToken::Opaque(format!("{signing_input}.{signature_b64}")),
        connect_url: request.focus.connect_url.clone(),
    })
}

/// Whether `issuer_kid` names a key of `service_id`.
///
/// `media-service-binding.md` §3: strip the verification-method fragment, then
/// project the DID through the registered adapter and require the result to
/// equal the current-epoch `service_id`. The cell carries a `did_core_id` while
/// the kid is a DID URL, so a textual prefix comparison would never match — and
/// a comparison that silently never matches is a gate that never fires.
fn issuer_kid_belongs_to_service(issuer_kid: &str, service_id: &str) -> bool {
    let Some((bare, fragment)) = issuer_kid.split_once('#') else {
        return false;
    };
    if fragment.is_empty() {
        return false;
    }
    arkret_wire::Did::new(bare.to_owned())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        .is_ok_and(|core| core.as_str() == service_id)
}

fn token_issuer_unauthorised(message: impl Into<String>) -> AppError {
    crate::app_error!(FailedPrecondition, message)
        .with_reason_code(arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED)
}

fn focus_unavailable_error(message: impl Into<String>) -> AppError {
    crate::app_error!(FailedPrecondition, message)
        .with_reason_code(arkret_wire::ReasonCode::FOCUS_UNAVAILABLE_FOR_CLIENT)
}

#[endpoint(
    operation_id = "ak.self.call.media.exchange.issue_token",
    summary = "Exchange a call media token",
    tags("media")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.call.media.exchange.issue_token.v1"))]
async fn arkret_rtc_token(
    aa: AuthArgs,
    body: JsonBody<CallMediaTokenExchangeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<CallMediaTokenExchangeResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let original: Value = serde_json::from_slice(
        req.payload()
            .await
            .map_err(|e| AppError::json_invalid(e.to_string()))?,
    )
    .map_err(|e| AppError::json_invalid(e.to_string()))?;
    handle_rtc_token_with_original(state, &session, body.into_inner(), Some(original)).await
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "media-token tests stay adjacent to the private token helpers"
)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the configured real LiveKit server and Python RTC SDK"]
    fn real_livekit_media_token_cannot_mute_another_publishers_track() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let lease = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = lease.local_addr().unwrap().port();
        drop(lease);
        let focus = MediaProviderConfig {
            provider: MediaProviderKind::LiveKit,
            focus_id: "livekit_test".to_owned(),
            token_endpoint: "https://station.example/_arkret/self/rtc/token".to_owned(),
            connect_url: format!("ws://127.0.0.1:{port}"),
        };
        let config = crate::config::LiveKitConfig {
            api_key: Some("2136-test-key".to_owned()),
            api_secret: Some("2136-owned-test-secret-at-least-32-bytes".to_owned()),
        };
        let issued_at = now();
        let mut tokens = Vec::new();
        for _ in 0..2 {
            let participant = format!("ak:rtc_participant:{}", uuid::Uuid::now_v7());
            let request = MediaTokenIssueRequestBody {
                focus: &focus,
                issuer_kid: "did:web:station.example#notary-key",
                realm_id: "ak:realm:AW2XhEBfjbMHqDBzRGwBXCaBZtSGUQTBe5CkC4pjU8O2",
                call_id: "ak:call:AbhvODyrIRCskAIoS9IXLjMfD-Zsr8lwDpiCU_zLR4it",
                participant_id: &participant,
                desired_media: (true, false, false),
                allow_screen_share: false,
                issued_at,
                expires_at: issued_at + Duration::seconds(300),
            };
            let issued = issue_livekit_backend_token(&request, &config).unwrap();
            let MediaBackendToken::Opaque(token) = issued.backend_token else {
                panic!("LiveKit issuer returned another backend branch");
            };
            tokens.push(token);
        }
        let moderator = arkret_models_collaboration::call_signal::CallMuteStateSignalData {
            audio_muted: true,
            video_muted: false,
            changed_by: arkret_models_collaboration::call_signal::MuteChangedBy::Moderator,
            target_actor_id: None,
            target_device_id: None,
        };
        assert!(
            moderator
                .validate()
                .unwrap_err()
                .to_string()
                .contains("unsupported_feature")
        );
        let mut child =
            Command::new(std::env::var("COLAND_TEST_SFU_PYTHON").expect("real Python RTC SDK"))
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/support/livekit_mute_probe.py"
                ))
                .env("LIVEKIT_LOG_LEVEL", "error")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
        serde_json::to_writer(
            child.stdin.as_mut().unwrap(),
            &json!({
                "tokens":tokens,"port":port,"api_key":config.api_key,"api_secret":config.api_secret,
            }),
        )
        .unwrap();
        child.stdin.take().unwrap().flush().unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "real SFU probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    fn actor(principal: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    #[test]
    fn removed_moderation_dot_does_not_remain_an_effective_ban() {
        let cell = CallMediaCells {
            accepted: None,
            focus: None,
            moderation: Some(json!([
                {
                    "tag": "ak:event:AcGlxGJUvk7f1IQL9A3Jlg9JcPIuUVquBS_eLDo7S71q",
                    "value": {
                        "actor_id": actor("ak:did_core:web:bob.example"),
                        "action": "ban"
                    },
                    "removed": true
                },
                {
                    "tag": "ak:event:AS4AFkLeK4cxIX2CmEC7OAwstCL0qkWN6ZHZB1fMNUMx",
                    "value": {
                        "actor_id": actor("ak:did_core:web:carol.example"),
                        "action": "ban"
                    }
                }
            ])),
        };

        assert!(!cell.actor_is_banned(&actor("ak:did_core:web:bob.example")));
        assert!(cell.actor_is_banned(&actor("ak:did_core:web:carol.example")));
        let other_station = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:carol.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(!cell.actor_is_banned(&other_station));
    }

    #[test]
    fn token_media_permissions_gate_screen_share() {
        let focus = MediaProviderConfig {
            provider: MediaProviderKind::ArkretNative,
            focus_id: "arkret_native_test".to_owned(),
            token_endpoint: "https://media.example/_arkret/self/rtc/token".to_owned(),
            connect_url: "https://media.example".to_owned(),
        };
        let issued_at = Utc::now();
        let request = MediaTokenIssueRequestBody {
            focus: &focus,
            issuer_kid: "did:webvh:z6mkfixture:media.example#media-1",
            realm_id: "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt",
            call_id: "ak:call:AXN8h1ovgRUvcxrjsoB4ffwwej16MPpikhZbvZ6pt_Hj",
            participant_id: "ak:rtc_participant:01904100-0000-7000-8000-000000000009",
            desired_media: (false, true, true),
            allow_screen_share: false,
            issued_at,
            expires_at: issued_at + Duration::seconds(300),
        };

        assert_eq!(token_media_permissions(&request), (false, true, false));
    }

    #[test]
    fn media_provider_kind_accepts_registered_arkret_native_backend() {
        assert_eq!(
            MediaProviderKind::parse("arkret_native").unwrap(),
            MediaProviderKind::ArkretNative
        );
    }

    #[test]
    fn webrtc_session_id_accepts_sdk_call_id() {
        assert!(is_valid_webrtc_session_id(
            "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0"
        ));
    }

    #[test]
    fn webrtc_session_id_rejects_non_call_and_malformed_ids() {
        for invalid in [
            "ak:event:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz0",
            "ak:call:AWRz9zKjOlGmvDeLp4ws-Eb6jsg4I5jJdj5J8o3cGYz!",
        ] {
            assert!(!is_valid_webrtc_session_id(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn media_epoch_accepts_spec_focus_id_without_private_prefix() {
        let descriptor = decode_media_service_descriptor(json!({
            "value": {
                "service_id": "ak:did_core:webvh:z6mkfixturemedia",
                "foci": [{
                    "focus_id": "fra-1",
                    "focus_kind": "livekit",
                    "token_endpoint": "https://media.example/_arkret/self/rtc/token",
                    "connect_url": "wss://media.example"
                }]
            }
        }))
        .expect("valid projected media descriptor");
        let epoch = media_service_epoch_from_descriptor(descriptor)
            .expect("spec focus ids are not required to use a private prefix");

        assert_eq!(epoch.foci[0].focus_id, "fra-1");
    }

    /// `media-service-binding.md` §2: `token_endpoint` and `connect_url` are
    /// normative required fields. A descriptor carrying provider issuance
    /// configuration instead is not a usable focus and must fail decode rather
    /// than be silently read as an empty one.
    #[test]
    fn a_focus_without_the_normative_endpoints_fails_closed() {
        let descriptor = decode_media_service_descriptor(json!({
            "value": {
                "service_id": "ak:did_core:webvh:z6mkfixturemedia",
                "foci": [{
                    "focus_id": "fra-1",
                    "focus_kind": "livekit",
                    "issuer_kid": "did:webvh:z6mkfixture:media.example#key-1",
                    "audience": "livekit-demo",
                    "ttl_seconds": 300
                }]
            }
        }));
        assert!(descriptor.is_err());
    }

    /// v1 has a normative backend binding for `livekit` and `arkret_native`
    /// only; the reserved placeholders must fail closed with
    /// `unknown_focus_type` instead of receiving an invented token envelope.
    #[test]
    fn reserved_focus_types_have_no_v1_binding() {
        assert!(MediaProviderKind::parse("livekit").is_ok());
        for reserved in ["mediasoup", "janus", "moq_relay"] {
            assert!(MediaProviderKind::parse(reserved).is_err(), "{reserved}");
        }
    }

    /// The kid is a DID URL and the cell carries a `did_core_id`, so the
    /// anchoring check must project rather than compare prefixes — a prefix
    /// comparison here would simply never fire.
    #[test]
    fn issuer_kid_is_anchored_by_projection_not_by_prefix() {
        assert!(issuer_kid_belongs_to_service(
            "did:webvh:z6mkfixturemedia:media.example#media-1",
            "ak:did_core:webvh:z6mkfixturemedia"
        ));
        assert!(!issuer_kid_belongs_to_service(
            "did:webvh:z6mkattacker:attacker.example#media-1",
            "ak:did_core:webvh:z6mkfixturemedia"
        ));
        assert!(!issuer_kid_belongs_to_service(
            "did:webvh:z6mkfixturemedia:media.example",
            "ak:did_core:webvh:z6mkfixturemedia"
        ));
    }
}

// `webrtc-signaling.md` §3 — canonical capability actions. The registry is
// the truth source; the spec body and this server MUST use the `ak.`-prefixed
// forms and MUST NOT accept the bare `call.*` names.

fn is_valid_webrtc_session_id(value: &str) -> bool {
    // Call IDs are derived from Event identity and share the SDK's canonical
    // 44-character event token. Keep this boundary on the authoritative typed
    // parser so future identifier migrations cannot drift into a private RTC
    // regex or the old producer-allocated UUID form.
    CallId::new(value.to_owned()).is_ok()
}
