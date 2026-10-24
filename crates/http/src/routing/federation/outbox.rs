//! G3.S0 — durable outbound federation HTTP delivery.
//!
//! ## Surface
//!
//! - [`enqueue_outbound`] — synchronous insert into the `federation_outbox` table, for the few call
//!   sites that are not themselves inside an Event commit transaction. Every path that accepts an
//!   Event builds its outbox rows *before* the commit and hands them to the storage unit-of-work
//!   instead.
//! - [`FederationDispatcher`] / [`spawn`] — background tokio task. Every [`POLL_INTERVAL`] it
//!   atomically claims up to [`POLL_BATCH_LIMIT`] due rows under a lease, POSTs each one to its
//!   peer with the spec-required headers, and applies the resulting terminal-or-retry transition
//!   under the same lease token.
//!
//! ## Delivery guarantees
//!
//! - source outbox to peer ingress: **at-least-once**;
//! - peer reducer side effect: idempotent on `(source, destination, idempotency_key,
//!   canonical_digest)` (`sync/federation.md` §8.5);
//! - every intent ends as `delivered`, `policy_suppressed`, `dead_lettered` or `superseded`;
//! - **no** exactly-once transport is promised.
//!
//! ## Two retry classes (`sync/federation.md` §8.5 + §4.1)
//!
//! - **Transport retry** — no response was received at all (timeout, connection reset, DNS). Same
//!   canonical body, same `Idempotency-Key`, fresh short-lived HTTP Message Signature, `attempts +
//!   1`, exponential backoff with bounded jitter and never earlier than the peer's `Retry-After`.
//! - **Semantic resubmission** — a response *was* received and requires re-evaluation
//!   (`dependency_missing`, partial outcome). The old attempt is terminated as `superseded`, the
//!   batch is mechanically diffed down to the still-unconfirmed Events, and a brand-new intent with
//!   a **new** `Idempotency-Key` is inserted in the same transaction. Reusing the old key here
//!   would keep hitting the receiver's cached failure.
//!
//! ## Parallel-work coordination
//!
//! - DOES NOT touch `reducer.rs` — G3.Y0 / G3.S3 own that.
//! - DOES NOT change the inbound federation handler shape — G2.T1 owns that.
//! - DOES NOT introduce a new HTTP client — reuses the existing `reqwest` async client coland
//!   already pulls in.

use std::sync::Arc;
use std::time::Duration;

use arkret_signatures::http_signature::{
    Component, SignedRequestParts, canonical_message, format_signature_input_component_list,
    parse_signature_input,
};
use coland_services::federation::{
    ClaimFederationDeliveriesCommand, FederationDeadLetter, FederationDeliveryOutcome,
    FederationDeliveryRecord, PendingFederationDelivery, RecordFederationAttemptCommand,
};
use coland_storage::FederationOutboxPolicyResolution;
use rand::RngExt;
use uuid::Uuid;

use crate::state::AppState;

/// How often the dispatcher polls the outbox when idle.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum rows the dispatcher claims per poll. Keeps a backlog from
/// monopolizing the tokio runtime; subsequent ticks drain the rest.
pub const POLL_BATCH_LIMIT: usize = 32;
/// How long a claimed row stays owned by one worker. Comfortably longer than
/// [`REQUEST_TIMEOUT`] so a slow peer never causes a second worker to take the
/// row over mid-flight, but short enough that a crashed worker's backlog
/// resumes promptly.
pub const LEASE_DURATION_SECS: i64 = 120;
/// Per-request full-response timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum transport attempts before the row is dead-lettered. Matches the
/// spec recommendation in `federation.md` §8 (≈ 10 attempts ≈ ~1h wallclock
/// with the capped exponential backoff below).
pub const MAX_ATTEMPTS: i32 = 10;
pub(crate) const ERASURE_PROPAGATION_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;
pub(crate) const ERASURE_RECEIPT_ENDPOINT: &str = "/_arkret/peer/erasure-receipts";
/// Maximum semantic resubmissions for one delivery intent chain. Independent
/// of the transport budget: `federation.md` §4.1 caps automatic re-submission
/// of a convergent dependency quarantine and requires the sender to stop and
/// raise an operator diagnostic instead of polling forever.
pub const MAX_SEMANTIC_ATTEMPTS: i32 = 8;
/// Transport backoff base — `5 * 2^attempts`, capped at 1h.
const TRANSPORT_BACKOFF_BASE_SECS: u64 = 5;
const TRANSPORT_BACKOFF_CAP_SECS: u64 = 3_600;
/// Semantic (dependency) backoff — `federation.md` §4.1 requires a start of
/// at least 1s and an upper bound of at least 60s, with jitter.
const SEMANTIC_BACKOFF_BASE_SECS: u64 = 1;
const SEMANTIC_BACKOFF_CAP_SECS: u64 = 300;
/// Fraction of the computed backoff spread randomly on top of it, so a fleet
/// that failed together does not retry together when the peer recovers.
const BACKOFF_JITTER_RATIO: f64 = 0.25;
/// Rows revalidated per pass when the egress policy version changed.
const POLICY_REVALIDATION_BATCH_LIMIT: usize = 32;
/// Cap on the response excerpt we persist. 1 KiB matches the spec's
/// postmortem-evidence size budget.
const RESPONSE_EXCERPT_BYTES: usize = 1024;

/// Stable `last_error_code` values. These are the operator-facing failure
/// vocabulary; they are also the `reason` on the dead-letter ledger rows.
pub mod error_code {
    pub const TRANSPORT_ERROR: &str = "transport_error";
    pub const RETRYABLE_HTTP_STATUS: &str = "retryable_http_status";
    pub const TERMINAL_HTTP_STATUS: &str = "terminal_http_status";
    pub const EGRESS_POLICY_DENIED: &str = "egress_policy_denied";
    pub const RETRY_BUDGET_EXHAUSTED: &str = "retry_budget_exhausted";
    pub const SEMANTIC_RETRY_BUDGET_EXHAUSTED: &str = "semantic_retry_budget_exhausted";
    pub const DEPENDENCY_MISSING: &str = "dependency_missing";
}

/// Compute the unix-second `now` the dispatcher and the enqueue path
/// agree on. Wraps `chrono::Utc::now()` so unit tests can swap the
/// clock without leaking `chrono` through the trait surfaces.
fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// G3.S0 — synchronous outbox enqueue.
///
/// Inserts one row per `(peer, resource)` tuple. Idempotent on
/// `(peer_id, idempotency_key)`: a re-enqueue (e.g. restart-time
/// re-broadcast of an already-sealed Move) returns the pre-existing
/// row instead of creating a duplicate, matching the spec's
/// `Idempotency-Key`-bound replay semantics in `federation.md` §8.5.
///
/// Returns the persisted [`FederationOutboxRecord`] so call sites can
/// log the row id without re-fetching.
pub async fn enqueue_outbound(
    state: &AppState,
    peer_url: &str,
    peer_id: &str,
    endpoint: &str,
    idempotency_key: &str,
    payload_json: &str,
) -> coland_services::ServiceResult<coland_services::federation::FederationDeliveryRecord> {
    enqueue_outbound_with_lane(
        state,
        Some(peer_url),
        peer_id,
        endpoint,
        idempotency_key,
        payload_json,
        None,
    )
    .await
}

/// Queue one monotonic state update while keeping at most one unfinished row
/// for the same `(peer, lane)`. A higher position atomically supersedes the
/// older row; a stale/equal enqueue is a no-op.
pub async fn enqueue_coalesced_outbound(
    state: &AppState,
    peer_url: Option<&str>,
    peer_id: &str,
    endpoint: &str,
    idempotency_key: &str,
    payload_json: &str,
    coalescing_key: &str,
    coalescing_position: i64,
) -> coland_services::ServiceResult<coland_services::federation::FederationDeliveryRecord> {
    enqueue_outbound_with_lane(
        state,
        peer_url,
        peer_id,
        endpoint,
        idempotency_key,
        payload_json,
        Some((coalescing_key, coalescing_position)),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_outbound_with_lane(
    state: &AppState,
    peer_url: Option<&str>,
    peer_id: &str,
    endpoint: &str,
    idempotency_key: &str,
    payload_json: &str,
    coalescing_lane: Option<(&str, i64)>,
) -> coland_services::ServiceResult<coland_services::federation::FederationDeliveryRecord> {
    let peer_id = arkret_wire::DidCoreId::new(peer_id.to_owned()).map_err(|error| {
        coland_services::ServiceError::SchemaViolation(format!("invalid peer service id: {error}"))
    })?;
    let now = now_unix_secs();
    let (coalescing_key, coalescing_position) = coalescing_lane
        .map(|(key, position)| (Some(key.to_owned()), Some(position)))
        .unwrap_or((None, None));
    let result = state
        .federation()
        .enqueue_delivery(
            coland_services::federation::EnqueueFederationDeliveryCommand {
                delivery: coland_services::federation::FederationDeliveryRecord {
                    id: Uuid::new_v4().to_string(),
                    peer_id,
                    peer_url: peer_url.map(|url| url.trim_end_matches('/').to_owned()),
                    endpoint: endpoint.to_owned(),
                    idempotency_key: idempotency_key.to_owned(),
                    payload_json: payload_json.to_owned(),
                    coalescing_key,
                    coalescing_position,
                    realm_fanout: None,
                    created_at: now,
                },
            },
        )
        .await?;
    Ok(result)
}

pub(crate) fn rfc9421_sign(
    state: &AppState,
    headers: reqwest::header::HeaderMap,
    method: &str,
    target_url: &str,
) -> reqwest::header::HeaderMap {
    rfc9421_sign_with_window(state, headers, method, target_url, 300)
}

fn operation_for_canonical_http_request(
    method: &str,
    target_url: &str,
) -> Option<arkret_wire::ServiceOperationId> {
    let url = reqwest::Url::parse(target_url).ok()?;
    arkret_wire::ServiceOperationId::from_http_request(method, url.path())
}

fn rfc9421_sign_with_window(
    state: &AppState,
    mut headers: reqwest::header::HeaderMap,
    method: &str,
    target_url: &str,
    validity_seconds: i64,
) -> reqwest::header::HeaderMap {
    let created = now_unix_secs();
    let expires = created + validity_seconds;
    let keyid = super::federation_service_signature_key_id(state.service_did().as_str());
    let mut covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("content-digest".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("source-trust-domain".to_owned()),
        Component::Header("destination-trust-domain".to_owned()),
    ];
    if let Some(operation) = operation_for_canonical_http_request(method, target_url) {
        insert_header_if_valid(&mut headers, "arkret-operation", operation.as_str());
        covered.push(Component::Header("arkret-operation".to_owned()));
    }
    let idempotency_key = header_value(&headers, "idempotency-key");
    if idempotency_key.is_some() {
        covered.push(Component::Header("idempotency-key".to_owned()));
    }
    let signature_input = format!(
        "{};created={created};expires={expires};keyid=\"{keyid}\";alg=\"ed25519\"",
        format_signature_input_component_list("sig1", &covered)
            .expect("federation signature component profile is valid")
    );
    let parsed_signature_input =
        parse_signature_input(&signature_input).expect("generated Signature-Input is valid");
    let authority = authority_from_target_url(target_url);
    let request = SignedRequestParts {
        method: method.to_owned(),
        target_uri: target_url.to_owned(),
        authority,
        path: String::new(),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body_digest: header_value(&headers, "content-digest"),
    };
    let signature_base = canonical_message(&request, &parsed_signature_input)
        .expect("generated federation signature components are present");
    let signature = arkret_signatures::http_signature::sign_message(
        &signature_base,
        &state.notary_signing_key(),
    );
    let signature_header = format!("sig1=:{signature}:");

    insert_header_if_valid(&mut headers, "signature-input", &signature_input);
    insert_header_if_valid(&mut headers, "signature", &signature_header);
    headers
}

/// Send one Signal peer relay request without a durable outbox or retry.
pub(crate) async fn relay_signal_once(
    state: &AppState,
    peer_id: &str,
    request: &arkret_wire::SignalRelayRequestBody,
) -> Result<(), String> {
    request.validate().map_err(|error| error.to_string())?;
    let body =
        arkret_canonical::canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let peer_target = super::resolved_peer_target(state, peer_id, "station", false).await?;
    let target = format!("{}/_arkret/peer/signal", peer_target.base_url);
    let (parsed_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Signal peer relay",
        state.config().development_mode,
        Duration::from_secs(5),
    )?;
    // Resolution and queueing may outlive the ingress authorization. Never
    // sign a stale ordinary-device grant, membership, MLS basis, or expired Signal.
    for envelope in &request.signals {
        crate::routing::events::sync::signal::admit_outbound_signal(state, peer_id, envelope)
            .await
            .map_err(|error| error.to_string())?;
    }
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    insert_header_if_valid(
        &mut headers,
        "content-digest",
        &content_digest_header_value(&body),
    );
    insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    insert_header_if_valid(&mut headers, "destination-service-id", peer_id);
    insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    insert_header_if_valid(
        &mut headers,
        "destination-trust-domain",
        &peer_target.trust_domain,
    );
    let headers = rfc9421_sign_with_window(state, headers, "POST", &target, 5);
    let response = client
        .post(parsed_url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Signal peer relay returned HTTP {}",
            response.status()
        ));
    }
    let outcome = response
        .json::<arkret_wire::SignalRelayResponseBody>()
        .await
        .map_err(|error| error.to_string())?;
    outcome.validate().map_err(|error| error.to_string())
}

/// One governance Station answer to a synchronous `authority_forward`.
#[derive(Debug)]
pub(crate) struct PeerSubmitResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// Transport attempts for one `authority_forward` whose response was lost.
const AUTHORITY_FORWARD_TRANSPORT_ATTEMPTS: usize = 3;

/// Send one `authority_forward` to the governance Station and return its
/// answer. The self response relays the governance outcome, so the forward
/// is synchronous and never queued in the outbox.
///
/// Only a lost response is retried, and it resends the byte-identical body
/// with its original `producer_device_evidence` (device-lifecycle §8.2.2);
/// every new forwarding attempt is a new call with freshly signed evidence.
pub(crate) async fn submit_authority_forward(
    state: &AppState,
    peer_id: &str,
    body: &[u8],
) -> Result<PeerSubmitResponse, String> {
    let peer_target = super::resolved_peer_target(state, peer_id, "station", false).await?;
    let target = format!("{}/_arkret/peer/events", peer_target.base_url);
    let (parsed_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "authority_forward",
        state.config().development_mode,
        REQUEST_TIMEOUT,
    )?;
    let mut last_error = String::from("authority_forward was not sent");
    for _ in 0..AUTHORITY_FORWARD_TRANSPORT_ATTEMPTS {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        insert_header_if_valid(
            &mut headers,
            "content-digest",
            &content_digest_header_value(body),
        );
        insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
        insert_header_if_valid(&mut headers, "destination-service-id", peer_id);
        insert_header_if_valid(
            &mut headers,
            "source-trust-domain",
            state.config().trust_domain.as_str(),
        );
        insert_header_if_valid(
            &mut headers,
            "destination-trust-domain",
            &peer_target.trust_domain,
        );
        let headers = rfc9421_sign(state, headers, "POST", &target);
        let response = match client
            .post(parsed_url.clone())
            .headers(headers)
            .body(body.to_vec())
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                last_error = error.to_string();
                continue;
            }
        };
        let status = response.status().as_u16();
        match response.bytes().await {
            Ok(bytes) => {
                return Ok(PeerSubmitResponse {
                    status,
                    body: bytes.to_vec(),
                });
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(format!("authority_forward response lost: {last_error}"))
}

/// Send one signed synchronous peer request (a peer read such as
/// `ak.peer.realm_join.read.bootstrap.v1` or `ak.peer.committed_event.read.scan.v1`)
/// to `peer_id` and return its bounded answer. Nothing is queued or retried.
pub(crate) async fn signed_peer_request(
    state: &AppState,
    peer_id: &str,
    path: &str,
    body: &[u8],
    max_response_bytes: usize,
) -> Result<PeerSubmitResponse, String> {
    let peer_target = super::resolved_peer_target(state, peer_id, "station", false).await?;
    let target = format!("{}{path}", peer_target.base_url);
    signed_peer_request_to_target(
        state,
        peer_id,
        &peer_target.trust_domain,
        &target,
        body,
        None,
        max_response_bytes,
    )
    .await
}

pub(crate) async fn signed_peer_command(
    state: &AppState,
    peer_id: &str,
    path: &str,
    body: &[u8],
    idempotency_key: &str,
    max_response_bytes: usize,
) -> Result<PeerSubmitResponse, String> {
    let peer_target = super::resolved_peer_target(state, peer_id, "station", false).await?;
    signed_peer_request_to_target(
        state,
        peer_id,
        &peer_target.trust_domain,
        &format!("{}{path}", peer_target.base_url),
        body,
        Some(idempotency_key),
        max_response_bytes,
    )
    .await
}

/// The deployment-pinned Account Authority is a separate endpoint of this
/// Station identity. Generic Station discovery would read the Station replica.
pub(crate) async fn signed_deployment_account_status_resolve(
    state: &AppState,
    authority_id: &arkret_wire::DidCoreId,
    authority_url: &arkret_models_identity::service_identity::CanonicalServiceUrl,
    body: &[u8],
) -> Result<PeerSubmitResponse, String> {
    if authority_id != &state.service_core_id() {
        return Err("Account Authority is not the deployment Station identity".to_owned());
    }
    let configured = state
        .config()
        .account_authority_url
        .as_deref()
        .ok_or_else(|| "Account Authority endpoint is not configured".to_owned())?;
    let configured =
        arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(configured)
            .map_err(|_| "Account Authority endpoint is invalid".to_owned())?;
    if &configured != authority_url {
        return Err("Account Authority endpoint differs from deployment configuration".to_owned());
    }
    let authority_trust_domain = state
        .config()
        .account_authority_trust_domain
        .as_ref()
        .ok_or_else(|| "Account Authority trust domain is not configured".to_owned())?;
    let target = format!(
        "{}/_arkret/peer/account-status/resolve",
        authority_url.as_str().trim_end_matches('/')
    );
    signed_peer_request_to_target(
        state,
        authority_id.as_str(),
        authority_trust_domain.as_str(),
        &target,
        body,
        None,
        2 * 1024 * 1024,
    )
    .await
}

async fn signed_peer_request_to_target(
    state: &AppState,
    peer_id: &str,
    trust_domain: &str,
    target: &str,
    body: &[u8],
    idempotency_key: Option<&str>,
    max_response_bytes: usize,
) -> Result<PeerSubmitResponse, String> {
    let (parsed_url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        target,
        "peer read",
        state.config().development_mode,
        REQUEST_TIMEOUT,
    )?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    insert_header_if_valid(
        &mut headers,
        "content-digest",
        &content_digest_header_value(body),
    );
    insert_header_if_valid(&mut headers, "source-service-id", state.service_id());
    insert_header_if_valid(&mut headers, "destination-service-id", peer_id);
    insert_header_if_valid(
        &mut headers,
        "source-trust-domain",
        state.config().trust_domain.as_str(),
    );
    insert_header_if_valid(&mut headers, "destination-trust-domain", trust_domain);
    if let Some(key) = idempotency_key {
        headers.insert(
            "idempotency-key",
            reqwest::header::HeaderValue::from_str(key).map_err(|error| error.to_string())?,
        );
    }
    let headers = rfc9421_sign(state, headers, "POST", target);
    let mut response = client
        .post(parsed_url)
        .headers(headers)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if bytes.len() + chunk.len() > max_response_bytes {
            return Err("peer answer exceeds the operation limit".to_owned());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(PeerSubmitResponse {
        status,
        body: bytes,
    })
}

fn authority_from_target_url(target_url: &str) -> String {
    let Ok(url) = reqwest::Url::parse(target_url) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    url.port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_owned())
}

pub(crate) fn insert_header_if_valid(
    headers: &mut reqwest::header::HeaderMap,
    name: &'static str,
    value: &str,
) {
    if let Ok(value) = reqwest::header::HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Compute the RFC 9530 `Content-Digest` header value for a body.
pub(crate) fn content_digest_header_value(body: &[u8]) -> String {
    super::rfc9530_content_digest(body)
}

/// Truncate a response body for the `last_response_excerpt` column.
fn excerpt(body: &str) -> String {
    if body.len() <= RESPONSE_EXCERPT_BYTES {
        body.to_owned()
    } else {
        // Avoid splitting a multi-byte char mid-sequence.
        let mut end = RESPONSE_EXCERPT_BYTES;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        body[..end].to_owned()
    }
}

fn peer_event_application_failure(
    endpoint: &str,
    request_body: &str,
    response_body: &str,
) -> Option<&'static str> {
    if endpoint == "/_arkret/peer/account-status" {
        use arkret_models_collaboration::account_lifecycle::{
            AccountStatusPublicationRequestBody, AccountStatusPublicationResponseBody,
            AccountStatusPublicationStatus,
        };
        let Some((request, outcome)) =
            serde_json::from_str::<AccountStatusPublicationRequestBody>(request_body)
                .ok()
                .zip(
                    serde_json::from_str::<AccountStatusPublicationResponseBody>(response_body)
                        .ok(),
                )
        else {
            return Some("invalid_account_status_outcome");
        };
        if outcome.validate_for_request(&request).is_err() {
            return Some("invalid_account_status_outcome");
        }
        return match outcome.status {
            AccountStatusPublicationStatus::Accepted
            | AccountStatusPublicationStatus::Duplicate => None,
            AccountStatusPublicationStatus::DependencyMissing => {
                Some(error_code::DEPENDENCY_MISSING)
            }
        };
    }
    if endpoint == "/_coland/peer/federation/operations" {
        return match serde_json::from_str::<serde_json::Value>(response_body)
            .ok()
            .and_then(|value| {
                value
                    .get("rejected")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
            }) {
            Some(rejected) if rejected.is_empty() => None,
            Some(_) => Some("partial_peer_operation_outcome"),
            None => Some("invalid_peer_operation_outcome"),
        };
    }
    if endpoint == "/_arkret/peer/invites" {
        // `invite-addressing.md` §5.1 / §7 step 9 — `accepted`, `duplicate` and
        // `deferred` are all authoritative receive outcomes; `deferred` covers
        // quarantine and every indistinguishable denial, so none of them is a
        // resubmittable failure. Only a body that is not a typed
        // `invite_delivery_response_body` at all is an application failure.
        return match serde_json::from_str::<
            arkret_models_collaboration::governance::invite_addressing::InviteDeliveryResponseBody,
        >(response_body)
        {
            Ok(_) => None,
            Err(_) => Some("invalid_peer_invite_outcome"),
        };
    }
    if endpoint != "/_arkret/peer/events" {
        return None;
    }
    use arkret_models_collaboration::authority_commit::{
        CommittedEventReplicationOutcome, PeerAuthoritySubmitRequestBody,
        PeerAuthoritySubmitResponseBody, RegisteredAtomicUnitAdmissionOutcome,
    };

    let Ok(request) = serde_json::from_str::<PeerAuthoritySubmitRequestBody>(request_body) else {
        return Some("invalid_peer_event_request");
    };
    // `authority_forward` is synchronous and every new attempt carries freshly
    // signed producer evidence (device-lifecycle §8.2.2); a queued forward
    // could only be resent with stale evidence, so it is never delivered here.
    if is_authority_forward(&request) {
        return Some(AUTHORITY_FORWARD_NOT_QUEUED);
    }
    let Ok(outcome) = serde_json::from_str::<PeerAuthoritySubmitResponseBody>(response_body) else {
        return Some("invalid_peer_event_outcome");
    };
    if outcome.validate_for_request(&request).is_err() {
        return Some("invalid_peer_event_outcome");
    }
    match outcome {
        PeerAuthoritySubmitResponseBody::AuthorityForward(_) => Some("invalid_peer_event_outcome"),
        PeerAuthoritySubmitResponseBody::CommittedReplication(value) => {
            if value.replication_outcomes.iter().all(|record| {
                matches!(
                    record,
                    CommittedEventReplicationOutcome::Stored {}
                        | CommittedEventReplicationOutcome::Duplicate {}
                )
            }) {
                None
            } else if value.replication_outcomes.iter().all(|record| {
                !matches!(record, CommittedEventReplicationOutcome::Rejected { reason_code }
                    if reason_code != error_code::DEPENDENCY_MISSING)
            }) {
                Some(error_code::DEPENDENCY_MISSING)
            } else {
                Some("peer_replication_rejected")
            }
        }
        PeerAuthoritySubmitResponseBody::RegisteredAtomicUnit(value) => match value.outcome {
            RegisteredAtomicUnitAdmissionOutcome::Rejected(rejection)
                if rejection.reason_code == error_code::DEPENDENCY_MISSING =>
            {
                Some(error_code::DEPENDENCY_MISSING)
            }
            RegisteredAtomicUnitAdmissionOutcome::Rejected(_) => Some("peer_atomic_unit_rejected"),
            _ => None,
        },
    }
}

const AUTHORITY_FORWARD_NOT_QUEUED: &str = "authority_forward_not_queued";

fn is_authority_forward(
    request: &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody,
) -> bool {
    use arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody;
    matches!(
        request,
        PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(_)
            | PeerAuthoritySubmitRequestBody::AuthorityForwardMls(_)
            | PeerAuthoritySubmitRequestBody::AuthorityForwardAtomic(_)
    )
}

/// Whether an outbox row carries an `authority_forward`, which is never
/// resubmitted: its evidence belongs to the attempt that signed it.
fn is_queued_authority_forward(endpoint: &str, payload_json: &str) -> bool {
    endpoint == "/_arkret/peer/events"
        && serde_json::from_str::<
            arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody,
        >(payload_json)
        .is_ok_and(|request| is_authority_forward(&request))
}

/// A rebuilt request that replaces a finished transport identity.
#[derive(Debug, PartialEq, Eq)]
struct SemanticResubmission {
    payload_json: String,
    idempotency_key: String,
    coalescing_position: Option<i64>,
}

/// `sync/federation.md` §8.5 — once a response has been received the old
/// `Idempotency-Key` is spent; re-evaluation MUST use a new one. The key is a
/// pure function of `(previous key, resubmission ordinal, new canonical body)`
/// so a crash between "decided to resubmit" and "wrote the successor row"
/// recomputes the same key, and the `(peer, idempotency_key)` unique index
/// collapses the replay instead of double-sending.
fn semantic_resubmission_key(
    previous_key: &str,
    semantic_attempts: i32,
    payload_json: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(previous_key.as_bytes());
    input.push(0);
    input.extend_from_slice(semantic_attempts.to_string().as_bytes());
    input.push(0);
    input.extend_from_slice(payload_json.as_bytes());
    format!(
        "ak:outbox:resubmit:{}",
        arkret_canonical::sha256_digest(&input)
    )
}

/// Whole-batch rejection that is convergent once the dependency lands. The
/// request body is unchanged (nothing was accepted), but the transport
/// identity is spent, so the resubmission still needs a fresh key.
fn dependency_resubmission(
    previous_key: &str,
    semantic_attempts: i32,
    request_body: &str,
) -> SemanticResubmission {
    SemanticResubmission {
        payload_json: request_body.to_owned(),
        idempotency_key: semantic_resubmission_key(previous_key, semantic_attempts, request_body),
        coalescing_position: None,
    }
}

/// Resubmit only dependency-missing replication records with a fresh transport
/// identity. The typed peer carrier has no generic partial Event batch.
fn peer_event_partial_retry(
    endpoint: &str,
    request_body: &str,
    response_body: &str,
    previous_key: &str,
    semantic_attempts: i32,
) -> Option<SemanticResubmission> {
    if endpoint != "/_arkret/peer/events" {
        return None;
    }
    use arkret_models_collaboration::authority_commit::{
        CommittedEventReplicationOutcome, PeerAuthoritySubmitRequestBody,
        PeerAuthoritySubmitResponseBody,
    };
    let mut request: PeerAuthoritySubmitRequestBody = serde_json::from_str(request_body).ok()?;
    let outcome: PeerAuthoritySubmitResponseBody = serde_json::from_str(response_body).ok()?;
    outcome.validate_for_request(&request).ok()?;
    let (
        PeerAuthoritySubmitRequestBody::CommittedReplication(request),
        PeerAuthoritySubmitResponseBody::CommittedReplication(outcome),
    ) = (&mut request, outcome)
    else {
        return None;
    };
    // `replication_outcomes[]` is same-order with `replications[]`; the array
    // position is the only row identity (no index or coordinate echo).
    let retry = outcome
        .replication_outcomes
        .iter()
        .map(|record| {
            matches!(record, CommittedEventReplicationOutcome::Rejected { reason_code }
                if reason_code == error_code::DEPENDENCY_MISSING)
        })
        .collect::<Vec<_>>();
    if !retry.contains(&true)
        || outcome.replication_outcomes.iter().any(|record| {
            matches!(record, CommittedEventReplicationOutcome::Rejected { reason_code }
            if reason_code != error_code::DEPENDENCY_MISSING)
        })
    {
        return None;
    }
    let mut retry = retry.into_iter();
    request
        .replications
        .retain(|_| retry.next().unwrap_or(false));
    if request.replications.is_empty() {
        return None;
    }
    let bytes = arkret_canonical::canonical_json_bytes(&request).ok()?;
    let payload_json = String::from_utf8(bytes).ok()?;
    let idempotency_key = semantic_resubmission_key(previous_key, semantic_attempts, &payload_json);
    Some(SemanticResubmission {
        payload_json,
        idempotency_key,
        coalescing_position: None,
    })
}

/// Exponential backoff with bounded jitter.
///
/// The deterministic part doubles per attempt and clamps at `cap`; the jitter
/// adds `[0, BACKOFF_JITTER_RATIO * delay]` so a fleet that failed against the
/// same peer does not stampede it the moment it recovers
/// (`federation.md` §4.1 requires jitter on convergent resubmission, §8.1
/// forbids retry storms generally).
fn backoff_delay_secs(attempts: i32, base: u64, cap: u64) -> u64 {
    let shift = (attempts.max(0) as u32).min(20);
    let delay = base.saturating_mul(1u64 << shift).min(cap);
    let spread = ((delay as f64) * BACKOFF_JITTER_RATIO) as u64;
    if spread == 0 {
        return delay;
    }
    delay + rand::rng().random_range(0..=spread)
}

fn transport_backoff_unix_secs(attempts: i32, now: i64) -> i64 {
    now + backoff_delay_secs(
        attempts,
        TRANSPORT_BACKOFF_BASE_SECS,
        TRANSPORT_BACKOFF_CAP_SECS,
    ) as i64
}

fn semantic_backoff_unix_secs(semantic_attempts: i32, now: i64) -> i64 {
    now + backoff_delay_secs(
        semantic_attempts.saturating_sub(1),
        SEMANTIC_BACKOFF_BASE_SECS,
        SEMANTIC_BACKOFF_CAP_SECS,
    ) as i64
}

/// The peer's own pacing instruction, as an absolute unix second.
///
/// `Retry-After` wins; the canonical `retry_after_ms` in the error envelope is
/// the fallback when the header is absent (`federation.md` §8.1 / §8.5).
fn peer_requested_retry_at(
    headers: &reqwest::header::HeaderMap,
    body: &str,
    now: i64,
) -> Option<i64> {
    if let Some(value) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
    {
        let value = value.trim();
        if let Ok(seconds) = value.parse::<i64>() {
            return Some(now + seconds.max(0));
        }
        if let Ok(date) = chrono::DateTime::parse_from_rfc2822(value) {
            return Some(date.timestamp().max(now));
        }
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let retry_after_ms = value
        .pointer("/error/retry_after_ms")
        .or_else(|| value.pointer("/retry_after_ms"))?
        .as_i64()?;
    Some(now + retry_after_ms.max(0).div_euclid(1_000))
}

/// Whether a received response asks the sender to re-evaluate and resubmit
/// rather than replay the same transport identity.
///
/// A peer answers with an RFC 9457 Problem Details envelope whose `type`
/// names the registered error code.
fn causal_dependencies_pending(body: &str) -> bool {
    serde_json::from_str::<arkret_wire::problem_details::Problem>(body).is_ok_and(|problem| {
        matches!(
            problem.code(),
            "dependency_missing" | "direct_binding_dependencies_pending"
        )
    })
}

/// Background outbound federation dispatcher.
pub struct FederationDispatcher {
    state: AppState,
    /// Durable-enough worker identity for the lease ledger: which process
    /// currently owns a row. Regenerated per process, which is exactly the
    /// granularity a crash-takeover needs to be attributable.
    worker_id: String,
}

impl FederationDispatcher {
    pub fn new(state: AppState) -> Self {
        let worker_id = format!("{}#{}", state.service_id(), Uuid::new_v4());
        Self { state, worker_id }
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Spawn the dispatcher loop on the current tokio runtime. Returns
    /// a `JoinHandle` the caller can `abort()` at shutdown.
    pub fn spawn(self) -> Arc<tokio::task::JoinHandle<()>> {
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(error) = self.run_one_pass().await {
                    tracing::warn!(
                        %error,
                        worker = "federation_outbox",
                        target = "federation_outbox",
                        "federation outbox pass failed (will retry on next tick)"
                    );
                }
            }
        });
        Arc::new(task)
    }

    /// Run one dispatch pass. Pulled out of [`spawn`] so the
    /// integration test can drive the loop deterministically.
    pub async fn run_one_pass(&self) -> Result<(), String> {
        if let Err(error) = super::mls_recipient_attestations::dispatch(&self.state).await {
            tracing::warn!(%error, "recipient MLS Add proof outbox scan is unavailable");
        }
        if let Err(error) =
            crate::routing::identity::account::materialize_contact_completions(&self.state).await
        {
            tracing::warn!(error=%error, "Contact completion scan is unavailable");
        }
        self.revalidate_policy_suppressed().await;
        let now = now_unix_secs();
        // One random token per pass. A row re-claimed by anyone (including this
        // worker on a later pass) gets a different token, which is exactly what
        // invalidates an in-flight holder's late write.
        let lease_token = Uuid::new_v4().to_string();
        let rows = self
            .state
            .federation()
            .claim_deliveries(ClaimFederationDeliveriesCommand {
                now,
                limit: POLL_BATCH_LIMIT,
                lease_owner: self.worker_id.clone(),
                lease_token: lease_token.clone(),
                lease_duration_secs: LEASE_DURATION_SECS,
            })
            .await
            .map_err(|e| e.to_string())?;
        for row in rows {
            self.deliver_one(row).await;
        }
        Ok(())
    }

    /// `federation.md` §4.4 — a row the local egress policy suppressed is not
    /// a delivery and not a network failure. It returns to the queue only when
    /// the policy version actually changed *and* the target revalidates; a
    /// bare restart never bypasses a policy that still denies the peer.
    async fn revalidate_policy_suppressed(&self) {
        let policy_version =
            crate::security::egress_policy_version(self.state.config().development_mode);
        let rows = match self
            .state
            .federation()
            .policy_suppressed_stale(&policy_version, POLICY_REVALIDATION_BATCH_LIMIT)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(
                    %error,
                    worker = "federation_outbox",
                    target = "federation_outbox",
                    "failed to read policy-suppressed federation outbox rows"
                );
                return;
            }
        };
        for row in rows {
            let peer_target = super::resolved_peer_target(
                &self.state,
                row.delivery.peer_id.as_str(),
                "station",
                false,
            )
            .await
            .ok();
            let Some(peer_target) = peer_target else {
                let _ = self
                    .state
                    .federation()
                    .resolve_policy_suppressed(
                        &row.delivery.id,
                        FederationOutboxPolicyResolution::Repin {
                            policy_version: policy_version.clone(),
                        },
                    )
                    .await;
                continue;
            };
            let url = format!("{}{}", peer_target.base_url, row.delivery.endpoint);
            // §8 is re-checked here for the same reason the URL gate is: a
            // released row goes straight back to the wire, so a policy that
            // still denies the peer must still deny it after a version bump.
            let trust_domain_denied = crate::security::federation_outbound_trust_domain_denial(
                row.delivery.peer_id.as_str(),
                Some(&peer_target.trust_domain),
            )
            .is_some();
            let egress_ok = !trust_domain_denied
                && crate::security::validate_http_url_for_egress(
                    &url,
                    "federation outbox",
                    self.state.config().development_mode,
                )
                .is_ok();
            let resolution = if egress_ok {
                FederationOutboxPolicyResolution::Release {
                    next_attempt_at: now_unix_secs(),
                }
            } else {
                FederationOutboxPolicyResolution::Repin {
                    policy_version: policy_version.clone(),
                }
            };
            let released = matches!(resolution, FederationOutboxPolicyResolution::Release { .. });
            match self
                .state
                .federation()
                .resolve_policy_suppressed(&row.delivery.id, resolution)
                .await
            {
                Ok(true) if released => {
                    crate::metrics::record_federation_retry_state("policy_suppressed_released");
                    tracing::info!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.delivery.id,
                        peer_id = %row.delivery.peer_id,
                        "federation outbox row revalidated under the new egress policy"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    %error,
                    worker = "federation_outbox",
                    outbox_id = %row.delivery.id,
                    target = "federation_outbox",
                    "failed to resolve policy-suppressed federation outbox row"
                ),
            }
        }
    }

    /// Deliver a single claimed row and apply its transition under the lease.
    async fn deliver_one(&self, row: PendingFederationDelivery) {
        let Some(lease_token) = row.lease_token.clone() else {
            tracing::error!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                "claimed federation outbox row carries no lease token"
            );
            return;
        };
        if row.delivery.endpoint == ERASURE_RECEIPT_ENDPOINT
            && now_unix_secs()
                >= row
                    .delivery
                    .created_at
                    .saturating_add(ERASURE_PROPAGATION_WINDOW_SECS)
        {
            self.commit(self.dead_letter(&row, &lease_token, row.attempts, row.last_http_status,
                "erasure_propagation_timed_out", "historical holder did not provide a verified acknowledgement within the propagation window".into(), now_unix_secs())).await;
            return;
        }
        let owed = match realm_fanout_still_owed(&self.state, &row).await {
            Ok(owed) => owed,
            Err(error) => {
                let command = self.transport_retry(
                    &row,
                    &lease_token,
                    row.attempts.saturating_add(1),
                    None,
                    error_code::TRANSPORT_ERROR,
                    excerpt(&format!("fanout_authority_unavailable: {error}")),
                    None,
                    now_unix_secs(),
                );
                self.commit(command).await;
                return;
            }
        };
        if !owed {
            self.commit(RecordFederationAttemptCommand {
                id: row.delivery.id.clone(),
                lease_token,
                attempts: row.attempts,
                semantic_attempts: row.semantic_attempts,
                last_http_status: None,
                last_error_code: Some("fanout_authority_lost".to_owned()),
                last_response_excerpt: None,
                observed_at: now_unix_secs(),
                outcome: FederationDeliveryOutcome::CancelledAuthorityLost,
            })
            .await;
            return;
        }
        let peer_target = super::resolved_peer_target(
            &self.state,
            row.delivery.peer_id.as_str(),
            "station",
            false,
        )
        .await;
        let peer_target = match peer_target {
            Ok(peer_target) => peer_target,
            Err(error) => {
                let attempts = row.attempts.saturating_add(1);
                let now = now_unix_secs();
                tracing::debug!(
                    target = "federation_outbox",
                    worker = "federation_outbox",
                    outbox_id = %row.delivery.id,
                    peer_id = %row.delivery.peer_id,
                    endpoint = %row.delivery.endpoint,
                    attempts,
                    %error,
                    "federation outbox route resolution is unavailable"
                );
                let command = if row.delivery.realm_fanout.is_some() {
                    if attempts >= MAX_ATTEMPTS && attempts % MAX_ATTEMPTS == 0 {
                        tracing::warn!(
                            target = "federation_outbox",
                            worker = "federation_outbox",
                            outbox_id = %row.delivery.id,
                            peer_id = %row.delivery.peer_id,
                            endpoint = %row.delivery.endpoint,
                            attempts,
                            "Realm fanout route remains unavailable past the operator alert threshold"
                        );
                    }
                    let next_attempt_at = transport_backoff_unix_secs(attempts, now);
                    RecordFederationAttemptCommand {
                        id: row.delivery.id.clone(),
                        lease_token,
                        attempts,
                        semantic_attempts: row.semantic_attempts,
                        last_http_status: None,
                        last_error_code: Some("service_route_unavailable".to_owned()),
                        last_response_excerpt: Some(excerpt(&error)),
                        observed_at: now,
                        outcome: FederationDeliveryOutcome::RouteUnavailable { next_attempt_at },
                    }
                } else if row.delivery.endpoint != ERASURE_RECEIPT_ENDPOINT
                    && (error.contains("quarantined") || error.contains("fork"))
                {
                    self.dead_letter(
                        &row,
                        &lease_token,
                        attempts,
                        None,
                        "service_route_quarantined",
                        excerpt(&error),
                        now,
                    )
                } else {
                    self.transport_retry(
                        &row,
                        &lease_token,
                        attempts,
                        None,
                        error_code::TRANSPORT_ERROR,
                        excerpt(&format!("service_route_unavailable: {error}")),
                        None,
                        now,
                    )
                };
                self.commit(command).await;
                return;
            }
        };
        if let Some(binding) = row.delivery.realm_fanout.as_ref()
            && crate::routing::organizations::organization_policy_blocks_federation(
                &self.state,
                &binding.realm_id,
                &row.delivery.peer_id,
            )
            .await
        {
            tracing::warn!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_id = %row.delivery.peer_id,
                realm_id = %binding.realm_id,
                "federation outbox delivery suppressed by accepted Organization moderation policy"
            );
            crate::metrics::record_federation_retry_state("policy_suppressed");
            let command = self.transport_retry(
                &row,
                &lease_token,
                row.attempts.saturating_add(1),
                None,
                error_code::EGRESS_POLICY_DENIED,
                excerpt("organization_policy_denied"),
                None,
                now_unix_secs(),
            );
            self.commit(command).await;
            return;
        }
        let url = format!("{}{}", peer_target.base_url, row.delivery.endpoint);
        // `sovereign-deployment.md` §8 — the target service_id's trust_domain
        // MUST be checked against the local federation_allowlist BEFORE the
        // request leaves, and the sender MUST NOT rely on the receiver to
        // refuse. The URL egress gate below cannot stand in for this: it
        // decides on the host, and §8 binds the decision to the peer's
        // service_id.
        if let Some(reason) = crate::security::federation_outbound_trust_domain_denial(
            row.delivery.peer_id.as_str(),
            Some(&peer_target.trust_domain),
        ) {
            tracing::warn!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_id = %row.delivery.peer_id,
                endpoint = %row.delivery.endpoint,
                %reason,
                "federation outbox delivery suppressed by sovereign outbound trust_domain policy"
            );
            crate::metrics::record_federation_retry_state("policy_suppressed");
            // Same discipline as the egress denial below: no socket was
            // opened, so this MUST NOT consume the transport retry budget.
            let now = now_unix_secs();
            let command = if row.delivery.realm_fanout.is_some() {
                self.transport_retry(
                    &row,
                    &lease_token,
                    row.attempts.saturating_add(1),
                    None,
                    error_code::EGRESS_POLICY_DENIED,
                    excerpt(&reason),
                    None,
                    now,
                )
            } else {
                RecordFederationAttemptCommand {
                    id: row.delivery.id.clone(),
                    lease_token,
                    attempts: row.attempts,
                    semantic_attempts: row.semantic_attempts,
                    last_http_status: None,
                    last_error_code: Some(error_code::EGRESS_POLICY_DENIED.to_owned()),
                    last_response_excerpt: Some(excerpt(&reason)),
                    observed_at: now,
                    outcome: FederationDeliveryOutcome::PolicySuppressed {
                        policy_version: crate::security::egress_policy_version(
                            self.state.config().development_mode,
                        ),
                    },
                }
            };
            self.commit(command).await;
            return;
        }
        let body_bytes = row.delivery.payload_json.as_bytes().to_vec();
        // SOL-03-002: build a per-delivery client that pins the validated IPs
        // (egress check and connection resolve to the same addresses), closing
        // the DNS-rebinding TOCTOU window. Peer URLs vary per delivery, so the
        // pinning is per-row rather than on a long-lived client.
        let (parsed_url, client) =
            match crate::security::validate_http_url_for_egress_with_pinned_client(
                &url,
                "federation outbox",
                self.state.config().development_mode,
                REQUEST_TIMEOUT,
            ) {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::warn!(
                        target = "federation_outbox",
                        worker = "federation_outbox",
                        outbox_id = %row.delivery.id,
                        peer_id = %row.delivery.peer_id,
                        endpoint = %row.delivery.endpoint,
                        %error,
                        "federation outbox delivery suppressed by egress policy"
                    );
                    crate::metrics::record_federation_retry_state("policy_suppressed");
                    // A policy denial never opened a socket, so it MUST NOT
                    // consume the transport retry budget.
                    let now = now_unix_secs();
                    let response_excerpt = excerpt(&format!("egress_policy_denied: {error}"));
                    let command = if row.delivery.realm_fanout.is_some() {
                        self.transport_retry(
                            &row,
                            &lease_token,
                            row.attempts.saturating_add(1),
                            None,
                            error_code::EGRESS_POLICY_DENIED,
                            response_excerpt,
                            None,
                            now,
                        )
                    } else {
                        RecordFederationAttemptCommand {
                            id: row.delivery.id.clone(),
                            lease_token,
                            attempts: row.attempts,
                            semantic_attempts: row.semantic_attempts,
                            last_http_status: None,
                            last_error_code: Some(error_code::EGRESS_POLICY_DENIED.to_owned()),
                            last_response_excerpt: Some(response_excerpt),
                            observed_at: now,
                            outcome: FederationDeliveryOutcome::PolicySuppressed {
                                policy_version: crate::security::egress_policy_version(
                                    self.state.config().development_mode,
                                ),
                            },
                        }
                    };
                    self.commit(command).await;
                    return;
                }
            };

        // Exact command replay reads the destination's durable ledger first;
        // no query-before-retry round trip or replacement request identity.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        // The private operations rail uses its own federation signature
        // transcript, which does not cover Idempotency-Key. Outbox persistence
        // still deduplicates the delivery by this key; only the HTTP header is
        // omitted for that wire profile.
        if row.delivery.endpoint != "/_coland/peer/federation/operations"
            && let Ok(value) = reqwest::header::HeaderValue::from_str(&row.delivery.idempotency_key)
        {
            headers.insert("idempotency-key", value);
        }
        let digest = content_digest_header_value(&body_bytes);
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&digest) {
            headers.insert("content-digest", value);
        }
        insert_header_if_valid(&mut headers, "source-service-id", self.state.service_id());
        insert_header_if_valid(
            &mut headers,
            "destination-service-id",
            row.delivery.peer_id.as_str(),
        );
        insert_header_if_valid(
            &mut headers,
            "source-trust-domain",
            self.state.config().trust_domain.as_str(),
        );
        insert_header_if_valid(
            &mut headers,
            "destination-trust-domain",
            &peer_target.trust_domain,
        );
        // A transport retry keeps the body and the key but always re-signs:
        // the signature window is short-lived and the old one has expired.
        let headers = rfc9421_sign(&self.state, headers, "POST", &url);

        let response = client
            .post(parsed_url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await;

        let attempts = row.attempts.saturating_add(1);
        let now = now_unix_secs();
        let command = match response {
            Ok(resp) => {
                let status = resp.status().as_u16() as i32;
                let response_headers = resp.headers().clone();
                let body_text = resp.text().await.unwrap_or_default();
                let account_status_resubmission = if (200..300).contains(&status) {
                    self.account_status_resubmission(
                        &row,
                        &body_text,
                        row.semantic_attempts.saturating_add(1),
                    )
                    .await
                } else {
                    Ok(None)
                };
                if (200..300).contains(&status)
                    && let Err(error) = self.verify_erasure_ack(&row, &body_text).await
                {
                    self.transport_retry(
                        &row,
                        &lease_token,
                        attempts,
                        Some(status),
                        error_code::TRANSPORT_ERROR,
                        excerpt(&format!("erasure_acknowledgement_invalid: {error}")),
                        None,
                        now,
                    )
                } else if (200..300).contains(&status)
                    && let Err(error) = self.capture_contact_outcome(&row, &body_text).await
                {
                    self.transport_retry(
                        &row,
                        &lease_token,
                        attempts,
                        Some(status),
                        error_code::TRANSPORT_ERROR,
                        excerpt(&format!("contact_receipt_persistence: {error}")),
                        None,
                        now,
                    )
                } else if (200..300).contains(&status)
                    && let Err(error) = self
                        .capture_keypackage_claim_outcome(&row, &body_text)
                        .await
                {
                    tracing::warn!(
                        worker = "federation_outbox",
                        outbox_id = %row.delivery.id,
                        peer_id = %row.delivery.peer_id,
                        %error,
                        "relayed KeyPackage claim outcome could not be stored; retrying"
                    );
                    self.transport_retry(
                        &row,
                        &lease_token,
                        attempts,
                        Some(status),
                        error_code::TRANSPORT_ERROR,
                        excerpt(&format!("keypackage_claim_outcome_persistence: {error}")),
                        None,
                        now,
                    )
                } else if (200..300).contains(&status)
                    && let Err(error) = self.capture_account_status_ack(&row, &body_text, now).await
                {
                    self.transport_retry(
                        &row,
                        &lease_token,
                        attempts,
                        Some(status),
                        error_code::TRANSPORT_ERROR,
                        excerpt(&format!("account_status_ack_persistence: {error}")),
                        None,
                        now,
                    )
                } else if let Err(error) = &account_status_resubmission {
                    self.transport_retry(
                        &row,
                        &lease_token,
                        attempts,
                        Some(status),
                        error_code::TRANSPORT_ERROR,
                        excerpt(&format!("account_status_lane_recovery: {error}")),
                        None,
                        now,
                    )
                } else {
                    self.classify_response(
                        &row,
                        &lease_token,
                        attempts,
                        status,
                        &response_headers,
                        &body_text,
                        now,
                        account_status_resubmission
                            .expect("account-status recovery error was handled above"),
                    )
                }
            }
            Err(error) => {
                // No response at all — transport retry: same body, same key.
                self.transport_retry(
                    &row,
                    &lease_token,
                    attempts,
                    None,
                    error_code::TRANSPORT_ERROR,
                    excerpt(&format!("network_error: {error}")),
                    None,
                    now,
                )
            }
        };
        self.commit(command).await;
    }

    async fn verify_erasure_ack(
        &self,
        row: &PendingFederationDelivery,
        response: &str,
    ) -> Result<(), String> {
        if row.delivery.endpoint != ERASURE_RECEIPT_ENDPOINT {
            return Ok(());
        }
        let body: arkret_models_collaboration::governance::erasure::ErasureReceiptSubmitRequestBody =
            serde_json::from_str(&row.delivery.payload_json).map_err(|error| error.to_string())?;
        super::erasure_receipts::verify_acceptance(
            &self.state,
            &body.package,
            &row.delivery.peer_id,
            response,
        )
        .await?;
        Ok(())
    }

    async fn capture_contact_outcome(
        &self,
        row: &PendingFederationDelivery,
        response_body: &str,
    ) -> Result<(), String> {
        if row.delivery.endpoint != "/_arkret/peer/contacts" {
            return Ok(());
        }
        let request: arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody =
            serde_json::from_str(&row.delivery.payload_json)
                .map_err(|error| format!("outbound Contact carrier decode failed: {error}"))?;
        let outcome: arkret_models_collaboration::contact_operations::PeerContactSubmitResponseBody =
            serde_json::from_str(response_body)
                .map_err(|error| format!("Contact carrier outcome decode failed: {error}"))?;
        outcome
            .validate()
            .map_err(|error| format!("invalid Contact carrier outcome: {error}"))?;
        crate::routing::identity::contact_federation::cache_contact_outcome_assertion_history(
            &self.state,
            &outcome,
        )
        .await
        .map_err(|error| error.to_string())?;
        match (&request,&outcome) {
            (
                arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::Request { .. }
                    | arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::Reject { .. }
                    | arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::Response { .. }
                    | arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::ScopeUpdate { .. }
                    | arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::Tombstone { .. },
                arkret_models_collaboration::contact_operations::PeerContactSubmitResponseBody::Event(
                    event_outcome,
                ),
            ) => crate::routing::identity::contact_federation::accept_outbound_contact_event_outcome(
                &self.state,
                &request,
                event_outcome,
                row.delivery.peer_id.as_str(),
            )
            .await
            .map_err(|error| error.to_string()),
            (
                arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::GlareFinalize { .. }
                    | arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::CurrentRefresh { .. },
                arkret_models_collaboration::contact_operations::PeerContactSubmitResponseBody::ControlDeferred(deferred),
            ) => crate::routing::identity::contact_federation::reenqueue_deferred_contact_control(
                &self.state,
                &request,
                deferred,
                row.delivery.peer_id.as_str(),
            )
            .await
            .map_err(|error| error.to_string()),
            (
                arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::GlareFinalize { .. }
                    | arkret_models_collaboration::contact_operations::PeerContactSubmitRequestBody::CurrentRefresh { .. },
                _,
            ) => crate::routing::identity::contact_federation::accept_outbound_contact_control_outcome(
                &self.state,
                &request,
                &outcome,
                row.delivery.peer_id.as_str(),
            )
            .await
            .map_err(|error| error.to_string()),
            _ => Ok(()),
        }
    }

    async fn capture_account_status_ack(
        &self,
        row: &PendingFederationDelivery,
        response_body: &str,
        acknowledged_at: i64,
    ) -> Result<(), String> {
        use arkret_models_collaboration::account_lifecycle::{
            AccountStatusPublicationRequestBody, AccountStatusPublicationResponseBody,
            AccountStatusPublicationStatus,
        };

        if row.delivery.endpoint != "/_arkret/peer/account-status" {
            return Ok(());
        }
        let request: AccountStatusPublicationRequestBody =
            serde_json::from_str(&row.delivery.payload_json)
                .map_err(|error| format!("account-status request decode failed: {error}"))?;
        let outcome: AccountStatusPublicationResponseBody = serde_json::from_str(response_body)
            .map_err(|error| format!("account-status outcome decode failed: {error}"))?;
        outcome
            .validate_for_request(&request)
            .map_err(|error| format!("account-status outcome binding failed: {error}"))?;
        if !matches!(
            outcome.status,
            AccountStatusPublicationStatus::Accepted | AccountStatusPublicationStatus::Duplicate
        ) {
            return Ok(());
        }
        let record = request.publication.record();
        let acknowledged_at = chrono::DateTime::from_timestamp(acknowledged_at, 0)
            .ok_or_else(|| "account-status ack timestamp is out of range".to_owned())?;
        if let Some(transition) = self
            .state
            .persistence()
            .acknowledge_account_status_propagation_destination(
                &record.account_status_record_id,
                &row.delivery.peer_id,
                acknowledged_at,
            )
            .await
            .map_err(|error| error.to_string())?
        {
            crate::routing::identity::account::lifecycle::
                audit_account_status_propagation_transition(
                    &self.state,
                    &transition,
                    record.status
                        == arkret_models_collaboration::objects::account_status::AccountStatus::Deactivated,
                )
                .await;
        }
        Ok(())
    }

    async fn capture_keypackage_claim_outcome(
        &self,
        row: &PendingFederationDelivery,
        response_body: &str,
    ) -> Result<(), String> {
        if row.delivery.endpoint != "/_arkret/peer/keys/keypackages/claim" {
            return Ok(());
        }
        let outcome: arkret_models_crypto::PeerKeyPackagesClaimQueryResponseBody =
            serde_json::from_str(response_body).map_err(|error| error.to_string())?;
        outcome
            .validate_command_shape()
            .map_err(|error| error.to_string())?;
        if outcome.state == arkret_models_crypto::PeerKeyPackagesClaimQueryState::Pending {
            return Err("destination claim reservation is pending".to_owned());
        }
        crate::routing::mls::capture_relayed_keypackage_claim_query(
            &self.state,
            row.delivery.peer_id.as_str(),
            &row.delivery.payload_json,
            &outcome,
        )
        .await
    }

    async fn account_status_resubmission(
        &self,
        row: &PendingFederationDelivery,
        response_body: &str,
        semantic_attempts: i32,
    ) -> Result<Option<SemanticResubmission>, String> {
        use arkret_models_collaboration::account_lifecycle::{
            AccountStatusPublication, AccountStatusPublicationRequestBody,
            AccountStatusPublicationStatus, AccountStatusReceiptedPublication,
        };

        if row.delivery.endpoint != "/_arkret/peer/account-status" {
            return Ok(None);
        }
        let outcome: arkret_models_collaboration::account_lifecycle::AccountStatusPublicationResponseBody =
            serde_json::from_str(response_body)
                .map_err(|error| format!("account-status outcome decode failed: {error}"))?;
        let request: AccountStatusPublicationRequestBody =
            serde_json::from_str(&row.delivery.payload_json)
                .map_err(|error| format!("account-status request decode failed: {error}"))?;
        outcome
            .validate_for_request(&request)
            .map_err(|error| format!("account-status outcome binding failed: {error}"))?;
        let submitted = request.publication.record();
        if matches!(
            outcome.status,
            AccountStatusPublicationStatus::Accepted | AccountStatusPublicationStatus::Duplicate
        ) {
            let mut ancestor_id = row.supersedes_outbox_id.clone();
            let mut desired: Option<(u64, String)> = None;
            for _ in 0..128 {
                let Some(id) = ancestor_id else {
                    break;
                };
                let Some(ancestor) = self
                    .state
                    .federation()
                    .delivery(&id)
                    .await
                    .map_err(|error| error.to_string())?
                else {
                    break;
                };
                if ancestor.delivery.endpoint != row.delivery.endpoint
                    || ancestor.delivery.peer_id != row.delivery.peer_id
                    || ancestor.delivery.coalescing_key != row.delivery.coalescing_key
                {
                    break;
                }
                let ancestor_request: AccountStatusPublicationRequestBody =
                    serde_json::from_str(&ancestor.delivery.payload_json).map_err(|error| {
                        format!("account-status ancestor request decode failed: {error}")
                    })?;
                let ancestor_seq = ancestor_request.publication.record().status_sequence;
                if ancestor_seq > submitted.status_sequence
                    && desired
                        .as_ref()
                        .is_none_or(|(desired_seq, _)| ancestor_seq > *desired_seq)
                {
                    desired = Some((ancestor_seq, ancestor.delivery.payload_json.clone()));
                }
                ancestor_id = ancestor.supersedes_outbox_id;
            }
            let Some((desired_seq, desired_payload_json)) = desired else {
                return Ok(None);
            };
            let next_seq = submitted.status_sequence.saturating_add(1);
            let payload_json = if next_seq == desired_seq {
                desired_payload_json
            } else {
                let next_record = self
                    .state
                    .persistence()
                    .resolve_account_status_records(
                        submitted.account_authority_id.as_str(),
                        &submitted.account_id,
                        next_seq,
                        1,
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        "local account-status replica omits the next sequential record".to_owned()
                    })?;
                let next_receipt = self
                    .state
                    .persistence()
                    .account_status_receipt(
                        submitted.account_authority_id.as_str(),
                        &submitted.account_id,
                        next_seq,
                    )
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| {
                        "local account-status next record omits durable receipt".to_owned()
                    })?;
                arkret_canonical::canonical_json_string(&AccountStatusPublicationRequestBody {
                    publication: AccountStatusPublication::Receipted(
                        AccountStatusReceiptedPublication {
                            record: next_record,
                            account_status_receipts: vec![next_receipt],
                        },
                    ),
                })
                .map_err(|error| error.to_string())?
            };
            return Ok(Some(SemanticResubmission {
                idempotency_key: semantic_resubmission_key(
                    &row.delivery.idempotency_key,
                    semantic_attempts,
                    &payload_json,
                ),
                payload_json,
                coalescing_position: Some(i64::try_from(next_seq).map_err(|_| {
                    "account-status desired sequence exceeds outbox lane range".to_owned()
                })?),
            }));
        }
        if outcome.status != AccountStatusPublicationStatus::DependencyMissing {
            return Ok(None);
        }
        let required = outcome.required_status_sequence.ok_or_else(|| {
            "dependency_missing outcome omits required_status_sequence".to_owned()
        })?;
        if required >= submitted.status_sequence {
            return Err(
                "account-status required_status_sequence does not precede submitted record"
                    .to_owned(),
            );
        }
        let predecessor = self
            .state
            .persistence()
            .resolve_account_status_records(
                submitted.account_authority_id.as_str(),
                &submitted.account_id,
                required,
                1,
            )
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
            .ok_or_else(|| "local account-status replica omits required predecessor".to_owned())?;
        let receipt = self
            .state
            .persistence()
            .account_status_receipt(
                submitted.account_authority_id.as_str(),
                &submitted.account_id,
                required,
            )
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "local account-status predecessor omits durable receipt".to_owned())?;
        let body = AccountStatusPublicationRequestBody {
            publication: AccountStatusPublication::Receipted(AccountStatusReceiptedPublication {
                record: predecessor.clone(),
                account_status_receipts: vec![receipt],
            }),
        };
        let payload =
            arkret_canonical::canonical_json_string(&body).map_err(|error| error.to_string())?;
        Ok(Some(SemanticResubmission {
            idempotency_key: semantic_resubmission_key(
                &row.delivery.idempotency_key,
                semantic_attempts,
                &payload,
            ),
            payload_json: payload,
            coalescing_position: Some(i64::try_from(required).map_err(|_| {
                "account-status required sequence exceeds outbox lane range".to_owned()
            })?),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_response(
        &self,
        row: &PendingFederationDelivery,
        lease_token: &str,
        attempts: i32,
        status: i32,
        headers: &reqwest::header::HeaderMap,
        body_text: &str,
        now: i64,
        account_status_resubmission: Option<SemanticResubmission>,
    ) -> RecordFederationAttemptCommand {
        let response_excerpt = excerpt(body_text);
        let transport_succeeded = (200..300).contains(&status);
        // The typed outcome only classifies a *successful* transport. On a
        // non-2xx the status is the verdict: an error envelope that happens not
        // to look like an `EventsSubmitOutcome` must not be mistaken for an
        // application-level rejection and skip the retry classification below.
        let application_failure = transport_succeeded
            .then(|| {
                peer_event_application_failure(
                    &row.delivery.endpoint,
                    &row.delivery.payload_json,
                    body_text,
                )
            })
            .flatten();
        if transport_succeeded && application_failure.is_none() {
            crate::metrics::record_federation_retry_state("delivered");
            tracing::info!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_id = %row.delivery.peer_id,
                endpoint = %row.delivery.endpoint,
                status,
                "federation outbox delivery succeeded"
            );
            return RecordFederationAttemptCommand {
                id: row.delivery.id.clone(),
                lease_token: lease_token.to_owned(),
                attempts,
                semantic_attempts: row.semantic_attempts,
                last_http_status: Some(status),
                last_error_code: None,
                last_response_excerpt: Some(response_excerpt),
                observed_at: now,
                outcome: FederationDeliveryOutcome::Delivered,
            };
        }

        if row.delivery.realm_fanout.is_some() || row.delivery.endpoint == ERASURE_RECEIPT_ENDPOINT
        {
            return self.transport_retry(
                row,
                lease_token,
                attempts,
                Some(status),
                application_failure.unwrap_or(error_code::RETRYABLE_HTTP_STATUS),
                response_excerpt,
                peer_requested_retry_at(headers, body_text, now),
                now,
            );
        }

        // A response was received. Anything that needs re-evaluation is a
        // semantic resubmission with a brand-new key, never a replay of this
        // transport identity (`federation.md` §8.5).
        let semantic_attempts = row.semantic_attempts.saturating_add(1);
        let resubmission = if transport_succeeded {
            account_status_resubmission
                .or_else(|| {
                    peer_event_partial_retry(
                        &row.delivery.endpoint,
                        &row.delivery.payload_json,
                        body_text,
                        &row.delivery.idempotency_key,
                        semantic_attempts,
                    )
                })
                .or_else(|| {
                    (application_failure == Some(error_code::DEPENDENCY_MISSING)).then(|| {
                        dependency_resubmission(
                            &row.delivery.idempotency_key,
                            semantic_attempts,
                            &row.delivery.payload_json,
                        )
                    })
                })
        } else if causal_dependencies_pending(body_text)
            && !is_queued_authority_forward(&row.delivery.endpoint, &row.delivery.payload_json)
        {
            Some(dependency_resubmission(
                &row.delivery.idempotency_key,
                semantic_attempts,
                &row.delivery.payload_json,
            ))
        } else {
            None
        };

        if let Some(resubmission) = resubmission {
            let reason = application_failure.unwrap_or(error_code::DEPENDENCY_MISSING);
            let semantic_limit = if row.delivery.endpoint == "/_arkret/peer/account-status" {
                128
            } else {
                MAX_SEMANTIC_ATTEMPTS
            };
            if semantic_attempts > semantic_limit {
                // `federation.md` §4.1: bounded resubmission. Stop the loop and
                // hand the case to an operator instead of polling forever.
                return self.dead_letter(
                    row,
                    lease_token,
                    attempts,
                    Some(status),
                    error_code::SEMANTIC_RETRY_BUDGET_EXHAUSTED,
                    response_excerpt,
                    now,
                );
            }
            let next_attempt_at = peer_requested_retry_at(headers, body_text, now)
                .unwrap_or(0)
                .max(semantic_backoff_unix_secs(semantic_attempts, now));
            crate::metrics::record_federation_retry_state("semantic_resubmission");
            crate::metrics::record_federation_retry_delay(next_attempt_at - now);
            tracing::info!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_id = %row.delivery.peer_id,
                endpoint = %row.delivery.endpoint,
                status,
                reason,
                semantic_attempts,
                "federation outbox attempt superseded by a resubmission with a fresh key"
            );
            return RecordFederationAttemptCommand {
                id: row.delivery.id.clone(),
                lease_token: lease_token.to_owned(),
                attempts,
                semantic_attempts,
                last_http_status: Some(status),
                last_error_code: Some(reason.to_owned()),
                last_response_excerpt: Some(response_excerpt),
                observed_at: now,
                outcome: FederationDeliveryOutcome::Superseded {
                    delivery: Box::new(FederationDeliveryRecord {
                        id: Uuid::new_v4().to_string(),
                        peer_id: row.delivery.peer_id.clone(),
                        peer_url: row.delivery.peer_url.clone(),
                        endpoint: row.delivery.endpoint.clone(),
                        idempotency_key: resubmission.idempotency_key,
                        payload_json: resubmission.payload_json,
                        coalescing_key: row.delivery.coalescing_key.clone(),
                        coalescing_position: resubmission
                            .coalescing_position
                            .or(row.delivery.coalescing_position),
                        realm_fanout: row.delivery.realm_fanout.clone(),
                        created_at: now,
                    }),
                    next_attempt_at,
                },
            };
        }

        if let Some(reason) = application_failure {
            // 2xx transport, non-success application outcome that no diff can
            // converge — terminal.
            return self.dead_letter(
                row,
                lease_token,
                attempts,
                Some(status),
                reason,
                response_excerpt,
                now,
            );
        }

        if is_retryable_status(status) {
            return self.transport_retry(
                row,
                lease_token,
                attempts,
                Some(status),
                error_code::RETRYABLE_HTTP_STATUS,
                response_excerpt,
                peer_requested_retry_at(headers, body_text, now),
                now,
            );
        }

        tracing::warn!(
            target = "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.delivery.id,
            peer_id = %row.delivery.peer_id,
            endpoint = %row.delivery.endpoint,
            status,
            attempts,
            response = %response_excerpt,
            "federation outbox permanent failure (no retry, dead-lettered)"
        );
        self.dead_letter(
            row,
            lease_token,
            attempts,
            Some(status),
            error_code::TERMINAL_HTTP_STATUS,
            response_excerpt,
            now,
        )
    }

    /// Same transport identity, later. The peer's `Retry-After` is a floor:
    /// exponential backoff may push the retry later, never earlier.
    #[allow(clippy::too_many_arguments)]
    fn transport_retry(
        &self,
        row: &PendingFederationDelivery,
        lease_token: &str,
        attempts: i32,
        status: Option<i32>,
        failure_code: &str,
        response_excerpt: String,
        peer_retry_at: Option<i64>,
        now: i64,
    ) -> RecordFederationAttemptCommand {
        if row.delivery.realm_fanout.is_none()
            && row.delivery.endpoint != ERASURE_RECEIPT_ENDPOINT
            && attempts >= MAX_ATTEMPTS
        {
            return self.dead_letter(
                row,
                lease_token,
                attempts,
                status,
                error_code::RETRY_BUDGET_EXHAUSTED,
                response_excerpt,
                now,
            );
        }
        if row.delivery.realm_fanout.is_some()
            && attempts >= MAX_ATTEMPTS
            && attempts % MAX_ATTEMPTS == 0
        {
            tracing::warn!(
                target = "federation_outbox",
                worker = "federation_outbox",
                outbox_id = %row.delivery.id,
                peer_id = %row.delivery.peer_id,
                endpoint = %row.delivery.endpoint,
                attempts,
                "Realm fanout remains pending past the operator alert threshold"
            );
        }
        let mut next_attempt_at =
            transport_backoff_unix_secs(attempts, now).max(peer_retry_at.unwrap_or(0));
        if row.delivery.endpoint == ERASURE_RECEIPT_ENDPOINT {
            next_attempt_at = next_attempt_at.min(
                row.delivery
                    .created_at
                    .saturating_add(ERASURE_PROPAGATION_WINDOW_SECS),
            );
        }
        crate::metrics::record_federation_retry_state("retry_scheduled");
        crate::metrics::record_federation_retry_delay(next_attempt_at - now);
        RecordFederationAttemptCommand {
            id: row.delivery.id.clone(),
            lease_token: lease_token.to_owned(),
            attempts,
            semantic_attempts: row.semantic_attempts,
            last_http_status: status,
            last_error_code: Some(failure_code.to_owned()),
            last_response_excerpt: Some(response_excerpt),
            observed_at: now,
            outcome: FederationDeliveryOutcome::Retry { next_attempt_at },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dead_letter(
        &self,
        row: &PendingFederationDelivery,
        lease_token: &str,
        attempts: i32,
        status: Option<i32>,
        reason: &str,
        response_excerpt: String,
        now: i64,
    ) -> RecordFederationAttemptCommand {
        // P5 (5.4) — bump the DLQ counter at the *decision* boundary (we have
        // given up on this row) rather than the persistence outcome, so an
        // alert fires even if the whole transaction later fails.
        crate::metrics::record_federation_outbox_dead_letter(reason);
        crate::metrics::record_federation_retry_state(reason);
        tracing::warn!(
            target = "federation_outbox",
            worker = "federation_outbox",
            outbox_id = %row.delivery.id,
            peer_id = %row.delivery.peer_id,
            endpoint = %row.delivery.endpoint,
            ?status,
            attempts,
            reason,
            "federation outbox row dead-lettered"
        );
        RecordFederationAttemptCommand {
            id: row.delivery.id.clone(),
            lease_token: lease_token.to_owned(),
            attempts,
            semantic_attempts: row.semantic_attempts,
            last_http_status: status,
            last_error_code: Some(reason.to_owned()),
            last_response_excerpt: Some(response_excerpt.clone()),
            observed_at: now,
            // Terminal state and failure ledger travel in one transaction, so
            // "stopped delivering" and "has evidence" can never disagree.
            outcome: FederationDeliveryOutcome::DeadLettered(Box::new(FederationDeadLetter {
                id: Uuid::new_v4().to_string(),
                outbox_id: row.delivery.id.clone(),
                peer_id: row.delivery.peer_id.clone(),
                endpoint: row.delivery.endpoint.clone(),
                idempotency_key: row.delivery.idempotency_key.clone(),
                last_http_status: status,
                attempts,
                response_excerpt: Some(response_excerpt),
                reason: reason.to_owned(),
                failed_at: now,
                requeued_outbox_id: None,
                requeued_by: None,
                requeue_reason: None,
                requeue_request_digest: None,
                requeued_at: None,
            })),
        }
    }

    async fn commit(&self, command: RecordFederationAttemptCommand) {
        let outbox_id = command.id.clone();
        match self
            .state
            .federation()
            .record_delivery_attempt(command)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                crate::metrics::record_federation_outbox_lease_takeover();
                tracing::warn!(
                    worker = "federation_outbox",
                    outbox_id = %outbox_id,
                    target = "federation_outbox",
                    "federation outbox lease moved on mid-delivery; discarding this worker's result"
                );
            }
            Err(error) => tracing::warn!(
                %error,
                worker = "federation_outbox",
                outbox_id = %outbox_id,
                target = "federation_outbox",
                "failed to persist federation outbox transition after delivery attempt"
            ),
        }
    }
}

/// Recheck, at the current accepted cut, that a Realm fanout intent is still
/// owed to its frozen target (`federation.md` §4.1.1): one frozen basis must
/// still hold as a whole. A row that is not a Realm fanout is always owed.
async fn realm_fanout_still_owed(
    state: &AppState,
    row: &PendingFederationDelivery,
) -> Result<bool, String> {
    let Some(binding) = row.delivery.realm_fanout.as_ref() else {
        return Ok(true);
    };
    let request = serde_json::from_str::<
        arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody,
    >(&row.delivery.payload_json)
    .map_err(|error| format!("Realm fanout body is not a peer submission: {error}"))?;
    use arkret_models_collaboration::authority_commit::{
        PeerAuthoritySubmitRequestBody, PeerRegisteredAtomicUnit,
    };
    let items = match &request {
        PeerAuthoritySubmitRequestBody::CommittedReplication(request) => {
            request.replications.as_slice()
        }
        PeerAuthoritySubmitRequestBody::RegisteredAtomicUnit(request) => match &request.unit {
            PeerRegisteredAtomicUnit::AuditPairedEvent(pair) => pair.committed_events.as_slice(),
            _ => return Err("Realm fanout has an unregistered atomic body".to_owned()),
        },
        _ => return Err("Realm fanout body has no source-committed events".to_owned()),
    };
    let now = chrono::Utc::now();
    for item in items {
        if !state
            .authority_commits()
            .realm_fanout_still_owed(
                &item.event_submission.event,
                &state.service_core_id(),
                &row.delivery.peer_id,
                &binding.authority_witnesses,
                now,
            )
            .await
            .map_err(|error| error.to_string())?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Spawn the dispatcher if `config.federation_outbound_enabled` is true.
/// Returns `None` (no-op) when disabled — mirrors the compactor's spawn
/// contract.
pub fn spawn(state: AppState) -> Option<Arc<tokio::task::JoinHandle<()>>> {
    if !state.config().federation_outbound_enabled {
        return None;
    }
    Some(FederationDispatcher::new(state).spawn())
}

/// Whether a non-2xx status code should be retried (per `federation.md`
/// §8 + standard HTTP semantics).
fn is_retryable_status(status: i32) -> bool {
    matches!(status, 408 | 429) || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_backoff_doubles_caps_at_one_hour_and_carries_jitter() {
        let base: i64 = 1_000_000;
        for (attempts, deterministic) in [(0_i32, 5_i64), (1, 10), (9, 2_560), (20, 3_600)] {
            let mut observed = std::collections::BTreeSet::new();
            for _ in 0..64 {
                let delay = transport_backoff_unix_secs(attempts, base) - base;
                // The deterministic floor is never undercut, and the jitter is
                // bounded so backoff stays predictable for capacity planning.
                assert!(delay >= deterministic, "attempts={attempts} delay={delay}");
                assert!(
                    delay <= deterministic + (deterministic as f64 * BACKOFF_JITTER_RATIO) as i64,
                    "attempts={attempts} delay={delay}"
                );
                observed.insert(delay);
            }
            // Anything above the 1s floor must actually spread, or a whole
            // fleet retries in lockstep the moment a peer recovers.
            assert!(observed.len() > 1, "attempts={attempts} produced no jitter");
        }
    }

    #[test]
    fn semantic_backoff_starts_at_one_second_and_bounds_above_a_minute() {
        let base: i64 = 1_000_000;
        // `federation.md` §4.1 — start >= 1s, upper bound >= 60s, with jitter.
        assert!(semantic_backoff_unix_secs(1, base) - base >= 1);
        assert!(semantic_backoff_unix_secs(20, base) - base >= 60);
        assert!(
            semantic_backoff_unix_secs(20, base) - base
                <= SEMANTIC_BACKOFF_CAP_SECS as i64
                    + (SEMANTIC_BACKOFF_CAP_SECS as f64 * BACKOFF_JITTER_RATIO) as i64
        );
    }

    #[test]
    fn peer_retry_after_header_and_body_are_honoured() {
        // A present-day `now`, so the fixed HTTP-date below is genuinely in the
        // past and exercises the clamp rather than the ordering.
        let now = 1_800_000_000;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("120"),
        );
        assert_eq!(peer_requested_retry_at(&headers, "", now), Some(now + 120));

        let mut dated = reqwest::header::HeaderMap::new();
        dated.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        // Past dates clamp to `now` — a peer can delay us, never rush us.
        assert_eq!(peer_requested_retry_at(&dated, "", now), Some(now));

        // Header absent: the canonical `retry_after_ms` in the error envelope.
        assert_eq!(
            peer_requested_retry_at(
                &reqwest::header::HeaderMap::new(),
                r#"{"error":{"code":"rate_limited","retry_after_ms":4500}}"#,
                now,
            ),
            Some(now + 4)
        );
        assert_eq!(
            peer_requested_retry_at(&reqwest::header::HeaderMap::new(), "not json", now),
            None
        );
    }

    #[test]
    fn semantic_resubmission_keys_are_deterministic_and_never_reuse_the_old_key() {
        let first = semantic_resubmission_key("ak:outbox:event:sha256:aa", 1, "{}");
        let again = semantic_resubmission_key("ak:outbox:event:sha256:aa", 1, "{}");
        let next_round = semantic_resubmission_key("ak:outbox:event:sha256:aa", 2, "{}");
        // Deterministic: a crash between "decided to resubmit" and "wrote the
        // successor" recomputes the same key, so the unique index collapses it.
        assert_eq!(first, again);
        // But each resubmission round is a distinct transport identity, even
        // when the body is byte-identical (whole-batch dependency rejection).
        assert_ne!(first, next_round);
        assert_ne!(first, "ak:outbox:event:sha256:aa");
        assert!(first.starts_with("ak:outbox:resubmit:sha256:"));
    }

    #[test]
    fn whole_batch_dependency_rejection_resubmits_the_same_body_under_a_new_key() {
        let body = r#"{"events":[]}"#;
        let resubmission = dependency_resubmission("ak:outbox:event:sha256:aa", 1, body);
        assert_eq!(resubmission.payload_json, body);
        assert_ne!(resubmission.idempotency_key, "ak:outbox:event:sha256:aa");
    }

    #[test]
    fn retryable_status_classification_matches_spec() {
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(404));
    }

    #[test]
    fn causal_dependency_responses_are_classified_for_prompt_retry() {
        let problem = |code: &str| {
            serde_json::to_string(&arkret_wire::problem_details::Problem::new(code, 409, "x"))
                .unwrap()
        };
        assert!(causal_dependencies_pending(&problem("dependency_missing")));
        assert!(causal_dependencies_pending(&problem(
            "direct_binding_dependencies_pending"
        )));
        assert!(!causal_dependencies_pending(&problem(
            "service_unavailable"
        )));
        assert!(!causal_dependencies_pending(
            r#"{"ok":false,"error":{"code":"dependency_missing"}}"#
        ));
        assert!(!causal_dependencies_pending("not json"));
    }

    #[test]
    fn content_digest_matches_rfc_9530_shape() {
        let body = br#"{"hello":"world"}"#;
        let header = content_digest_header_value(body);
        assert!(header.starts_with("sha-256=:"));
        assert!(header.ends_with(':'));
    }

    #[test]
    fn peer_event_response_requires_current_typed_carrier() {
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", "{}", "{}"),
            Some("invalid_peer_event_request")
        );
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/contacts", "{}", "{}"),
            None
        );
    }

    #[test]
    fn authority_forward_is_never_delivered_or_resubmitted_from_the_outbox() {
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x44; 32],
        ));
        let mut event = crate::test_event::raw_event_at(
            arkret_wire::EventKind::RealmProfile.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            arkret_wire::DidCoreId::new("ak:did_core:web:queued-producer.example").unwrap(),
            0,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            serde_json::json!({"name": "queued"}),
            chrono::Utc::now(),
        )
        .unwrap();
        // This classifier does not admit a producer; use a valid non-Agent
        // forward shape without fabricating Agent authority evidence.
        event.actor_id = arkret_wire::ActorId::service(
            arkret_wire::DidCoreId::new("ak:did_core:web:queued-producer.example").unwrap(),
        );
        crate::test_event::attach_structural_only_producer_proof(
            &mut event,
            arkret_wire::DidUrl::new("did:web:queued-producer.example#key-1").unwrap(),
        );
        let body = serde_json::to_string(
            &arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
                arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody::new(
                    arkret_wire::EventAdmissionSubmission::new(event),
                    None,
                    None,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", &body, "{}"),
            Some(AUTHORITY_FORWARD_NOT_QUEUED)
        );
        assert!(is_queued_authority_forward("/_arkret/peer/events", &body));
        assert!(!is_queued_authority_forward("/_arkret/peer/events", "{}"));
    }

    #[test]
    fn replication_retry_rejects_untyped_legacy_batch() {
        assert!(
            peer_event_partial_retry(
                "/_arkret/peer/events",
                r#"{"events":[]}"#,
                r#"{"status":"partial"}"#,
                "old-key",
                1,
            )
            .is_none()
        );
    }

    fn replication_item() -> serde_json::Value {
        let fixture_path = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("arkret-spec artifacts checkout")
            .join("fixtures/approval-signature-kat-fixture.json");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
        let mut submission = fixture["event_id_invariance"]["submission_with_evidence"].clone();
        submission
            .as_object_mut()
            .unwrap()
            .remove("approval_signatures");
        let event = &submission["event"];
        let source_commit = serde_json::json!({
            "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "realm_id": event["realm_id"],
            "stream_ref": event["scope_ref"],
            "stream_position": 0,
            "previous_commit_ref": null,
            "event_ref": event["event_id"],
            "governance_generation": "0",
            "authority_ref": event["event_id"],
            "committed_at": "2026-09-20T00:00:00.000Z",
            "signature": {
                "context": "ak.realm_commit_signature.v1",
                "signature_algorithm": "Ed25519",
                "verification_method": "did:web:station.example#authority",
                "signed_digest": format!("sha256:{}", "4".repeat(64)),
                "created_at": "2026-09-20T00:00:00.000Z",
                "signature": "A".repeat(86)
            }
        });
        serde_json::json!({"event_submission": submission, "source_commit": source_commit})
    }

    #[test]
    fn replicated_event_rejects_first_admission_approval_votes() {
        let fixture_path = arkret_schema_conformance::default_spec_artifacts_dir()
            .expect("arkret-spec artifacts checkout")
            .join("fixtures/approval-signature-kat-fixture.json");
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
        let mut item = replication_item();
        item["event_submission"]["approval_signatures"] =
            fixture["event_id_invariance"]["submission_with_evidence"]["approval_signatures"]
                .clone();
        let request: arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequestBody =
            serde_json::from_value(serde_json::json!({
                "branch": "committed_replication", "replications": [item]
            }))
            .unwrap();
        let error = request.validate().unwrap_err();
        assert!(
            error.to_string().contains("schema_violation"),
            "the peer dispatch must reject the entire body before a replica write: {error}"
        );
    }

    #[test]
    fn replication_retry_resends_only_same_order_dependency_missing_rows() {
        let item = replication_item();
        let mut second = item.clone();
        second["source_commit"]["committed_at"] = serde_json::json!("2026-09-20T00:00:01.000Z");
        let request = serde_json::json!({
            "branch": "committed_replication",
            "replications": [item, second.clone()]
        })
        .to_string();
        let partial = serde_json::json!({
            "branch": "committed_replication",
            "replication_outcomes": [
                {"status": "stored"},
                {"status": "rejected", "reason_code": "dependency_missing"}
            ]
        })
        .to_string();
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", &request, &partial),
            Some(error_code::DEPENDENCY_MISSING)
        );
        let retry =
            peer_event_partial_retry("/_arkret/peer/events", &request, &partial, "old-key", 1)
                .expect("dependency-missing row is resubmitted");
        let resent: serde_json::Value = serde_json::from_str(&retry.payload_json).unwrap();
        assert_eq!(resent["branch"], "committed_replication");
        assert_eq!(resent["replications"], serde_json::json!([second]));
        assert_ne!(retry.idempotency_key, "old-key");

        let stored = serde_json::json!({
            "branch": "committed_replication",
            "replication_outcomes": [{"status": "stored"}, {"status": "duplicate"}]
        })
        .to_string();
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", &request, &stored),
            None
        );

        // A retired echo row (index / committed_ref) or a length mismatch is
        // not a valid outcome for this request and never drives a retry.
        let echoed = serde_json::json!({
            "branch": "committed_replication",
            "results": [
                {"status": "stored", "index": 0},
                {"status": "rejected", "index": 1, "reason_code": "dependency_missing"}
            ]
        })
        .to_string();
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", &request, &echoed),
            Some("invalid_peer_event_outcome")
        );
        assert!(
            peer_event_partial_retry("/_arkret/peer/events", &request, &echoed, "old-key", 1)
                .is_none()
        );
        let short = serde_json::json!({
            "branch": "committed_replication",
            "replication_outcomes": [{"status": "rejected", "reason_code": "dependency_missing"}]
        })
        .to_string();
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", &request, &short),
            Some("invalid_peer_event_outcome")
        );
        assert!(
            peer_event_partial_retry("/_arkret/peer/events", &request, &short, "old-key", 1)
                .is_none()
        );

        let legacy_request = serde_json::json!({
            "branch": "committed_replication",
            "processing": "per_item",
            "submissions": [{"committed_event": replication_item(), "recipient_witnesses": []}]
        })
        .to_string();
        assert_eq!(
            peer_event_application_failure("/_arkret/peer/events", &legacy_request, &partial),
            Some("invalid_peer_event_request")
        );
    }

    #[test]
    fn excerpt_truncates_at_one_kib_on_char_boundary() {
        let body = "a".repeat(2048);
        let trimmed = excerpt(&body);
        assert_eq!(trimmed.len(), RESPONSE_EXCERPT_BYTES);
    }
}
#[test]
fn canonical_http_request_selects_exact_operation_version() {
    assert_eq!(
        operation_for_canonical_http_request(
            "POST",
            "https://peer.example/_arkret/peer/events?ignored=yes",
        )
        .map(arkret_wire::ServiceOperationId::as_str),
        Some(arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1)
    );
    assert_eq!(
        operation_for_canonical_http_request(
            "GET",
            "https://peer.example/_private/not-a-canonical-route",
        ),
        None
    );
}
