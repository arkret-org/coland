//! Describe handlers (the `*_describe` family).
//!
//! These are the introspection / capability-probe surfaces every Arkret
//! client uses to discover what the server actually implements. None of them
//! mutate state; most are static JSON literals + a small amount of state
//! injection (config, registry version metadata).
//!
//! Surfaces:
//! - `GET /health` — liveness + database/events health
//! - `GET /readyz` — readiness gate for deploy orchestrators
//! - `GET /_arkret/describe`
//! - `GET /_coland/describe`
//! - `GET /_coland/gate/auth/bridge/describe`
//! - `GET /_coland/self/integration/describe`
//!
//! `sync_describe` is still in `mod.rs` pending sync-module extraction.

use arkret_identity::service_identity::DidCoreIdentityState;
use arkret_models_discovery::ServiceDescribe;
use salvo::http::StatusCode;
use salvo::oapi::extract::QueryParam;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::state::AppState;
use crate::wire::{
    AuthBridgeAuthDescriptor, AuthBridgeDescription, AuthBridgeExamples, AuthBridgePushDescriptor,
    ColandServiceDescription, HealthReport, IntegrationDependencyDescriptor, IntegrationManifest,
    IntegrationSurfaceDescriptor, UnsupportedProfileDescriptor, describe,
};
use crate::{JsonResult, json_ok};

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct ReadyzOutcome {
    ok: bool,
    service: String,
    storage: String,
    reason: Option<String>,
    checks: ReadyzChecks,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct ReadyzChecks {
    database: ReadyzDatabaseCheck,
    migrations: ReadyzMigrationCheck,
    session_grant_introspection: ReadyzConfiguredCheck,
    external_webvh_provider: ReadyzExternalWebvhProviderCheck,
    pq_hybrid_tls: ReadyzConfiguredCheck,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct ReadyzDatabaseCheck {
    ok: bool,
    mode: String,
    migrations: String,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct ReadyzMigrationCheck {
    ok: bool,
    mode: String,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct ReadyzConfiguredCheck {
    ok: bool,
    configured: bool,
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
struct ReadyzExternalWebvhProviderCheck {
    ok: bool,
    configured: bool,
    active: bool,
}

pub(super) fn health_router() -> Router {
    Router::new()
        .push(Router::with_path("health").get(health))
        .push(Router::with_path("readyz").get(readyz))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        // `/_arkret/describe` — root meta position (no trust segment).
        .push(Router::with_path("describe").get(server_describe))
}

pub(super) fn local_router() -> Router {
    Router::new()
        .push(Router::with_path("describe").get(coland_describe))
        // coland-local integration describe → self-scoped.
        .push(Router::with_path("self/integration/describe").get(integration_describe))
}

#[endpoint(operation_id = "org.arkret.coland.system.health")]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.system.health"))]
async fn health(depot: &mut Depot, res: &mut Response) -> JsonResult<HealthReport> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let database_ok = database_ready(state).await;
    let identity_state = state.service_identity_state();
    let service_identity_ok = identity_state.is_ready();
    let ok = database_ok && service_identity_ok;
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    json_ok(HealthReport {
        ok,
        service: "coland",
        storage: state.jobs().storage_mode(),
        checks: json!({
            "database": {
                "ok": database_ok,
                "mode": state.jobs().storage_mode(),
            },
            "events": {
                "ok": true,
            },
            "service_identity": service_identity_health(identity_state.as_ref()),
        }),
        development_mode: state.config().development_mode,
        proof_verifier_mode: state.config().proof_verifier_mode(),
        admin_auth_mode: state.admin_auth_mode(),
        hardening: state.config().hardening_status(),
    })
}

#[endpoint(operation_id = "org.arkret.coland.system.readyz")]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.system.readyz"))]
async fn readyz(depot: &mut Depot, res: &mut Response) -> JsonResult<ReadyzOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let database_ok = database_ready(state).await;
    // P5 (5.4 readiness gate for migrations) — keep /readyz in 503 until the
    // embedded diesel batch has been applied. Before this gate landed,
    // orchestrators that drained traffic onto a still-migrating replica
    // could observe transient `relation does not exist` errors on the
    // first few requests; the gate makes that race fail-closed.
    let migrations_applied = state.jobs().migrations_applied();
    let local_issuer_requested = state.config().local_account_authority_config.is_some();
    let session_grant_introspection_ready =
        !local_issuer_requested || state.local_account_authority().is_some();
    let external_webvh_provider_ready = state.config().external_webvh_provider_url.is_none()
        || state.config().external_webvh_provider_active;
    let service_identity_ready = state.service_identity_state().is_ready();
    let pq_hybrid_tls_ready = state.config().pq_hybrid_tls_ready();
    let ok = database_ok
        && migrations_applied
        && session_grant_introspection_ready
        && external_webvh_provider_ready
        && service_identity_ready
        && pq_hybrid_tls_ready;
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    // When migrations are the *only* thing blocking readiness, surface a
    // dedicated reason code at the top level so orchestrators can
    // distinguish "still booting" from "configured wrong".
    let reason = if !migrations_applied {
        Some("migrations_pending".to_owned())
    } else if !database_ok {
        Some("database_unreachable".to_owned())
    } else if !pq_hybrid_tls_ready {
        Some("pq_hybrid_tls_probe_missing".to_owned())
    } else if !service_identity_ready {
        Some("service_identity_unavailable".to_owned())
    } else {
        None
    };
    let migrations = if state.jobs().database_configured() {
        if migrations_applied {
            "applied"
        } else {
            "pending"
        }
    } else {
        "not_required"
    };
    json_ok(ReadyzOutcome {
        ok,
        service: "coland".to_owned(),
        storage: state.jobs().storage_mode().to_owned(),
        reason,
        checks: ReadyzChecks {
            database: ReadyzDatabaseCheck {
                ok: database_ok,
                mode: state.jobs().storage_mode().to_owned(),
                migrations: migrations.to_owned(),
            },
            migrations: ReadyzMigrationCheck {
                ok: migrations_applied,
                mode: state.jobs().storage_mode().to_owned(),
            },
            session_grant_introspection: ReadyzConfiguredCheck {
                ok: session_grant_introspection_ready,
                configured: local_issuer_requested,
            },
            external_webvh_provider: ReadyzExternalWebvhProviderCheck {
                ok: external_webvh_provider_ready,
                configured: state.config().external_webvh_provider_url.is_some(),
                active: state.config().external_webvh_provider_active,
            },
            pq_hybrid_tls: ReadyzConfiguredCheck {
                ok: pq_hybrid_tls_ready,
                configured: state.config().pq_hybrid_tls_probe_configured(),
            },
        },
    })
}

fn service_identity_health(state: &DidCoreIdentityState) -> Value {
    match state {
        DidCoreIdentityState::Ready { identity } => json!({
            "state": "ready",
            "service_id": identity.service_id,
            "provider_endpoint": identity.provider.as_ref().map(|provider| provider.endpoint.as_str()),
            "last_verified_at": identity.last_verified_at,
            "retry_at": null,
            "next_action": null,
        }),
        DidCoreIdentityState::DegradedStored {
            identity,
            retry_at,
            last_error,
        } => json!({
            "state": "degraded_stored",
            "service_id": identity.service_id,
            "provider_endpoint": identity.provider.as_ref().map(|provider| provider.endpoint.as_str()),
            "last_verified_at": identity.last_verified_at,
            "retry_at": retry_at,
            "last_error": last_error,
            "next_action": null,
        }),
        DidCoreIdentityState::WaitingProvider {
            registration_key,
            retry_at,
        } => json!({
            "state": "waiting_provider",
            "service_id": null,
            "provider_endpoint": null,
            "registration_key": registration_key,
            "last_verified_at": null,
            "retry_at": retry_at,
            "next_action": null,
        }),
        DidCoreIdentityState::RegistrationKeyDrift {
            identity,
            stored_key,
            computed_key,
        } => json!({
            "state": "registration_key_drift",
            "service_id": identity.service_id,
            "provider_endpoint": identity.provider.as_ref().map(|provider| provider.endpoint.as_str()),
            "stored_key": stored_key,
            "computed_key": computed_key,
            "last_verified_at": identity.last_verified_at,
            "retry_at": null,
            "next_action": "restore the stored public base URL, or stop serving and run coland service-identity migrate-base --from OLD_URL --to NEW_URL --preflight before applying the signed migration",
        }),
        DidCoreIdentityState::Conflict {
            stored_service_id,
            provider_id,
        } => json!({
            "state": "conflict",
            "service_id": stored_service_id,
            "provider_id": provider_id,
            "provider_endpoint": null,
            "last_verified_at": null,
            "retry_at": null,
            "next_action": "run `coland service-identity doctor` and restore the authoritative identity",
        }),
        DidCoreIdentityState::Faulted {
            diagnostic,
            next_action,
        } => json!({
            "state": "faulted",
            "diagnostic": diagnostic,
            "service_id": null,
            "provider_endpoint": null,
            "last_verified_at": null,
            "retry_at": null,
            "next_action": next_action,
        }),
    }
}

async fn database_ready(state: &AppState) -> bool {
    state.jobs().database_ready().await
}

#[endpoint(operation_id = "ak.server.read.describe")]
#[tracing::instrument(skip_all, fields(op = "ak.server.read.describe.v1"))]
async fn server_describe(
    service_kind: QueryParam<String, false>,
    depot: &mut Depot,
) -> JsonResult<ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    if let Some(service_kind) = service_kind.into_inner()
        && service_kind != arkret_wire::ServiceKind::Station.as_str()
    {
        return Err(coland_http::error::AppError::param_invalid(format!(
            "service_kind {service_kind:?} is not available on this binding"
        )));
    }
    json_ok(build_server_description_resolved(state).await?)
}

#[endpoint(operation_id = "org.arkret.coland.system.describe")]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.system.describe"))]
async fn coland_describe(depot: &mut Depot) -> JsonResult<ColandServiceDescription> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service = build_server_description_resolved(state).await?;
    let unsupported_profiles = unsupported_profiles_from_limits(&service.limits);
    json_ok(ColandServiceDescription {
        service,
        unsupported_profiles,
        proof_verifier_mode: state.config().proof_verifier_mode().to_owned(),
        admin_auth_mode: state.admin_auth_mode().to_owned(),
        erasure_receipts_endpoint: "/_arkret/peer/erasure-receipts/{receipt_id}".to_owned(),
        hardening: state.config().hardening_status(),
    })
}

fn unsupported_profiles_from_limits(
    limits: &arkret_models_discovery::service_description::ServerLimits,
) -> Vec<UnsupportedProfileDescriptor> {
    limits
        .extensions
        .get("profile_status")
        .and_then(|value| value.get("unsupported_profiles"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some(UnsupportedProfileDescriptor {
                profile: item.get("profile")?.as_str()?.to_owned(),
                status: item.get("status")?.as_str()?.to_owned(),
                reason: item.get("reason")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

pub(crate) fn build_server_description(state: &AppState) -> ServiceDescribe {
    // Configuration drift keeps serving the accepted identity. Discovery must
    // confirm its signed endpoint, rather than advertise an unsigned new base.
    let mut description_config = state.config().clone();
    if let Some(identity) = state.service_identity_state().identity() {
        description_config.public_base_url =
            identity.registration_key.public_base_url().to_string();
    }
    let mut description = describe(
        state.service_resolution_commitment().as_ref(),
        state.jobs().storage_mode(),
        &description_config,
    );
    description.receive_policy_constraints = state.config().receive_policy_constraints.clone();
    // Advertise the LIVE rate-limit ceilings (from the runtime overlay, which
    // the middleware also enforces) rather than the boot-config defaults, so
    // the advertised==enforced invariant holds after an admin hot-swap.
    description.rate_limit_policy = Some(
        state
            .settings()
            .rate_limit
            .to_limiter_config()
            .advertised_policy(),
    );
    // Partition conformance claims while the response remains the SDK's
    // closed ServiceDescribe type.
    apply_conformance_evidence(&mut description, state.verified_profiles());

    // Validate the Arkret v1 invariants. development_mode=true MUST
    // forbid non-empty verified_profiles; protocol_version MUST equal the
    // SDK constant. A failure here means the producer drifted from the
    // canonical ServiceDescribe schema.
    if let Err(err) = description.validate() {
        tracing::error!(
            error = %err,
            "ServiceDescribe validation failed; this is a build-time invariant"
        );
    }
    description
}

async fn build_server_description_resolved(
    state: &AppState,
) -> Result<ServiceDescribe, coland_http::error::AppError> {
    let description = build_server_description(state);
    Ok(description)
}

/// Inject the conformance claim fields into a describe response.
///
/// Invariants enforced here:
/// - `verified_profiles` MUST be empty when `development_mode=true`. The loader
///   [`crate::verified_profiles::load_from_env`] already returns an empty vec when the env var is
///   unset, but we additionally enforce the dev-mode rule below: even if an operator points
///   `COLAND_VERIFIED_PROFILES_ARTIFACT` at a real file while running with `development_mode=true`,
///   the wire surface emits `[]`.
/// - Verified evidence must refer to a profile in `supported_profiles`.
pub(crate) fn apply_conformance_evidence(
    description: &mut arkret_models_discovery::ServiceDescribe,
    loaded_verified: &[crate::verified_profiles::VerifiedProfileArtifactEntry],
) {
    let advertised_profile_ids = description
        .supported_profiles
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let profile_requirements =
        arkret_policy::collect_profile_semantic_requirements(&advertised_profile_ids)
            .expect("advertised profiles must exist in SDK-generated profile requirements");
    description
        .supported_features
        .extend(profile_requirements.required_features);
    description.supported_profiles.sort();
    description.supported_profiles.dedup();
    description.supported_operation_bundles.sort();
    description.supported_operation_bundles.dedup();
    description.supported_features.sort();
    description.supported_features.dedup();

    let supported_id_set: std::collections::BTreeSet<String> =
        description.supported_profiles.iter().cloned().collect();

    // verified_profiles: populated by the G4.T3 cotest artifact loader.
    // `loaded_verified` is the deserialised + role-filtered slice from
    // `state.verified_profiles`. Dev-mode posture overrides any artifact:
    // even with the env var pointed at a real file, `development_mode=true`
    // forces `[]` per service-surface.md §3.0.
    //
    // Cross-check: every loaded entry's `profile_id` MUST also appear in
    // the `supported_profiles[]` advertised above. Entries that fail the
    // cross-check are dropped with a warn — we never advertise a verified
    // profile we don't also self-claim.
    let verified_profiles: Vec<arkret_models_discovery::service_description::VerifiedProfileEntry> =
        if description.development_mode {
            if !loaded_verified.is_empty() {
                tracing::warn!(
                    target: "verified_profiles",
                    count = loaded_verified.len(),
                    "development_mode=true overrides loaded verified-profile artifact; \
                     emitting verified_profiles=[] per service-surface.md §3.0"
                );
            }
            Vec::new()
        } else {
            loaded_verified
            .iter()
            .filter_map(|entry| {
                if !supported_id_set.contains(&entry.profile_id) {
                    tracing::warn!(
                        target: "verified_profiles",
                        profile_id = %entry.profile_id,
                        "dropping verified-profile entry: profile_id absent from supported_profiles"
                    );
                    return None;
                }
                Some(arkret_models_discovery::service_description::VerifiedProfileEntry {
                    profile_id: entry.profile_id.clone(),
                    claim_kind: arkret_models_discovery::service_description::ConformanceVerifiedKind::ConformanceVerified,
                    verification_run_id: entry.verification_run_id.clone(),
                    artifact_digest: entry.artifact_digest.clone(),
                    artifact_ref: entry.artifact_ref.clone(),
                    verifier_id: entry.verifier_id.clone(),
                    signature: entry.signature.clone(),
                    verified_at: entry.verified_at,
                    expires_at: entry.expires_at,
                    extra: Default::default(),
                })
            })
            .collect()
        };
    debug_assert!(
        !description.development_mode || verified_profiles.is_empty(),
        "development_mode=true requires verified_profiles=[] (service-surface.md §3.0)"
    );
    description.verified_profiles = verified_profiles;
    description.interop_surfaces.clear();
}

#[endpoint(operation_id = "org.arkret.coland.auth.bridge.describe")]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.auth.bridge.describe"))]
pub(in crate::routing) async fn auth_bridge_describe() -> JsonResult<AuthBridgeDescription> {
    json_ok(AuthBridgeDescription {
        contract: "arkret.rest.principal_bridge.v1".to_owned(),
        version: "2026-06-21-session-grant-direct".to_owned(),
        api_base_path: "/_coland".to_owned(),
        auth: AuthBridgeAuthDescriptor {
            #[cfg(any(test, feature = "conformance-harness"))]
            dev_login_path: "/_coland/gate/auth/dev-login".to_owned(),
            session_grant_issuance_path: "/_arkret/gate/account/session-grants".to_owned(),
            session_grant_presentation:
                "Authorization: DPoP <ak.session.grant> with a DPoP proof on /_arkret/self/*"
                    .to_owned(),
            principal_id_body_field: "principal_id".to_owned(),
        },
        push: AuthBridgePushDescriptor {
            register_device_path: "/_arkret/edge/push/register-device".to_owned(),
            unregister_device_path: "/_arkret/edge/push/unregister-device".to_owned(),
            principal_id_body_field: "principal_id".to_owned(),
            register_device_mode: "session_grant_presentation".to_owned(),
        },
        examples: AuthBridgeExamples {
            session_grant_issue_request: json!({
                "principal_id": "ak:did_core:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "proof": {
                    "proof_kind": "did_bound_signature",
                    "challenge": "challenge-01js0000000000000000000000",
                    "request_canonical_digest": "sha256:7e4f3a0b6f0d0f3d9f8c3a2b1e0d9c8b7a6f5e4d3c2b1a009988776655443322",
                    "audience": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:coland.local:webvh:service",
                    "signature": "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYjphbGljZS5leGFtcGxlI2RldmljZS1rZXkifQ.example"
                }
            }),
            register_device_request: json!({
                "principal_id": "ak:did_core:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "push_gateway": "https://floria.example/_arkret/edge/push/notify",
                "push_key": "webpush:https://fcm.googleapis.com/wp/01js0000000000000000000000",
                "platform": "web"
            }),
            unregister_device_request: json!({
                "principal_id": "ak:did_core:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "registration_id": "push:01904100-0000-7000-8000-000000000001.webpush"
            }),
        },
        todos: Vec::new(),
    })
}

#[endpoint(operation_id = "org.arkret.coland.integration.describe")]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.integration.describe"))]
async fn integration_describe() -> JsonResult<IntegrationManifest> {
    json_ok(IntegrationManifest {
        contract: "arkret.rest.integration_manifest.v1".to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        service: "coland".to_owned(),
        service_kind: "station".to_owned(),
        api_base_path: "/_arkret".to_owned(),
        describe_path: "/_coland/self/integration/describe".to_owned(),
        dependencies: vec![IntegrationDependencyDescriptor {
                service: "floria".to_owned(),
                purpose: "push_gateway_delivery".to_owned(),
                required_contract:
                    arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1.to_owned(),
                discovery_path: "/_arkret/describe".to_owned(),
                mode: "canonical_service_describe".to_owned(),
            }],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "auth_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_coland/gate/auth/bridge/describe".to_owned(),
                contract: "arkret.rest.principal_bridge.v1".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "publish the same session-grant presentation requirements in the registry artifact.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "session_grant_presentation".to_owned(),
                method: "Authorization".to_owned(),
                path: "all protected /_arkret routes".to_owned(),
                contract: "ak.session.grant+dpop".to_owned(),
                stability: "scaffold".to_owned(),
                todo: "make the session-grant introspection cache/timeout policy explicit in the published contract.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_register_device".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/edge/push/register-device".to_owned(),
                contract: "arkret.rest.principal_push_register.v1".to_owned(),
                stability: "limited".to_owned(),
                todo: "unify push registration behind the same session-grant presentation used by ordinary requests.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "member_identity_update".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/self/events".to_owned(),
                contract: arkret_wire::event_kind_str::MEMBER_IDENTITY_UPDATE.to_owned(),
                stability: "partial_fail_closed".to_owned(),
                todo: "plaintext Ed25519 MemberIdentity proofs are verified; encrypted proof verification and ES256/ES384 are unsupported and rejected.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "agent_runtime_attestation".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/gate/account/agent-key-pair".to_owned(),
                contract: arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1.to_owned(),
                stability: "unsupported_fail_closed".to_owned(),
                todo: "runtime_attestation verifier and controller approval ledger are not wired; requests carrying runtime_attestation are rejected.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "blob_presign".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/self/blob/presign".to_owned(),
                contract: arkret_wire::ServiceOperationId::SELF_BLOB_COMMAND_PRESIGN_V1.to_owned(),
                stability: "local_direct_serve".to_owned(),
                todo: "issues coland-signed local /blob/get URLs; backend-native object-store presign is not claimed.".to_owned(),
            },
        ],
        examples: json!({
            "compose_strand": {
                "step_1": {"service": "coauth", "path": "/_arkret/gate/account/session-grants", "method": "POST"},
                "step_2": {"service": "coland", "path": "protected route", "method": "Authorization: DPoP <ak.session.grant> + DPoP"},
                "step_3": {"service": "coland", "path": "/_arkret/edge/push/register-device", "method": "POST"}
            }
        }),
        todos: vec![
            "publish the same integration manifest fields in the OpenAPI surface.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_discovery::service_description::ServiceDescribe;
    use arkret_wire::{Did, ServiceKind, TrustDomainId};

    use super::apply_conformance_evidence;

    #[test]
    fn conformance_discovery_tokens_are_not_wire_features() {
        let mut description = ServiceDescribe::development(
            Did::new("did:web:coland.example".to_owned()).unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.describe.v1".to_owned(),
                "ak.operation_bundle.station.http_core_current.v1".to_owned(),
            ],
            vec![arkret_models_discovery::TransportBinding::HttpJson {
                base_url: "https://coland.example/".to_owned(),
                extension_profile_required: (),
            }],
        );
        description
            .supported_profiles
            .push("ak.profile.chat_mvp.v1".to_owned());
        apply_conformance_evidence(&mut description, &[]);
        for feature in [
            "discussion_history_access",
            "supported_event_kinds",
            "supported_sync_profiles",
        ] {
            assert!(
                !description
                    .supported_features
                    .iter()
                    .any(|supported| supported == feature)
            );
        }
    }

    #[test]
    fn sovereign_security_posture_is_not_a_conformance_claim() {
        let mut description = ServiceDescribe::development(
            Did::new("did:web:coland.example".to_owned()).unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.describe.v1".to_owned(),
                "ak.operation_bundle.station.http_core_current.v1".to_owned(),
            ],
            vec![arkret_models_discovery::TransportBinding::HttpJson {
                base_url: "https://coland.example/".to_owned(),
                extension_profile_required: (),
            }],
        );
        apply_conformance_evidence(&mut description, &[]);

        assert!(
            !description
                .supported_profiles
                .iter()
                .any(|profile| { profile == arkret_wire::ProfileId::SOVEREIGN_ENCLAVE_V1 })
        );
    }
}
