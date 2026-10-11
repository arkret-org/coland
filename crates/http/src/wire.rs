pub use arkret_models_collaboration::contact_operations::{
    ContactListRow, ContactState, DirectConversationSummary, DirectConversationSummaryState,
};
pub use arkret_models_collaboration::device_messages::{
    DeviceMessageEnvelope, DeviceMessageSender, DeviceMessageTarget, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
    DeviceMessagesSendRequestBody,
};
pub use arkret_models_collaboration::session_grants::{
    SessionGrantHolderProof, SessionGrantValidationInput, SessionGrantValidationMetadata,
    SessionGrantValidationOutcome,
};
pub use arkret_models_crypto::{
    DeviceStatus, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome, KeysQueryRequestBody,
    KeysUploadOutcome, KeysUploadRequestBody, KeysUploadUnsignedRequest, PeerQueryDeviceRecord,
    QueryDeviceRecord,
};
pub use arkret_models_discovery::ops::HardeningStatus;
use arkret_models_discovery::{
    AccountAuthority, AuthGrantExchange, AuthGrantExchangeKind, AuthMetadata, AuthMethod,
    AuthMethodKind, ServiceDescribe,
};
pub use arkret_models_identity::admin_grant::SessionGrantAdminIntrospectionStatus;
pub use arkret_models_identity::identity::IdentityResolveRequestBody;
pub use arkret_models_integration::OkOutcome;
use arkret_wire::{
    MAX_AUTHORIZED_BY_REFS, MAX_EVENT_ENVELOPE_BYTES, MAX_EVENT_SUBMIT_BATCH, MAX_SEMANTIC_REFS,
    ProfileId,
};
use chrono::{DateTime, Utc};
pub use coland_contracts::admin::{
    AuthorizedDeviceSigningKey, DeviceSigningKeyDirectoryOutcome,
    DeviceSigningKeyDirectoryQueryRequestBody,
};
use coland_services::protocol_artifacts as artifacts;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct HealthOutcome {
    pub ok: bool,
    pub service: &'static str,
    pub storage: &'static str,
    pub checks: Value,
    /// True when coland is running with `COLAND_DEVELOPMENT_MODE=true`.
    /// Surfaced here so operators / dashboards (e.g. codmin) can flag the
    /// deployment with a "DEVELOPMENT MODE — do not use in production"
    /// banner without having to scrape `/_arkret/describe`.
    pub development_mode: bool,
    /// Formal proof verification is always enabled, including in a harness.
    /// This diagnostic never advertises relaxed unsigned or weak-proof trust.
    pub proof_verifier_mode: &'static str,
    /// Effective admin-API authentication posture:
    ///   - `"development"` — synthetic local admin sessions are enabled in an explicit harness
    ///     build
    ///   - `"principal_id_allowlist"` — production gate via `COLAND_ADMIN_PRINCIPAL_IDS`
    ///   - `"closed"` — production mode with no admin principals; admin endpoints are locked.
    pub admin_auth_mode: &'static str,
    /// T8.3 — non-sensitive production hardening checklist snapshot.
    /// Surfaced on `/health` so codmin's `/hardening` dashboard can
    /// aggregate it across all services without scraping the more
    /// expensive describe payload.
    pub hardening: HardeningStatus,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct ColandServerDescribeOutcome {
    #[serde(flatten)]
    pub service: ServiceDescribe,
    pub unsupported_profiles: Vec<UnsupportedProfileDescriptor>,
    pub proof_verifier_mode: String,
    pub admin_auth_mode: String,
    pub erasure_receipts_endpoint: String,
    pub hardening: HardeningStatus,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct UnsupportedProfileDescriptor {
    pub profile: String,
    pub status: String,
    pub reason: String,
}

impl UnsupportedProfileDescriptor {
    pub fn unsupported(
        profile: impl Into<String>,
        reason: impl Into<String>,
    ) -> UnsupportedProfileDescriptor {
        UnsupportedProfileDescriptor {
            profile: profile.into(),
            status: "unsupported".to_owned(),
            reason: reason.into(),
        }
    }
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgeDescribeOutcome {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub auth: AuthBridgeAuthDescriptor,
    pub push: AuthBridgePushDescriptor,
    pub examples: AuthBridgeExamples,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgeAuthDescriptor {
    #[cfg(any(test, feature = "conformance-harness"))]
    pub dev_login_path: String,
    pub session_grant_issuance_path: String,
    pub session_grant_presentation: String,
    pub principal_id_body_field: String,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub principal_id_body_field: String,
    pub register_device_mode: String,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize, Deserialize)]
pub struct AuthBridgeExamples {
    pub session_grant_issue_request: Value,
    pub register_device_request: Value,
    pub unregister_device_request: Value,
}

// Shared `/_floria/integration/describe` manifest shape: re-exported from
// the SDK contracts crate (the authoritative definition shared by floria,
// coland, and coauth) instead of a local copy.
// Client-sync family DTOs come straight from the SDK (`ServiceDescribe`
// answers `account/describe`, `SyncRequestBody` carries the subscribe/sync
// request); both are shared SDK wire types, so coland keeps
// no private copies that could drift. NOTE: the explicit `model::` path
// matters — the SDK root re-exports a different, client-side typed
// `sync::SyncRequestBody` under the same name.
// Snapshot head operations return the full signed `ak.schema.realm_state_snapshot.v1`
// manifest. coland answers both operations with `not_implemented` until it can
// produce a real Snapshot detached proof.

// authz check DTOs are now the spec-authoritative SDK types. The SDK
// `AuthzDecision` enum was aligned to the spec five-valued form
// (allow / soft_deny / hard_deny / quarantine / require_review) and
// `AuthzCheckRequestBody` to `{ actor_id, action, resource?, context? }`,
// so coland re-uses them directly instead of carrying local copies.
pub use arkret_models_collaboration::governance::authorization::{
    AuthzCheckOutcome, AuthzCheckRequestBody,
};
// Moderation report request/outcome are the SDK DTOs (`arkret-models-collaboration` carries
// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`:
// `status` enum `submitted|resolved`, `routed_to` is an array of DIDs);
// no coland mirrors.
pub use arkret_models_collaboration::governance::moderation::{
    ModerationReportOutcome, ModerationReportRequestBody,
};
pub use arkret_models_collaboration::sync_frames::account_subscribe::SyncRequestBody;
pub use arkret_models_integration::integration::{
    IntegrationDependencyDescriptor, IntegrationDescribeOutcome, IntegrationSurfaceDescriptor,
};
pub use arkret_models_integration::{
    PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};
// The policy document surface is one definition shared with the operator
// console (`coland-contracts::admin::policy`); see that module for why.
pub use coland_contracts::admin::policy::{
    AdminPolicyDocument, AdminPolicyDocumentPage, AdminPolicyPayload, PolicyEffect,
    UpsertPolicyDocumentRequestBody,
};

#[cfg(any(test, feature = "conformance-harness"))]
#[derive(salvo::oapi::ToSchema, Debug, Deserialize)]
pub struct DevLoginRequestBody {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
}

#[cfg(any(test, feature = "conformance-harness"))]
#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct SessionLoginOutcome {
    pub session_credential: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(salvo::oapi::ToSchema, Debug, Serialize)]
pub struct ColandAccountRegisterOutcome {
    pub principal_id: arkret_wire::DidCoreId,
    pub handle: String,
    pub display_name: Option<String>,
    pub state: String,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

// Identity log / receipts outcomes are owned by the corresponding SDK model crates;
// authoritative carrier for identity operation shapes); no coland mirrors.
// AKP-0008 / AKP-0009 — Agent operations. Every request/response
// DTO is the SDK-authoritative `arkret_models_collaboration::agent_operations` shape (spec
// `agent-operations.schema.json`): `agent_view`/`agent_list` carry the spec
// `agent_projection`; the `agent_key_pair` outcome is
// `{ok, authorized_event_ref}`; grant attach/detach outcomes are
// `{ok, grant_id}` / `{ok, revoked_at}`; Sidecar ensure carries the typed
// event-derived `sidecar_id` and native `source_context_ref`. The lifecycle
// outcome (`agent_lifecycle_state` = `operation_status_outcome` =
// `{ok: true, status}`) has no struct mirror in the SDK and is emitted as a
// spec-exact JSON object by the agents handler. `AgentProvisionRequestBody` /
// `AgentProvisionOutcome` were already SDK-backed.
// ── AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — media
// token exchange wire shapes. Both the request body and the response types
// come straight from the SDK (`CallMediaTokenExchangeRequestBody` carries
// typed ids `realm_id`/`call_id`/`actor_id`/`device_id` plus the optional
// `capability_refs`/`desired_media` inputs; `CallMediaTokenExchangeOutcome`
// / `CallMediaParticipantBinding` are shared SDK wire types),
// so coland no longer mints private mirrors that can drift from the spec DTOs.
pub use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentList,
    AgentPauseRequestBody, AgentResumeRequestBody, AgentSidecarList, AgentSidecarView, AgentView,
};
pub use arkret_models_collaboration::objects::media::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
};
pub use arkret_models_collaboration::sidecar_operations::{
    SidecarEnsureOutcome, SidecarEnsureRequestBody,
};
pub use arkret_models_crypto::KeysBackupsPutRequestBody;
// Key-backup replace/delete outcomes are the SDK server-side DTOs
// (`arkret-models-crypto` is the authoritative carrier for
// `keys-operations.schema.json#/$defs/keys_backups_replace_outcome` /
// `keys_backups_delete_outcome`); no coland mirrors.
pub use arkret_models_crypto::{
    KeyBackupPutStatus, KeysBackupsDeleteOutcome, KeysBackupsList, KeysBackupsReplaceOutcome,
};
pub use arkret_models_identity::identity::{IdentityLogListOutcome, IdentityReceiptListOutcome};

// Recovery policy / receipt endpoints validate against the spec REC-1 shapes in
// `routing::identity::recovery`: policy publish uses the SDK request body,
// while receipt write keeps a signed JSON wrapper so the raw signed fields can
// be verified before being projected into typed outcomes. The SDK carries the
// authoritative typed forms (`arkret_models_crypto::{RecoveryPolicy,
// RecoveryReceipt}`) for clients; no coland-private mirror exists.

fn local_extension_operations() -> Vec<String> {
    crate::routing::coland_extension_operation_ids()
}

fn profile_limitations() -> Vec<Value> {
    vec![
        json!({
            "area": "federation.outbound_push",
            "status": "partial",
            "landed": [
                "per-peer durable fanout transcript",
                "signed fanout intent evidence",
                "retry/durability metadata"
            ],
            "remaining": [
                "network HTTP dispatch",
                "RFC 9421 HTTP Message Signatures header emission",
                "automatic retry worker"
            ],
            "reason": "outbound Move/Seal fanout persists a signed intent and retry boundary per peer; actual RFC 9421 HTTP delivery is still not claimed"
        }),
        json!({
            "area": "authz.capability_engine_depth",
            "status": "partial",
            "standard_self_surface": "implemented",
            "reason": "standard /_arkret/self/authz/check, effective-grants, and invites are advertised and SDK-backed; deeper selector, constraint, delegation, and policy lifecycle semantics are tracked by dedicated AUTHZ audit items"
        }),
        json!({
            "area": "policies.describe",
            "status": "scaffold_contract",
            "reason": "policy collection describe is artifact-shaped metadata for the local policy document store; it is not a complete policy profile claim"
        }),
        json!({
            "area": "admin.bottom.manual_repair",
            "status": "unsupported_signing_path",
            "reason": "manual Bottom repair validates effect scope but does not submit or sign arbitrary manual effects"
        }),
        json!({
            "area": "index.query",
            "status": "limited_projection",
            "reason": "index query is backed by the local materialized projection and demo fallback, not a full durable index-node profile"
        }),
        json!({
            "area": "event_submit.batch_receipt",
            "status": "unsupported",
            "reason": "current profile accepts one Event Envelope per request"
        }),
        json!({
            "area": "member_identity.proof",
            "status": "partial_fail_closed",
            "supported": "plaintext identity_payload.member_identity with Ed25519 raw signature verified against the subject_id DID verification method",
            "unsupported": [
                "encrypted identity_payload proof verification",
                "ES256 / ES384 MemberIdentityProof.signature_algorithm"
            ],
            "reason": "non-Ed25519 and encrypted MemberIdentity proof forms are refused rather than shape-accepted"
        }),
        json!({
            "area": "agents.runtime_attestation",
            "status": "unsupported_fail_closed",
            "reason": "runtime_attestation verifier/controller approval ledger is not wired; supplied attestations are rejected"
        }),
        json!({
            "area": "blob.presign",
            "status": "local_direct_serve",
            "reason": "presign issues a short-lived coland-signed local /blob/get URL; backend-native object-store presign is not claimed"
        }),
        json!({
            "area": "snapshot.head",
            "status": "standard_self_supported",
            "reason": "ak.self.realm_state_snapshot.read.manifest_head.v1 returns a signed ak.schema.realm_state_snapshot.v1 manifest; the /_coland dev bundle is development-only diagnostics"
        }),
        json!({
            "area": "account_auth.device_pair",
            "status": "account_authority_owned",
            "spec_operation": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1,
            "canonical_path": "/_arkret/gate/account/device-pair",
            "reason": "ak.gate.account.command.pair_device.v1 and its pending pairing ledger belong to the Account Authority; this Station only admits the relayed accepted_device ak.device.authorize through its registered accepted-device unit over the private admission channel (device-lifecycle.md §2.1.1, §5.4)."
        }),
        json!({
            "area": "consent.scope_any_cross_service_cascade",
            "status": "partial_local_only",
            "spec": "T17",
            "implemented": "holder Consent reads and invite introduction evidence use durable PCR current; revoking any invalidates its own record and leaves independently granted concrete scopes active",
            "unsupported": "cross-service freshness and invalidation of downstream directory, MIMI, push and in-flight consumers remain unverified",
            "reason": "no cross-service completion is claimed by the local current-result path"
        }),
        json!({
            "area": "identity.resolver_health_signal",
            "status": "unsupported",
            "spec": "SEC-01 / identity-did.md §3.4",
            "unsupported": "resolver degraded/health signal verification is not wired into production paths",
            "reason": "coland has no inbound resolver-health signal feed or per-write gate for this verdict"
        }),
        json!({
            "area": "audit.policy_receipt_emit",
            "status": "unsupported",
            "spec": "B1.12 / B1.16",
            "unsupported": "coland does not emit signed audit policy receipts on any production route",
            "reason": "no production audit-receipt emission path is wired in this deployment"
        }),
    ]
}

fn full_station_gap_summary() -> Vec<Value> {
    vec![json!({
        "profile": arkret_wire::ProfileId::STATION_V1,
        "status": "not_claimed",
        "first_batch_landed": [
            "artifact-derived supported operation advertisement",
            "SDK-backed state model family/kind/bottom registry bindings",
            "outbound Move/Seal fanout signed intent evidence",
            "per-peer retry/durability transcript metadata"
        ],
        "remaining_gaps": [
            "RFC 9421 HTTP Message Signatures on outbound and inbound federation HTTP",
            "automatic retry dispatcher with durable backoff lease",
            "full identity registry, directory service, blob node, and authorization profile coverage",
            "complete full-profile conformance matrix generated from artifacts"
        ]
    })]
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum MimiInteropProfileStatus {
    ProviderFacadeFirstRound {
        drafts: MimiInteropDrafts,
        not_replaced: Vec<String>,
        principal_conformance: MimiPrincipalConformance,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MimiInteropDrafts {
    protocol: String,
    content: String,
    room_policy: String,
    identifiers: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MimiPrincipalConformance {
    NotClaimed,
}

/// Build the service description.
///
/// The seven configuration values this used to take positionally were, by its
/// own comment, "AppConfig fields" — so it takes `AppConfig`. Every caller
/// already had `state.config()` in hand, and threading them one by one is how
/// a tenth (`key_backup_daily_download_limit`) would otherwise have been added
/// to a signature that already carried a `too_many_arguments` waiver.
pub fn describe(
    service_resolution: &arkret_models_identity::ResolutionCommitment,
    storage: &'static str,
    config: &crate::config::AppConfig,
) -> ServiceDescribe {
    let mimi_interop_profile_status = MimiInteropProfileStatus::ProviderFacadeFirstRound {
        drafts: MimiInteropDrafts {
            protocol: "draft-ietf-mimi-protocol-06".to_owned(),
            content: "draft-ietf-mimi-content-08".to_owned(),
            room_policy: "draft-ietf-mimi-room-policy-03".to_owned(),
            identifiers: "draft-kohbrok-mimi-identifiers-01".to_owned(),
        },
        not_replaced: [
            "arkret_signed_event_reducer",
            "realm_id",
            "did",
            "hlc",
            "capability",
            "auth_refs",
            "mls_state",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        principal_conformance: MimiPrincipalConformance::NotClaimed,
    };
    let public_base_url = config.public_base_url.as_str();
    let websocket_binding = url::Url::parse(public_base_url)
        .ok()
        .and_then(|mut endpoint| {
            if endpoint.scheme() != "https"
                || endpoint.path() != "/"
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
            {
                return None;
            }
            endpoint.set_scheme("wss").ok()?;
            endpoint.set_path("/_arkret/ws");
            let binding = arkret_models_discovery::TransportBinding::websocket(
                endpoint.to_string(),
                crate::routing::events::sync::websocket::MAX_FRAME,
                crate::routing::events::sync::websocket::MAX_CHANNELS,
            );
            arkret_models_discovery::websocket_binding::validate_websocket_transport(&binding)
                .ok()?;
            Some(binding)
        });
    let development_mode = config.development_mode;
    let account_authority_url = config.account_authority_url.as_deref();
    let oidc_client_id = config.oidc_client_id.as_deref();
    let trust_domain = config.trust_domain.as_str();
    let resumable_upload_incomplete_ttl_seconds = config.resumable_upload_incomplete_ttl_seconds;
    let to_device_queue_capacity = config.to_device_queue_capacity;
    // Account Authority discovery (service-surface §2.5.1): the client-visible
    // owner of the auth-side `/_arkret/gate/account/*` ops the client posts to
    // (session-grant issuance + hard logout). Those are served by the Auth
    // Server (coauth), which DPoP-binds holder proofs to its OWN origin. When
    // an external Account Authority is configured, clients post gate/account
    // requests there directly and the DPoP `htu` aligns with that public base.
    // Personal deployments may co-locate this role at the Principal origin.
    let account_origin = account_authority_url
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(public_base_url)
        .trim_end_matches('/')
        .to_owned();
    let gate_account_base_url = format!("{account_origin}/_arkret/gate/account");

    // Authentication methods are pure provider discovery; they do not decide
    // gate/account routing. Advertise OIDC when an Account Authority process is configured;
    // the client uses standard OIDC discovery and submits an
    // OIDC proof to the Account Authority's one-shot account-handoff operation.
    let mut methods = Vec::new();
    if let Some(account_authority_url) =
        account_authority_url.filter(|value| !value.trim().is_empty())
    {
        // `AppConfig` stores the Account Authority endpoint as a canonical
        // service URL, including its trailing slash. OIDC discovery requires
        // clients to compare the advertised issuer with the provider's
        // `issuer` value exactly, so preserve that canonical spelling here.
        let issuer = account_authority_url.to_owned();
        let openid_configuration = format!("{issuer}.well-known/openid-configuration");
        methods.push(AuthMethod {
            method: AuthMethodKind::Oidc,
            issuer_uri: Some(issuer.clone()),
            provider_uri: None,
            openid_configuration_url: Some(openid_configuration.clone()),
            // Registered OAuth `client_id` (coauth keys clients by ULID). The
            // web client uses this verbatim; absent it, it has no valid id to
            // fall back to and coauth answers `could not find client`.
            client_id: oidc_client_id
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            grant_exchange: AuthGrantExchange {
                kind: AuthGrantExchangeKind::AccountHandoff,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
    }

    // `development_mode` is the registered top-level ServiceDescribe field for
    // this fact; auth_metadata MUST NOT carry a second unregistered copy.
    let auth_metadata = AuthMetadata {
        account_authority: Some(AccountAuthority {
            origin: arkret_wire::WebOrigin::new(account_origin)
                .expect("configured account authority base has a valid Web origin"),
            gate_account_base_url,
            extra: Default::default(),
        }),
        methods,
        did_binding_methods: Vec::new(),
        extra: Default::default(),
    };
    let local_extension_operations = local_extension_operations();

    // Round 4 (B1) — ServiceDescribe: 17 required top-level fields.
    // Implemented / claimed / verified profiles are partitioned per spec
    // service-surface.md §3.0; `verified_profiles` MUST be empty when
    // `development_mode=true`. The full T6.1 claim-level partition layer
    // in routing::system::describe::apply_conformance_evidence still
    // overrides these typed fields before serialization — we keep typed
    // defaults here so out-of-tree typed consumers see the correct shape
    // and pass `ServiceDescribe::validate`.
    let verified_profiles = Vec::new();
    let interop_surfaces = Vec::new();
    let service_id = arkret_wire::project_did_to_core_id(&service_resolution.did)
        .expect("service resolution DID must project to a stable service id");
    let plaintext_visibility = arkret_models_discovery::service_description::PlaintextVisibility {
        data_classes: vec![
            arkret_wire::PlaintextDataClassKind::MessageContent,
            arkret_wire::PlaintextDataClassKind::AttachmentPlaintext,
            arkret_wire::PlaintextDataClassKind::AttachmentPreview,
            arkret_wire::PlaintextDataClassKind::Thumbnail,
            arkret_wire::PlaintextDataClassKind::FullTextIndex,
            arkret_wire::PlaintextDataClassKind::NotificationSummary,
            arkret_wire::PlaintextDataClassKind::MediaPlaintext,
        ],
        max_visibility: Some(arkret_models_discovery::service_description::PlaintextMaxVisibility::PrivatePlaintext),
        event_kinds: vec![
            arkret_wire::event_kind_str::MESSAGE_CREATE.to_owned(),
            arkret_wire::event_kind_str::REALM_POLICY_BUNDLE.to_owned(),
            arkret_wire::event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES.to_owned(),
        ],
        payload_paths: vec![
            "payload.content".to_owned(),
            "payload.body".to_owned(),
            "payload.media_service_decrypts".to_owned(),
        ],
        blob_purposes: vec![
            "download".to_owned(),
            "file_transfer".to_owned(),
            "attachment_preview".to_owned(),
            "thumbnail".to_owned(),
            "search_index_shard".to_owned(),
        ],
        projection_outputs: vec![
            "timeline.message_content".to_owned(),
            "blob.upload".to_owned(),
            "push.minimal_or_visible_notification".to_owned(),
            "search.encrypted_or_authorized_index".to_owned(),
        ],
        notes: Some(
            "Coland only accepts private plaintext when the current Realm policy lists this service DID with matching plaintext_visible_services.data_classes; otherwise it fails closed."
                .to_owned(),
        ),
        extra: Default::default(),
    };

    ServiceDescribe {
        service_id: service_id.clone(),
        service_resolution: service_resolution.clone(),
        trust_domain: trust_domain
            .parse()
            .expect("trust_domain must be ak:trust_domain:<scope>"),
        service_kind: arkret_wire::ServiceKind::Station,
        protocol_version: arkret_models_discovery::ServiceProtocolVersion::V1,
        supported_profiles: {
            let mut profiles = vec![
                arkret_wire::ProfileId::CORE_EVENT_STORE_V1.to_owned(),
                arkret_wire::ProfileId::STATION_V1.to_owned(),
                arkret_wire::ProfileId::STATION_EVENTS_API_V1.to_owned(),
                arkret_wire::ProfileId::MIMI_INTEROP_V1.to_owned(),
                arkret_wire::ProfileId::FILE_TRANSFER_V1.to_owned(),
                arkret_wire::ProfileId::WEBRTC_MEDIA_V1.to_owned(),
                ProfileId::DIRECT_CONVERSATION_REALM_V1.to_owned(),
            ];
            // PROF-1 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) —
            // advertise `ak.profile.media_service_binding.v1` whenever the
            // server exposes the `ak.self.call.media.exchange.issue_token.v1`
            // handler. coland mounts the handler unconditionally, and also
            // claims the required `ak.profile.webrtc_media.v1` dependency above.
            profiles.push(arkret_wire::ProfileId::MEDIA_SERVICE_BINDING_V1.to_owned());
            if websocket_binding.is_some() {
                profiles.push(arkret_wire::ProfileId::BINDING_WEBSOCKET_V1.to_owned());
            }
            profiles
        },
        profile_bindings: Default::default(),
        supported_operation_bundles: {
            let mut bundles = vec![
            // Caller-signed actor-private Events without a dedicated operation
            // (actor-private-effects.md §2.1).
            "ak.operation_bundle.station.actor_private_events.v1".to_owned(),
            "ak.operation_bundle.station.agent_pairing_handoff.v1".to_owned(),
            "ak.operation_bundle.station.agent_runtime.v1".to_owned(),
            "ak.operation_bundle.station.applet.v1".to_owned(),
            "ak.operation_bundle.station.applet_ghost.v1".to_owned(),
            "ak.operation_bundle.station.applet_install.v1".to_owned(),
            "ak.operation_bundle.station.describe.v1".to_owned(),
            // service-surface.md 2.7: the client-visible stage/resolve/status
            // origin is the Station, which forwards the exact DTO to its
            // Account Authority. The Authority is a Station-internal role, so
            // its unavailability is runtime availability, not a missing member.
            "ak.operation_bundle.station.device_pairing_handoff.v1".to_owned(),
            "ak.operation_bundle.station.http_core_current.v1".to_owned(),
            // Private invite dispatch is a mounted optional operation. It has
            // its own bundle so core tier no longer implies reachability.
            "ak.operation_bundle.station.invite_delivery.v1".to_owned(),
            // The recipient's own read of the claim a Welcome names
            // (device-lifecycle.md §9 `claims/query`, decision 0119).
            "ak.operation_bundle.station.keypackage_claim_read.v1".to_owned(),
            "ak.operation_bundle.station.mimi_interop.v1".to_owned(),
            "ak.operation_bundle.station.push.v1".to_owned(),
            // Exact by-ref read of a Snapshot this Station issued to the
            // caller at `/head`, re-proved for disclosure at the read cut.
            "ak.operation_bundle.station.snapshot_exact_read.v1".to_owned(),
            // The Station issues this proof independently of a third-party
            // provider's complete token handoff and delivery capabilities.
            "ak.operation_bundle.station.third_party_invite_acceptance_attestation.v1".to_owned(),
            "ak.operation_bundle.station.tus_upload.v1".to_owned(),
            ];
            if websocket_binding.is_some() {
                bundles.push("ak.operation_bundle.station.websocket.v1".to_owned());
            }
            bundles
        },
        transport_bindings: {
            let mut bindings = vec![
            arkret_models_discovery::TransportBinding::HttpJson {
                base_url: format!("{}/", public_base_url.trim_end_matches('/')),
                extension_profile_required: (),
            },
            arkret_models_discovery::TransportBinding::Tus {
                base_url: format!(
                    "{}/_arkret/self/blob/resumable",
                    public_base_url.trim_end_matches('/')
                ),
                extension_profile_required: (),
                tus_version: vec![
                    arkret_models_discovery::service_description::TusVersion::V1_0_0,
                ],
                tus_extensions: vec![
                    arkret_models_discovery::service_description::TusExtension::Creation,
                    arkret_models_discovery::service_description::TusExtension::CreationWithUpload,
                    arkret_models_discovery::service_description::TusExtension::Checksum,
                    arkret_models_discovery::service_description::TusExtension::Expiration,
                    arkret_models_discovery::service_description::TusExtension::Termination,
                ],
            },
            ];
            if let Some(binding) = websocket_binding {
                bindings.push(binding);
            }
            bindings
        },
        plaintext_visibility,
        calendar_tzdb_versions: Vec::new(),
        verified_profiles,
        interop_surfaces,
        invite_addressing: None,
        development_mode,
        // service-describe.schema.json requires `rate_limit_policy` or
        // `rate_limit_policy_id`. Derive the advertised per-class policy from the SAME runtime
        // config the HTTP middleware enforces so wire and
        // enforcement can never drift — a conformant client budgeting against
        // this policy cannot trip a 429 it could not predict.
        rate_limit_policy: Some(
            config.rate_limiter.advertised_policy(),
        ),
        rate_limit_policy_id: None,
        egress_network_policy: Some(arkret_models_discovery::service_description::EgressNetworkPolicy::deny_private_defaults()),
        resource_kinds: Vec::new(),
        supported_features: vec![
            "ak.feature.agent_runtime_approval_notifications.v1".to_owned(),
            "ak.feature.blob.resumable_upload.tus.v1".to_owned(),
            arkret_models_collaboration::objects::direct_conversation::DIRECT_CONVERSATION_REALM_ROLE_FEATURE.to_owned(),
            "ak.feature.mls_last_resort_keypackage.v1".to_owned(),
        ],
        auth_metadata,
        privacy_derivation: Some(crate::routing::push_target_privacy_derivation_claim(now())),
        receive_policy_constraints: None,
        limits: arkret_models_discovery::service_description::ServerLimits {
            extensions: serde_json::from_value(serde_json::json!({
            "storage": storage,
            "max_limit": 100,
            // Spec media-and-blob.md §2.1 limits keys for the resumable
            // (tus) upload binding.
            "resumable_upload_incomplete_ttl_seconds": resumable_upload_incomplete_ttl_seconds,
            "resumable_upload_max_bytes": crate::routing::MAX_BLOB_UPLOAD_BYTES,
            "registries": artifacts::registry_summary(),
            "plaintext_visible_service_capability": {
                "supported": true,
                "service_id": service_id,
                "enforced_on": [
                    "self.events.message_content",
                    "federation.push_operations",
                    "federation.transaction",
                    "blob.upload.attachment_plaintext",
                    "blob.upload.attachment_preview",
                    "blob.upload.thumbnail",
                    "blob.upload.full_text_index",
                    "search.index.full_text_index"
                ],
                "requires_data_classes": true
            },
            "authz_policy": {
                "surface": "authz_policy",
                "tier": "extension",
                "self_surface_status": "standard_self_supported",
                "operation_registry_source": "arkret-spec/spec/v1/artifacts/registry/operation-registry.json",
                "error_mapping_source": "arkret-spec/spec/v1/artifacts/registry/operations-error-mapping.json",
                "universal_error_codes_inherited": true,
                "operations": [
                    arkret_wire::ServiceOperationId::SELF_AUTHZ_READ_CHECK_V1,
                    arkret_wire::ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1,
                    arkret_wire::ServiceOperationId::SELF_AUTHZ_INVITES_READ_LIST_V1
                ],
                "authz_check": {
                    "operation_id": arkret_wire::ServiceOperationId::SELF_AUTHZ_READ_CHECK_V1,
                    "method": "POST",
                    "path": "/_arkret/self/authz/check",
                    "request_shape": "AuthzCheckRequestBody",
                    "response_shape": "AuthzCheckOutcome",
                    "operation_specific_error_codes": [],
                    "decision_source": "local_projection_preflight_diagnostic",
                    "signed_decision": false,
                    "emits_dynamic_obligations": false,
                    "usable_as_event_auth_context": false,
                    "explain_fields": [
                        "matched_grants",
                        "applied_constraints",
                        "policy_results",
                        "missing_proofs",
                        "reason_code"
                    ],
                    "policy_boundary": {
                        "dynamic_claim_or_approval": false,
                        "usable_as_policy_obligation_proof": false,
                        "cross_service_signed_authorization_fact": false
                    }
                },
                "effective_grants": {
                    "operation_id": arkret_wire::ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1,
                    "method": "GET",
                    "path": "/_arkret/self/authz/effective-grants",
                    "query": ["realm_id", "subject", "subject_station_id", "at"],
                    "response_shape": "GrantList",
                    "subject_scope": "authenticated_actor_or_realm_owner_for_realm_scoped_queries",
                    "operation_specific_error_codes": []
                },
                "invites": {
                    "operation_id": arkret_wire::ServiceOperationId::SELF_AUTHZ_INVITES_READ_LIST_V1,
                    "method": "GET",
                    "path": "/_arkret/self/authz/invites",
                    "query": ["realm_id", "subject", "cursor"],
                    "response_schema_ref": "schemas/authz-operations.schema.json#/$defs/authz_invite_list",
                    "subject_scope": "authenticated_actor_or_inviter_or_realm_owner",
                    "operation_specific_error_codes": []
                }
            },
            "search": {
                "directory": {
                    "operation_prefix": "ak.find.directory.",
                    "resource_kinds": ["realm"],
                    "returns_message_hits": false,
                    "returns_snippets": false
                },
                "client_index": {
                    "profile": arkret_wire::ProfileId::SEARCH_CLIENT_INDEX_V1,
                    "manifest_account_data_key": arkret_wire::AccountDataKey::SEARCH_INDEX_MANIFEST_V1,
                    "manifest_storage": "encrypted_private_account_data",
                    "shard_blob_purpose": "search_index_shard",
                    "shard_storage": "encrypted_blob_bytes",
                    "returns_hits": false,
                    "returns_snippets": false,
                    "term_metadata": false
                },
                "realm_private_message_search": {
                    "plaintext_remote_search": false,
                    "directory_surface": "directory_only",
                    "requires_plaintext_visible_services_for_plaintext": true
                }
            },
            "personal_productivity": {
                "reminders": {
                    "profile": arkret_wire::ProfileId::PERSONAL_PRODUCTIVITY_V1,
                    "account_data_key": arkret_wire::AccountDataKey::REMINDERS_V1,
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "server_action": "local_or_push_wake_only",
                    "wakeup_kind": "reminder",
                    "target_ref_visible_in_shared_event": false,
                    "note_visible_in_shared_event": false
                },
                "scheduled_send": {
                    "profile": arkret_wire::ProfileId::PERSONAL_PRODUCTIVITY_V1,
                    "account_data_key": arkret_wire::AccountDataKey::SCHEDULED_SEND_V1,
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "server_dispatches_message_create": false,
                    "server_action": "holder_wake_sync_only",
                    "wakeup_kind": "scheduled_send",
                    "planned_message_id_anchor": "ak.message.create.payload.message_id",
                    "shared_history_materialization": "client_submitted_ak.message.create_only"
                },
                "snooze": {
                    "profile": arkret_wire::ProfileId::PERSONAL_PRODUCTIVITY_V1,
                    "account_data_key": arkret_wire::AccountDataKey::SNOOZE_V1,
                    "storage": "encrypted_private_account_data",
                    "plaintext_payload_accepted": false,
                    "target_key": "holder_derived_unlinkable",
                    "private_projection_scope": "holder_only",
                    "shared_state_mutation": false,
                    "target_ref_visible_in_shared_event": false
                }
            },
            "scalability_constraints": {
                "source": "arkret-spec/spec/v1/zh/conformance/scalability-constraints.md",
                "max_event_bytes": MAX_EVENT_ENVELOPE_BYTES,
                "max_events_batch_submit": MAX_EVENT_SUBMIT_BATCH,
                "max_page_items": 100,
                "max_semantic_refs": MAX_SEMANTIC_REFS,
                "max_auth_refs": MAX_AUTHORIZED_BY_REFS,
                "max_relation_expansion_depth": 32,
                "max_authority_depth": 4,
                "max_grants_per_decision": 1024,
                "max_grant_constraints": 64,
                "max_resource_selector_depth": 16,
                "daily_principal_download_limit": config.key_backup_daily_download_limit,
                "max_to_device_page": 1000,
                "max_to_device_queue_per_device": to_device_queue_capacity
            },
            "profile_status": {
                "conformance": "limited_reference",
                "unsupported_profiles": [
                    {
                        "profile": "org.arkret.coland.profile.limited_server.v1",
                        "status": "unsupported",
                        "reason": "limited profile is a limitation descriptor, not a conformance claim"
                    }
                ],
                "full_profiles_not_claimed": [
                    arkret_wire::ProfileId::STATION_V1,
                    arkret_wire::ProfileId::DIRECTORY_SERVICE_V1,
                    arkret_wire::ProfileId::IDENTITY_REGISTRY_V1,
                    arkret_wire::ProfileId::BLOB_NODE_V1
                ],
                "station_full_profile_gaps": full_station_gap_summary(),
                "local_extension_operations": local_extension_operations,
                "local_extension_operation_source": "transport_registry+live_openapi",
                "implemented_surfaces": [
                    "station",
                    "events_api_minimal",
                    "sync",
                    "index",
                    "authz_policy",
                    "circle_management",
                    "identity_registry_local_dev",
                    "blob_node_local",
                    "directory_service",
                    "mimi_provider_facade"
                ],
                "limitations": profile_limitations(),
                "mimi_interop": mimi_interop_profile_status
            }
            }))
            .expect("server limits must be a JSON object"),
        },
        extensions: Default::default(),
    }
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

// ── Conversation Model DTOs ──

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_service_resolution() -> arkret_models_identity::ResolutionCommitment {
        arkret_models_identity::ResolutionCommitment {
            did: arkret_wire::Did::new("did:web:coland.example").unwrap(),
            method_history_head: "fixture-history-head".to_owned(),
            version_id: "fixture-v1".to_owned(),
        }
    }

    #[test]
    fn service_describe_preserves_canonical_oidc_issuer() {
        let description = describe(
            &fixture_service_resolution(),
            "memory",
            &crate::config::AppConfig {
                account_authority_url: Some("https://auth.example/".to_owned()),
                oidc_client_id: Some("01GFWR28C4KNE04WG3HKXB7C9R".to_owned()),
                ..crate::config::AppConfig::test_default()
            },
        );

        let method = description
            .auth_metadata
            .methods
            .first()
            .expect("configured Account Authority advertises OIDC");
        assert_eq!(method.issuer_uri.as_deref(), Some("https://auth.example/"));
        assert_eq!(
            method.openid_configuration_url.as_deref(),
            Some("https://auth.example/.well-known/openid-configuration")
        );
    }

    #[test]
    fn websocket_advertisement_is_complete_on_https_and_http_keeps_fallback() {
        for development_mode in [false, true] {
            for base_url in ["https://coland.example/", "http://localhost/"] {
                let description = describe(
                    &fixture_service_resolution(),
                    "memory",
                    &crate::config::AppConfig {
                        public_base_url: base_url.to_owned(),
                        development_mode,
                        ..crate::config::AppConfig::test_default()
                    },
                );
                let secure = base_url.starts_with("https:");
                assert_eq!(
                    description
                        .supported_profiles
                        .iter()
                        .any(|id| id.as_str() == arkret_wire::ProfileId::BINDING_WEBSOCKET_V1),
                    secure
                );
                assert_eq!(
                    arkret_models_discovery::websocket_binding::websocket_operations_reachable(
                        &description
                    ),
                    secure
                );
                assert_eq!(
                    arkret_models_discovery::websocket_binding::select_websocket_binding(
                        &description,
                        262_144
                    )
                    .is_some(),
                    secure
                );
                for operation in [
                    arkret_wire::WebSocketOperationId::AccountStreamSubscribe,
                    arkret_wire::WebSocketOperationId::CommittedEventStreamSubscribe,
                    arkret_wire::WebSocketOperationId::SignalStreamSubscribe,
                ] {
                    let operation =
                        arkret_wire::ServiceOperationId::from_wire(operation.as_str()).unwrap();
                    assert!(
                        description.supports_operation_binding(
                            operation,
                            arkret_wire::BindingKind::HttpJson
                        )
                    );
                    assert_eq!(
                        description.supports_operation_binding(
                            operation,
                            arkret_wire::BindingKind::Websocket
                        ),
                        secure
                    );
                }
            }
        }
    }

    #[test]
    fn service_describe_advertises_bundles_and_transport_roots() {
        let description = describe(
            &fixture_service_resolution(),
            "memory",
            &crate::config::AppConfig {
                public_base_url: "https://coland.example/".to_owned(),
                development_mode: true,
                ..crate::config::AppConfig::test_default()
            },
        );
        for operation in [
            arkret_wire::ServiceOperationId::SelfMessagesCommandPrepareV1,
            arkret_wire::ServiceOperationId::SelfRealmJoinCommandPrepareV1,
            arkret_wire::ServiceOperationId::PeerRealmJoinReadBootstrapV1,
            arkret_wire::ServiceOperationId::SelfRealmStateSnapshotReadManifestHeadV1,
            arkret_wire::ServiceOperationId::SelfRealmStateSnapshotReadByRefV1,
            arkret_wire::ServiceOperationId::SelfThirdPartyInviteReadAcceptanceAttestationV1,
        ] {
            assert!(
                description
                    .supports_operation_binding(operation, arkret_wire::BindingKind::HttpJson,)
            );
        }
        description
            .validate()
            .expect("advertised bundles are registered");
        assert!(
            arkret_models_discovery::websocket_binding::websocket_operations_reachable(
                &description
            )
        );
        assert!(matches!(
            arkret_models_discovery::websocket_binding::select_websocket_binding(&description, 262_144),
            Some(arkret_models_discovery::TransportBinding::Websocket { base_url, max_frame_bytes: 262_144, max_channels: 16 })
                if base_url == "wss://coland.example/_arkret/ws"
        ));
        let value = serde_json::to_value(description).expect("description serializes");
        assert!(value["limits"].get("mls_governance_proof").is_none());
        assert_eq!(value["transport_bindings"][0]["kind"], "http_json");
        assert_eq!(
            value["transport_bindings"][0]["base_url"],
            "https://coland.example/"
        );
        let bundles = value["supported_operation_bundles"]
            .as_array()
            .expect("operation bundle ids are present");
        assert!(bundles.contains(&json!(
            "ak.operation_bundle.station.actor_private_events.v1"
        )));
        assert!(bundles.contains(&json!("ak.operation_bundle.station.describe.v1")));
        assert!(bundles.contains(&json!(
            "ak.operation_bundle.station.device_pairing_handoff.v1"
        )));
        assert!(bundles.contains(&json!(
            "ak.operation_bundle.station.third_party_invite_acceptance_attestation.v1"
        )));
        assert!(!bundles.contains(&json!(
            "ak.operation_bundle.station.third_party_invite_handoff.v1"
        )));
        assert!(!bundles.contains(&json!(
            "ak.operation_bundle.station.history_key_recovery.v1"
        )));
        assert!(bundles.contains(&json!("ak.operation_bundle.station.http_core_current.v1")));
        assert!(bundles.contains(&json!("ak.operation_bundle.station.invite_delivery.v1")));
        assert!(bundles.contains(&json!("ak.operation_bundle.station.tus_upload.v1")));
        assert!(value["transport_bindings"][0]["extension_profile_required"].is_null());
        assert!(value["transport_bindings"][0].get("operations").is_none());
        assert_eq!(
            value["transport_bindings"][1]["kind"],
            json!("tus"),
            "tus companion binding advertised"
        );
        assert_eq!(
            value["transport_bindings"][1]["base_url"],
            json!("https://coland.example/_arkret/self/blob/resumable")
        );
        assert!(value["transport_bindings"][1].get("operations").is_none());
        assert!(value["transport_bindings"][1]["extension_profile_required"].is_null());
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!("ak.feature.blob.resumable_upload.tus.v1"))
        );
        assert!(
            !value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!("ak.feature.history_key_recovery.v1"))
        );
        assert!(
            value["supported_features"]
                .as_array()
                .expect("features array")
                .contains(&json!("ak.feature.agent_runtime_approval_notifications.v1"))
        );
        let description: arkret_models_discovery::ServiceDescribe =
            serde_json::from_value(value.clone()).expect("description round-trips");
        for operation in [
            arkret_wire::ServiceOperationId::OpenDevicePairingCommandStageV1,
            arkret_wire::ServiceOperationId::OpenDevicePairingReadResolveV1,
            arkret_wire::ServiceOperationId::OpenDevicePairingReadStatusV1,
        ] {
            assert!(
                description
                    .supports_operation_binding(operation, arkret_wire::BindingKind::HttpJson)
            );
        }
        assert!(!description.supports_operation_binding(
            arkret_wire::ServiceOperationId::OpenThirdPartyInviteCommandPresentTokenV1,
            arkret_wire::BindingKind::HttpJson
        ));
        for operation in [
            arkret_wire::ServiceOperationId::SelfSecurityTransactionCommandContinueV1,
            arkret_wire::ServiceOperationId::SelfSecurityTransactionCommandCreateV1,
            arkret_wire::ServiceOperationId::SelfSecurityTransactionResourceGetV1,
        ] {
            assert!(
                description
                    .supports_operation_binding(operation, arkret_wire::BindingKind::HttpJson,)
            );
        }
        description
            .validate()
            .expect("service description advertisement must remain transport-closed");
        assert_eq!(
            value["privacy_derivation"]["push_target_id_derivation"]["derivation_profile"],
            json!("ak.push_target_id.hmac_sha256.v1")
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id_derivation"]["secret_scope"],
            json!("per_service")
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id_derivation"]["salt_rotation_seconds"],
            json!(30 * 24 * 60 * 60)
        );
        assert_eq!(
            value["privacy_derivation"]["push_target_id_derivation"]["input_binding"],
            json!(["account_id", "device_id", "push_route_id", "salt_epoch_id"])
        );
        assert_eq!(
            value["limits"]["resumable_upload_incomplete_ttl_seconds"],
            json!(86_400)
        );
        assert_eq!(
            value["limits"]["resumable_upload_max_bytes"],
            json!(10 * 1024 * 1024)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_event_bytes"],
            json!(arkret_wire::event_envelope::MAX_EVENT_ENVELOPE_BYTES)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_events_batch_submit"],
            json!(arkret_wire::event_envelope::MAX_EVENT_SUBMIT_BATCH)
        );
        assert!(
            value["limits"]["scalability_constraints"]
                .get("max_prev_refs")
                .is_none()
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_semantic_refs"],
            json!(arkret_wire::event_envelope::MAX_SEMANTIC_REFS)
        );
        assert_eq!(
            value["limits"]["search"]["directory"]["returns_message_hits"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["search"]["client_index"]["manifest_storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["search"]["client_index"]["shard_blob_purpose"],
            json!("search_index_shard")
        );
        assert_eq!(
            value["limits"]["search"]["realm_private_message_search"]["plaintext_remote_search"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["self_surface_status"],
            json!("standard_self_supported")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["operations"],
            json!([
                "ak.self.authz.read.check.v1",
                "ak.self.authz.grants.read.effective.v1",
                "ak.self.authz.invites.read.list.v1"
            ])
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["decision_source"],
            json!("local_projection_preflight_diagnostic")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["path"],
            json!("/_arkret/self/authz/check")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["operation_specific_error_codes"],
            json!([])
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["signed_decision"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["authz_check"]["emits_dynamic_obligations"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["authz_policy"]["effective_grants"]["path"],
            json!("/_arkret/self/authz/effective-grants")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["effective_grants"]["subject_scope"],
            json!("authenticated_actor_or_realm_owner_for_realm_scoped_queries")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["invites"]["path"],
            json!("/_arkret/self/authz/invites")
        );
        assert_eq!(
            value["limits"]["authz_policy"]["invites"]["response_schema_ref"],
            json!("schemas/authz-operations.schema.json#/$defs/authz_invite_list")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["wakeup_kind"],
            json!("reminder")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["target_ref_visible_in_shared_event"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["reminders"]["note_visible_in_shared_event"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["server_dispatches_message_create"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["server_action"],
            json!("holder_wake_sync_only")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["scheduled_send"]["wakeup_kind"],
            json!("scheduled_send")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["snooze"]["storage"],
            json!("encrypted_private_account_data")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["snooze"]["target_key"],
            json!("holder_derived_unlinkable")
        );
        assert_eq!(
            value["limits"]["personal_productivity"]["snooze"]["shared_state_mutation"],
            json!(false)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["max_to_device_queue_per_device"],
            json!(10_000)
        );
        assert_eq!(
            value["limits"]["scalability_constraints"]["daily_principal_download_limit"],
            json!(coland_services::runtime_guards::KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
        );
    }
}
