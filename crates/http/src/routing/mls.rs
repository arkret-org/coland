//! G3.S1 — MLS / E2EE lifecycle HTTP surface.
//!
//! Spec-canonical binding under `/_arkret/self/keys/keypackages/*` (see
//! `arkret-service-api.openapi.yaml §/keys/keypackages/*`):
//!
//! - `POST /_arkret/self/keys/keypackages/upload` — op `ak.self.keys.keypackages.upload.create.v1`
//!   (publishes a fresh KeyPackage).
//! - `POST /_arkret/self/keys/keypackages/claim`  — op `ak.self.keys.keypackages.command.claim.v1`
//!   (atomically claim a published KeyPackage; second claim of the same id returns `409
//!   cas_conflict`).
//!
//! MLS *commits* have no dedicated REST surface: clients submit
//! `ak.mls.genesis` and `ak.mls.commit` through `POST /_arkret/self/events`
//! (`ak.self.events.command.submit.v1`), and the MLS authority unit
//! (`state::authority_mls_unit`) installs the `mls_group` typed current with
//! every Welcome at the covering RealmCommit.
//!
//! Each handler:
//!   1. authenticates the caller via [`AuthArgs`] (bearer session);
//!   2. applies the KeyPackage lifecycle transition to the durable ledger;
//!   3. mirrors accepted KeyPackage state into the in-process projection.
//!
//! Deferred (mapped to TODO(G3.S1-followup) markers in `reducer/mls.rs`):
//!   - decryption_pending   — deferred-decryption queue + retry.
//!
//! Recipient-private Welcome delivery is carried by the formal authority-commit
//! transaction, never by a shared Realm Event.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{Hash, RealmId};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
use arkret_models_crypto::{
    Failure as KeypackageFailure, KeyOperationSignature, KeyPackageClaimRecord,
    KeyPackageClaimTerminalReceipt, KeyPackageClaimTerminalState, KeyPackageConsumeReceipt,
    KeyPackageUploadEntry, KeyPackagesClaimOutcome, KeyPackagesClaimQueryRequestBody,
    KeyPackagesClaimRequestBody, KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody,
    KeyPackagesRevokeOutcome, KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome,
    KeyPackagesUploadRequestBody, PeerKeyPackageClaimErrorCode, PeerKeyPackageClaimPurpose,
    PeerKeyPackageClaimReceipt, PeerKeyPackageRequesterAuthorization, PeerKeyPackagesClaimOutcome,
    PeerKeyPackagesClaimQueryOutcome, PeerKeyPackagesClaimQueryRequestBody,
    PeerKeyPackagesClaimQueryState, PeerKeyPackagesClaimRequestBody,
    keypackage_claim_authorization_signing_bytes, peer_keypackage_claim_receipt_signing_bytes,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use coland_domain::reducer::mls::KeyPackageTrustBinding;
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::events::{
    ClaimMlsKeyPackageCommand, ClaimMlsKeyPackageTarget, MlsKeyPackageState as MlsKeyPackageRow,
    PeerKeyPackageClaimCommand as PeerKeyPackageClaimAttempt,
    PeerKeyPackageClaimLedgerState as PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult,
    PeerKeyPackageClaimResult as PeerKeyPackageClaimAttemptResult, PersistedKeyPackageClaimState,
    PersistedKeyPackageReusePolicy,
};
use coland_services::identity::SessionIdentityState as SessionRecord;
use coland_services::projection::{MlsProjectionEffect, ProjectionEffectView};
use ed25519_dalek::Signer as _;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::Value;

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::now;

/// Canonical MLS event-payload field readers shared by every surface that
/// inspects a raw `ak.mls.*` payload (submit preflight, projection mirroring,
/// sync visibility, sidecar binding, MIMI interop, circle scope rotation).
#[path = "mls_payload_fields.rs"]
pub(crate) mod payload_fields;

#[path = "mls_roster_read.rs"]
mod mls_roster_read;
#[path = "mls_roster_signature.rs"]
mod mls_roster_signature;

const LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

async fn ensure_keypackage_owner_account_active(
    state: &AppState,
    owner_account_pk: coland_storage::AccountPk,
) -> Result<(), AppError> {
    let account = state
        .identities()
        .account_by_id(owner_account_pk)
        .await
        .map_err(|error| AppError::internal(format!("owner account lookup failed: {error}")))?
        .ok_or_else(|| AppError::capability_denied("owner account is unavailable"))?;
    if state.account_lifecycle_status(account.principal_id.as_str())
        != arkret_models_collaboration::objects::account_status::AccountStatus::Active
    {
        return Err(AppError::capability_denied("owner account is not active"));
    }
    Ok(())
}

async fn local_keypackage_owner_account_pk(
    state: &AppState,
    session: &SessionRecord,
) -> Result<coland_storage::AccountPk, AppError> {
    if session.agent_session().is_some() {
        let principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|_| AppError::capability_denied("Agent principal id is invalid"))?;
        let station_id = arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|_| AppError::internal("local Station id is invalid"))?;
        let actor =
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal_id, station_id));
        let agent = crate::routing::identity::agent_pcr::agent_record_for_actor(state, &actor)
            .await?
            .ok_or_else(|| AppError::capability_denied("Agent principal is unavailable"))?;
        let controller =
            crate::routing::identity::agent_pcr::agent_controller_account(state, &agent).await?;
        let account = state
            .identities()
            .account(&controller)
            .await
            .map_err(|error| {
                AppError::internal(format!("Agent controller Account lookup failed: {error}"))
            })?
            .ok_or_else(|| {
                AppError::capability_denied("Agent controller Account is unavailable")
            })?;
        ensure_keypackage_owner_account_active(state, account.pk).await?;
        return Ok(account.pk);
    }

    let actor_id = &session.actor;
    let principal_id = arkret_wire::DidCoreId::new(actor_id.to_owned())
        .map_err(|_| AppError::capability_denied("owner principal id is invalid"))?;
    let station_id = arkret_wire::DidCoreId::new(state.service_id().clone())
        .map_err(|_| AppError::internal("local Station id is invalid"))?;
    let account_id = arkret_wire::AccountId::new(principal_id, station_id);
    let account = state
        .identities()
        .account(&account_id)
        .await
        .map_err(|error| AppError::internal(format!("owner account lookup failed: {error}")))?
        .ok_or_else(|| AppError::capability_denied("owner account is unavailable"))?;
    if account.principal_id.as_str() != actor_id {
        return Err(AppError::capability_denied(
            "owner account principal binding is invalid",
        ));
    }
    if state.account_lifecycle_status(account.principal_id.as_str())
        != arkret_models_collaboration::objects::account_status::AccountStatus::Active
    {
        return Err(AppError::capability_denied("owner account is not active"));
    }
    Ok(account.pk)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyPackageTrustSelector {
    Principal(KeyPackageTrustBinding),
    PerDevice(BTreeMap<String, KeyPackageTrustBinding>),
}

/// Lift the reducer's exactly-one-of validation into this layer's error type.
/// The reducer owns the rule and the `claim_generation_mismatch` reason code;
/// only the operator-facing message differs per call site.
fn trust_binding_from_parts(
    device_authorize_event_id: Option<String>,
    agent_key_authorize_event_id: Option<String>,
    message: &'static str,
) -> Result<KeyPackageTrustBinding, AppError> {
    KeyPackageTrustBinding::from_parts(device_authorize_event_id, agent_key_authorize_event_id)
        .map_err(|reason_code| {
            crate::app_error!(FailedPrecondition, message).with_rejection_code(reason_code)
        })
}

fn trust_binding_from_keypackage(
    kp: &MlsKeyPackageRow,
) -> Result<KeyPackageTrustBinding, AppError> {
    trust_binding_from_parts(
        kp.device_authorize_event_id.clone(),
        kp.agent_key_authorize_event_id.clone(),
        "KeyPackage trust binding is invalid",
    )
}

fn trust_binding_from_row(row: &MlsKeyPackageRow) -> Result<KeyPackageTrustBinding, AppError> {
    trust_binding_from_parts(
        row.device_authorize_event_id.clone(),
        row.agent_key_authorize_event_id.clone(),
        "KeyPackage claim is missing a valid trust binding",
    )
}

fn trust_binding_matches_keypackage(
    binding: &KeyPackageTrustBinding,
    kp: &MlsKeyPackageRow,
) -> bool {
    kp.device_authorize_event_id == binding.device_authorize_event_id
        && kp.agent_key_authorize_event_id == binding.agent_key_authorize_event_id
}

impl KeyPackageTrustSelector {
    fn matches_keypackage(&self, kp: &MlsKeyPackageRow) -> bool {
        match self {
            Self::Principal(binding) => trust_binding_matches_keypackage(binding, kp),
            Self::PerDevice(bindings) => bindings
                .get(kp.device_id.as_deref().unwrap_or(""))
                .is_some_and(|binding| trust_binding_matches_keypackage(binding, kp)),
        }
    }
}

/// Mount the `/keys/keypackages/*` sub-router. Mounted under
/// `/_arkret/self` from `routing::mod::arkret_protocol_router`.
///
/// Spec-canonical paths (see
/// `arkret-service-api.openapi.yaml §/keys/keypackages/*`):
///   - `POST /_arkret/self/keys/keypackages/upload`
///   - `POST /_arkret/self/keys/keypackages/claim`
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("keys").push(
                Router::with_path("keypackages")
                    .push(Router::with_path("upload").post(upload_keypackage))
                    .push(Router::with_path("claim").post(claim_keypackage))
                    .push(Router::with_path("claims/query").post(query_own_keypackage_claim))
                    .push(Router::with_path("consume").post(consume_keypackages))
                    .push(Router::with_path("revoke").post(revoke_keypackages)),
            ),
        )
        .push(
            Router::with_path("mls/group-state-material/query")
                .post(resolve_self_mls_group_state_material),
        )
        .push(
            Router::with_path("mls/roster-authority/query")
                .post(mls_roster_read::resolve_self_mls_roster_authority),
        )
}

pub(crate) fn peer_router() -> Router {
    Router::new()
        .push(
            Router::with_path("keys/keypackages")
                .push(Router::with_path("claim").post(peer_claim_keypackage))
                .push(Router::with_path("claims/query").post(peer_query_keypackage_claim)),
        )
        .push(
            Router::with_path("mls/group-state-material")
                .post(resolve_peer_mls_group_state_material),
        )
        .push(
            Router::with_path("mls/roster-authority/query")
                .post(mls_roster_read::resolve_peer_mls_roster_authority),
        )
        .push(Router::with_path("mls/add-authority-attestations").post(peer_mls_attest_add))
}

/// HTTP-local schema carrier: the protocol's closed nested DTOs remain owned
/// by arkret-models-collaboration. The normative OpenAPI schema is generated
/// from arkret-spec; these value_type annotations avoid adding Salvo derives
/// to SDK protocol types just for this service router.
#[derive(serde::Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
struct MlsAttestAddHttpRequest {
    #[salvo(schema(value_type = serde_json::Value))]
    attestation: arkret_models_collaboration::mls_roster_authority::MlsAddAuthorityAttestation,
    #[salvo(schema(value_type = serde_json::Value))]
    claim_outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome,
}

#[derive(serde::Serialize, salvo::oapi::ToSchema)]
struct MlsAttestAddHttpOutcome {
    #[salvo(schema(value_type = String))]
    status: arkret_models_collaboration::mls_roster_authority::MlsAttestAddStatus,
    #[salvo(schema(value_type = String))]
    attestation_digest: arkret_wire::Hash,
}

fn mls_attest_add_service_error(error: coland_services::ServiceError) -> AppError {
    use coland_services::ServiceError;
    match error {
        ServiceError::NotFound(_) => AppError::not_found("MLS Add authority source unavailable"),
        ServiceError::Conflict(detail) => {
            let code = coland_storage::ConflictCode::from_detail(&detail);
            let wire_code = match code {
                Some(coland_storage::ConflictCode::DuplicateConflict) => {
                    arkret_wire::ErrorCode::DuplicateConflict
                }
                Some(coland_storage::ConflictCode::FailedPrecondition) => {
                    arkret_wire::ErrorCode::FailedPrecondition
                }
                _ => arkret_wire::ErrorCode::Conflict,
            };
            AppError::from_rejection(
                wire_code,
                "MLS Add authority conflicts with accepted evidence",
            )
        }
        ServiceError::SchemaViolation(_) => {
            crate::app_error!(SchemaViolation, "invalid MLS Add authority request",)
        }
        ServiceError::Database(_)
        | ServiceError::Internal(_)
        | ServiceError::UnsupportedEventKind(_) => {
            AppError::internal("MLS Add authority installation unavailable")
        }
    }
}

// RFC 9421 authenticates the exact peer body before it is parsed. Independent
// historical signatures bind the recipient claim receipt and Add attestation;
// governance storage then checks the accepted Commit, Welcome, Proposal and
// current authority tenure in one transaction before any installation.
#[salvo::oapi::endpoint(
    operation_id = "ak.peer.mls.command.attest_add",
    request_body = MlsAttestAddHttpRequest,
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.mls.command.attest_add.v1"))]
async fn peer_mls_attest_add(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<MlsAttestAddHttpOutcome> {
    use arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody;

    let state = depot.get_typed::<AppState>().expect("state injected");
    let peer = super::events::peer::authenticated_peer_context(state, req, true).await?;
    let body = req
        .parse_json::<MlsAttestAddHttpRequest>()
        .await
        .map_err(|error| {
            super::events::peer::schema_violation(format!(
                "invalid MLS Add attestation body: {error}"
            ))
        })?;
    let request = MlsAttestAddRequestBody {
        attestation: body.attestation,
        claim_outcome: body.claim_outcome,
    };
    request.validate_claim_binding().map_err(|error| {
        super::events::peer::schema_violation(format!("invalid MLS Add attestation: {error}"))
    })?;
    let attestor_resolution = mls_roster_signature::verify_peer_attest_add_signatures(
        state,
        &peer.source_service_id,
        &request,
    )
    .await?;
    let verified = coland_storage::VerifiedMlsAddAuthorityAttestation {
        source_station_id: peer.source_service_id,
        request,
        attestor_resolution,
    };
    let outcome = state
        .authority_commits()
        .install_mls_add_authority_attestation(&verified, &state.service_core_id())
        .await
        .map_err(mls_attest_add_service_error)?;
    json_ok(MlsAttestAddHttpOutcome {
        status: outcome.status,
        attestation_digest: outcome.attestation_digest,
    })
}

fn mls_group_state_material_not_found() -> AppError {
    AppError::not_found("MLS group-state material not found")
}

fn mls_group_state_material_revision_unavailable() -> AppError {
    crate::app_error!(
        RevisionUnavailable,
        "authorized MLS group-state material is unavailable at the requested cut",
    )
}

/// A member's Account Station checks the exact session Actor and the current
/// and target membership cut before asking governance for the public bytes.
/// Governance independently repeats that check for the signed peer request.
#[salvo::oapi::endpoint(operation_id = "ak.self.mls.read.group_state_material", tags("mls.rs"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.mls.read.group_state_material.v1"))]
async fn resolve_self_mls_group_state_material(
    aa: AuthArgs,
    body: JsonBody<arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialOutcome>
{
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let request = body.into_inner();
    request
        .validate()
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
    if request.caller_actor_id != caller || caller.route_service_id() != &state.service_core_id() {
        return Err(mls_group_state_material_not_found());
    }
    json_ok(read_member_group_state_material(state, &request).await?)
}

pub(crate) async fn read_member_group_state_material(
    state: &AppState,
    request: &arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody,
) -> Result<
    arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialOutcome,
    AppError,
> {
    use coland_storage::MlsMemberGroupStateMaterialRead as Read;
    let peer_request = request.as_peer_request();
    let local_read = state
        .authority_commits()
        .mls_member_group_state_material_read(&peer_request, &state.service_core_id(), None)
        .await
        .map_err(|error| {
            AppError::internal(format!("member MLS material authorization: {error}"))
        })?;
    let genesis = match local_read {
        Read::NotFound => return Err(mls_group_state_material_not_found()),
        Read::RevisionUnavailable => return Err(mls_group_state_material_revision_unavailable()),
        Read::Authorized { genesis } => genesis,
    };
    let authority = state
        .authority_commits()
        .current_authority(&request.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("MLS material authority lookup: {error}")))?
        .ok_or_else(mls_group_state_material_not_found)?;
    if authority.service_id == state.service_core_id() {
        let event = genesis.ok_or_else(mls_group_state_material_revision_unavailable)?;
        return serve_group_state_material(state, &peer_request, &event.event).await;
    }

    crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &request.realm_id,
        &authority.service_id,
    )
    .await
    .map_err(|_| mls_group_state_material_revision_unavailable())?;

    // The Account Station never exposes a peer credential to the device. The
    // signed request carries the same exact caller and target selectors that
    // the governance Station will recheck at its own durable cut.
    let body = arkret_canonical::canonical_json_bytes(&peer_request)
        .map_err(|error| AppError::internal(format!("MLS material peer body: {error}")))?;
    let max_bytes = arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES as usize * 2;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        authority.service_id.as_str(),
        arkret_wire::PATH_PEER_MLS_GROUP_STATE_MATERIAL,
        &body,
        max_bytes,
    )
    .await
    .map_err(|error| AppError::internal(format!("MLS material peer read: {error}")))?;
    match response.status {
        404 => return Err(mls_group_state_material_not_found()),
        409 | 503 => return Err(mls_group_state_material_revision_unavailable()),
        200 => {}
        _ => return Err(mls_group_state_material_revision_unavailable()),
    }
    let outcome: arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialOutcome =
        serde_json::from_slice(&response.body)
            .map_err(|_| mls_group_state_material_revision_unavailable())?;
    outcome
        .validate_for_request(&peer_request)
        .map_err(|_| mls_group_state_material_revision_unavailable())?;
    Ok(outcome)
}

// The body is parsed by hand after the peer trust check, so the extractor does
// not document it; the registry declares this POST with a request schema, so
// the generated document must still publish it.
#[salvo::oapi::endpoint(
    operation_id = "ak.peer.mls.read.group_state_material",
    request_body = arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody,
    tags("governance")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.mls.read.group_state_material.v1"))]
async fn resolve_peer_mls_group_state_material(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialOutcome>
{
    use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;

    let state = depot.get_typed::<AppState>().expect("state injected");
    super::events::peer::validate_peer_request(state, req, true).await?;
    let source_id = super::events::peer::source_id_from_request(req)?;
    let request = req
        .parse_json::<MlsGroupStateMaterialRequestBody>()
        .await
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
    request
        .validate()
        .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;

    // federation.md §4.1.1: the Genesis is served only to a peer whose
    // replication right on the Realm stream covers its Commit at this
    // governing cut, the rule a peer stream scan applies.
    let source = arkret_wire::DidCoreId::new(source_id.clone())
        .map_err(|_| mls_group_state_material_not_found())?;
    let event = if let Some(caller) = &request.caller_actor_id {
        use coland_storage::MlsMemberGroupStateMaterialRead as Read;

        if caller.route_service_id() != &source {
            return Err(mls_group_state_material_not_found());
        }
        match state
            .authority_commits()
            .mls_member_group_state_material_read(&request, &state.service_core_id(), Some(&source))
            .await
            .map_err(|error| {
                AppError::internal(format!("peer member MLS material read: {error}"))
            })? {
            Read::NotFound => return Err(mls_group_state_material_not_found()),
            Read::RevisionUnavailable => {
                return Err(mls_group_state_material_revision_unavailable());
            }
            Read::Authorized {
                genesis: Some(genesis),
            } => genesis.event,
            Read::Authorized { genesis: None } => {
                return Err(mls_group_state_material_revision_unavailable());
            }
        }
    } else {
        state
            .authority_commits()
            .committed_event_for_peer(
                &request.group_state_event_id,
                &source,
                &state.service_core_id(),
            )
            .await
            .map_err(|error| AppError::internal(format!("peer MLS Genesis read: {error}")))?
            .ok_or_else(mls_group_state_material_not_found)?
            .event
    };
    json_ok(serve_group_state_material(state, &request, &event).await?)
}

/// The accepted Genesis selector and raw public bytes are checked identically
/// for the original peer replication read and the member-authorized path.
async fn serve_group_state_material(
    state: &AppState,
    request: &arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody,
    event: &arkret_wire::Event,
) -> Result<
    arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialOutcome,
    AppError,
> {
    use arkret_models_collaboration::mls_group_state_material::{
        MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES, MlsGroupStateMaterialOutcome,
        material_digest_from_ref,
    };
    let unavailable_material = || {
        if request.caller_actor_id.is_some() {
            mls_group_state_material_revision_unavailable()
        } else {
            mls_group_state_material_not_found()
        }
    };
    if event.kind != arkret_wire::EventKind::MlsGenesis
        || event.event_id != request.group_state_event_id
        || event.realm_id != request.realm_id
    {
        return Err(mls_group_state_material_not_found());
    }
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::to_value(&event.payload)
            .ok()
            .and_then(|payload| serde_json::from_value(payload).ok())
            .ok_or_else(mls_group_state_material_not_found)?;
    if payload.effective_scope() != &request.effective_scope
        || payload.mls_group_id().ok().as_ref() != Some(&request.mls_group_id)
        || payload.group_info_ref != request.group_info_ref
        || payload.ratchet_tree_ref != request.ratchet_tree_ref
    {
        return Err(mls_group_state_material_not_found());
    }

    let realm_digest_suite = state
        .projections()
        .realm_digest_suite(request.realm_id.as_str());
    for (field, blob_ref) in [
        ("group_info_ref", &request.group_info_ref),
        ("ratchet_tree_ref", &request.ratchet_tree_ref),
    ] {
        let suite = material_digest_from_ref(blob_ref)
            .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?
            .digest_suite()
            .map_err(|error| mls_group_state_material_schema_violation(error.to_string()))?;
        if suite != realm_digest_suite {
            return Err(mls_group_state_material_schema_violation(format!(
                "{field} digest suite {} does not match Realm digest_algorithm {}",
                suite.as_str(),
                realm_digest_suite.as_str()
            )));
        }
    }

    let limit = request
        .max_response_bytes
        .unwrap_or(MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES) as usize;
    let group_info_bytes = load_mls_public_blob(state, request.group_info_ref.as_str(), limit)
        .await
        .map_err(|_| unavailable_material())?;
    let ratchet_tree_bytes = load_mls_public_blob(
        state,
        request.ratchet_tree_ref.as_str(),
        limit - group_info_bytes.len(),
    )
    .await
    .map_err(|_| unavailable_material())?;
    let outcome = MlsGroupStateMaterialOutcome {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        epoch: request.epoch,
        group_state_event_id: request.group_state_event_id.clone(),
        group_info_ref: request.group_info_ref.clone(),
        group_info_bytes_b64: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(&group_info_bytes),
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
        ratchet_tree_ref: request.ratchet_tree_ref.clone(),
        ratchet_tree_bytes_b64: arkret_wire::Base64UrlString::new(
            arkret_canonical::base64url_encode(&ratchet_tree_bytes),
        )
        .map_err(|error| AppError::internal(error.to_string()))?,
    };
    // Selector echo, raw-byte content addresses and the response bound are
    // checked by the same validator the consumer runs; the RFC 9420 check then
    // proves GroupInfo and the ratchet tree describe the requested group at
    // epoch zero. Stored material failing either is not served.
    let validated = outcome
        .validate_for_request(request)
        .map_err(|_| unavailable_material())?;
    arkret_mls::validate_public_group_state(
        &validated.group_info_bytes,
        &validated.ratchet_tree_bytes,
        request.mls_group_id.as_str(),
        0,
    )
    .map_err(|_| unavailable_material())?;
    Ok(outcome)
}

fn mls_group_state_material_schema_violation(message: impl Into<String>) -> AppError {
    super::events::peer::schema_violation(format!(
        "invalid MLS group-state material request: {}",
        message.into()
    ))
}

/// Read one public MLS blob (`group_info_ref` / `ratchet_tree_ref`) under a hard
/// byte bound, refusing redacted rows and any object whose delivered length
/// disagrees with the durable `size_bytes` the caller budgeted against.
///
/// The bound is checked twice on purpose: once against the declared size before
/// the object store is touched, so an oversized blob never streams, and once
/// against the delivered bytes, so a store that returns more than it declared
/// cannot slip past the budget the caller already spent.
pub(crate) async fn load_mls_public_blob(
    state: &AppState,
    blob_ref: &str,
    limit: usize,
) -> Result<Vec<u8>, AppError> {
    let blob = state
        .deliveries()
        .blob(blob_ref)
        .await
        .map_err(|error| AppError::internal(format!("MLS blob metadata lookup: {error}")))?
        .filter(|blob| !blob.redacted && blob.size_bytes >= 0)
        .ok_or_else(|| AppError::not_found("MLS group-state material not found"))?;
    let declared_size = usize::try_from(blob.size_bytes)
        .map_err(|_| AppError::not_found("MLS group-state material not found"))?;
    if declared_size > limit {
        return Err(crate::app_error!(
            LimitExceeded,
            "MLS group-state material exceeds requested bound",
        ));
    }
    let bytes = state
        .deliveries()
        .get_object(&blob.storage_key)
        .await
        .map_err(|_| AppError::not_found("MLS group-state material not found"))?;
    if bytes.len() != declared_size || bytes.len() > limit {
        return Err(AppError::not_found("MLS group-state material not found"));
    }
    Ok(bytes)
}

// ── publish ───────────────────────────────────────────────────────────

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.upload.create",
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.upload.create.v1"))]
async fn upload_keypackage(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesUploadRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesUploadOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if session.account_pk.is_none() && session.agent_session().is_none() {
        return Err(AppError::capability_denied(
            "KeyPackage upload requires an account- or Agent-bound session",
        ));
    }
    // `account_pk` belongs to the credential issuer (normally the
    // Account Authority process), whereas KeyPackage rows are owned by this Station's local account
    // id. Resolve that local id through the stable principal carried by the authenticated
    // session; never reinterpret one service's local account id in another service's account
    // namespace.
    let owner_account_pk = local_keypackage_owner_account_pk(state, &session).await?;

    let body = body.into_inner();
    body.validate_shape().map_err(AppError::param_invalid)?;
    if session.agent_session().is_some()
        != (body.device_id.is_none()
            && body.agent_verification_method.is_some()
            && body.agent_key_authorize_event_id.is_some())
    {
        return Err(AppError::capability_denied(
            "KeyPackage signer branch must match the calling session",
        ));
    }
    let principal_id = body.principal_id.clone();
    let actor_id = body.principal_id.to_string();
    let expected_actor = arkret_wire::ActorId::account(arkret_wire::AccountId {
        principal_id: principal_id.clone(),
        station_id: state.service_core_id().clone(),
    });
    if actor_id != session.actor || body.actor_id != expected_actor {
        return Err(AppError::capability_denied(
            "actor_id must match the calling session",
        ));
    }
    if body.keypackages.is_empty() {
        return Err(AppError::param_missing("keypackages is required"));
    }
    let (device_id, trust_binding, publish_trust_anchor) = if let Some(device_id) = &body.device_id
    {
        if device_id.as_str() != session.require_human_device_id() {
            return Err(AppError::capability_denied(
                "device_id must match the calling session",
            ));
        }
        // `device-lifecycle.md` 15: an Applet-managed principal's delegated
        // device loses new KeyPackage publication the moment its install is
        // fenced, without waiting for an `ak.device.revoke`. The accepted
        // authorize still standing in the PCR is explicitly not enough.
        crate::routing::extensions::applet_bridge::ensure_delegated_device_not_fenced(
            state,
            &principal_id,
        )
        .await?;
        let binding =
            current_keypackage_trust_binding(state, &principal_id, device_id.as_str()).await?;
        let anchor = match (
            binding.device_authorize_event_id.as_ref(),
            binding.agent_key_authorize_event_id.as_ref(),
        ) {
            (Some(event_id), None) => {
                coland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::DeviceAuthorize(
                    event_id.clone(),
                )
            }
            _ => {
                return Err(AppError::param_invalid(
                    "device upload has no active device authorization",
                ));
            }
        };
        (Some(device_id.as_str().to_owned()), Some(binding), anchor)
    } else if let (Some(method), Some(event_id)) = (
        &body.agent_verification_method,
        &body.agent_key_authorize_event_id,
    ) {
        if !current_agent_key_authorization_matches_method(
            state,
            &principal_id,
            event_id.as_str(),
            method.as_str(),
        )
        .await
        {
            return Err(AppError::capability_denied(
                "Agent KeyPackage method or authorization is not current",
            ));
        }
        (
            None,
            Some(KeyPackageTrustBinding::agent_key_authorize(
                event_id.as_str().to_owned(),
            )),
            coland_domain::reducer::mls::MlsKeyPackagePublishTrustAnchor::AgentKeyAuthorize {
                event_id: event_id.as_str().to_owned(),
                verification_method: method.as_str().to_owned(),
            },
        )
    } else {
        return Err(AppError::param_invalid(
            "KeyPackage upload has no valid endpoint",
        ));
    };
    let endpoint_device_id = device_id.as_deref();
    let unsigned_upload = body.unsigned();
    let upload_signing_input =
        arkret_models_crypto::http_bodies::keypackages_upload_signing_input(&unsigned_upload)
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "KeyPackage upload canonical input failed: {error}"
                ))
            })?;
    if let Some(authorize_event_id) = trust_binding
        .as_ref()
        .and_then(|binding| binding.agent_key_authorize_event_id.as_deref())
    {
        verify_agent_keypackage_batch(
            state,
            &principal_id,
            authorize_event_id,
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .await
        .map_err(AppError::param_invalid)?;
    } else if device_id.is_some() {
        verify_device_keypackage_signature(
            state,
            &principal_id,
            endpoint_device_id.expect("validated device upload has a device id"),
            &body.endpoint_signature,
            &upload_signing_input,
        )
        .await?;
    } else {
        return Err(AppError::param_invalid(
            "KeyPackage upload has no authorized signer",
        ));
    }

    let mut accepted = 0_u32;
    let mut key_package_refs = Vec::new();
    let mut rejected = Vec::new();
    for entry in body.keypackages {
        if entry.keypackage_id.is_empty() {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "keypackage_id_missing",
            ));
            continue;
        }
        let keypackage_id = entry.keypackage_id.clone();
        if entry.keypackage_ref.is_empty() {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "keypackage_ref_missing",
            ));
            continue;
        }
        let keypackage_ref = entry.keypackage_ref.clone();
        let key_package_bytes_b64 = entry.keypackage.to_string();
        let key_package_bytes = match decode_key_package(&key_package_bytes_b64) {
            Ok(bytes) => bytes,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
                continue;
            }
        };
        if let Err(reason) = validate_keypackage_ciphersuite(&entry, &key_package_bytes) {
            rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
            continue;
        }
        let keypackage_digest = arkret_canonical::sha256_digest(&key_package_bytes);
        let capabilities = match validate_capabilities(&entry.capabilities) {
            Ok(value) => value,
            Err(reason) => {
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
                continue;
            }
        };
        if arkret_mls::validate_keypackage_capability_binding(&key_package_bytes, &capabilities)
            .is_err()
        {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "keypackage_capabilities_signed_binding_invalid",
            ));
            continue;
        }
        if let Some(authorize_event_id) = trust_binding
            .as_ref()
            .and_then(|binding| binding.agent_key_authorize_event_id.as_deref())
            && let Err(reason) = validate_agent_keypackage_leaf(
                state,
                &principal_id,
                authorize_event_id,
                &key_package_bytes,
            )
            .await
        {
            rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
            continue;
        }
        if let Some(endpoint_device_id) = endpoint_device_id
            && let Err(reason) = validate_device_keypackage_leaf(
                state,
                &principal_id,
                endpoint_device_id,
                &key_package_bytes,
            )
            .await
        {
            rejected.push(keypackage_failure(&entry, Some(endpoint_device_id), reason));
            continue;
        }
        let created_at = entry.created_at.timestamp();
        let expires_at = entry.expires_at.timestamp();
        let last_resort = entry.last_resort.unwrap_or(false);
        if last_resort
            && expires_at.saturating_sub(created_at) > LAST_RESORT_KEYPACKAGE_MAX_LIFETIME_SECS
        {
            rejected.push(keypackage_failure(
                &entry,
                endpoint_device_id,
                "last_resort_keypackage_lifetime_too_long",
            ));
            continue;
        }

        // KeyPackage upload is a local HTTP/storage workflow, not an accepted
        // Event. Keep its reducer input typed instead of manufacturing a
        // `ProjectedEventOperation` with a synthetic Event identity.
        let trust_anchor = publish_trust_anchor.clone();
        let projection = coland_domain::reducer::mls::MlsKeyPackagePublishProjection {
            keypackage_id: keypackage_id.clone(),
            keypackage_ref: keypackage_ref.clone(),
            keypackage_digest,
            owner_account_pk: owner_account_pk.get(),
            actor_id: actor_id.clone(),
            device_id: device_id.clone(),
            lifetime: coland_domain::reducer::KeyPackageLifetimeProjection {
                not_before: created_at,
                not_after: expires_at,
            },
            key_package_bytes,
            capabilities,
            last_resort,
            trust_anchor,
            created_at,
        };
        let effect = state
            .projections()
            .apply_mls_keypackage_publish(&projection);
        match effect {
            ProjectionEffectView::Mls(MlsProjectionEffect::KeyPackagePublished { .. }) => {}
            ProjectionEffectView::Rejected { reason } => {
                rejected.push(keypackage_failure(&entry, endpoint_device_id, reason));
                continue;
            }
            other => {
                return Err(AppError::internal(format!(
                    "unexpected reducer effect: {other:?}"
                )));
            }
        }

        // Mirror into the durable store. We snapshot the freshly-applied
        // projection row instead of re-parsing the body so persistence and
        // in-process state stay aligned.
        let record = state
            .projections()
            .mls_key_package_record(&keypackage_id)
            .expect("publish reducer landed the row");
        let _attached = state
            .mls_key_packages()
            .store_key_package(&record)
            .await
            .map_err(|err| AppError::internal(format!("mls_key_packages.put: {err}")))?;
        accepted += 1;
        key_package_refs.push(keypackage_ref);
    }

    json_ok(KeyPackagesUploadOutcome {
        accepted,
        rejections: rejected,
        key_package_refs,
    })
}

// ── claim ─────────────────────────────────────────────────────────────

#[salvo::oapi::endpoint(
    operation_id = "ak.peer.keys.keypackages.command.claim",
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.peer.keys.keypackages.command.claim.v1"))]
async fn peer_claim_keypackage(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerKeyPackagesClaimQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let (body, authorization) = verify_peer_claim_source_attestation(state, req).await?;
    let digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(&body)
            .map_err(|error| AppError::internal(error.to_string()))?,
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    let source_id = body.service_binding.source_id.to_string();
    let query = PeerKeyPackagesClaimQueryRequestBody {
        claim_request_id: body.claim_request_id.clone(),
        request_digest: digest,
    };
    // Source/transport and canonical bytes are authenticated above. Existing
    // ledger identity is resolved before the original execution window.
    if state
        .mls_key_packages()
        .peer_claim(&source_id, body.claim_request_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some()
    {
        return query_claim_ledger(state, query, source_id).await;
    }
    let execution = claim_keypackage_at_destination(state, &body, authorization).await;
    match execution {
        Ok(_) => query_claim_ledger(state, query, source_id).await,
        Err(error) => {
            if state
                .mls_key_packages()
                .peer_claim(&source_id, body.claim_request_id.as_str())
                .await
                .map_err(|failure| AppError::internal(failure.to_string()))?
                .is_some()
            {
                query_claim_ledger(state, query, source_id).await
            } else {
                Err(error)
            }
        }
    }
}

async fn claim_keypackage_at_destination(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    authorization: VerifiedClaimAuthorization,
) -> JsonResult<PeerKeyPackagesClaimOutcome> {
    let target_principal_id = body
        .unsigned_request()
        .target_principal_id()
        .ok_or_else(|| peer_claim_schema_violation("claim target identity is incomplete"))?;
    let requester_id = body
        .unsigned_request()
        .requester_principal_id(&body.requester_authorization)
        .ok_or_else(|| peer_claim_schema_violation("claim requester identity is incomplete"))?;
    let target_rate_limit_key = if let Some(account_id) = &body.target_account_id {
        account_id
            .canonical_key()
            .map_err(|error| AppError::internal(format!("target AccountId key: {error}")))?
    } else if let Some(agent_id) = &body.target_agent_id {
        agent_id.as_str().to_owned()
    } else {
        return Err(peer_claim_schema_violation(
            "claim target rate-limit identity is incomplete",
        ));
    };
    let body_value = serde_json::to_value(body)
        .map_err(|error| AppError::internal(format!("KeyPackage claim serialize: {error}")))?;
    let source_id = body.service_binding.source_id.as_str().to_owned();
    let claim_request_id = body.claim_request_id.as_str();
    let request_digest = arkret_canonical::canonical_sha256(&body_value)
        .map_err(|error| AppError::internal(format!("peer claim digest: {error}")))?;
    authorization.validate_request(body, &request_digest)?;
    revoke_expired_peer_claims(state).await?;
    if let Some(existing) = state
        .mls_key_packages()
        .peer_claim(&source_id, claim_request_id)
        .await
        .map_err(|error| AppError::internal(format!("peer claim ledger lookup: {error}")))?
    {
        return replay_peer_claim(existing, &request_digest);
    }
    validate_peer_claim_time_window(body)?;
    if state.peer_keypackage_claim_rate_limited(&source_id, &target_rate_limit_key) {
        tracing::warn!(
            %source_id,
            target_rate_limit_key,
            reason = "keypackage_claim_rate_limited",
            "peer KeyPackage claim rejected by protocol quota"
        );
        record_peer_claim_failed(state, body, &source_id, &request_digest).await?;
        return Err(peer_claim_failed());
    }

    let policy_authorized = peer_claim_policy_authorized(state, body, &source_id).await?;
    if !policy_authorized {
        tracing::warn!(
            %source_id,
            requester_id = %requester_id,
            target_principal_id = %target_principal_id,
            policy_authorized,
            "peer KeyPackage claim authorization rejected"
        );
        record_peer_claim_failed(state, body, &source_id, &request_digest).await?;
        return Err(peer_claim_failed());
    }

    let required_capabilities = body
        .required_capabilities
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let required_capabilities = required_capability_set(&required_capabilities)?;
    let target_device_ids = body
        .target_device_ids
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let target_principal_id = target_principal_id.as_str();
    let target_keypackage_ref = body
        .target_keypackage_ref
        .as_ref()
        .map(|reference| reference.as_str());
    let trust_selector = current_keypackage_claim_trust_selector(
        state,
        &arkret_wire::DidCoreId::new(target_principal_id.to_owned())
            .map_err(|_| peer_claim_schema_violation("claim target identity is invalid"))?,
        &target_device_ids,
        Some(body.intended_realm_id.as_str()),
    )
    .await
    .map_err(|_| peer_claim_failed())?;
    let now_unix_ms = now().timestamp_millis();
    let now_secs = now_unix_ms.div_euclid(1000);
    let candidate_ids = {
        let keypackages = state.projections().mls_key_package_records();
        let mut candidates = keypackages
            .iter()
            .filter_map(|keypackage| {
                if ordinary_keypackage_is_available(keypackage) {
                    Some((0_u8, keypackage))
                } else if body.last_resort_allowed == Some(true)
                    && last_resort_matches_realm(keypackage, body.intended_realm_id.as_str())
                {
                    Some((1_u8, keypackage))
                } else {
                    None
                }
            })
            .filter(|(_, keypackage)| {
                target_keypackage_ref.is_none_or(|expected| keypackage.keypackage_ref == expected)
            })
            .filter(|(_, keypackage)| {
                keypackage.lifetime_not_after.saturating_mul(1000)
                    >= body.expires_at.timestamp_millis()
            })
            .filter(|(_, keypackage)| {
                keypackage_matches_claim(
                    keypackage,
                    target_principal_id,
                    &target_device_ids,
                    &trust_selector,
                    now_secs,
                    &required_capabilities,
                )
            })
            .map(|(priority, keypackage)| {
                (
                    priority,
                    keypackage.created_at,
                    keypackage.id.clone(),
                    trust_binding_from_keypackage(keypackage),
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2))
        });
        candidates
    };

    for (priority, _, candidate_id, binding) in candidate_ids {
        let binding = binding.map_err(|_| peer_claim_failed())?;
        let Some(mut predicted) = state
            .mls_key_packages()
            .key_package(&candidate_id)
            .await
            .map_err(|error| AppError::internal(format!("peer claim candidate lookup: {error}")))?
        else {
            continue;
        };
        if ensure_keypackage_owner_account_active(state, predicted.owner_account_pk)
            .await
            .is_err()
        {
            continue;
        }
        if target_keypackage_ref
            .is_some_and(|expected| predicted.keypackage_ref.as_str() != expected)
        {
            continue;
        }
        let is_last_resort = priority == 1;
        if if is_last_resort {
            body.last_resort_allowed != Some(true)
                || !last_resort_matches_realm(&predicted, body.intended_realm_id.as_str())
        } else {
            !ordinary_keypackage_is_available(&predicted)
        } {
            continue;
        }
        if !is_last_resort {
            predicted.claimed_by_mls_group_id = Some(body.mls_group_id.as_str().to_owned());
            predicted.claimed_at = Some(now_secs);
            predicted.claim_expires_at_unix_ms = Some(body.expires_at.timestamp_millis());
            predicted.consumed_at = None;
        }
        let outcome =
            build_peer_claim_outcome(state, body, &source_id, &request_digest, &predicted).await?;
        let outcome_value = serde_json::to_value(&outcome).map_err(|error| {
            AppError::internal(format!("peer claim outcome serialize: {error}"))
        })?;
        let ledger = PeerKeyPackageClaimLedgerRecord {
            source_id: source_id.clone(),
            claim_request_id: claim_request_id.to_owned(),
            request_digest: request_digest.clone(),
            key_package_use: if is_last_resort {
                "last_resort"
            } else {
                "single_use"
            }
            .to_owned(),
            state: if is_last_resort {
                "last_resort_claimed"
            } else {
                "claimed"
            }
            .to_owned(),
            outcome: Some(outcome_value),
            consume_receipt: None,
            terminal_receipt: None,
            keypackage_id: Some(candidate_id.clone()),
            claim_expires_at_unix_ms: Some(body.expires_at.timestamp_millis()),
            expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
            updated_at: now_secs,
        };
        let device_revocation_gate = if binding.device_authorize_event_id.is_some() {
            let Some(predicted_device_id) = predicted.device_id.as_deref() else {
                continue;
            };
            match keypackage_device_revocation_gate(
                state,
                &predicted.actor_id,
                predicted_device_id,
                binding.device_authorize_event_id.as_deref(),
            )
            .await
            {
                Ok(selector) => selector,
                Err(_) => continue,
            }
        } else {
            None
        };
        match state
            .mls_key_packages()
            .claim_peer_key_package(PeerKeyPackageClaimAttempt {
                keypackage_id: &candidate_id,
                mls_group_id: body.mls_group_id.as_str(),
                device_authorize_event_id: binding.device_authorize_event_id.as_deref(),
                agent_key_authorize_event_id: binding.agent_key_authorize_event_id.as_deref(),
                device_revocation_gate: device_revocation_gate.as_ref(),
                claimed_at_unix_ms: now_unix_ms,
                claim_expires_at_unix_ms: body.expires_at.timestamp_millis(),
                ledger: &ledger,
            })
            .await
            .map_err(|error| AppError::internal(format!("peer KeyPackage CAS: {error}")))?
        {
            PeerKeyPackageClaimAttemptResult::Claimed(claimed) => {
                if !is_last_resort {
                    state.projections().mark_key_package_claimed(
                        &candidate_id,
                        body.mls_group_id.as_str().to_owned(),
                        now_secs,
                        Some(body.expires_at.timestamp_millis()),
                    );
                }
                debug_assert_eq!(claimed.id, candidate_id);
                return json_ok(outcome);
            }
            PeerKeyPackageClaimAttemptResult::Existing(existing) => {
                return replay_peer_claim(*existing, &request_digest);
            }
            PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable => continue,
        }
    }

    record_peer_claim_failed(state, body, &source_id, &request_digest).await?;
    Err(peer_claim_failed())
}

#[salvo::oapi::endpoint(operation_id = "ak.peer.keys.keypackages.read.claim", tags("mls.rs"))]
#[tracing::instrument(skip_all, fields(op = "ak.peer.keys.keypackages.read.claim.v1"))]
async fn peer_query_keypackage_claim(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<PeerKeyPackagesClaimQueryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = req
        .parse_json::<PeerKeyPackagesClaimQueryRequestBody>()
        .await
        .map_err(|_| AppError::json_invalid("invalid peer KeyPackage claim query body"))?;
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    let transport = peer_claim_transport_binding(state, req)?;
    let source_id = transport.source_id.as_str().to_owned();
    query_claim_ledger(state, body, source_id).await
}

async fn query_claim_ledger(
    state: &AppState,
    body: PeerKeyPackagesClaimQueryRequestBody,
    source_id: String,
) -> JsonResult<PeerKeyPackagesClaimQueryOutcome> {
    revoke_expired_peer_claims(state).await?;
    let Some(record) = state
        .mls_key_packages()
        .peer_claim(&source_id, body.claim_request_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("peer claim query ledger: {error}")))?
    else {
        return json_ok(PeerKeyPackagesClaimQueryOutcome {
            claim_request_id: body.claim_request_id,
            state: PeerKeyPackagesClaimQueryState::Unknown,
            claim_outcome: None,
            consume_receipt: None,
            terminal_receipt: None,
            retry_after_ms: None,
            error_code: None,
        });
    };
    if record.request_digest != body.request_digest.as_str() {
        return Err(peer_claim_duplicate_conflict());
    }
    let claim_outcome = record
        .outcome
        .clone()
        .map(serde_json::from_value::<PeerKeyPackagesClaimOutcome>)
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("stored peer claim outcome invalid: {error}"))
        })?;
    let (state_value, error_code) = match record.state.as_str() {
        "claimed" | "last_resort_claimed" => (PeerKeyPackagesClaimQueryState::Claimed, None),
        "consumed" => (PeerKeyPackagesClaimQueryState::Consumed, None),
        "expired" => (PeerKeyPackagesClaimQueryState::Expired, None),
        "revoked" => (PeerKeyPackagesClaimQueryState::Revoked, None),
        "claim_failed" => (
            PeerKeyPackagesClaimQueryState::ClaimFailed,
            Some(PeerKeyPackageClaimErrorCode::ClaimFailed),
        ),
        _ => return Err(AppError::internal("stored peer claim state invalid")),
    };
    let consume_receipt = record
        .consume_receipt
        .clone()
        .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored consume receipt invalid: {error}")))?;
    let mut terminal_receipt = record
        .terminal_receipt
        .clone()
        .map(serde_json::from_value::<KeyPackageClaimTerminalReceipt>)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored terminal receipt invalid: {error}")))?;
    if matches!(record.state.as_str(), "expired" | "revoked") && terminal_receipt.is_none() {
        let claim = claim_outcome.as_ref().ok_or_else(|| {
            AppError::internal(
                "terminal peer claim has no durable claim_outcome source; refusing to fabricate a receipt",
            )
        })?;
        let refs = claim
            .claims
            .iter()
            .map(|claim| claim.keypackage_ref.clone())
            .collect::<Vec<_>>();
        if refs.is_empty() {
            return Err(AppError::internal(
                "terminal peer claim has no durable KeyPackage refs; refusing to fabricate a receipt",
            ));
        }
        let terminal_state = if record.state == "expired" {
            KeyPackageClaimTerminalState::Expired
        } else {
            KeyPackageClaimTerminalState::Revoked
        };
        let receipt = build_peer_claim_terminal_receipt(
            state,
            body.claim_request_id.clone(),
            body.request_digest.clone(),
            terminal_state,
            Some(refs),
            arkret_wire::DidCoreId::new(source_id.clone()).map_err(|error| {
                AppError::internal(format!("peer source service id invalid: {error}"))
            })?,
            now(),
        )?;
        let receipt_value = serde_json::to_value(&receipt)
            .map_err(|error| AppError::internal(format!("terminal receipt serialize: {error}")))?;
        let _attached = state
            .mls_key_packages()
            .attach_peer_claim_terminal_receipt(
                &source_id,
                body.claim_request_id.as_str(),
                body.request_digest.as_str(),
                &receipt_value,
                now().timestamp(),
            )
            .await
            .map_err(|error| AppError::internal(format!("terminal receipt persist: {error}")))?
            .ok_or_else(|| {
                AppError::conflict("peer claim terminal state changed while persisting receipt")
            })?;
        terminal_receipt = Some(receipt);
    }
    if record.state == "consumed" && consume_receipt.is_none() {
        return Err(AppError::internal(
            "consumed peer claim has no durable consume_receipt; refusing to fabricate one",
        ));
    }
    if record.state == "claim_failed" && terminal_receipt.is_none() {
        return Err(AppError::internal(
            "failed peer claim has no durable terminal_receipt; refusing to fabricate one",
        ));
    }
    let outcome = PeerKeyPackagesClaimQueryOutcome {
        claim_request_id: body.claim_request_id,
        state: state_value,
        claim_outcome,
        consume_receipt,
        terminal_receipt,
        retry_after_ms: None,
        error_code,
    };
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored peer claim query shape: {error}")))?;
    json_ok(outcome)
}

#[derive(Debug)]
struct PeerClaimHttpTransportBinding {
    source_id: arkret_wire::DidCoreId,
    destination_id: arkret_wire::DidCoreId,
}

/// Private, exact-body authority carried only from successful source admission.
/// Peer HTTP signatures attest source-local participant verification; the
/// destination must never substitute its own same-principal device directory.
struct VerifiedClaimAuthorization {
    request_digest: String,
}

impl VerifiedClaimAuthorization {
    fn for_verified_request(body: &PeerKeyPackagesClaimRequestBody) -> Result<Self, AppError> {
        Ok(Self {
            request_digest: arkret_canonical::canonical_sha256(body).map_err(|error| {
                AppError::internal(format!("claim authorization digest: {error}"))
            })?,
        })
    }

    fn validate_request(
        &self,
        body: &PeerKeyPackagesClaimRequestBody,
        request_digest: &str,
    ) -> Result<(), AppError> {
        if self.request_digest != request_digest {
            return Err(peer_claim_schema_violation(
                "claim changed after source authentication",
            ));
        }
        validate_peer_claim_time_window(body)
    }
}

async fn verify_peer_claim_source_attestation(
    state: &AppState,
    req: &mut Request,
) -> Result<(PeerKeyPackagesClaimRequestBody, VerifiedClaimAuthorization), AppError> {
    // Authenticate before any target lookup to preserve opaque peer admission.
    crate::routing::events::peer::validate_peer_request(state, req, true).await?;
    // Decode exactly the body whose digest the source signature authenticated;
    // callers cannot pair a verified request with a separately supplied DTO.
    let body = req
        .parse_json::<PeerKeyPackagesClaimRequestBody>()
        .await
        .map_err(|error| {
            if matches!(&error, salvo::http::ParseError::SerdeJson(error) if error.is_data()) {
                peer_claim_schema_violation("peer KeyPackage claim body violates its schema")
            } else {
                AppError::json_invalid("invalid peer KeyPackage claim request body")
            }
        })?;
    let transport = peer_claim_transport_binding(state, req)?;
    if body.service_binding.source_id != transport.source_id
        || body.service_binding.destination_id != transport.destination_id
    {
        return Err(peer_claim_schema_violation(
            "request service_binding must equal the authenticated HTTP service coordinates",
        ));
    }
    if peer_required_header(req, "idempotency-key")? != body.claim_request_id.as_str() {
        return Err(peer_claim_schema_violation(
            "Idempotency-Key must equal claim_request_id",
        ));
    }
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    if let PeerKeyPackageRequesterAuthorization::Device {
        verification_method,
        requester_device_id,
        ..
    } = &body.requester_authorization
        && !verification_method_binds_core_device(
            verification_method,
            &body
                .requester_account_id
                .as_ref()
                .ok_or_else(|| peer_claim_schema_violation("device requester omits AccountId"))?
                .principal_id,
            requester_device_id,
        )
    {
        return Err(peer_claim_schema_violation(
            "requester device verification method must bind requester AccountId principal and requester_device_id",
        ));
    }
    // The authenticated canonical body is the attestation. This function does
    // not resolve a remote participant through a local principal-keyed facet.
    let authorization = VerifiedClaimAuthorization::for_verified_request(&body)?;
    Ok((body, authorization))
}

fn peer_claim_transport_binding(
    state: &AppState,
    req: &Request,
) -> Result<PeerClaimHttpTransportBinding, AppError> {
    let source_id = arkret_wire::DidCoreId::new(peer_required_header(req, "source-service-id")?)
        .map_err(|_| peer_claim_schema_violation("source-service-id must be a core_id"))?;
    let destination_id =
        arkret_wire::DidCoreId::new(peer_required_header(req, "destination-service-id")?)
            .map_err(|_| peer_claim_schema_violation("destination-service-id must be a core_id"))?;
    let source_trust_domain =
        arkret_identifiers::TrustDomainId::new(peer_required_header(req, "source-trust-domain")?)
            .map_err(|_| peer_claim_schema_violation("source-trust-domain is invalid"))?;
    let destination_trust_domain = arkret_identifiers::TrustDomainId::new(peer_required_header(
        req,
        "destination-trust-domain",
    )?)
    .map_err(|_| peer_claim_schema_violation("destination-trust-domain is invalid"))?;
    let local_trust_domain = state.config().trust_domain.clone();
    if destination_id.as_str() != state.service_id()
        || source_id == destination_id
        || source_trust_domain != local_trust_domain
        || destination_trust_domain != local_trust_domain
    {
        return Err(crate::routing::events::peer::cross_domain_replay(
            "peer KeyPackage claim transport binding does not target this service in the same trust domain",
        ));
    }
    Ok(PeerClaimHttpTransportBinding {
        source_id,
        destination_id,
    })
}

fn validate_peer_claim_time_window(body: &PeerKeyPackagesClaimRequestBody) -> Result<(), AppError> {
    let authorization = &body.requester_authorization;
    let signed_at = match authorization {
        PeerKeyPackageRequesterAuthorization::Device { signed_at, .. }
        | PeerKeyPackageRequesterAuthorization::Agent { signed_at, .. } => *signed_at,
    };
    let current = now();
    if signed_at > current + chrono::Duration::seconds(60)
        || body.expires_at <= signed_at
        || body.expires_at.signed_duration_since(signed_at) > chrono::Duration::minutes(5)
        || body.expires_at <= current
    {
        return Err(peer_claim_schema_violation(
            "peer KeyPackage claim authorization time window is invalid",
        ));
    }
    Ok(())
}

fn verification_method_binds_core_device(
    verification_method: &arkret_wire::DidUrl,
    principal_id: &arkret_wire::DidCoreId,
    device_id: &arkret_wire::DeviceId,
) -> bool {
    let Some((controller, fragment)) = verification_method.rsplit_once('#') else {
        return false;
    };
    if fragment != device_id.as_str() {
        return false;
    }
    arkret_wire::Did::new(controller.to_owned())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        .is_ok_and(|core| core == *principal_id)
}

async fn verify_local_claim_participant_authorization(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
) -> Result<bool, AppError> {
    if body.service_binding.source_id != state.service_core_id() {
        return Ok(false);
    }
    let authorization = &body.requester_authorization;
    let requester_id = body
        .unsigned_request()
        .requester_principal_id(authorization)
        .ok_or_else(|| peer_claim_schema_violation("claim requester identity is incomplete"))?;
    let target_principal_id = body
        .unsigned_request()
        .target_principal_id()
        .ok_or_else(|| peer_claim_schema_violation("claim target identity is incomplete"))?;
    let reject = |reason: &'static str| {
        tracing::warn!(
            requester_id = %requester_id,
            target_principal_id = %target_principal_id,
            reason,
            "peer KeyPackage participant authorization rejected"
        );
        Ok::<bool, AppError>(false)
    };
    if let PeerKeyPackageRequesterAuthorization::Agent {
        verification_method,
        requester_agent_id,
        agent_key_authorize_event_id,
        signature,
        ..
    } = authorization
    {
        let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            requester_agent_id.clone(),
            body.service_binding.source_id.clone(),
        ));
        let agent =
            crate::routing::identity::agent_pcr::agent_record_for_actor(state, &agent_actor)
                .await?;
        let Some(agent) = agent else {
            return reject("agent_missing");
        };
        if agent.state != AgentLifecycleState::Active
            || !current_agent_key_authorization_matches_method(
                state,
                requester_agent_id,
                agent_key_authorize_event_id.as_str(),
                verification_method.as_str(),
            )
            .await
            || requester_agent_id != &requester_id
        {
            return reject("agent_authorization_stale");
        }
        if signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
            || signature.kid.as_str() != verification_method.as_str()
        {
            return reject("agent_signature_shape");
        }
        let signing_bytes = keypackage_claim_authorization_signing_bytes(
            &body.unsigned_request(),
            &body.service_binding,
            authorization,
        )
        .map_err(|error| {
            AppError::internal(format!("peer claim authorization transcript: {error}"))
        })?;
        return match verify_agent_keypackage_batch(
            state,
            requester_agent_id,
            agent_key_authorize_event_id.as_str(),
            signature,
            &signing_bytes,
        )
        .await
        {
            Ok(()) => Ok(true),
            Err(_) => reject("agent_signature_invalid"),
        };
    }
    let (verification_method, signature, requester_device_id, device_authorize_event_id) =
        match authorization {
            PeerKeyPackageRequesterAuthorization::Device {
                verification_method,
                requester_device_id,
                device_authorize_event_id,
                signature,
                ..
            } => (
                verification_method,
                signature,
                requester_device_id,
                device_authorize_event_id,
            ),
            PeerKeyPackageRequesterAuthorization::Agent { .. } => unreachable!(),
        };
    if signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return reject("signature_algorithm");
    }
    let signing_bytes = keypackage_claim_authorization_signing_bytes(
        &body.unsigned_request(),
        &body.service_binding,
        authorization,
    )
    .map_err(|error| AppError::internal(format!("peer claim authorization transcript: {error}")))?;
    let key = {
        let device_id = requester_device_id;
        let facet =
            crate::routing::identity::device_signing::try_resolve_device_signing_directory_facet(
                state,
                requester_id.as_str(),
                device_id.as_str(),
            )
            .await
            .map_err(|error| {
                AppError::internal(format!("requester_id device directory: {error}"))
            })?;
        if !matches!(
            facet.status,
            arkret_models_crypto::keys::DeviceStatus::Active
        ) || facet
            .device_authorize_event_id
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(device_authorize_event_id.as_str())
            || !verification_method_binds_core_device(verification_method, &requester_id, device_id)
        {
            return reject("local_device_directory_binding");
        }
        let Some(multibase) = facet
            .signing_key_did
            .as_deref()
            .and_then(|value| value.strip_prefix("did:key:"))
        else {
            return reject("local_device_directory_key_format");
        };
        crate::routing::identity::device_signing::decode_ed25519_key(multibase, "multibase")
            .map_err(|_| peer_claim_failed())?
    };
    let signature_valid = crate::routing::identity::device_signing::ed25519_verify(
        &key,
        &signing_bytes,
        signature.sig.as_str(),
    );
    if !signature_valid {
        return reject("directory_governance_proof_signature_invalid");
    }
    Ok(true)
}

/// Record which destination gate refused a claim; the external answer stays
/// the uniform `claim_failed`.
fn policy_refused(reason: &'static str) -> bool {
    tracing::debug!(reason, "peer KeyPackage claim policy refused");
    false
}

async fn peer_claim_policy_authorized(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_id: &str,
) -> Result<bool, AppError> {
    let requester_id = body
        .unsigned_request()
        .requester_principal_id(&body.requester_authorization)
        .ok_or_else(|| peer_claim_schema_violation("claim requester identity is incomplete"))?;
    let target_authority_current = if let (Some(agent_id), Some(method), Some(event_id)) = (
        &body.target_agent_id,
        &body.target_agent_verification_method,
        &body.target_agent_key_authorize_event_id,
    ) {
        current_agent_key_authorization_matches_method(
            state,
            agent_id,
            event_id.as_str(),
            method.as_str(),
        )
        .await
    } else {
        state
            .identities()
            .account(
                body.target_account_id
                    .as_ref()
                    .ok_or_else(|| peer_claim_schema_violation("human target omits AccountId"))?,
            )
            .await
            .map_err(|error| AppError::internal(format!("target authority lookup: {error}")))?
            .is_some()
    };
    if !target_authority_current {
        return Ok(policy_refused("target_authority_not_current"));
    }
    match body.claim_purpose {
        PeerKeyPackageClaimPurpose::RealmMembership => {
            // device-lifecycle §9.2.1 / §9.2.2: the requester and the target
            // are both current joined members of the exact Realm in this
            // service's own accepted state, and the requester is routed
            // through the authenticated source service.
            let source = arkret_wire::DidCoreId::new(source_id.to_owned())
                .map_err(|_| AppError::param_invalid("invalid source_id"))?;
            let requester_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                requester_id.clone(),
                source,
            ));
            if body.requester_account_id.as_ref().is_some_and(|account| {
                arkret_wire::ActorId::account(account.clone()) != requester_actor
            }) {
                return Ok(policy_refused("requester_route_unacceptable"));
            }
            let target_actor = match (&body.target_account_id, &body.target_agent_id) {
                (Some(account), None) => arkret_wire::ActorId::account(account.clone()),
                (None, Some(agent_id)) => arkret_wire::ActorId::account(
                    arkret_wire::AccountId::new(agent_id.clone(), state.service_core_id()),
                ),
                _ => return Ok(policy_refused("target_not_routed_member")),
            };
            for (actor, reason) in [
                (&requester_actor, "requester_not_joined"),
                (&target_actor, "target_not_joined"),
            ] {
                if !state
                    .authority_commits()
                    .accepted_current_member_joined(&body.intended_realm_id, actor)
                    .await
                    .map_err(|error| {
                        AppError::internal(format!("claim membership read: {error}"))
                    })?
                {
                    return Ok(policy_refused(reason));
                }
            }
        }
        PeerKeyPackageClaimPurpose::DirectConversation => {
            let scope = "direct_message";
            let contact = crate::routing::identity::account::accepted_contact_for_pair(
                state,
                &arkret_wire::ActorId::account(body.target_account_id.clone().ok_or_else(
                    || {
                        peer_claim_schema_violation(
                            "direct-conversation target must be an AccountId",
                        )
                    },
                )?),
                &arkret_wire::ActorId::account(body.requester_account_id.clone().ok_or_else(
                    || {
                        peer_claim_schema_violation(
                            "direct-conversation requester must be an AccountId",
                        )
                    },
                )?),
                scope,
            )
            .await?;
            let Some(contact) = contact else {
                return Ok(policy_refused("direct_contact_missing"));
            };
            if contact
                .peer_host_id
                .as_ref()
                .map(arkret_wire::DidCoreId::as_str)
                != Some(source_id)
            {
                return Ok(policy_refused("direct_contact_host_mismatch"));
            }
            let trust_domain = state.config().trust_domain.clone();
            let expected_pair_key = arkret_models_collaboration::objects::direct_conversation::direct_conversation_pair_key(
                trust_domain,
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                    arkret_wire::ActorId::account(body.requester_account_id.clone().ok_or_else(|| {
                        peer_claim_schema_violation("direct-conversation requester must be an AccountId")
                    })?),
                ),
                arkret_models_collaboration::objects::direct_conversation::DirectConversationPairKeyParticipant::unmapped(
                    arkret_wire::ActorId::account(body.target_account_id.clone().ok_or_else(|| {
                        peer_claim_schema_violation("direct-conversation target must be an AccountId")
                    })?),
                ),
            )
            .map_err(|_| peer_claim_failed())?;
            if body.pair_key.as_ref() != Some(&expected_pair_key)
                || body.last_resort_allowed == Some(true)
                || body.strand_id.is_none()
            {
                return Ok(policy_refused("direct_binding_mismatch"));
            }
        }
    }
    Ok(true)
}

async fn build_peer_claim_outcome(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_id: &str,
    request_digest: &str,
    claimed: &MlsKeyPackageRow,
) -> Result<PeerKeyPackagesClaimOutcome, AppError> {
    let claims = vec![keypackage_claim_record(state, claimed, body).await?];
    let claims_value = serde_json::to_value(&claims)
        .map_err(|error| AppError::internal(format!("peer claim records serialize: {error}")))?;
    let claims_digest = arkret_canonical::canonical_sha256(&claims_value)
        .map_err(|error| AppError::internal(format!("peer claims digest: {error}")))?;
    let service_did = state.service_resolution_commitment().did.clone();
    let verification_method = format!("{service_did}#notary-key");
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: body.claim_request_id.clone(),
        request_digest: Hash::new(request_digest.to_owned())
            .map_err(|error| AppError::internal(format!("request digest invalid: {error}")))?,
        claims_digest: Hash::new(claims_digest)
            .map_err(|error| AppError::internal(format!("claims digest invalid: {error}")))?,
        source_id: arkret_wire::DidCoreId::new(source_id.to_owned())
            .map_err(|error| AppError::internal(format!("source service id invalid: {error}")))?,
        destination_id: arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service id invalid: {error}")))?,
        request: body.unsigned_request(),
        claimed_at: unix_timestamp_datetime(
            claimed.claimed_at.unwrap_or_else(|| now().timestamp()),
        )?,
        expires_at: body.expires_at,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(verification_method.clone())
                .map_err(|error| AppError::internal(format!("receipt kid invalid: {error}")))?,
            signature_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            ),
            sig: arkret_wire::Base64UrlString::new("AA")
                .expect("placeholder receipt signature is base64url"),
        },
    };
    let signing_bytes = peer_keypackage_claim_receipt_signing_bytes(&receipt)
        .map_err(|error| AppError::internal(format!("peer claim receipt transcript: {error}")))?;
    let signature = state.notary_signing_key().sign(&signing_bytes);
    receipt.signature.sig =
        arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
            .map_err(|error| AppError::internal(format!("receipt signature invalid: {error}")))?;
    let outcome = PeerKeyPackagesClaimOutcome {
        claim_request_id: body.claim_request_id.clone(),
        claims,
        claim_receipt: receipt,
    };
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("peer claim outcome shape: {error}")))?;
    Ok(outcome)
}

async fn record_peer_claim_failed(
    state: &AppState,
    body: &PeerKeyPackagesClaimRequestBody,
    source_id: &str,
    request_digest: &str,
) -> Result<(), AppError> {
    let timestamp = now().timestamp();
    let terminal_receipt = build_peer_claim_terminal_receipt(
        state,
        body.claim_request_id.clone(),
        Hash::new(request_digest.to_owned()).map_err(|error| {
            AppError::internal(format!("peer claim request digest invalid: {error}"))
        })?,
        KeyPackageClaimTerminalState::NeverClaimed,
        None,
        arkret_wire::DidCoreId::new(source_id.to_owned())
            .map_err(|error| AppError::internal(format!("peer service DID invalid: {error}")))?,
        now(),
    )?;
    let record = PeerKeyPackageClaimLedgerRecord {
        source_id: source_id.to_owned(),
        claim_request_id: body.claim_request_id.as_str().to_owned(),
        request_digest: request_digest.to_owned(),
        key_package_use: "none".to_owned(),
        state: "claim_failed".to_owned(),
        outcome: None,
        consume_receipt: None,
        terminal_receipt: Some(serde_json::to_value(terminal_receipt).map_err(|error| {
            AppError::internal(format!("peer claim terminal receipt serialize: {error}"))
        })?),
        keypackage_id: None,
        claim_expires_at_unix_ms: None,
        expires_at: (body.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: timestamp,
    };
    match state
        .mls_key_packages()
        .store_peer_claim_terminal(&record)
        .await
        .map_err(|error| AppError::internal(format!("peer claim failure ledger: {error}")))?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(()),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
            if existing.request_digest == request_digest =>
        {
            Ok(())
        }
        PeerKeyPackageClaimLedgerWriteResult::Existing(_) => Err(peer_claim_duplicate_conflict()),
    }
}

fn build_peer_claim_terminal_receipt(
    state: &AppState,
    claim_request_id: arkret_wire::Base64UrlString,
    request_digest: Hash,
    terminal_state: KeyPackageClaimTerminalState,
    key_package_refs: Option<Vec<String>>,
    source_id: arkret_wire::DidCoreId,
    terminal_at: DateTime<Utc>,
) -> Result<KeyPackageClaimTerminalReceipt, AppError> {
    let verification_method = format!("{}#notary-key", state.service_resolution_commitment().did);
    let mut receipt = KeyPackageClaimTerminalReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::KEYPACKAGE_CLAIM_TERMINAL_RECEIPT_V1,
        )
        .expect("terminal receipt domain is non-empty"),
        claim_request_id,
        request_digest,
        terminal_state,
        key_package_refs,
        source_id,
        destination_id: arkret_wire::DidCoreId::new(state.service_id().clone())
            .map_err(|error| AppError::internal(format!("service id invalid: {error}")))?,
        terminal_at,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(verification_method)
                .expect("service notary method is non-empty"),
            signature_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            ),
            sig: arkret_wire::Base64UrlString::new("AA")
                .expect("placeholder signature is base64url"),
        },
    };
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "terminal receipt signing transcript invalid: {error}"
        ))
    })?;
    receipt.signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&signing_input).to_bytes()),
    )
    .map_err(|error| AppError::internal(format!("terminal receipt signature invalid: {error}")))?;
    Ok(receipt)
}

fn replay_peer_claim(
    record: PeerKeyPackageClaimLedgerRecord,
    request_digest: &str,
) -> JsonResult<PeerKeyPackagesClaimOutcome> {
    if record.request_digest != request_digest {
        return Err(peer_claim_duplicate_conflict());
    }
    if !matches!(
        record.state.as_str(),
        "claimed" | "last_resort_claimed" | "consumed"
    ) {
        return Err(peer_claim_failed());
    }
    let Some(outcome) = record.outcome else {
        return Err(peer_claim_failed());
    };
    let outcome: PeerKeyPackagesClaimOutcome =
        serde_json::from_value(outcome).map_err(|error| {
            AppError::internal(format!("stored peer claim outcome invalid: {error}"))
        })?;
    outcome
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored peer claim outcome shape: {error}")))?;
    json_ok(outcome)
}

async fn revoke_expired_peer_claims(state: &AppState) -> Result<(), AppError> {
    let revoked = state
        .mls_key_packages()
        .revoke_expired_peer_claims(now().timestamp_millis())
        .await
        .map_err(|error| AppError::internal(format!("peer claim expiry sweep: {error}")))?;
    if revoked.is_empty() {
        return Ok(());
    }
    state.projections().mark_key_packages_revoked(&revoked);
    Ok(())
}

fn peer_required_header(req: &Request, name: &'static str) -> Result<String, AppError> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| peer_claim_schema_violation(format!("required header {name} missing")))
}

fn peer_claim_schema_violation(message: impl Into<String>) -> AppError {
    crate::routing::events::peer::schema_violation(message)
}

fn peer_claim_duplicate_conflict() -> AppError {
    AppError::conflict("claim_request_id is already bound to another request")
        .with_wire_code("duplicate_conflict")
}

fn peer_claim_failed() -> AppError {
    // `claim_failed` is a registered endpoint code with its own status:
    // `error-code-registry.json` binds it to HTTP 400, not to the 409 of the
    // `failed_precondition` base code. Building it as `FailedPrecondition`
    // plus a wire-code override rendered `type: .../claim_failed` under a 409,
    // because `AppError::http_status()` resolves the status from the canonical
    // `ErrorCode` and the override only rewrites the rendered string.
    crate::app_error!(ClaimFailed, "KeyPackage claim failed")
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.command.claim",
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.command.claim.v1"))]
async fn claim_keypackage(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesClaimRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;

    let body = body.into_inner();
    if session.agent_session().is_some()
        != matches!(
            &body.requester_authorization,
            PeerKeyPackageRequesterAuthorization::Agent { .. }
        )
    {
        return Err(AppError::capability_denied(
            "KeyPackage requester branch must match the calling session",
        ));
    }
    let requester_id = body
        .unsigned_request()
        .requester_principal_id(&body.requester_authorization)
        .ok_or_else(|| peer_claim_schema_violation("claim requester identity is incomplete"))?;
    body.unsigned_request()
        .target_principal_id()
        .ok_or_else(|| peer_claim_schema_violation("claim target identity is incomplete"))?;
    let session_actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    if matches!(
        &body.requester_authorization,
        PeerKeyPackageRequesterAuthorization::Device { .. }
    ) && session_actor.as_account_id() != body.requester_account_id.as_ref()
        || matches!(
            &body.requester_authorization,
            PeerKeyPackageRequesterAuthorization::Agent { .. }
        ) && session_actor.signing_principal_id() != &requester_id
    {
        return Err(AppError::capability_denied(
            "requester account must match the calling session and source Station",
        ));
    }
    body.validate_shape()
        .map_err(|error| peer_claim_schema_violation(error.to_string()))?;
    let peer_body = PeerKeyPackagesClaimRequestBody::from(&body);
    validate_peer_claim_time_window(&peer_body)?;
    let local_service_id = state.service_id();
    if body.service_binding.source_id.as_str() != local_service_id {
        return Err(peer_claim_schema_violation(
            "self claim transport source must be the authenticated local service",
        ));
    }
    match &body.requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device {
            requester_device_id,
            ..
        } if requester_device_id.as_str() == session.require_human_device_id() => {}
        PeerKeyPackageRequesterAuthorization::Agent {
            requester_agent_id, ..
        } if requester_agent_id.as_str() == session.actor => {}
        _ => {
            return Err(AppError::capability_denied(
                "requester authorization must match the authenticated session AccountId",
            ));
        }
    }
    if !verify_local_claim_participant_authorization(state, &peer_body).await? {
        return Err(AppError::capability_denied(
            "requester authorization is not current at the source service",
        ));
    }
    let authorization = VerifiedClaimAuthorization::for_verified_request(&peer_body)?;
    if body.claim_purpose == PeerKeyPackageClaimPurpose::RealmMembership
        && !state
            .authority_commits()
            .accepted_current_member_joined(&body.intended_realm_id, &session_actor)
            .await
            .map_err(|error| AppError::internal(format!("claim membership read: {error}")))?
    {
        return Err(AppError::capability_denied(
            "requester identity has no current source-side Realm membership",
        ));
    }
    if body.service_binding.destination_id.as_str() != local_service_id {
        let destination = body.service_binding.destination_id.as_str();
        // The destination is the exact target account's own Station, and that
        // account is a current joined member in this service's accepted
        // state; nothing is inferred from a principal or an endpoint.
        let target_actor = match (&body.target_account_id, &body.target_agent_id) {
            (Some(account), None) => arkret_wire::ActorId::account(account.clone()),
            (None, Some(agent_id)) => arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                agent_id.clone(),
                body.service_binding.destination_id.clone(),
            )),
            _ => {
                return Err(AppError::capability_denied(
                    "target actor route is not current",
                ));
            }
        };
        if target_actor.route_service_id().as_str() != destination
            || (body.claim_purpose == PeerKeyPackageClaimPurpose::RealmMembership
                && !state
                    .authority_commits()
                    .accepted_current_member_joined(&body.intended_realm_id, &target_actor)
                    .await
                    .map_err(|error| {
                        AppError::internal(format!("claim target membership read: {error}"))
                    })?)
        {
            return Err(AppError::capability_denied(
                "destination Station must match the exact target account in the Realm",
            ));
        }
        let body_value = serde_json::to_value(&body)
            .map_err(|error| AppError::internal(format!("remote claim serialize: {error}")))?;
        let request_digest = arkret_canonical::canonical_sha256(&body_value)
            .map_err(|error| AppError::internal(format!("remote claim digest: {error}")))?;
        if let Some(existing) = state
            .mls_key_packages()
            .peer_claim(local_service_id, body.claim_request_id.as_str())
            .await
            .map_err(|error| AppError::internal(format!("remote claim relay ledger: {error}")))?
        {
            return replay_peer_claim(existing, &request_digest)
                .map(|Json(outcome)| Json(outcome.into()));
        }
        let target =
            crate::routing::federation::resolved_peer_target(state, destination, "station", false)
                .await
                .map_err(|error| {
                    crate::app_error!(
                        FailedPrecondition,
                        format!("remote KeyPackage authority route unavailable: {error}"),
                    )
                    .with_internal_reason("dependency_unavailable")
                })?;
        let payload = String::from_utf8(arkret_canonical::canonical_json_bytes(&body).map_err(
            |error| AppError::internal(format!("remote claim canonical body: {error}")),
        )?)
        .map_err(|error| AppError::internal(format!("remote claim body utf8: {error}")))?;
        crate::routing::federation::outbox::enqueue_outbound(
            state,
            &target.base_url,
            destination,
            "/_arkret/peer/keys/keypackages/claim",
            body.claim_request_id.as_str(),
            &payload,
        )
        .await
        .map_err(|error| AppError::internal(format!("remote claim durable relay: {error}")))?;
        return Err(crate::app_error!(
            FailedPrecondition,
            "remote KeyPackage claim has been durably accepted for relay",
        )
        .with_internal_reason("dependency_unavailable"));
    }
    claim_keypackage_at_destination(state, &peer_body, authorization)
        .await
        .map(|Json(outcome)| Json(outcome.into()))
}

/// The one recipient endpoint a claim read is answered for
/// (device-lifecycle.md §9 `claims/query`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimReader {
    /// A human device session: its complete AccountId and device.
    Device {
        actor: arkret_wire::ActorId,
        device_id: String,
    },
    /// An Agent runtime session under its current key authorization.
    Agent {
        agent_id: String,
        verification_method: String,
        authorize_event_id: String,
    },
}

/// Whether `record` is the claim of exactly `reader`'s endpoint.
fn claim_record_names_reader(record: &KeyPackageClaimRecord, reader: &ClaimReader) -> bool {
    match reader {
        ClaimReader::Device { actor, device_id } => {
            &record.actor_id == actor
                && record.device_id.as_ref().map(|id| id.as_str()) == Some(device_id.as_str())
                && record.agent_id.is_none()
                && record.agent_verification_method.is_none()
        }
        ClaimReader::Agent {
            agent_id,
            verification_method,
            authorize_event_id,
        } => {
            record.actor_id.signing_principal_id().as_str() == agent_id
                && record.agent_id.as_ref().map(|id| id.as_str()) == Some(agent_id.as_str())
                && record
                    .agent_verification_method
                    .as_ref()
                    .map(|method| method.as_str())
                    == Some(verification_method.as_str())
                && record
                    .agent_key_authorize_event_id
                    .as_ref()
                    .map(|event| event.as_str())
                    == Some(authorize_event_id.as_str())
                && record.device_id.is_none()
        }
    }
}

/// The endpoint an authenticated session reads claims as, or `None` when the
/// session names no current endpoint.
async fn claim_reader(state: &AppState, session: &SessionRecord) -> Option<ClaimReader> {
    match crate::routing::identity::device_messages::recipient_queue_selector(session).ok()? {
        coland_services::delivery::RecipientQueueSelector::HumanDevice { device_id, .. } => {
            let actor =
                crate::routing::identity::session_actor::validated_session_actor(state, session)
                    .await
                    .ok()?;
            actor.as_account_id()?;
            Some(ClaimReader::Device { actor, device_id })
        }
        coland_services::delivery::RecipientQueueSelector::AgentRuntime {
            agent_id,
            verification_method,
            authorization_event_ref,
        } => {
            let principal = arkret_wire::DidCoreId::new(agent_id.clone()).ok()?;
            current_agent_key_authorization_matches_method(
                state,
                &principal,
                &authorization_event_ref,
                &verification_method,
            )
            .await
            .then_some(ClaimReader::Agent {
                agent_id,
                verification_method,
                authorize_event_id: authorization_event_ref,
            })
        }
    }
}

fn keypackage_claim_unknown() -> AppError {
    crate::app_error!(KeypackageUnknown, "KeyPackage claim is unknown")
}

/// `ak.self.keys.keypackages.read.claim.v1`: the byte-identical outcome of
/// the claim request that allocated `claim_id`, for that claim's own
/// endpoint only (device-lifecycle.md §9 `claims/query`).
///
/// An unknown id, another endpoint's claim, a replaced Agent authorization,
/// a failed claim without an outcome and a ledger row past its §9.2.3
/// retention all answer the same `keypackage_unknown`. Nothing is written.
#[salvo::oapi::endpoint(operation_id = "ak.self.keys.keypackages.read.claim", tags("mls.rs"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.read.claim.v1"))]
async fn query_own_keypackage_claim(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesClaimQueryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesClaimOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let reader = claim_reader(state, &session)
        .await
        .ok_or_else(keypackage_claim_unknown)?;
    let row = state
        .mls_key_packages()
        .peer_claim_by_claim_id(body.claim_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("claim read ledger: {error}")))?
        .filter(|row| row.keypackage_id.is_some() && row.expires_at > now().timestamp())
        .ok_or_else(keypackage_claim_unknown)?;
    let outcome = row
        .outcome
        .map(serde_json::from_value::<PeerKeyPackagesClaimOutcome>)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored claim outcome invalid: {error}")))?
        .ok_or_else(keypackage_claim_unknown)?;
    let owned = outcome.claim_receipt.destination_id.as_str() == state.service_id()
        && outcome
            .claims
            .iter()
            .find(|record| record.claim_id == body.claim_id.as_str())
            .is_some_and(|record| claim_record_names_reader(record, &reader));
    if !owned {
        return Err(keypackage_claim_unknown());
    }
    json_ok(outcome.into())
}

pub(crate) async fn capture_relayed_keypackage_claim_outcome(
    state: &AppState,
    destination_id: &str,
    request_body: &str,
    response_body: &str,
) -> Result<(), String> {
    let request: KeyPackagesClaimRequestBody =
        serde_json::from_str(request_body).map_err(|error| error.to_string())?;
    let outcome: KeyPackagesClaimOutcome =
        serde_json::from_str(response_body).map_err(|error| error.to_string())?;
    outcome
        .validate_shape()
        .map_err(|error| error.to_string())?;
    let receipt = &outcome.claim_receipt;
    if request.service_binding.source_id.as_str() != state.service_id()
        || request.service_binding.destination_id.as_str() != destination_id
        || receipt.source_id != request.service_binding.source_id
        || receipt.destination_id != request.service_binding.destination_id
        || receipt.request != request.unsigned_request()
    {
        return Err("relayed KeyPackage claim outcome binding mismatch".to_owned());
    }
    let request_digest =
        arkret_canonical::canonical_sha256(&request).map_err(|error| error.to_string())?;
    if receipt.request_digest.as_str() != request_digest {
        return Err("relayed KeyPackage claim request digest mismatch".to_owned());
    }
    if !receipt
        .signature
        .signature_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.as_str() == "Ed25519")
    {
        return Err("relayed KeyPackage claim receipt algorithm invalid".to_owned());
    }
    let signing_bytes =
        peer_keypackage_claim_receipt_signing_bytes(receipt).map_err(|error| error.to_string())?;
    crate::jws_verify::validate_verification_method_controller(
        destination_id,
        receipt.signature.kid.as_str(),
    )?;
    let verification_key = crate::jws_verify::resolve_ed25519_pubkey_at(
        state,
        receipt.signature.kid.as_str(),
        receipt.claimed_at,
    )
    .await?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &verification_key,
        &signing_bytes,
        receipt.signature.sig.as_str(),
    ) {
        return Err("relayed KeyPackage claim receipt signature invalid".to_owned());
    }
    let is_last_resort = outcome
        .claims
        .iter()
        .any(|claim| claim.last_resort == Some(true));
    let record = PeerKeyPackageClaimLedgerRecord {
        source_id: state.service_id().clone(),
        claim_request_id: request.claim_request_id.as_str().to_owned(),
        request_digest,
        key_package_use: if is_last_resort {
            "last_resort"
        } else {
            "single_use"
        }
        .to_owned(),
        state: if is_last_resort {
            "last_resort_claimed"
        } else {
            "claimed"
        }
        .to_owned(),
        outcome: Some(serde_json::to_value(outcome).map_err(|error| error.to_string())?),
        consume_receipt: None,
        terminal_receipt: None,
        keypackage_id: None,
        claim_expires_at_unix_ms: Some(request.expires_at.timestamp_millis()),
        expires_at: (request.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: now().timestamp(),
    };
    match state
        .mls_key_packages()
        .store_peer_claim_terminal(&record)
        .await
        .map_err(|error| error.to_string())?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(()),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
            if existing.request_digest == record.request_digest
                && existing.key_package_use == record.key_package_use
                && existing.outcome == record.outcome =>
        {
            Ok(())
        }
        PeerKeyPackageClaimLedgerWriteResult::Existing(_) => {
            Err("relayed KeyPackage claim request id conflict".to_owned())
        }
    }
}

pub(crate) async fn capture_relayed_keypackage_claim_query(
    state: &AppState,
    destination_id: &str,
    request_body: &str,
    query: &PeerKeyPackagesClaimQueryOutcome,
) -> Result<(), String> {
    query.validate_shape().map_err(|error| error.to_string())?;
    if matches!(
        query.state,
        PeerKeyPackagesClaimQueryState::Claimed | PeerKeyPackagesClaimQueryState::Consumed
    ) {
        let outcome = query
            .claim_outcome
            .as_ref()
            .ok_or_else(|| "claim query omitted its outcome".to_owned())?;
        capture_relayed_keypackage_claim_outcome(
            state,
            destination_id,
            request_body,
            &serde_json::to_string(outcome).map_err(|error| error.to_string())?,
        )
        .await?;
        if query.state == PeerKeyPackagesClaimQueryState::Claimed {
            return Ok(());
        }
        let request: KeyPackagesClaimRequestBody =
            serde_json::from_str(request_body).map_err(|error| error.to_string())?;
        let request_digest =
            arkret_canonical::canonical_sha256(&request).map_err(|error| error.to_string())?;
        let consume = query
            .consume_receipt
            .as_ref()
            .ok_or_else(|| "consumed claim query omitted its consume receipt".to_owned())?;
        consume.validate_shape().map_err(str::to_owned)?;
        let claim = outcome
            .claims
            .first()
            .filter(|_| outcome.claims.len() == 1)
            .ok_or_else(|| "consumed claim query has no unique claim".to_owned())?;
        if consume.recipient_durable_receipt.claim_request_id != request.claim_request_id
            || consume.recipient_durable_receipt.recipient_id.as_str() != destination_id
            || consume.claim_id.as_str() != claim.claim_id
            || consume.recipient_durable_receipt.key_package_ref.as_str() != claim.keypackage_ref
        {
            return Err("consumed claim query receipt binding mismatch".to_owned());
        }
        crate::jws_verify::validate_verification_method_controller(
            consume.recipient_durable_receipt.recipient_id.as_str(),
            consume.signature.kid.as_str(),
        )?;
        let signing_bytes = consume
            .canonical_signing_bytes()
            .map_err(|error| error.to_string())?;
        let key =
            crate::jws_verify::resolve_ed25519_pubkey_async(state, consume.signature.kid.as_str())
                .await?;
        if !crate::routing::identity::device_signing::ed25519_verify(
            &key,
            &signing_bytes,
            consume.signature.sig.as_str(),
        ) {
            return Err("consumed claim query receipt signature invalid".to_owned());
        }
        let consume_value = serde_json::to_value(consume).map_err(|error| error.to_string())?;
        let outcome_value = serde_json::to_value(outcome).map_err(|error| error.to_string())?;
        let attached = state
            .mls_key_packages()
            .transition_peer_claim_consumed(
                state.service_id(),
                request.claim_request_id.as_str(),
                &request_digest,
                &outcome_value,
                &consume_value,
                consume.consumed_at.timestamp_millis(),
            )
            .await
            .map_err(|error| error.to_string())?;
        if attached.is_none() {
            let winner = state
                .mls_key_packages()
                .peer_claim(state.service_id(), request.claim_request_id.as_str())
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    "consumed claim query could not reload its durable source ledger".to_owned()
                })?;
            if !consumed_query_source_winner_matches(
                &winner.state,
                &winner.request_digest,
                winner.consume_receipt.as_ref(),
                &request_digest,
                &consume_value,
            ) {
                return Err(
                    "consumed claim query conflicts with the durable source winner".to_owned(),
                );
            }
        }
        return Ok(());
    }
    let request: KeyPackagesClaimRequestBody =
        serde_json::from_str(request_body).map_err(|error| error.to_string())?;
    let request_digest =
        arkret_canonical::canonical_sha256(&request).map_err(|error| error.to_string())?;
    let terminal = query
        .terminal_receipt
        .as_ref()
        .ok_or_else(|| "terminal claim query omitted its signed receipt".to_owned())?;
    if terminal.validate_shape().is_err()
        || terminal.claim_request_id != request.claim_request_id
        || terminal.request_digest.as_str() != request_digest
        || terminal.source_id != request.service_binding.source_id
        || terminal.destination_id != request.service_binding.destination_id
        || terminal.destination_id.as_str() != destination_id
        || terminal.terminal_state
            != match query.state {
                PeerKeyPackagesClaimQueryState::ClaimFailed => {
                    KeyPackageClaimTerminalState::NeverClaimed
                }
                PeerKeyPackagesClaimQueryState::Expired => KeyPackageClaimTerminalState::Expired,
                PeerKeyPackagesClaimQueryState::Revoked => KeyPackageClaimTerminalState::Revoked,
                _ => return Err("non-terminal claim query cannot close relay".to_owned()),
            }
    {
        return Err("terminal claim query binding mismatch".to_owned());
    }
    let signing_bytes = terminal
        .canonical_signing_bytes()
        .map_err(|error| error.to_string())?;
    crate::jws_verify::validate_verification_method_controller(
        destination_id,
        terminal.signature.kid.as_str(),
    )?;
    let verification_key =
        crate::jws_verify::resolve_ed25519_pubkey_async(state, terminal.signature.kid.as_str())
            .await?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &verification_key,
        &signing_bytes,
        terminal.signature.sig.as_str(),
    ) {
        return Err("terminal claim query receipt signature invalid".to_owned());
    }
    let state_name = match query.state {
        PeerKeyPackagesClaimQueryState::ClaimFailed => "claim_failed",
        PeerKeyPackagesClaimQueryState::Expired => "expired",
        PeerKeyPackagesClaimQueryState::Revoked => "revoked",
        _ => return Err("non-terminal claim query cannot close relay".to_owned()),
    };
    if matches!(state_name, "expired" | "revoked") {
        let outcome = query.claim_outcome.as_ref().ok_or_else(|| {
            "terminal successful claim query omitted its claim outcome".to_owned()
        })?;
        let outcome_refs = outcome
            .claims
            .iter()
            .map(|claim| claim.keypackage_ref.as_str())
            .collect::<Vec<_>>();
        let terminal_refs = terminal.key_package_refs.as_deref().ok_or_else(|| {
            "terminal successful claim receipt omitted KeyPackage refs".to_owned()
        })?;
        if !terminal_claim_coordinates_match(
            state_name,
            request.expires_at.timestamp_millis(),
            terminal.terminal_at.timestamp_millis(),
            terminal_refs.iter().map(String::as_str),
            outcome_refs,
        ) {
            return Err("terminal claim query receipt coordinates mismatch".to_owned());
        }
    }
    let terminal_receipt_value =
        serde_json::to_value(terminal).map_err(|error| error.to_string())?;
    let record = PeerKeyPackageClaimLedgerRecord {
        source_id: state.service_id().clone(),
        claim_request_id: request.claim_request_id.as_str().to_owned(),
        request_digest,
        key_package_use: "none".to_owned(),
        state: state_name.to_owned(),
        outcome: query
            .claim_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| error.to_string())?,
        consume_receipt: query
            .consume_receipt
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| error.to_string())?,
        terminal_receipt: Some(terminal_receipt_value.clone()),
        keypackage_id: None,
        claim_expires_at_unix_ms: Some(request.expires_at.timestamp_millis()),
        expires_at: (request.expires_at + chrono::Duration::minutes(10)).timestamp(),
        updated_at: now().timestamp(),
    };
    if matches!(state_name, "expired" | "revoked") {
        let expected_outcome = record.outcome.as_ref().ok_or_else(|| {
            "terminal successful claim query omitted its claim outcome".to_owned()
        })?;
        if state
            .mls_key_packages()
            .transition_peer_claim_terminal(
                coland_services::events::PeerClaimTerminalTransitionCommand {
                    source_id: state.service_id(),
                    claim_request_id: request.claim_request_id.as_str(),
                    request_digest: &record.request_digest,
                    expected_outcome,
                    terminal_state: state_name,
                    terminal_receipt: &terminal_receipt_value,
                    now_unix_ms: now().timestamp_millis(),
                },
            )
            .await
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        if let Some(existing) = state
            .mls_key_packages()
            .peer_claim(state.service_id(), request.claim_request_id.as_str())
            .await
            .map_err(|error| error.to_string())?
        {
            if existing.request_digest == record.request_digest
                && existing.state == state_name
                && existing.outcome == record.outcome
                && existing.terminal_receipt.as_ref() == Some(&terminal_receipt_value)
            {
                return Ok(());
            }
            return Err("terminal claim query conflicts with durable source ledger".to_owned());
        }
    }
    match state
        .mls_key_packages()
        .store_peer_claim_terminal(&record)
        .await
        .map_err(|error| error.to_string())?
    {
        PeerKeyPackageClaimLedgerWriteResult::Inserted => Ok(()),
        PeerKeyPackageClaimLedgerWriteResult::Existing(existing)
            if claim_failed_source_winner_matches(&existing, &record) =>
        {
            Ok(())
        }
        PeerKeyPackageClaimLedgerWriteResult::Existing(_) => {
            Err("terminal claim query request id conflict".to_owned())
        }
    }
}

fn consumed_query_source_winner_matches(
    state: &str,
    stored_request_digest: &str,
    stored_consume_receipt: Option<&Value>,
    expected_request_digest: &str,
    expected_consume_receipt: &Value,
) -> bool {
    state == "consumed"
        && stored_request_digest == expected_request_digest
        && stored_consume_receipt == Some(expected_consume_receipt)
}

fn terminal_claim_coordinates_match<'a>(
    state: &str,
    request_expires_at_unix_ms: i64,
    terminal_at_unix_ms: i64,
    terminal_refs: impl IntoIterator<Item = &'a str>,
    outcome_refs: impl IntoIterator<Item = &'a str>,
) -> bool {
    terminal_refs.into_iter().eq(outcome_refs)
        && (state != "expired" || terminal_at_unix_ms >= request_expires_at_unix_ms)
}

fn claim_failed_source_winner_matches(
    stored: &PeerKeyPackageClaimLedgerRecord,
    expected: &PeerKeyPackageClaimLedgerRecord,
) -> bool {
    stored.request_digest == expected.request_digest
        && stored.key_package_use == "none"
        && stored.state == "claim_failed"
        && stored.outcome.is_none()
        && stored.consume_receipt.is_none()
        && stored.keypackage_id.is_none()
        && stored.claim_expires_at_unix_ms == expected.claim_expires_at_unix_ms
        && stored.expires_at == expected.expires_at
        && stored.terminal_receipt == expected.terminal_receipt
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.command.consume",
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.command.consume.v1"))]
async fn consume_keypackages(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesConsumeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesConsumeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let durable_receipt = &body.recipient_durable_receipt;
    let recipient_principal_id = durable_receipt
        .recipient_principal_id()
        .ok_or_else(|| AppError::param_invalid("durable recipient identity is incomplete"))?;
    if recipient_principal_id.as_str() != session.actor {
        return Err(AppError::capability_denied(
            "durable recipient principal must match the calling principal",
        ));
    }
    let consume_signing_input =
        arkret_models_crypto::http_bodies::keypackages_consume_signing_input(&body.unsigned())
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "KeyPackage consume canonical input failed: {error}"
                ))
            })?;
    let keypackage_refs = [durable_receipt.key_package_ref.to_string()];
    let cached_keypackage = verify_keypackage_consumer_signature(
        state,
        &session,
        &recipient_principal_id,
        &durable_receipt.recipient,
        &keypackage_refs,
        &body.signature,
        &consume_signing_input,
        None,
    )
    .await?;
    validate_recipient_durable_receipt(state, &session, &body, cached_keypackage.as_ref()).await?;
    let group_id = consume_group_ref(&body);
    // Signature verification may reuse immutable KeyPackage authoring bytes,
    // but lifecycle admission deliberately reloads the row here. Claim state
    // can change while Welcome and durable-receipt evidence is being checked;
    // the consume CAS must start from the freshest durable lifecycle snapshot.
    let record = state
        .mls_key_packages()
        .key_package_by_ref(durable_receipt.key_package_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage lookup failed: {error}")))?
        .ok_or_else(|| AppError::conflict("KeyPackage is missing or no longer claimable"))?;
    if !keypackage_record_matches_consumer(&record, &body, &session) {
        return Err(AppError::capability_denied(
            "KeyPackage consume endpoint is not the published owner",
        ));
    }
    let lifecycle = record.lifecycle().map_err(AppError::internal)?;
    if matches!(
        lifecycle.reuse_policy,
        PersistedKeyPackageReusePolicy::LastResort { .. }
    ) {
        return Err(crate::app_error!(
            FailedPrecondition,
            "last-resort consume requires the formal Welcome delivery current result",
        ));
    }
    if let PersistedKeyPackageClaimState::Consumed { mls_group_id, .. } = &lifecycle.claim_state {
        if mls_group_id.as_str() != group_id.as_str() {
            return Err(AppError::conflict(
                "KeyPackage was consumed by another MLS group",
            ));
        }
        let ledger = state
            .mls_key_packages()
            .peer_claim_by_keypackage_id(&record.id)
            .await
            .map_err(|error| {
                AppError::internal(format!("peer claim replay lookup failed: {error}"))
            })?
            .ok_or_else(|| {
                AppError::internal("consumed KeyPackage is missing its durable claim ledger")
            })?;
        if ledger.state != "consumed" {
            return Err(AppError::internal(
                "consumed KeyPackage ledger is not terminal",
            ));
        }
        let stored_receipt = ledger
            .consume_receipt
            .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("stored consume receipt invalid: {error}"))
            })?
            .ok_or_else(|| {
                AppError::internal("consumed KeyPackage ledger has no durable receipt")
            })?;
        validate_consume_receipt_replay(state, &body, &stored_receipt)?;
        return json_ok(KeyPackagesConsumeOutcome {
            consume_receipt: stored_receipt,
        });
    }
    if !matches!(
        lifecycle.claim_state,
        PersistedKeyPackageClaimState::Claimed { .. }
    ) {
        return Err(AppError::conflict(
            "KeyPackage has no active claim to consume",
        ));
    }
    let consumed_at_datetime = now();
    let consumed_at_unix_ms = consumed_at_datetime.timestamp_millis();
    let prepared_consume_receipt =
        build_keypackage_consume_receipt(state, &body, consumed_at_datetime)?;
    let prepared_consume_receipt_value = serde_json::to_value(&prepared_consume_receipt)
        .map_err(|error| AppError::internal(format!("consume receipt serialize: {error}")))?;
    let Some(consumed) = state
        .mls_key_packages()
        .consume_key_package_claim(
            &record.id,
            &group_id,
            consumed_at_unix_ms,
            Some(&prepared_consume_receipt_value),
        )
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage consume CAS failed: {error}")))?
    else {
        let winner = state
            .mls_key_packages()
            .peer_claim_by_keypackage_id(&record.id)
            .await
            .map_err(|error| {
                AppError::internal(format!("concurrent consume winner lookup failed: {error}"))
            })?
            .filter(|ledger| ledger.state == "consumed")
            .and_then(|ledger| ledger.consume_receipt)
            .map(serde_json::from_value::<KeyPackageConsumeReceipt>)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("concurrent consume receipt invalid: {error}"))
            })?
            .ok_or_else(|| AppError::conflict("KeyPackage claim changed before consume"))?;
        validate_consume_receipt_replay(state, &body, &winner)?;
        return json_ok(KeyPackagesConsumeOutcome {
            consume_receipt: winner,
        });
    };
    state
        .projections()
        .mark_key_package_consumed(&consumed.id, consumed_at_unix_ms.div_euclid(1000));
    json_ok(KeyPackagesConsumeOutcome {
        consume_receipt: prepared_consume_receipt,
    })
}

async fn validate_recipient_durable_receipt(
    state: &AppState,
    session: &SessionRecord,
    body: &KeyPackagesConsumeRequestBody,
    cached_keypackage: Option<&MlsKeyPackageRow>,
) -> Result<(), AppError> {
    let receipt = &body.recipient_durable_receipt;
    let recipient_principal_id = receipt
        .recipient_principal_id()
        .ok_or_else(|| AppError::param_invalid("durable recipient identity is incomplete"))?;
    if receipt.domain.as_str() != arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1
        || receipt.recipient_id.as_str() != state.service_id()
    {
        return Err(AppError::conflict(
            "recipient durable receipt differs from the consume coordinates",
        ));
    }
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "durable receipt signing transcript invalid: {error}"
        ))
    })?;
    verify_keypackage_consumer_signature(
        state,
        session,
        &recipient_principal_id,
        &receipt.recipient,
        std::slice::from_ref(&receipt.key_package_ref.to_string()),
        &receipt.signature,
        &signing_input,
        cached_keypackage,
    )
    .await?;
    receipt_matches_welcome_binding(state, body).await
}

/// device-lifecycle.md §9 consume (decision 0121): the durable receipt must
/// equal, value for value, the Welcome binding the claim destination recorded
/// when it queued the Welcome and the exact claim record with its original
/// request. The recipient queue is never read, so consume and ACK have no
/// order. No binding or any difference is the universal `conflict`.
async fn receipt_matches_welcome_binding(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
) -> Result<(), AppError> {
    let receipt = &body.recipient_durable_receipt;
    let mismatch = |detail: &str| AppError::conflict(format!("KeyPackage consume: {detail}"));
    let claim_id = body.claim_id.as_str();
    let binding = state
        .mls_key_packages()
        .claim_welcome_binding(claim_id)
        .await
        .map_err(|error| AppError::internal(format!("claim Welcome binding: {error}")))?
        .ok_or_else(|| mismatch("the claim has no queued Welcome"))?;
    if receipt.welcome_ref.as_str() != binding.welcome_id
        || receipt.welcome_digest.as_str() != binding.welcome_digest
    {
        return Err(mismatch(
            "the receipt names another Welcome than the claim's",
        ));
    }
    let commit_ref = arkret_wire::EventId::new(binding.commit_event_ref.clone())
        .map_err(|error| AppError::internal(format!("stored Welcome Commit ref: {error}")))?;
    let commit = state
        .authority_commits()
        .committed_event(&commit_ref)
        .await
        .map_err(|error| AppError::internal(format!("Welcome Commit lookup: {error}")))?
        .ok_or_else(|| AppError::internal("the bound Welcome Commit is not committed"))?;
    let payload: arkret_models_crypto::MlsCommitPayload =
        serde_json::to_value(&commit.event.payload)
            .and_then(serde_json::from_value)
            .map_err(|error| {
                AppError::internal(format!("bound Welcome Commit payload: {error}"))
            })?;
    if receipt.mls_epoch != payload.next_epoch() {
        return Err(mismatch(
            "the receipt epoch is not the Welcome Commit's epoch",
        ));
    }
    let ledger = state
        .mls_key_packages()
        .peer_claim_by_claim_id(claim_id)
        .await
        .map_err(|error| AppError::internal(format!("consume claim ledger: {error}")))?
        .filter(|ledger| {
            ledger.source_id == binding.source_id
                && ledger.claim_request_id == binding.claim_request_id
        })
        .ok_or_else(|| AppError::internal("the bound claim has no ledger row"))?;
    let outcome = ledger
        .outcome
        .map(serde_json::from_value::<PeerKeyPackagesClaimOutcome>)
        .transpose()
        .map_err(|error| AppError::internal(format!("stored claim outcome invalid: {error}")))?
        .ok_or_else(|| AppError::internal("the bound claim has no success outcome"))?;
    let record = outcome
        .claims
        .iter()
        .find(|record| record.claim_id == claim_id)
        .ok_or_else(|| AppError::internal("the bound claim is not in its outcome"))?;
    let request = &outcome.claim_receipt.request;
    let endpoint_matches = match &receipt.recipient {
        arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_account_id,
            recipient_device_id,
            ..
        } => {
            record.actor_id.as_account_id() == Some(recipient_account_id)
                && record.device_id.as_ref() == Some(recipient_device_id)
        }
        arkret_models_crypto::RecipientMlsDurableSigner::Agent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => {
            record.agent_id.as_ref() == Some(recipient_agent_id)
                && record.agent_verification_method.as_ref()
                    == Some(recipient_agent_verification_method)
                && record.agent_key_authorize_event_id.as_ref()
                    == Some(agent_key_authorize_event_id)
        }
    };
    if receipt.claim_request_id != outcome.claim_request_id
        || receipt.key_package_ref.as_str() != record.keypackage_ref
        || !endpoint_matches
        || receipt.realm_id != request.intended_realm_id
        || receipt.mls_group_id != request.mls_group_id
    {
        return Err(mismatch("the receipt differs from the exact claim record"));
    }
    Ok(())
}

async fn verify_keypackage_consumer_signature(
    state: &AppState,
    session: &SessionRecord,
    owner: &arkret_wire::DidCoreId,
    consumer: &arkret_models_crypto::RecipientMlsDurableSigner,
    keypackage_refs: &[String],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
    cached_keypackage: Option<&MlsKeyPackageRow>,
) -> Result<Option<MlsKeyPackageRow>, AppError> {
    let recipient_is_agent = matches!(
        consumer,
        arkret_models_crypto::RecipientMlsDurableSigner::Agent { .. }
    );
    if session.agent_session().is_some() != recipient_is_agent {
        return Err(AppError::capability_denied(
            "durable recipient signer branch must match the calling session",
        ));
    }
    match consumer {
        arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_device_id,
            ..
        } => {
            if recipient_device_id.as_str() != session.require_human_device_id() {
                return Err(AppError::capability_denied(
                    "durable recipient device must match the calling session",
                ));
            }
            // `device-lifecycle.md` 15: without this AND a revoked Applet's
            // Bot keeps signing MLS durable receipts, because its delegated
            // device's authorize is still accepted in the PCR.
            crate::routing::extensions::applet_bridge::ensure_delegated_device_not_fenced(
                state, owner,
            )
            .await?;
            verify_session_keypackage_write_signature(
                state,
                session,
                keypackage_refs,
                signature,
                signing_input,
                cached_keypackage,
            )
            .await
        }
        arkret_models_crypto::RecipientMlsDurableSigner::Agent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
        } => {
            if recipient_agent_id != owner
                || signature.kid.as_str() != recipient_agent_verification_method.as_str()
                || !current_agent_key_authorization_matches_method(
                    state,
                    recipient_agent_id,
                    agent_key_authorize_event_id.as_str(),
                    recipient_agent_verification_method.as_str(),
                )
                .await
            {
                return Err(AppError::capability_denied(
                    "Agent consume authority is not current",
                ));
            }
            verify_agent_keypackage_batch(
                state,
                recipient_agent_id,
                agent_key_authorize_event_id.as_str(),
                signature,
                signing_input,
            )
            .await
            .map_err(|error| {
                AppError::capability_denied(format!("Agent consume signature rejected: {error}"))
            })?;
            Ok(cached_keypackage.cloned())
        }
    }
}

fn keypackage_record_matches_consumer(
    record: &coland_services::events::MlsKeyPackageState,
    body: &KeyPackagesConsumeRequestBody,
    session: &SessionRecord,
) -> bool {
    let receipt = &body.recipient_durable_receipt;
    match &receipt.recipient {
        arkret_models_crypto::RecipientMlsDurableSigner::Device {
            recipient_account_id,
            recipient_device_id,
            ..
        } => {
            record.actor_id == recipient_account_id.principal_id.as_str()
                && session.actor == record.actor_id
                && record.device_id.as_deref() == Some(recipient_device_id.as_str())
                && record.endpoint_verification_method.is_none()
        }
        arkret_models_crypto::RecipientMlsDurableSigner::Agent {
            recipient_agent_id,
            recipient_agent_verification_method,
            agent_key_authorize_event_id,
            ..
        } => {
            record.actor_id == recipient_agent_id.as_str()
                && session.actor == record.actor_id
                && record.device_id.is_none()
                && record.endpoint_verification_method.as_deref()
                    == Some(recipient_agent_verification_method.as_str())
                && record.agent_key_authorize_event_id.as_deref()
                    == Some(agent_key_authorize_event_id.as_str())
        }
    }
}

fn build_keypackage_consume_receipt(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
    consumed_at: DateTime<Utc>,
) -> Result<KeyPackageConsumeReceipt, AppError> {
    let verification_method = format!("{}#notary-key", state.service_resolution_commitment().did);
    let mut receipt = KeyPackageConsumeReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::KEYPACKAGE_CONSUME_RECEIPT_V1,
        )
        .expect("receipt domain is non-empty"),
        request_digest: consume_request_digest(body)?,
        claim_id: body.claim_id.clone(),
        recipient_durable_receipt: body.recipient_durable_receipt.clone(),
        consumed_at,
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(verification_method)
                .expect("service notary method is non-empty"),
            signature_algorithm: Some(
                arkret_wire::NonEmptyString::new("Ed25519").expect("Ed25519 is non-empty"),
            ),
            sig: arkret_wire::Base64UrlString::new("AA")
                .expect("placeholder signature is base64url"),
        },
    };
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "consume receipt signing transcript invalid: {error}"
        ))
    })?;
    receipt.signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(state.notary_signing_key().sign(&signing_input).to_bytes()),
    )
    .map_err(|error| AppError::internal(format!("consume receipt signature invalid: {error}")))?;
    Ok(receipt)
}

fn consume_request_digest(
    body: &KeyPackagesConsumeRequestBody,
) -> Result<arkret_wire::Hash, AppError> {
    let digest = arkret_canonical::canonical_sha256(&body.unsigned())
        .map_err(|error| AppError::internal(format!("consume request digest failed: {error}")))?;
    arkret_wire::Hash::new(digest)
        .map_err(|error| AppError::internal(format!("consume request digest invalid: {error}")))
}

fn validate_consume_receipt_replay(
    state: &AppState,
    body: &KeyPackagesConsumeRequestBody,
    receipt: &KeyPackageConsumeReceipt,
) -> Result<(), AppError> {
    receipt
        .validate_shape()
        .map_err(|error| AppError::internal(format!("stored consume receipt shape: {error}")))?;
    if receipt.recipient_durable_receipt.recipient_id.as_str() != state.service_id()
        || receipt.request_digest != consume_request_digest(body)?
        || receipt.claim_id != body.claim_id
        || serde_json::to_value(&receipt.recipient_durable_receipt).map_err(|error| {
            AppError::internal(format!("stored durable receipt serialize: {error}"))
        })? != serde_json::to_value(&body.recipient_durable_receipt).map_err(|error| {
            AppError::internal(format!("request durable receipt serialize: {error}"))
        })?
    {
        return Err(AppError::conflict(
            "consume replay differs from the durably accepted request",
        ));
    }
    let expected_method = format!("{}#notary-key", state.service_resolution_commitment().did);
    if receipt.signature.kid.as_str() != expected_method
        || receipt
            .signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return Err(AppError::internal(
            "stored consume receipt service signer is invalid",
        ));
    }
    let signing_input = receipt.canonical_signing_bytes().map_err(|error| {
        AppError::internal(format!(
            "stored consume receipt transcript invalid: {error}"
        ))
    })?;
    if !crate::routing::identity::device_signing::ed25519_verify(
        &state.notary_verifying_key(),
        &signing_input,
        receipt.signature.sig.as_str(),
    ) {
        return Err(AppError::internal(
            "stored consume receipt service signature is invalid",
        ));
    }
    Ok(())
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.keypackages.command.revoke",
    tags("mls.rs")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.keypackages.command.revoke.v1"))]
async fn revoke_keypackages(
    aa: AuthArgs,
    body: JsonBody<KeyPackagesRevokeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyPackagesRevokeOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    if session.account_pk.is_none() && session.agent_session().is_none() {
        return Err(AppError::capability_denied(
            "KeyPackage revoke requires an account- or Agent-bound session",
        ));
    }
    let session_owner_account_pk = local_keypackage_owner_account_pk(state, &session).await?;
    let device_id = body.device_id.to_string();
    if device_id.as_str() != session.require_human_device_id() {
        return Err(AppError::capability_denied(
            "device_id must match the calling session",
        ));
    }
    let refs = non_empty_keypackage_refs(&body.key_package_refs)?;
    let revoke_signing_input =
        arkret_models_crypto::http_bodies::keypackages_revoke_signing_input(&body.unsigned())
            .map_err(|error| {
                AppError::param_invalid(format!(
                    "KeyPackage revoke canonical input failed: {error}"
                ))
            })?;
    verify_session_keypackage_revoke_signature(
        state,
        &session,
        &refs,
        &body.signature,
        &revoke_signing_input,
    )
    .await?;
    let revoked_at = now().timestamp();
    let mut revoked = Vec::new();
    let mut failures = Vec::new();
    for keypackage_ref in refs {
        match state
            .mls_key_packages()
            .key_package_by_ref(&keypackage_ref)
            .await
        {
            Ok(Some(record))
                if record.owner_account_pk != session_owner_account_pk
                    || record.actor_id != session.actor =>
            {
                failures.push(keypackage_ref_failure(keypackage_ref, "not_owner"));
            }
            Ok(Some(record))
                if record.lifecycle().is_ok_and(|lifecycle| {
                    matches!(
                        lifecycle.claim_state,
                        PersistedKeyPackageClaimState::Consumed { .. }
                    )
                }) =>
            {
                failures.push(keypackage_ref_failure(
                    keypackage_ref,
                    arkret_wire::ErrorCode::KEYPACKAGE_ALREADY_CONSUMED,
                ));
            }
            Ok(Some(record)) => {
                match state
                    .mls_key_packages()
                    .claim_key_package(coland_services::events::ClaimMlsKeyPackageCommand {
                        id: &record.id,
                        target: coland_services::events::ClaimMlsKeyPackageTarget::Revoke,
                        intended_realm_id: None,
                        device_authorize_event_id: None,
                        agent_key_authorize_event_id: None,
                        device_revocation_gate: None,
                        claimed_at: revoked_at,
                        claim_expires_at_unix_ms: None,
                    })
                    .await
                {
                    Ok(Some(_)) => {
                        state
                            .projections()
                            .mark_key_packages_revoked(std::slice::from_ref(&record.id));
                        revoked.push(keypackage_ref);
                    }
                    Ok(None) => {
                        failures.push(keypackage_ref_failure(
                            keypackage_ref,
                            arkret_wire::ErrorCode::KEYPACKAGE_ALREADY_CONSUMED,
                        ));
                    }
                    Err(error) => {
                        failures.push(keypackage_ref_failure(keypackage_ref, error.to_string()));
                    }
                }
            }
            Ok(None) => {
                failures.push(keypackage_ref_failure(
                    keypackage_ref,
                    arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN,
                ));
            }
            Err(error) => {
                failures.push(keypackage_ref_failure(keypackage_ref, error.to_string()));
            }
        }
    }
    json_ok(KeyPackagesRevokeOutcome { revoked, failures })
}

/// The governance binding of the Event that made `current` the scope's
/// current group: its accepted Genesis or winning Commit. It is read from the
/// exact committed Event, never restated in the typed current.
pub(crate) async fn current_mls_group_binding(
    state: &AppState,
    current: &arkret_wire::MlsGroupCurrent,
) -> Result<arkret_models_crypto::MlsGovernanceBindingPayload, AppError> {
    let event = state
        .event_queries()
        .canonical_event(current.current_mls_commit_event_ref.as_str())
        .await
        .map_err(|error| AppError::internal(format!("current MLS Event lookup: {error}")))?
        .ok_or_else(|| AppError::internal("the current MLS group Event is unavailable"))?;
    let binding = event
        .envelope
        .get("payload")
        .and_then(payload_fields::governance_binding)
        .cloned()
        .ok_or_else(|| AppError::internal("the current MLS Event has no governance binding"))?;
    serde_json::from_value(binding)
        .map_err(|error| AppError::internal(format!("current MLS governance binding: {error}")))
}

// ── helpers ───────────────────────────────────────────────────────────

async fn keypackage_device_revocation_gate(
    state: &AppState,
    actor_id: &str,
    device_id: &str,
    device_authorize_event_id: Option<&str>,
) -> Result<Option<coland_storage::DeviceRevocationGateSelector>, AppError> {
    let Some(device_authorize_event_id) = device_authorize_event_id else {
        return Ok(None);
    };
    let selector =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state, actor_id, device_id,
        )
        .await
        .map_err(|_| {
            crate::app_error!(
                ClaimFailed,
                "KeyPackage device authorization is unavailable",
            )
        })?;
    if selector.authorization_ref.event_id.as_str() != device_authorize_event_id {
        return Err(crate::app_error!(
            ClaimFailed,
            "KeyPackage device authorization is not current",
        ));
    }
    Ok(Some(selector))
}

/// A published KeyPackage names exactly the active registry suite its bytes
/// declare (encryption-and-audit §2.1). An unregistered or reserved suite, a
/// second advertised suite, or an outer label that differs from the bytes is
/// `unsupported_ciphersuite`; nothing is tried in turn or rewritten locally.
fn validate_keypackage_ciphersuite(
    entry: &KeyPackageUploadEntry,
    key_package_bytes: &[u8],
) -> Result<(), &'static str> {
    if arkret_mls::author_leaf_from_key_package_bytes(key_package_bytes, 0).is_err() {
        return Err("key_package_invalid");
    }
    let declared = arkret_mls::keypackage_ciphersuite_canonical_id(key_package_bytes)
        .map_err(|_| arkret_wire::ReasonCode::UNSUPPORTED_CIPHERSUITE)?;
    if entry.cipher_suites.len() != 1
        || entry.cipher_suites[0] != declared
        || !arkret_wire::MLS_CIPHERSUITES
            .iter()
            .any(|suite| suite.canonical_id == declared && suite.status == "active")
    {
        return Err(arkret_wire::ReasonCode::UNSUPPORTED_CIPHERSUITE);
    }
    Ok(())
}

fn validate_capabilities(capabilities: &[String]) -> Result<Vec<String>, String> {
    let capabilities_ref = capabilities.iter().map(String::as_str).collect::<Vec<_>>();
    arkret_models_crypto::validate_advertised_keypackage_capabilities(&capabilities_ref)
        .map_err(|_| "capabilities_invalid".to_owned())?;
    Ok(capabilities.to_vec())
}

fn decode_key_package(encoded: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .map_err(|_| "key_package_invalid_b64".to_owned())
        .and_then(|bytes| {
            if bytes.is_empty() {
                Err("key_package_empty".to_owned())
            } else {
                Ok(bytes)
            }
        })
}

async fn validate_agent_keypackage_upload(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    key_package_bytes: &[u8],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    verify_agent_keypackage_batch(
        state,
        principal,
        authorize_event_id,
        signature,
        signing_input,
    )
    .await?;
    validate_agent_keypackage_leaf(state, principal, authorize_event_id, key_package_bytes).await
}

async fn verify_agent_keypackage_batch(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), String> {
    let authorized_key =
        current_agent_keypackage_authorized_key(state, principal, authorize_event_id).await?;
    let verification_method = authorized_key.verification_method.as_str();
    let expected_public_key_digest = authorized_key.public_key_digest.as_str();
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(authorized_key.public_key.key.as_str())
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .as_slice()
        .try_into()
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    // `from_event` already validates the four-field Agent key and computes
    // its digest from these raw bytes. Its projection deliberately omits
    // `kid`, so passing it back through the full wire-key parser fails.
    if arkret_canonical::sha256_digest(public_key) != expected_public_key_digest
        || signature.kid.as_str() != verification_method
        || signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|algorithm| algorithm.as_str() != "Ed25519")
    {
        return Err("claim_generation_mismatch".to_owned());
    }
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public_key,
        verification_method,
        signing_input,
        signature,
    )
    .map_err(|_| "device_signature_invalid".to_owned())
}

async fn current_agent_keypackage_authorized_key(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
) -> Result<arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey, String> {
    if !current_agent_key_authorization_matches(state, principal, authorize_event_id).await {
        return Err("claim_generation_mismatch".to_owned());
    }
    let accepted = state
        .event_queries()
        .accepted_event(authorize_event_id)
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let event = serde_json::from_value::<arkret_wire::Event>(accepted.envelope)
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    if event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || event.actor_id.signing_principal_id().as_str() != principal.as_str()
    {
        return Err("claim_generation_mismatch".to_owned());
    }
    let authorized_key =
        arkret_models_identity::agent_signer_evidence::AgentAuthorizedSigningKey::from_event(
            &event,
        )
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    if authorized_key.agent_key_authorize_event_id.as_str() != authorize_event_id
        || authorized_key.agent_id != *principal
    {
        return Err("claim_generation_mismatch".to_owned());
    }
    Ok(authorized_key)
}

async fn validate_agent_keypackage_leaf(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let binding =
        current_agent_keypackage_authorized_key(state, principal, authorize_event_id).await?;
    let public_key = URL_SAFE_NO_PAD
        .decode(binding.public_key.key.as_str())
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let owner = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal.clone(),
        state.service_core_id(),
    ));
    validate_actor_keypackage_leaf(&owner, &public_key, key_package_bytes)
}

/// The KeyPackage LeafNode must carry the owner's exact v1 BasicCredential,
/// `UTF8(RFC8785_JCS(actor_id))` of the complete ActorId (never a collapsed
/// principal, DID or device id), and be signed by the owner's authorized key
/// (encryption-and-audit §2.1).
fn validate_actor_keypackage_leaf(
    owner: &arkret_wire::ActorId,
    public_key: &[u8],
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let expected_identity = arkret_models_crypto::mls_basic_credential_identity(owner)
        .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(key_package_bytes, 0)
        .map_err(|_| "key_package_invalid".to_owned())?;
    match leaf.credential {
        arkret_mls::AuthorLeafCredential::Basic { identity }
            if identity.as_slice() == expected_identity.as_slice() => {}
        _ => return Err("claim_generation_mismatch".to_owned()),
    }
    if leaf.signature_key.as_slice() != public_key {
        return Err("claim_generation_mismatch".to_owned());
    }
    Ok(())
}

async fn validate_device_keypackage_leaf(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    device_id: &str,
    key_package_bytes: &[u8],
) -> Result<(), String> {
    let device = state
        .identities()
        .find_device(coland_services::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|_| "claim_generation_mismatch".to_owned())?
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Err("claim_generation_mismatch".to_owned());
    }
    let device_public_key = device
        .payload
        .get("device_public_key_did")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "claim_generation_mismatch".to_owned())?;
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|_| "claim_generation_mismatch".to_owned())?;
    let owner = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal.clone(),
        state.service_core_id(),
    ));
    validate_actor_keypackage_leaf(&owner, &verifying_key.to_bytes(), key_package_bytes)
}

async fn verify_device_keypackage_signature(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    device_id: &str,
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), AppError> {
    let device = state
        .identities()
        .find_device(coland_services::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "accepted device authorization is required for KeyPackage signature",
            )
            .with_internal_reason("claim_generation_mismatch")
        })?;
    if device.verification_state != "verified" || device.revoked_at.is_some() {
        return Err(crate::app_error!(
            FailedPrecondition,
            "KeyPackage signature requires a verified, non-revoked device",
        )
        .with_internal_reason("claim_generation_mismatch"));
    }
    let device_public_key = device
        .payload
        .get("device_public_key_did")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid("authorized device signing key is unavailable"))?;
    if !crate::routing::identity::device_signature_kid_points_to_device_key(
        signature.kid.as_str(),
        principal.as_str(),
        device_public_key,
    ) {
        return Err(AppError::param_invalid(
            "KeyPackage signature kid does not point to the authorized device key",
        ));
    }
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|error| AppError::param_invalid(format!("device signing key is invalid: {error}")))?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &verifying_key.to_bytes(),
        signature.kid.as_str(),
        signing_input,
        signature,
    )
    .map_err(|_| AppError::param_invalid("device_signature_invalid"))
}

async fn verify_session_keypackage_write_signature(
    state: &AppState,
    session: &SessionRecord,
    keypackage_refs: &[String],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
    cached_keypackage: Option<&MlsKeyPackageRow>,
) -> Result<Option<MlsKeyPackageRow>, AppError> {
    let principal = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::param_invalid(format!("invalid session principal: {error}")))?;
    if session.agent_session().is_some() {
        let binding = current_agent_keypackage_trust_binding(state, &principal)
            .await?
            .ok_or_else(|| AppError::capability_denied("Agent key authorization is unavailable"))?;
        let authorize_event_id = binding
            .agent_key_authorize_event_id
            .as_deref()
            .expect("Agent trust binding always carries authorization Event");
        let mut resolved_single = None;
        for keypackage_ref in keypackage_refs {
            let record = if let Some(record) = cached_keypackage
                .filter(|record| record.keypackage_ref.as_str() == keypackage_ref.as_str())
            {
                record.clone()
            } else {
                state
                    .mls_key_packages()
                    .key_package_by_ref(keypackage_ref)
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?
                    .ok_or_else(|| {
                        AppError::param_invalid("KeyPackage signature target is missing")
                    })?
            };
            if record.actor_id != session.actor
                || record.device_id.is_some()
                || record.agent_key_authorize_event_id.as_deref() != Some(authorize_event_id)
            {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "Agent KeyPackage write binding differs from current authorization",
                )
                .with_internal_reason("claim_generation_mismatch"));
            }
            validate_agent_keypackage_upload(
                state,
                &principal,
                authorize_event_id,
                &record.key_package_bytes,
                signature,
                signing_input,
            )
            .await
            .map_err(AppError::param_invalid)?;
            if keypackage_refs.len() == 1 {
                resolved_single = Some(record);
            }
        }
        return Ok(resolved_single);
    }
    verify_device_keypackage_signature(
        state,
        &principal,
        session.require_human_device_id(),
        signature,
        signing_input,
    )
    .await?;
    Ok(cached_keypackage.cloned())
}

async fn verify_session_keypackage_revoke_signature(
    state: &AppState,
    session: &SessionRecord,
    keypackage_refs: &[String],
    signature: &KeyOperationSignature,
    signing_input: &[u8],
) -> Result<(), AppError> {
    let principal = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::param_invalid(format!("invalid session principal: {error}")))?;
    if session.agent_session().is_some() {
        let binding = current_agent_keypackage_trust_binding(state, &principal)
            .await?
            .ok_or_else(|| AppError::capability_denied("Agent key authorization is unavailable"))?;
        let authorize_event_id = binding
            .agent_key_authorize_event_id
            .as_deref()
            .expect("Agent trust binding always carries authorization Event");
        verify_agent_keypackage_batch(
            state,
            &principal,
            authorize_event_id,
            signature,
            signing_input,
        )
        .await
        .map_err(AppError::param_invalid)?;
        for keypackage_ref in keypackage_refs {
            let Some(record) = state
                .mls_key_packages()
                .key_package_by_ref(keypackage_ref)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
            else {
                // A locally-created package may race an asynchronous upload.
                // The revoke outcome reports it as not_found (and therefore
                // already unclaimable) instead of rejecting the whole signed
                // batch before per-reference processing.
                continue;
            };
            if record.actor_id != session.actor
                || record.device_id.is_some()
                || record.agent_key_authorize_event_id.as_deref() != Some(authorize_event_id)
            {
                return Err(crate::app_error!(
                    FailedPrecondition,
                    "Agent KeyPackage write binding differs from current authorization",
                )
                .with_internal_reason("claim_generation_mismatch"));
            }
        }
        return Ok(());
    }
    verify_device_keypackage_signature(
        state,
        &principal,
        session.require_human_device_id(),
        signature,
        signing_input,
    )
    .await
}

fn required_capability_set(capabilities: &[String]) -> Result<BTreeSet<String>, AppError> {
    let capabilities_ref = capabilities.iter().map(String::as_str).collect::<Vec<_>>();
    arkret_models_crypto::validate_required_keypackage_capabilities(
        &capabilities_ref,
        &capabilities_ref,
    )
    .map_err(|_| AppError::param_invalid("required_capabilities is invalid or unsupported"))?;
    Ok(capabilities.iter().cloned().collect())
}

fn capabilities_satisfy(published: &[String], required: &BTreeSet<String>) -> bool {
    let published: BTreeSet<_> = published.iter().cloned().collect();
    required.is_subset(&published)
}

async fn current_agent_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
) -> Result<Option<KeyPackageTrustBinding>, AppError> {
    let Some(agent) = state
        .agent_pairings()
        .agent(principal.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    else {
        return Ok(None);
    };
    if agent.state != AgentLifecycleState::Active {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Agent must be active before publishing or claiming a KeyPackage",
        )
        .with_internal_reason("claim_generation_mismatch"));
    }
    let event_ref = agent.authorized_event_ref.as_deref().ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "Agent has no accepted key authorization",
        )
        .with_internal_reason("claim_generation_mismatch")
    })?;
    let verification_method = agent
        .authorized_verification_method
        .as_deref()
        .ok_or_else(|| {
            crate::app_error!(FailedPrecondition, "Agent key authorization is incomplete",)
                .with_internal_reason("claim_generation_mismatch")
        })?;
    let active_event =
        crate::routing::identity::agents::accepted_active_agent_key_authorizations(state, &agent)
            .await?
            .into_iter()
            .any(|(_, active_event_ref)| active_event_ref == event_ref);
    if !active_event {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Agent key authorization is no longer active",
        )
        .with_internal_reason("claim_generation_mismatch"));
    }
    let accepted = state
        .event_queries()
        .accepted_event(event_ref)
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent key authorization lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "Agent key authorization Event is unavailable",
            )
            .with_internal_reason("claim_generation_mismatch")
        })?;
    let event =
        serde_json::from_value::<arkret_wire::Event>(accepted.envelope).map_err(|error| {
            AppError::internal(format!(
                "stored Agent key authorization Event invalid: {error}"
            ))
        })?;
    let payload = serde_json::to_value(event.payload)
        .map_err(|error| AppError::internal(format!("Agent key authorization payload: {error}")))?;
    let expired = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expires_at| expires_at.with_timezone(&Utc) <= now());
    if event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || event.actor_id.signing_principal_id().as_str() != principal.as_str()
        || payload.get("agent_id").and_then(Value::as_str) != Some(principal.as_str())
        || payload.get("verification_method").and_then(Value::as_str) != Some(verification_method)
        || expired
    {
        return Err(crate::app_error!(
            FailedPrecondition,
            "Agent key authorization does not match current accepted state",
        )
        .with_internal_reason("claim_generation_mismatch"));
    }
    Ok(Some(KeyPackageTrustBinding::agent_key_authorize(
        event_ref.to_owned(),
    )))
}

pub(crate) async fn current_agent_key_authorization_matches(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
) -> bool {
    current_agent_keypackage_trust_binding(state, principal)
        .await
        .ok()
        .flatten()
        .and_then(|binding| binding.agent_key_authorize_event_id)
        .as_deref()
        == Some(authorize_event_id)
}

pub(crate) async fn current_agent_key_authorization_matches_method(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    authorize_event_id: &str,
    verification_method: &str,
) -> bool {
    if !current_agent_key_authorization_matches(state, principal, authorize_event_id).await {
        return false;
    }
    state
        .agent_pairings()
        .agent(principal.as_str())
        .await
        .ok()
        .flatten()
        .and_then(|agent| agent.authorized_verification_method)
        .as_deref()
        == Some(verification_method)
}

async fn current_keypackage_trust_binding(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    device_id: &str,
) -> Result<KeyPackageTrustBinding, AppError> {
    if let Some(binding) = current_agent_keypackage_trust_binding(state, principal).await? {
        return Ok(binding);
    }
    let device = state
        .identities()
        .find_device(coland_services::identity::FindDeviceQuery {
            actor_id: principal.to_string(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "accepted device authorization is required for KeyPackage publish",
            )
            .with_internal_reason("claim_generation_mismatch")
        })?;
    device_authorize_trust_binding(&device).ok_or_else(|| {
        crate::app_error!(
            FailedPrecondition,
            "accepted device authorization is required for KeyPackage publish",
        )
        .with_internal_reason("claim_generation_mismatch")
    })
}

async fn current_keypackage_claim_trust_selector(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    target_device_ids: &BTreeSet<String>,
    intended_realm_id: Option<&str>,
) -> Result<KeyPackageTrustSelector, AppError> {
    if let Some(binding) = current_agent_keypackage_trust_binding(state, principal).await? {
        if let Some(realm_id) = intended_realm_id {
            let agent = state
                .agent_pairings()
                .agent(principal.as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| {
                    crate::app_error!(FailedPrecondition, "Agent membership is unavailable",)
                        .with_internal_reason("claim_generation_mismatch")
                })?;
            crate::routing::identity::agent_pcr::validate_effective_agent_realm_membership(
                state,
                &agent,
                realm_id,
                now(),
            )
            .await
            .map_err(|error| {
                tracing::warn!(agent_id = %principal, %realm_id, error = %error,
                    "Agent KeyPackage claim rejected by effective membership");
                crate::app_error!(FailedPrecondition, "Agent is not an effective Realm member",)
                    .with_internal_reason("claim_generation_mismatch")
            })?;
        }
        return Ok(KeyPackageTrustSelector::Principal(binding));
    }
    let mut bindings = BTreeMap::new();
    if target_device_ids.is_empty() {
        for device in state
            .identities()
            .devices_for_actor(principal.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            if let Some(binding) = device_authorize_trust_binding(&device) {
                bindings.insert(device.device_id, binding);
            }
        }
    } else {
        for device_id in target_device_ids {
            if let Some(device) = state
                .identities()
                .find_device(coland_services::identity::FindDeviceQuery {
                    actor_id: principal.to_string(),
                    device_id: device_id.clone(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                && let Some(binding) = device_authorize_trust_binding(&device)
            {
                bindings.insert(device_id.clone(), binding);
            }
        }
    }
    Ok(KeyPackageTrustSelector::PerDevice(bindings))
}

fn device_authorize_trust_binding(
    device: &coland_services::identity::DeviceIdentity,
) -> Option<KeyPackageTrustBinding> {
    if device.revoked_at.is_some() || device.verification_state != "verified" {
        return None;
    }
    device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|event_id| KeyPackageTrustBinding::device_authorize(event_id.to_owned()))
}

fn keypackage_failure(
    entry: &KeyPackageUploadEntry,
    device_id: Option<&str>,
    reason_code: impl AsRef<str>,
) -> KeypackageFailure {
    let keypackage_ref = if entry.keypackage_ref.is_empty() {
        entry.keypackage_id.clone()
    } else {
        entry.keypackage_ref.clone()
    };
    KeypackageFailure {
        keypackage_ref: (!keypackage_ref.is_empty()).then_some(keypackage_ref),
        device_id: device_id.map(str::to_owned),
        reason_code: keypackage_reason_code(reason_code.as_ref()),
        retry_after_ms: None,
    }
}

fn keypackage_ref_failure(
    keypackage_ref: String,
    reason_code: impl AsRef<str>,
) -> KeypackageFailure {
    KeypackageFailure {
        keypackage_ref: Some(keypackage_ref),
        device_id: None,
        reason_code: keypackage_reason_code(reason_code.as_ref()),
        retry_after_ms: None,
    }
}

fn keypackage_reason_code(reason_code: &str) -> arkret_wire::ReasonCode {
    if arkret_wire::ReasonCode::is_valid_wire(reason_code) {
        arkret_wire::ReasonCode::from_wire(reason_code)
    } else {
        // The failure DTO has a closed lexical profile. A diagnostic string
        // must never make the whole batch outcome fail JSON serialization and
        // turn a per-entry rejection into HTTP 500.
        arkret_wire::ReasonCode::from_wire("key_package_invalid")
    }
}

fn non_empty_keypackage_refs(refs: &[String]) -> Result<Vec<String>, AppError> {
    if refs.is_empty() {
        return Err(AppError::param_missing("key_package_refs is required"));
    }
    Ok(refs.to_vec())
}

fn consume_group_ref(body: &KeyPackagesConsumeRequestBody) -> String {
    body.recipient_durable_receipt.mls_group_id.to_string()
}

/// Whether `actor_id` currently has a KeyPackage that the canonical Realm
/// membership admission path can actually claim.
///
/// This intentionally reuses the same accepted-device trust
/// selector and capability-subset rules as `claim_keypackages_for_request`.
/// Merely having an untrusted or capability-incomplete KeyPackage row is not
/// sufficient for the Agent `leave -> join` carve-out in actor.md
/// section 3.3 / realm-and-space.md section 2.7.
pub(crate) async fn has_claimable_realm_membership_keypackage(
    state: &AppState,
    actor_id: &str,
    intended_realm_id: &str,
) -> bool {
    let Ok(principal) = arkret_wire::DidCoreId::new(actor_id.to_owned()) else {
        return false;
    };
    let target_device_ids = BTreeSet::new();
    // This is the admission preflight for the membership transition which
    // establishes the Agent's effective Realm membership. Requiring that
    // membership inside the trust selector would make the first join
    // impossible. The accepted Agent-key authorization is still checked
    // here, and the KeyPackage's Realm binding is checked below; actual claim
    // paths continue to pass `Some(intended_realm_id)` and recheck effective
    // membership at commit time.
    let Ok(trust_selector) =
        current_keypackage_claim_trust_selector(state, &principal, &target_device_ids, None).await
    else {
        return false;
    };
    let required_capabilities =
        BTreeSet::from(["ak.content.v1".to_owned(), "mimi.content.v1".to_owned()]);
    let now_secs = now().timestamp();
    state
        .projections()
        .mls_key_package_records()
        .iter()
        .any(|keypackage| {
            (ordinary_keypackage_is_available(keypackage)
                || last_resort_matches_realm(keypackage, intended_realm_id))
                && keypackage_matches_claim(
                    keypackage,
                    actor_id,
                    &target_device_ids,
                    &trust_selector,
                    now_secs,
                    &required_capabilities,
                )
        })
}

/// Claim the exact single-use KeyPackage requested through the MIMI facade.
/// The MIMI adapter deliberately delegates the state transition to the same
/// durable CAS used by the native KeyPackage lifecycle.
pub(crate) async fn claim_mimi_keypackage(
    state: &AppState,
    principal: &arkret_wire::DidCoreId,
    device_id: &arkret_wire::DeviceId,
    realm_id: &str,
    group_id: &str,
) -> Result<Option<MlsKeyPackageRow>, AppError> {
    let target_device_ids = BTreeSet::from([device_id.to_string()]);
    let trust_selector = current_keypackage_claim_trust_selector(
        state,
        principal,
        &target_device_ids,
        Some(realm_id),
    )
    .await?;
    let now_secs = now().timestamp();
    let candidate_ids = state
        .projections()
        .mls_key_package_records()
        .iter()
        .filter(|record| ordinary_keypackage_is_available(record))
        .filter(|record| {
            keypackage_matches_claim(
                record,
                principal.as_str(),
                &target_device_ids,
                &trust_selector,
                now_secs,
                &BTreeSet::from(["mimi.content.v1".to_owned()]),
            )
        })
        .map(|record| (record.created_at, record.id.clone()))
        .collect::<BTreeSet<_>>();

    for (_, candidate_id) in candidate_ids {
        let Some(candidate) = state
            .mls_key_packages()
            .key_package(&candidate_id)
            .await
            .map_err(|error| AppError::internal(format!("MIMI KeyPackage lookup: {error}")))?
        else {
            continue;
        };
        let binding = trust_binding_from_keypackage(&candidate)?;
        let device_revocation_gate = if binding.device_authorize_event_id.is_some() {
            let Some(candidate_device_id) = candidate.device_id.as_deref() else {
                continue;
            };
            keypackage_device_revocation_gate(
                state,
                &candidate.actor_id,
                candidate_device_id,
                binding.device_authorize_event_id.as_deref(),
            )
            .await?
        } else {
            None
        };
        let claimed = state
            .mls_key_packages()
            .claim_key_package(ClaimMlsKeyPackageCommand {
                id: &candidate_id,
                target: ClaimMlsKeyPackageTarget::Group(group_id),
                intended_realm_id: Some(realm_id),
                device_authorize_event_id: binding.device_authorize_event_id.as_deref(),
                agent_key_authorize_event_id: binding.agent_key_authorize_event_id.as_deref(),
                device_revocation_gate: device_revocation_gate.as_ref(),
                claimed_at: now_secs,
                claim_expires_at_unix_ms: Some(
                    (now() + chrono::Duration::minutes(10)).timestamp_millis(),
                ),
            })
            .await
            .map_err(|error| AppError::internal(format!("MIMI KeyPackage claim: {error}")))?;
        if let Some(claimed) = claimed {
            state.projections().mark_key_package_claimed(
                &candidate_id,
                group_id.to_owned(),
                now_secs,
                claimed.claim_expires_at_unix_ms,
            );
            return Ok(Some(claimed));
        }
    }
    Ok(None)
}

fn ordinary_keypackage_is_available(keypackage: &MlsKeyPackageRow) -> bool {
    keypackage.lifecycle().is_ok_and(|lifecycle| {
        matches!(
            lifecycle.reuse_policy,
            PersistedKeyPackageReusePolicy::SingleUse
        ) && matches!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
        )
    })
}

fn keypackage_matches_claim(
    kp: &MlsKeyPackageRow,
    actor_id: &str,
    target_device_ids: &BTreeSet<String>,
    trust_selector: &KeyPackageTrustSelector,
    now_secs: i64,
    required_capabilities: &BTreeSet<String>,
) -> bool {
    kp.actor_id == actor_id
        && (target_device_ids.is_empty()
            || kp
                .device_id
                .as_ref()
                .is_some_and(|device_id| target_device_ids.contains(device_id)))
        && kp.lifecycle().is_ok_and(|lifecycle| {
            matches!(
                lifecycle.claim_state,
                PersistedKeyPackageClaimState::Available
                    | PersistedKeyPackageClaimState::Claimed { .. }
            )
        })
        && trust_selector.matches_keypackage(kp)
        && kp.lifetime_not_after > now_secs
        && capabilities_satisfy(&kp.capabilities, required_capabilities)
}

fn last_resort_matches_realm(kp: &MlsKeyPackageRow, intended_realm_id: &str) -> bool {
    kp.lifecycle().is_ok_and(|lifecycle| {
        matches!(
            lifecycle.reuse_policy,
            PersistedKeyPackageReusePolicy::LastResort { ref bound_realm_id }
                if bound_realm_id
                    .as_ref()
                    .map(RealmId::as_str)
                    .is_none_or(|realm_id| realm_id == intended_realm_id)
        ) && matches!(
            lifecycle.claim_state,
            PersistedKeyPackageClaimState::Available
        )
    })
}

async fn keypackage_claim_record(
    state: &AppState,
    record: &MlsKeyPackageRow,
    request: &PeerKeyPackagesClaimRequestBody,
) -> Result<KeyPackageClaimRecord, AppError> {
    if record.device_authorize_event_id.is_none() && record.agent_key_authorize_event_id.is_none() {
        return Err(AppError::capability_denied(
            "retired pairwise KeyPackage cannot be claimed",
        ));
    }
    let principal_id = arkret_wire::DidCoreId::new(record.actor_id.clone())
        .map_err(|error| AppError::internal(format!("invalid principal_id: {error}")))?;
    let owner = state
        .identities()
        .account_by_id(record.owner_account_pk)
        .await
        .map_err(|error| AppError::internal(format!("KeyPackage owner lookup failed: {error}")))?
        .ok_or_else(|| AppError::internal("KeyPackage owner account is unavailable"))?;
    if record.agent_key_authorize_event_id.is_some() {
        // Agent KeyPackages are stored under the controller's local Account
        // row; the Agent has its own principal and no Human Account row.
        // Recheck that exact controller relation before exposing the claim.
        let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal_id.clone(),
            owner.account_id.station_id.clone(),
        ));
        let agent =
            crate::routing::identity::agent_pcr::agent_record_for_actor(state, &agent_actor)
                .await?
                .ok_or_else(|| AppError::capability_denied("target Agent is unavailable"))?;
        let controller =
            crate::routing::identity::agent_pcr::agent_controller_account(state, &agent).await?;
        if controller != owner.account_id
            || request.target_account_id.is_some()
            || request.target_agent_id.as_ref() != Some(&principal_id)
        {
            return Err(AppError::capability_denied(
                "Agent KeyPackage target differs from its durable controller binding",
            ));
        }
    } else if owner.principal_id != principal_id
        || request
            .target_account_id
            .as_ref()
            .is_some_and(|target| target != &owner.account_id)
    {
        return Err(AppError::capability_denied(
            "KeyPackage claim target account differs from its durable owner",
        ));
    }
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        principal_id.clone(),
        owner.account_id.station_id,
    ));
    let trust_binding = Some(trust_binding_from_row(record)?);
    let (device_id, agent_id, agent_verification_method) = if trust_binding
        .as_ref()
        .and_then(|binding| binding.agent_key_authorize_event_id.as_ref())
        .is_some()
    {
        let agent = state
            .agent_pairings()
            .agent(principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(format!("target Agent lookup failed: {error}")))?
            .ok_or_else(|| AppError::internal("target Agent projection is unavailable"))?;
        let method = agent
            .authorized_verification_method
            .ok_or_else(|| AppError::internal("target Agent verification method is unavailable"))?;
        let method = arkret_wire::DidUrl::new(method).map_err(|error| {
            AppError::internal(format!("target Agent verification method invalid: {error}"))
        })?;
        (None, Some(principal_id.clone()), Some(method))
    } else {
        (
            record
                .device_id
                .clone()
                .map(arkret_wire::DeviceId::new)
                .transpose()
                .map_err(|error| AppError::internal(format!("invalid device_id: {error}")))?,
            None,
            None,
        )
    };
    let keypackage = URL_SAFE_NO_PAD.encode(&record.key_package_bytes);
    let claim_id = format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7());
    Ok(KeyPackageClaimRecord {
        claim_id,
        keypackage_ref: record.keypackage_ref.clone(),
        actor_id,
        principal_id,
        device_id,
        agent_id,
        agent_verification_method,
        keypackage,
        capabilities: record.capabilities.clone(),
        device_authorize_event_id: trust_binding
            .as_ref()
            .and_then(|binding| binding.device_authorize_event_id.clone())
            .map(arkret_wire::EventId::new)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("device authorization Event id invalid: {error}"))
            })?,
        agent_key_authorize_event_id: trust_binding
            .as_ref()
            .and_then(|binding| binding.agent_key_authorize_event_id.clone())
            .map(arkret_wire::EventId::new)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("Agent authorization Event id invalid: {error}"))
            })?,
        expires_at: match record.claim_expires_at_unix_ms {
            Some(expires_at_unix_ms) => unix_millis_datetime(expires_at_unix_ms)?,
            None => unix_timestamp_datetime(record.lifetime_not_after)?,
        },
        revocation_status: Some("active".to_owned()),
        last_resort: record.last_resort.then_some(true),
    })
}

fn unix_timestamp_datetime(timestamp: i64) -> Result<DateTime<Utc>, AppError> {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| AppError::internal(format!("invalid unix timestamp: {timestamp}")))
}

fn unix_millis_datetime(timestamp_millis: i64) -> Result<DateTime<Utc>, AppError> {
    DateTime::from_timestamp_millis(timestamp_millis).ok_or_else(|| {
        AppError::internal(format!(
            "invalid unix millisecond timestamp: {timestamp_millis}"
        ))
    })
}

#[cfg(test)]
mod trust_binding_tests {
    use serde_json::json;

    use super::*;

    /// The requesting device's exact identity and its accepted authorization.
    struct ClaimRequester {
        principal_id: String,
        device_id: String,
        verification_method: String,
        device_authorize_event_id: String,
    }

    fn fixed_claim_requester() -> ClaimRequester {
        ClaimRequester {
            principal_id: "ak:did_core:web:claim-requester.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            verification_method:
                "did:web:claim-requester.example#ak:device:01904100-0000-7000-8000-000000000001"
                    .to_owned(),
            device_authorize_event_id: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"
                .to_owned(),
        }
    }

    fn signed_claim_authorization_fixture(
        source: arkret_wire::DidCoreId,
        destination: arkret_wire::DidCoreId,
        requester: &ClaimRequester,
        key: &ed25519_dalek::SigningKey,
    ) -> PeerKeyPackagesClaimRequestBody {
        let signed_at = arkret_canonical::normalize_timestamp_canonical(now());
        let mut body: PeerKeyPackagesClaimRequestBody = serde_json::from_value(serde_json::json!({
            "claim_request_id": URL_SAFE_NO_PAD.encode([71_u8; 16]),
            "target_account_id": {
                "principal_id": "ak:did_core:web:claim-target.example",
                "station_id": destination.clone()
            },
            "target_device_ids": ["ak:device:01904100-0000-7000-8000-000000000002"],
            "requester_account_id": {
                "principal_id": requester.principal_id,
                "station_id": source.clone()
            },
            "intended_realm_id": "ak:realm:ARaz6Z8HFGLoPkpji4ac9NxCUjXT81HDezufw7yJGiju",
            "mls_group_id": URL_SAFE_NO_PAD.encode([73_u8; 32]),
            "claim_purpose": "realm_membership",
            "required_capabilities": ["ak.content.v1"],
            "expires_at": signed_at + chrono::Duration::minutes(4),
            "service_binding": {"source_id": source, "destination_id": destination},
            "requester_authorization": {
                "kind": "device",
                "verification_method": requester.verification_method,
                "requester_device_id": requester.device_id,
                "device_authorize_event_id": requester.device_authorize_event_id,
                "signed_at": signed_at,
                "signature": {
                    "kid": requester.verification_method,
                    "signature_algorithm": "Ed25519",
                    "sig": "AA"
                }
            }
        }))
        .unwrap();
        let bytes = keypackage_claim_authorization_signing_bytes(
            &body.unsigned_request(),
            &body.service_binding,
            &body.requester_authorization,
        )
        .unwrap();
        let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
            &mut body.requester_authorization
        else {
            unreachable!();
        };
        signature.sig =
            arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()))
                .unwrap();
        body.validate_shape().unwrap();
        body
    }

    #[test]
    fn verified_claim_context_rejects_body_changes_and_expired_authorization() {
        let source = arkret_wire::DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination =
            arkret_wire::DidCoreId::new("ak:did_core:web:destination.example").unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[71_u8; 32]);
        let body =
            signed_claim_authorization_fixture(source, destination, &fixed_claim_requester(), &key);
        let authorization = VerifiedClaimAuthorization::for_verified_request(&body).unwrap();
        let digest = arkret_canonical::canonical_sha256(&body).unwrap();
        authorization.validate_request(&body, &digest).unwrap();
        let mut tampered = body.clone();
        tampered.service_binding.source_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:other-source.example").unwrap();
        assert!(
            authorization
                .validate_request(
                    &tampered,
                    &arkret_canonical::canonical_sha256(&tampered).unwrap()
                )
                .is_err()
        );
        tampered = body;
        tampered.expires_at = now() - chrono::Duration::seconds(1);
        let expired = VerifiedClaimAuthorization::for_verified_request(&tampered).unwrap();
        assert!(
            expired
                .validate_request(
                    &tampered,
                    &arkret_canonical::canonical_sha256(&tampered).unwrap()
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn local_claim_verifier_never_lends_same_principal_device_to_foreign_station() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        // The requester stands on a genuinely accepted PCR genesis: its founding
        // device is the only authority a claim authorization may cite.
        let fixture = coland_test_support::pcr_genesis::PcrGenesisFixture::new(state.service_did());
        fixture
            .admit_into(state.test_persistence().as_ref())
            .await
            .expect("accepted PCR genesis");
        let history = &fixture.history;
        let requester = ClaimRequester {
            principal_id: history.account.principal_id.to_string(),
            device_id: history.founding_device_id.to_string(),
            verification_method: history.device_verification_method.to_string(),
            device_authorize_event_id: history.events[1].event_id.to_string(),
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&history.founding_device_signing_seed);
        let local = signed_claim_authorization_fixture(
            state.service_core_id(),
            state.service_core_id(),
            &requester,
            &key,
        );
        assert!(
            verify_local_claim_participant_authorization(&state, &local)
                .await
                .unwrap()
        );
        // Even a valid signature by this local device cannot lend its accepted
        // authorization to a request belonging to another Station account.
        let foreign = signed_claim_authorization_fixture(
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap(),
            state.service_core_id(),
            &requester,
            &key,
        );
        assert!(
            !verify_local_claim_participant_authorization(&state, &foreign)
                .await
                .unwrap()
        );
    }

    #[test]
    fn upload_failure_carries_only_a_real_device_selector() {
        let entry = KeyPackageUploadEntry {
            keypackage_id: "kp-fixture".to_owned(),
            keypackage_ref: format!("sha256:{}", "1".repeat(64)),
            keypackage: arkret_wire::Base64UrlString::new("AA").unwrap(),
            cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            capabilities: vec!["ak.content.v1".to_owned()],
            expires_at: now() + chrono::Duration::minutes(5),
            created_at: now(),
            last_resort: None,
        };

        let pairwise_failure = keypackage_failure(&entry, None, "schema_violation");
        assert!(pairwise_failure.device_id.is_none());
        let device_failure = keypackage_failure(
            &entry,
            Some("ak:device:01964137-0000-7000-8000-000000000001"),
            "schema_violation",
        );
        assert_eq!(
            device_failure.device_id.as_deref(),
            Some("ak:device:01964137-0000-7000-8000-000000000001")
        );
    }

    fn device_keypackage(
        owner: &arkret_wire::ActorId,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> (KeyPackageUploadEntry, Vec<u8>) {
        let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
            owner.clone(),
            arkret_wire::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000011").unwrap(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(signing_key.clone()),
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let entry = identity.key_package_upload_entry(&record).unwrap();
        let bytes = decode_key_package(entry.keypackage.as_str()).unwrap();
        (entry, bytes)
    }

    /// A published LeafNode carries `UTF8(RFC8785_JCS(actor_id))` of the
    /// complete owner ActorId and the owner's authorized key; a collapsed
    /// principal, device id or another Station's AccountId is refused.
    #[test]
    fn keypackage_leaf_must_carry_the_complete_owner_actor() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x21; 32]);
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:kp-owner.example").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:kp-station.example").unwrap();
        let owner =
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(principal.clone(), station));
        let (_, bytes) = device_keypackage(&owner, &key);
        validate_actor_keypackage_leaf(&owner, &key.verifying_key().to_bytes(), &bytes).unwrap();

        let other_station = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        let collapsed = arkret_wire::ActorId::service(principal);
        for wrong_owner in [other_station, collapsed] {
            assert_eq!(
                validate_actor_keypackage_leaf(
                    &wrong_owner,
                    &key.verifying_key().to_bytes(),
                    &bytes
                ),
                Err("claim_generation_mismatch".to_owned())
            );
        }
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        assert_eq!(
            validate_actor_keypackage_leaf(&owner, &other_key.verifying_key().to_bytes(), &bytes),
            Err("claim_generation_mismatch".to_owned())
        );
    }

    /// Publication names exactly the active registry suite the bytes declare.
    #[test]
    fn keypackage_upload_names_only_the_declared_active_suite() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x23; 32]);
        let owner = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:kp-suite.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:kp-station.example").unwrap(),
        ));
        let (entry, bytes) = device_keypackage(&owner, &key);
        validate_keypackage_ciphersuite(&entry, &bytes).unwrap();
        for cipher_suites in [
            vec!["MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519".to_owned()],
            vec!["0x7fff".to_owned()],
            vec![
                "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519".to_owned(),
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            ],
            Vec::new(),
        ] {
            let mut presented = entry.clone();
            presented.cipher_suites = cipher_suites;
            assert_eq!(
                validate_keypackage_ciphersuite(&presented, &bytes),
                Err("unsupported_ciphersuite")
            );
        }
        assert_eq!(
            validate_keypackage_ciphersuite(&entry, b"not a keypackage"),
            Err("key_package_invalid")
        );
    }

    #[test]
    fn agent_binding_is_an_exclusive_branch() {
        let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let binding = trust_binding_from_parts(None, Some(event_id.to_owned()), "invalid").unwrap();
        assert_eq!(
            binding.agent_key_authorize_event_id.as_deref(),
            Some(event_id)
        );
        assert!(trust_binding_from_parts(None, None, "invalid").is_err());
        assert!(
            trust_binding_from_parts(
                Some(event_id.to_owned()),
                Some(event_id.to_owned()),
                "invalid"
            )
            .is_err()
        );
    }

    #[test]
    fn stored_agent_endpoint_preserves_exclusive_authorization_binding() {
        let authorization = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut row = MlsKeyPackageRow {
            id: "keypackage-fixture".into(),
            keypackage_ref: format!("sha256:{}", "1".repeat(64)),
            keypackage_digest: format!("sha256:{}", "2".repeat(64)),
            owner_account_pk: coland_storage::AccountPk(1),
            actor_id: "ak:did_core:web:agent.example".into(),
            device_id: None,
            endpoint_verification_method: Some("did:web:agent.example#runtime-1".into()),
            key_package_bytes: vec![],
            capabilities: vec![],
            capabilities_digest: format!("sha256:{}", "3".repeat(64)),
            last_resort: false,
            last_resort_realm_id: None,
            lifetime_not_before: 0,
            lifetime_not_after: i64::MAX,
            claimed_by_mls_group_id: None,
            device_authorize_event_id: None,
            agent_key_authorize_event_id: Some(authorization.into()),
            claimed_at: None,
            claim_expires_at_unix_ms: None,
            consumed_at: None,
            created_at: 0,
        };
        for binding in [
            trust_binding_from_keypackage(&row),
            trust_binding_from_row(&row),
        ] {
            let binding = binding.unwrap();
            assert_eq!(
                binding.agent_key_authorize_event_id.as_deref(),
                Some(authorization)
            );
        }
        row.device_authorize_event_id = Some(authorization.into());
        assert!(trust_binding_from_keypackage(&row).is_err());
        assert!(trust_binding_from_row(&row).is_err());
    }

    #[test]
    fn repeated_consumed_query_accepts_only_the_exact_durable_winner() {
        let receipt = json!({"domain": "ak.keypackage.consume_receipt.v1"});
        assert!(consumed_query_source_winner_matches(
            "consumed",
            "sha256:request",
            Some(&receipt),
            "sha256:request",
            &receipt,
        ));
        assert!(!consumed_query_source_winner_matches(
            "consumed",
            "sha256:request",
            Some(&receipt),
            "sha256:other",
            &receipt,
        ));
        assert!(!consumed_query_source_winner_matches(
            "last_resort_claimed",
            "sha256:request",
            Some(&receipt),
            "sha256:request",
            &receipt,
        ));
    }

    #[test]
    fn terminal_query_requires_exact_refs_and_non_early_expiry() {
        assert!(terminal_claim_coordinates_match(
            "expired",
            20_500,
            20_500,
            ["kp-a", "kp-b"],
            ["kp-a", "kp-b"],
        ));
        assert!(!terminal_claim_coordinates_match(
            "expired",
            20_500,
            20_499,
            ["kp-a", "kp-b"],
            ["kp-a", "kp-b"],
        ));
        assert!(!terminal_claim_coordinates_match(
            "expired",
            20_500,
            20_500,
            ["kp-b", "kp-a"],
            ["kp-a", "kp-b"],
        ));
        assert!(terminal_claim_coordinates_match(
            "revoked",
            20_500,
            19_000,
            ["kp-a"],
            ["kp-a"],
        ));
    }

    #[test]
    fn claim_failed_query_rejects_a_contradictory_existing_winner() {
        let expected = PeerKeyPackageClaimLedgerRecord {
            source_id: "ak:did_core:web:source.example".to_owned(),
            claim_request_id: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            request_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            key_package_use: "none".to_owned(),
            keypackage_id: None,
            outcome: None,
            terminal_receipt: Some(json!({"terminal_state": "never_claimed"})),
            consume_receipt: None,
            claim_expires_at_unix_ms: Some(20_500),
            expires_at: 620,
            state: "claim_failed".to_owned(),
            updated_at: 10,
        };
        let mut replay = expected.clone();
        replay.updated_at = 11;
        assert!(claim_failed_source_winner_matches(&replay, &expected));

        let mut contradictory = expected.clone();
        contradictory.key_package_use = "last_resort".to_owned();
        contradictory.state = "last_resort_claimed".to_owned();
        contradictory.outcome = Some(json!({"claims": ["kp-a"]}));
        assert!(!claim_failed_source_winner_matches(
            &contradictory,
            &expected
        ));
    }

    #[test]
    fn keypackage_failure_reason_never_breaks_the_typed_outcome() {
        assert_eq!(
            keypackage_reason_code("claim_generation_mismatch").as_str(),
            "claim_generation_mismatch"
        );
        assert_eq!(
            keypackage_reason_code("param_invalid: claim generation mismatch").as_str(),
            "key_package_invalid"
        );
    }

    /// device-lifecycle.md §9 `claims/query`: a claim is read only by its own
    /// exact endpoint -- the complete AccountId and device, or the Agent with
    /// its exact method and authorize Event -- never by the same principal on
    /// another Station, another device or a replaced Agent authorization.
    #[test]
    fn a_claim_record_is_read_only_by_its_exact_endpoint() {
        let station = "ak:did_core:web:claim-read-station.example";
        let account = |station: &str| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:claim-owner.example").unwrap(),
                arkret_wire::DidCoreId::new(station).unwrap(),
            ))
        };
        let device = "ak:device:01964137-0000-7000-8000-000000000021";
        let record = KeyPackageClaimRecord {
            claim_id: "ak:keypackage_claim:01964137-0000-7000-8000-000000000022".to_owned(),
            keypackage_ref: format!("sha256:{}", "2".repeat(64)),
            actor_id: account(station),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:claim-owner.example")
                .unwrap(),
            device_id: Some(arkret_wire::DeviceId::new(device).unwrap()),
            agent_id: None,
            agent_verification_method: None,
            keypackage: "AA".to_owned(),
            capabilities: Vec::new(),
            device_authorize_event_id: None,
            agent_key_authorize_event_id: None,
            expires_at: now(),
            revocation_status: None,
            last_resort: None,
        };
        let owner = ClaimReader::Device {
            actor: account(station),
            device_id: device.to_owned(),
        };
        assert!(claim_record_names_reader(&record, &owner));
        for other in [
            ClaimReader::Device {
                actor: account("ak:did_core:web:other-station.example"),
                device_id: device.to_owned(),
            },
            ClaimReader::Device {
                actor: account(station),
                device_id: "ak:device:01964137-0000-7000-8000-000000000023".to_owned(),
            },
        ] {
            assert!(!claim_record_names_reader(&record, &other), "{other:?}");
        }

        let agent = "ak:did_core:web:claim-agent.example";
        let method = "did:web:claim-agent.example#runtime";
        let authorize = "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
        let agent_record = KeyPackageClaimRecord {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(agent).unwrap(),
                arkret_wire::DidCoreId::new(station).unwrap(),
            )),
            principal_id: arkret_wire::DidCoreId::new(agent).unwrap(),
            device_id: None,
            agent_id: Some(arkret_wire::DidCoreId::new(agent).unwrap()),
            agent_verification_method: Some(arkret_wire::DidUrl::new(method).unwrap()),
            agent_key_authorize_event_id: Some(arkret_wire::EventId::new(authorize).unwrap()),
            ..record.clone()
        };
        let runtime = ClaimReader::Agent {
            agent_id: agent.to_owned(),
            verification_method: method.to_owned(),
            authorize_event_id: authorize.to_owned(),
        };
        assert!(claim_record_names_reader(&agent_record, &runtime));
        assert!(!claim_record_names_reader(&record, &runtime));
        assert!(!claim_record_names_reader(&agent_record, &owner));
        let replaced = ClaimReader::Agent {
            agent_id: agent.to_owned(),
            verification_method: method.to_owned(),
            authorize_event_id: "ak:event:AQ3uiXLNG8rmS8ghzZ8LQ9xk2-NHOvG9AuFbl3QdMB0f".to_owned(),
        };
        assert!(!claim_record_names_reader(&agent_record, &replaced));
    }
}
