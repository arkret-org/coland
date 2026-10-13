//! The MLS Genesis and Commit admission unit.
//!
//! `ak.mls.genesis` (encryption-and-audit.md §5.1) and `ak.mls.commit` with
//! every Welcome of its Add proposals (§2.2) are admitted by the current
//! governance Station in the guarded Event unit, extended with the public
//! group transition and the recipient queue writes.
//!
//! Before the transaction this Station verifies, from the exact Event bytes
//! and nothing a producer asserts separately:
//!
//! - the RFC 9420 public transition. A Genesis is its GroupInfo and ratchet tree Blobs at epoch 0
//!   with only the creator's leaf; a Commit is one member-sent `PublicMessage` processed by the
//!   public tracker restored from the scope's current group. The GroupContext `0xF1C0` binding must
//!   equal the Event payload binding and the current group field for field (§2.5.1).
//! - every Welcome. It is producer-signed by the Commit's producer method (§2.6.1) and names the
//!   exact Commit. A recipient on this Station names a live claim of this Station's claim ledger
//!   whose destination-signed receipt binds the requester, target, Realm, group, endpoint and
//!   KeyPackage (device-lifecycle.md claim ledger rules), and its claimed KeyPackage is exactly one
//!   leaf the Commit adds. A recipient another Station hosts owns one added leaf of its own; its
//!   claim is that Station's, which re-verifies it when the Welcome arrives with the Commit's
//!   committed replication (§2.2).
//!
//! The accepting transaction then re-decides everything that can change
//! concurrently at one cut: same-cut authorization, the current group the
//! transition was verified against, the current key-access revision, every
//! claim row, recipient endpoint authorization and queue capacity. Any
//! refusal leaves zero writes.

use std::collections::BTreeMap;

use arkret_mls::{MlsPublicEndpointLeaf, MlsPublicGroupTracker, MlsPublicHandshakeTransition};
use arkret_models_collaboration::authority_commit::MlsGenesisMaterial;
use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::events_payloads::mls_proposal_admission::MlsProposalSenderClass;
use arkret_models_collaboration::mls_roster_authority::{
    MlsAddAuthorityAttestation, MlsAttestAddRequestBody,
};
use arkret_models_crypto::{
    KeyOperationSignature, KeyPackageClaimRecord, MlsCommitPayload, PeerKeyPackagesClaimOutcome,
};
use arkret_wire::{
    AuthoritySubmitOutcome, Base64UrlString, DetachedSignatureContext, Event,
    EventAdmissionSubmission, EventKind, MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, ScopeRef,
};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{
    ConflictCode, MlsConsumedProposalInstallation, MlsInstalledBase, MlsProposalLeafProvenance,
    MlsPublicBlob, MlsStateInstallation, MlsWelcomeClaimLedgerKey,
    VerifiedMlsRecipientRosterWitness, VerifiedMlsWelcome,
};

use super::AppState;
use super::authority_self_event_unit::{AdmittedProducer, SelfEventUnitEffects};

/// The verified public transition and Welcomes an MLS Event commits with.
pub(super) struct MlsUnitInstallation {
    pub(super) state: MlsStateInstallation,
    pub(super) welcomes: Vec<VerifiedMlsWelcome>,
}

fn refused(code: ConflictCode, detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("{code}: {detail}"))
}

fn failed_precondition(detail: impl std::fmt::Display) -> ServiceError {
    refused(ConflictCode::FailedPrecondition, detail)
}

fn binding_mismatch(detail: impl std::fmt::Display) -> ServiceError {
    refused(ConflictCode::GovernanceBindingMismatch, detail)
}

fn schema(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::SchemaViolation(detail.to_string())
}

fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> ServiceResult<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(schema)?).map_err(schema)
}

/// Admit one producer-verified MLS Event with its Welcomes.
///
/// `producer_key` is the key the Event producer proof verified under; every
/// Welcome must be sealed by the same method (§2.6.1).
///
/// `genesis_material` is the raw GroupInfo and ratchet tree an
/// `authority_forward` of a cross-Station Genesis carried (§5.1.2); a
/// same-Station Genesis reads its local Blobs and passes `None`.
pub(super) fn admit_mls_event<'a>(
    state: &'a AppState,
    event: &'a Event,
    welcomes: &'a [MlsWelcomeDelivery],
    genesis_material: Option<&'a MlsGenesisMaterial>,
    producer: AdmittedProducer,
    producer_key: &'a arkret_signatures::PublicKeyMaterial,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = ServiceResult<AuthoritySubmitOutcome>> + Send + 'a>,
> {
    // Keep the public-transition future out of ordinary submit-port frames.
    Box::pin(admit_mls_event_inner(
        state,
        event,
        welcomes,
        genesis_material,
        producer,
        producer_key,
    ))
}

async fn admit_mls_event_inner(
    state: &AppState,
    event: &Event,
    welcomes: &[MlsWelcomeDelivery],
    genesis_material: Option<&MlsGenesisMaterial>,
    producer: AdmittedProducer,
    producer_key: &arkret_signatures::PublicKeyMaterial,
) -> ServiceResult<AuthoritySubmitOutcome> {
    if let Some(outcome) = super::authority_self_event_unit::exact_replay(state, event).await? {
        return Ok(outcome);
    }
    if !matches!(&event.scope_ref, ScopeRef::Realm { realm_id } | ScopeRef::Circle { realm_id, .. } | ScopeRef::Sidecar { realm_id, .. } if realm_id == &event.realm_id)
    {
        return Err(ServiceError::Internal(
            "the MLS effective scope has no supported authority cut".to_owned(),
        ));
    }
    let refusal_authority = if event.kind == EventKind::MlsCommit {
        state
            .authority_commits()
            .current_authority(&event.realm_id)
            .await?
    } else {
        None
    };
    let (installation, added_leaves) = match event.kind {
        EventKind::MlsGenesis => {
            if !welcomes.is_empty() {
                return Err(schema("an MLS Genesis carries no Welcome"));
            }
            (
                verify_genesis(state, event, genesis_material).await?,
                Vec::new(),
            )
        }
        EventKind::MlsCommit if genesis_material.is_none() => {
            match prepare_commit(state, event).await? {
                PreparedCommit::Ready(installation, added_leaves) => (installation, added_leaves),
                PreparedCommit::KeyAccessRefused(added_leaves) => {
                    // A malformed or unsealed Welcome is a request refusal,
                    // never a durable Event-level rejection.
                    verify_welcomes(state, event, welcomes, &added_leaves, producer_key).await?;
                    let authority = refusal_authority.as_ref().ok_or_else(|| {
                        failed_precondition("MLS refusal has no current authority")
                    })?;
                    return state
                        .authority_commits()
                        .finalize_mls_rejection(
                            event,
                            authority,
                            arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH,
                        )
                        .await;
                }
            }
        }
        _ => {
            return Err(ServiceError::Internal(
                "the MLS unit admits only ak.mls.genesis and ak.mls.commit".to_owned(),
            ));
        }
    };
    let welcomes = verify_welcomes(state, event, welcomes, &added_leaves, producer_key).await?;
    let outcome = super::authority_self_event_unit::commit_event_unit(
        state,
        &EventAdmissionSubmission::new(event.clone()),
        producer,
        SelfEventUnitEffects {
            mls: Some(MlsUnitInstallation {
                state: installation,
                welcomes,
            }),
            ..SelfEventUnitEffects::default()
        },
    )
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error)
            if event.kind == EventKind::MlsCommit
                && error.conflict_code() == Some(ConflictCode::GovernanceBindingMismatch) =>
        {
            // The complete request was verified above; a revision race at the
            // locked admission cut needs the same exclusive refusal fence.
            let authority = refusal_authority
                .as_ref()
                .ok_or_else(|| failed_precondition("MLS refusal has no current authority"))?;
            return state
                .authority_commits()
                .finalize_mls_rejection(
                    event,
                    authority,
                    arkret_wire::ReasonCode::GOVERNANCE_BINDING_MISMATCH,
                )
                .await;
        }
        Err(error) => return Err(error),
    };
    if let AuthoritySubmitOutcome::Rejected {
        status: arkret_wire::AuthorityRejectionStatus::Rejected,
        reason_code,
    } = &outcome
        && event.kind == EventKind::MlsCommit
    {
        let authority = refusal_authority
            .ok_or_else(|| failed_precondition("MLS refusal has no current authority"))?;
        return state
            .authority_commits()
            .finalize_mls_rejection(event, &authority, reason_code)
            .await;
    }
    Ok(outcome)
}

/// Sign the original local claim's Add proof after the covering Commit has
/// received its exact stream position, but before the accepting transaction.
/// The transaction rechecks all selectors against its locked accepted cut.
pub(super) async fn attach_local_roster_witnesses(
    state: &AppState,
    transaction: &mut coland_storage::AuthorityCommitTransaction,
) -> ServiceResult<()> {
    if transaction.event.kind != EventKind::MlsCommit {
        return Ok(());
    }
    if !transaction
        .welcomes
        .iter()
        .any(|welcome| welcome.claim.is_some())
    {
        return Ok(());
    }
    let current = state
        .mls_groups()
        .current(&transaction.event.scope_ref)
        .await?
        .ok_or_else(|| failed_precondition("the scope has no accepted MLS Genesis"))?;
    let installation = transaction
        .mls_state
        .as_ref()
        .ok_or_else(|| schema("MLS Commit has no public transition"))?;
    let added = installation
        .consumed_proposals
        .iter()
        .filter(|proposal| proposal.proposal_type == 1)
        .map(|proposal| {
            arkret_mls::verify_add_proposal_leaf(&proposal.proposal_wire).map_err(schema)
        })
        .collect::<ServiceResult<Vec<_>>>()?;
    sign_local_roster_witnesses(
        state,
        &transaction.event,
        &transaction.commit,
        &current.value.genesis_event_ref,
        installation.epoch,
        transaction.commit.committed_at,
        &added,
        &mut transaction.welcomes,
    )
    .await
}

/// A replica recipient signs the exact Add after its original governance
/// receipt has been verified. It does not reconstruct a pre-join MLS group.
pub(super) async fn attach_replicated_roster_witnesses(
    state: &AppState,
    item: &arkret_models_collaboration::authority_commit::CommittedEventSubmission,
    welcomes: &mut [VerifiedMlsWelcome],
) -> ServiceResult<()> {
    if welcomes.is_empty() {
        return Ok(());
    }
    let event = &item.event_submission.event;
    let payload: MlsCommitPayload = payload(event)?;
    let genesis = item
        .genesis_event_ref
        .as_ref()
        .ok_or_else(|| failed_precondition("replicated Welcome lacks accepted Genesis selector"))?;
    let group = event.scope_ref.canonical_mls_group_id().map_err(schema)?;
    let added = arkret_mls::verify_adds_from_accepted_public_commit(
        &arkret_canonical::base64url_decode(payload.commit_bytes_b64()).map_err(schema)?,
        group.as_str(),
        payload.governance_binding().previous_epoch(),
    )
    .map_err(schema)?;
    for welcome in welcomes.iter_mut() {
        if let Some(request) = state
            .authority_commits()
            .mls_recipient_attestation(&event.event_id, &welcome.delivery.welcome_id)
            .await?
        {
            welcome.roster_witness =
                Some(VerifiedMlsRecipientRosterWitness {
                    accepted_genesis_event_ref: genesis.clone(),
                    signed_attest_add_request_canonical_json:
                        arkret_canonical::canonical_json_bytes(&request).map_err(schema)?,
                    local_attestor_resolution: None,
                });
        }
    }
    sign_local_roster_witnesses(
        state,
        event,
        &item.source_commit,
        genesis,
        payload.next_epoch(),
        crate::wire::now(),
        &added,
        welcomes,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn sign_local_roster_witnesses(
    state: &AppState,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    genesis: &arkret_wire::EventId,
    epoch: u64,
    attested_at: chrono::DateTime<chrono::Utc>,
    added: &[arkret_mls::MlsVerifiedAddProposalLeaf],
    welcomes: &mut [VerifiedMlsWelcome],
) -> ServiceResult<()> {
    if welcomes
        .iter()
        .all(|welcome| welcome.roster_witness.is_some())
    {
        return Ok(());
    }
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("local Station history unavailable: {error}"))
            })?;
    let station = state.service_core_id();
    let method = format!("{}#notary-key", state.service_did());
    let group = event.scope_ref.canonical_mls_group_id().map_err(schema)?;
    for welcome in welcomes {
        if welcome.roster_witness.is_some() {
            continue;
        }
        let Some(claim_key) = &welcome.claim else {
            continue;
        };
        let row = state
            .mls_key_packages()
            .peer_claim_by_claim_id(welcome.delivery.keypackage_claim_ref.as_str())
            .await?
            .ok_or_else(|| failed_precondition("local Add claim outcome is unavailable"))?;
        if row.source_id != claim_key.source_id
            || row.claim_request_id != claim_key.claim_request_id
            || row.request_digest != claim_key.request_digest
            || !matches!(row.state.as_str(), "claimed" | "last_resort_claimed")
        {
            return Err(failed_precondition(
                "local Add claim differs from the verified claim",
            ));
        }
        let outcome: PeerKeyPackagesClaimOutcome = serde_json::from_value(
            row.outcome
                .ok_or_else(|| failed_precondition("local Add claim has no signed outcome"))?,
        )
        .map_err(schema)?;
        let selected = outcome
            .claims
            .iter()
            .find(|claim| claim.claim_id == welcome.delivery.keypackage_claim_ref.as_str())
            .ok_or_else(|| failed_precondition("local Add claim id is absent"))?;
        let package = arkret_canonical::base64url_decode(&selected.keypackage).map_err(schema)?;
        let mut matching = added.iter().filter(|parsed| {
            parsed.actor_id == welcome.delivery.recipient_actor_id
                && parsed.key_package_bytes == package
        });
        let parsed = matching
            .next()
            .ok_or_else(|| failed_precondition("local claim does not match a consumed Add"))?;
        if matching.next().is_some() {
            return Err(failed_precondition(
                "local claim matches multiple consumed Adds",
            ));
        }
        let authorization_event_ref = match &welcome.delivery.recipient_endpoint {
            MlsWelcomeRecipientEndpoint::Device { .. } => {
                selected.device_authorize_event_id.clone()
            }
            MlsWelcomeRecipientEndpoint::AgentRuntime { .. } => {
                selected.agent_key_authorize_event_id.clone()
            }
        }
        .ok_or_else(|| failed_precondition("local Add lacks endpoint authorization"))?;
        let mut attestation = MlsAddAuthorityAttestation {
            attestor_station_id: station.clone(),
            realm_id: event.realm_id.clone(),
            effective_scope: event.scope_ref.clone(),
            mls_group_id: group.clone(),
            genesis_event_ref: genesis.clone(),
            commit_event_ref: event.event_id.clone(),
            commit_stream_position: commit.stream_position,
            epoch,
            welcome_id: welcome.delivery.welcome_id.clone(),
            claim_id: welcome.delivery.keypackage_claim_ref.clone(),
            actor_id: welcome.delivery.recipient_actor_id.clone(),
            endpoint: welcome.delivery.recipient_endpoint.clone(),
            authorization_event_ref,
            leaf_signature_key_b64u: parsed.leaf_signature_key.clone(),
            claim_record_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(selected).map_err(schema)?,
            )
            .map_err(schema)?,
            claim_receipt: outcome.claim_receipt.clone(),
            attested_at,
            signature: KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(method.clone()).map_err(schema)?,
                signature_algorithm: Some(
                    arkret_wire::NonEmptyString::new("Ed25519").map_err(schema)?,
                ),
                sig: Base64UrlString::new("AA").map_err(schema)?,
            },
        };
        attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &state.notary_signing_key().to_bytes(),
            &method,
            &attestation.signing_bytes().map_err(schema)?,
        )
        .map_err(schema)?;
        let request = MlsAttestAddRequestBody {
            attestation,
            claim_outcome: outcome,
        };
        request.validate_claim_binding().map_err(schema)?;
        arkret::verify_mls_attest_add_request(&request, &resolution).map_err(schema)?;
        welcome.roster_witness = Some(VerifiedMlsRecipientRosterWitness {
            accepted_genesis_event_ref: genesis.clone(),
            signed_attest_add_request_canonical_json: arkret_canonical::canonical_json_bytes(
                &request,
            )
            .map_err(schema)?,
            local_attestor_resolution: Some(resolution.clone()),
        });
    }
    Ok(())
}

/// §5.1: the Genesis GroupInfo and ratchet tree are content-addressed Blobs
/// describing the scope's group at epoch 0 with the creator as its only leaf,
/// under the exact `0 -> 0` binding the Event signs. A cross-Station Genesis
/// carries their raw bytes (§5.1.2): each must address its own ref before
/// anything is written, and both are stored with the Genesis Commit.
async fn verify_genesis(
    state: &AppState,
    event: &Event,
    genesis_material: Option<&MlsGenesisMaterial>,
) -> ServiceResult<MlsStateInstallation> {
    let payload: MlsGenesisPayload = payload(event)?;
    payload.validate().map_err(schema)?;
    let authority = &payload.creator_leaf_authority;
    if payload.effective_scope() != &event.scope_ref {
        return Err(binding_mismatch(
            "the Genesis binding names another effective scope",
        ));
    }
    if state
        .mls_groups()
        .current(&event.scope_ref)
        .await?
        .is_some()
    {
        return Err(refused(
            ConflictCode::MlsActivationIrreversible,
            "the scope's MLS Genesis is already accepted",
        ));
    }
    let group_id = payload.mls_group_id().map_err(schema)?;
    let (group_info, tree) = match genesis_material {
        Some(material) => {
            let (group_info, tree) = material.decode().map_err(|error| {
                ServiceError::protocol(
                    error
                        .error_code()
                        .unwrap_or(arkret_wire::ErrorCode::SchemaViolation),
                    error,
                )
            })?;
            carried_blob_addresses(&payload.group_info_ref, &group_info)?;
            carried_blob_addresses(&payload.ratchet_tree_ref, &tree)?;
            (group_info, tree)
        }
        None => (
            public_blob(state, payload.group_info_ref.as_str()).await?,
            public_blob(state, payload.ratchet_tree_ref.as_str()).await?,
        ),
    };
    let tracker = MlsPublicGroupTracker::from_external(&group_info, &tree, group_id.as_str(), 0)
        .map_err(|error| schema(format!("MLS Genesis public state is invalid: {error}")))?;
    let suite = tracker
        .ciphersuite_canonical_id()
        .map_err(|error| schema(error.to_string()))?;
    if payload.cipher_suite.as_str() != suite || !ciphersuite_is_active(suite) {
        return Err(schema(
            "MLS Genesis cipher_suite is not the group's active registered suite",
        ));
    }
    let extension = tracker
        .governance_binding()
        .map_err(|error| binding_mismatch(error.to_string()))?;
    if extension != payload.governance_binding {
        return Err(binding_mismatch(
            "the GroupContext binding differs from the Genesis payload binding",
        ));
    }
    let leaves = tracker
        .leaves()
        .map_err(|error| schema(error.to_string()))?;
    if leaves.len() != 1
        || leaves[0].actor_id != event.actor_id
        || leaves[0].signature_key != authority.leaf_signature_key_b64u
    {
        return Err(failed_precondition(
            "the MLS Genesis public tree does not match the creator leaf authority",
        ));
    }
    let member_principals = leaves.iter().map(|leaf| leaf.actor_id.clone()).collect();
    let public_state = tracker
        .export_state()
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let public_blobs = match genesis_material {
        Some(_) => vec![
            stage_mls_public_blob(state, &payload.group_info_ref, group_info).await?,
            stage_mls_public_blob(state, &payload.ratchet_tree_ref, tree).await?,
        ],
        None => Vec::new(),
    };
    Ok(MlsStateInstallation {
        effective_scope: event.scope_ref.clone(),
        base: None,
        epoch: 0,
        public_state,
        member_principals,
        consumed_proposals: Vec::new(),
        public_blobs,
    })
}

/// §5.1.2: carried bytes address the Genesis ref under the ref's own digest
/// suite, or the forward is `digest_mismatch`.
fn carried_blob_addresses(blob_ref: &arkret_wire::BlobRef, bytes: &[u8]) -> ServiceResult<()> {
    let digest = blob_ref
        .as_str()
        .strip_prefix("ak:blob:")
        .ok_or_else(|| schema("MLS public Blob ref is not an ak:blob ref"))?;
    arkret_canonical::verify_digest(bytes, digest).map_err(|_| {
        ServiceError::protocol(
            arkret_wire::ErrorCode::DigestMismatch,
            format!("carried Genesis material does not address {blob_ref}"),
        )
    })
}

/// Put verified carried or post-transition public bytes into the object store
/// ahead of the accepting transaction, which writes the Blob row serving it.
async fn stage_mls_public_blob(
    state: &AppState,
    blob_ref: &arkret_wire::BlobRef,
    bytes: Vec<u8>,
) -> ServiceResult<MlsPublicBlob> {
    let sha256 = arkret_canonical::sha256_digest(&bytes)
        .strip_prefix("sha256:")
        .map(ToOwned::to_owned)
        .ok_or_else(|| ServiceError::Internal("SHA-256 digest has no suite prefix".to_owned()))?;
    let deliveries = state.deliveries();
    let storage_key = deliveries.object_key_for_sha256(&sha256);
    let size_bytes = i64::try_from(bytes.len())
        .map_err(|_| ServiceError::Internal("MLS public Blob size exceeds BIGINT".to_owned()))?;
    deliveries
        .put_object(&storage_key, bytes)
        .await
        .map_err(|error| {
            ServiceError::Conflict(format!(
                "{}: MLS public Blob object store: {error}",
                ConflictCode::TemporarilyUnavailable
            ))
        })?;
    Ok(MlsPublicBlob {
        blob_ref: blob_ref.clone(),
        sha256,
        size_bytes,
        storage_backend: deliveries.object_storage_backend_name(),
        storage_key,
    })
}

/// §2.2 and §2.5: one member-sent public Commit processed against the
/// scope's current group, whose resulting GroupContext binding is the
/// payload binding and names the current base, epoch and key-access revision.
enum PreparedCommit {
    Ready(MlsStateInstallation, Vec<MlsPublicEndpointLeaf>),
    KeyAccessRefused(Vec<MlsPublicEndpointLeaf>),
}

#[cfg(test)]
async fn verify_commit(
    state: &AppState,
    event: &Event,
) -> ServiceResult<(MlsStateInstallation, Vec<MlsPublicEndpointLeaf>)> {
    match prepare_commit(state, event).await? {
        PreparedCommit::Ready(installation, leaves) => Ok((installation, leaves)),
        PreparedCommit::KeyAccessRefused(_) => Err(binding_mismatch(
            "the Commit does not cover the current key-access revision",
        )),
    }
}

async fn prepare_commit(state: &AppState, event: &Event) -> ServiceResult<PreparedCommit> {
    let payload: MlsCommitPayload = payload(event)?;
    let binding = payload.governance_binding();
    if binding.effective_scope() != &event.scope_ref {
        return Err(binding_mismatch(
            "the Commit binding names another effective scope",
        ));
    }
    let current = state
        .mls_groups()
        .current(&event.scope_ref)
        .await?
        .ok_or_else(|| failed_precondition("the scope has no accepted MLS Genesis"))?;
    let group = &current.value;
    let group_id = event.scope_ref.canonical_mls_group_id().map_err(schema)?;
    let mut tracker =
        MlsPublicGroupTracker::restore(&current.public_state, group_id.as_str(), group.epoch)
            .map_err(|error| {
                ServiceError::Internal(format!("stored public MLS state is unusable: {error}"))
            })?;
    let commit_bytes =
        arkret_canonical::base64url_decode(payload.commit_bytes_b64()).map_err(schema)?;
    let transition = tracker
        .process_public_handshake(&commit_bytes)
        .map_err(|error| {
            if matches!(error, arkret_mls::MlsError::UnsupportedFeature(_)) {
                ServiceError::protocol(
                    arkret_wire::ErrorCode::UnsupportedFeature,
                    format!("MLS Commit public transition is unsupported: {error}"),
                )
            } else {
                schema(format!("MLS Commit public transition is invalid: {error}"))
            }
        })?;
    let MlsPublicHandshakeTransition::Commit {
        sender_class,
        sender_leaf,
        previous_epoch,
        epoch,
        added_leaves,
        consumed_proposals,
        ..
    } = transition
    else {
        return Err(schema(
            "ak.mls.commit carries an MLS Commit, not a Proposal",
        ));
    };
    if sender_class != MlsProposalSenderClass::Member
        || sender_leaf.is_none_or(|leaf| leaf.actor_id != event.actor_id)
    {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::CapabilityDenied,
            "the Commit is not sent by the Event actor's own member leaf",
        ));
    }
    let extension = tracker
        .governance_binding()
        .map_err(|error| binding_mismatch(error.to_string()))?;
    let binding_check = arkret_mls::verify_governance_binding_against_public_state_and_payload(
        &extension,
        &arkret_mls::MlsGovernanceBindingPublicState::new(
            event.scope_ref.clone(),
            Some(group.current_mls_commit_event_ref.clone()),
            group.epoch,
            group.current_key_access_revision,
        ),
        binding,
    );
    if let Err(rejection) = binding_check {
        #[cfg(feature = "conformance-harness")]
        tracing::warn!(
            extension_matches_payload = &extension == binding,
            scope_matches = extension.effective_scope() == &event.scope_ref,
            group_matches =
                extension.mls_group_id().ok() == event.scope_ref.canonical_mls_group_id().ok(),
            base_matches =
                extension.base_group_state_ref() == Some(&group.current_mls_commit_event_ref),
            previous_epoch_matches = extension.previous_epoch() == group.epoch,
            next_epoch_matches = group.epoch.checked_add(1) == Some(extension.next_epoch()),
            key_access_matches =
                extension.key_access_revision() == group.current_key_access_revision,
            extension_key_access = extension.key_access_revision(),
            current_key_access = group.current_key_access_revision,
            "MLS public binding coordinate refusal"
        );
        // Only the current membership revision may differ. The real public
        // base, member-sent handshake and complete payload remain exact.
        if extension.key_access_revision() != group.current_key_access_revision
            && &extension == binding
            && extension.effective_scope() == &event.scope_ref
            && extension.base_group_state_ref() == Some(&group.current_mls_commit_event_ref)
            && previous_epoch == group.epoch
            && epoch == payload.next_epoch()
            && payload.covers_key_access_revision() == extension.key_access_revision()
            && arkret_mls::verify_next_epoch_governance_binding(&group_id, group.epoch, &extension)
                .is_ok()
        {
            return Ok(PreparedCommit::KeyAccessRefused(added_leaves));
        }
        return Err(binding_mismatch(rejection.code()));
    }
    if previous_epoch != group.epoch
        || epoch != payload.next_epoch()
        || payload.covers_key_access_revision() != group.current_key_access_revision
    {
        return Err(binding_mismatch(
            "the Commit does not advance the current group by one covering epoch",
        ));
    }
    let member_principals = tracker
        .leaves()
        .map_err(|error| schema(error.to_string()))?
        .into_iter()
        .map(|leaf| leaf.actor_id)
        .collect();
    let consumed_proposals = consumed_proposals
        .into_iter()
        .map(|proposal| MlsConsumedProposalInstallation {
            ordinal: proposal.ordinal,
            proposal_ref: proposal.proposal_ref,
            proposal_type: proposal.proposal_type,
            proposal_wire: proposal.proposal_wire,
            sender_leaf: installed_leaf(proposal.sender_leaf),
            target_before: proposal.target_before.map(installed_leaf),
            target_after: proposal.target_after.map(installed_leaf),
        })
        .collect();
    let tree = tracker.ratchet_tree_bytes().map_err(schema)?;
    let tree_digest_suite =
        arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
            &group.public_tree_ref,
        )
        .map_err(schema)?
        .digest_suite()
        .map_err(schema)?;
    let tree_ref = arkret_wire::BlobRef::new(format!(
        "ak:blob:{}",
        arkret_canonical::digest(tree_digest_suite, &tree)
    ))
    .map_err(schema)?;
    let public_blobs = vec![stage_mls_public_blob(state, &tree_ref, tree).await?];
    Ok(PreparedCommit::Ready(
        MlsStateInstallation {
            effective_scope: event.scope_ref.clone(),
            base: Some(MlsInstalledBase {
                current_mls_commit_event_ref: group.current_mls_commit_event_ref.clone(),
                epoch: group.epoch,
            }),
            epoch,
            public_state: tracker
                .export_state()
                .map_err(|error| ServiceError::Internal(error.to_string()))?,
            member_principals,
            consumed_proposals,
            public_blobs,
        },
        added_leaves,
    ))
}

fn installed_leaf(leaf: MlsPublicEndpointLeaf) -> MlsProposalLeafProvenance {
    MlsProposalLeafProvenance {
        leaf_index: leaf.leaf_index,
        actor_id: leaf.actor_id,
        signature_key: leaf.signature_key,
    }
}

/// Every Welcome, and exactly one per leaf the Commit adds.
///
/// A recipient this Station hosts has its claim resolved in the local ledger
/// and its claimed KeyPackage matched to the exact added leaf. A recipient
/// another Station hosts is that Station's claim (encryption-and-audit.md
/// §2.2 "跨站 recipient"): everything but the claim is verified here -- the
/// producer proof, the exact Commit binding and one added leaf of the
/// recipient -- and its Account Station re-verifies the claim when the
/// Welcome arrives with the Commit's committed replication.
async fn verify_welcomes(
    state: &AppState,
    event: &Event,
    welcomes: &[MlsWelcomeDelivery],
    added_leaves: &[MlsPublicEndpointLeaf],
    producer_key: &arkret_signatures::PublicKeyMaterial,
) -> ServiceResult<Vec<VerifiedMlsWelcome>> {
    if welcomes.len() != added_leaves.len() {
        return Err(failed_precondition(
            "a Welcome is required for exactly every leaf the Commit adds",
        ));
    }
    let producer_method = event
        .producer_proof
        .as_ref()
        .map(|proof| &proof.verification_method)
        .ok_or_else(|| schema("an MLS Commit carries its producer proof"))?;
    let mut unmatched = added_leaves
        .iter()
        .map(|leaf| (leaf.signature_key.as_str().to_owned(), leaf))
        .collect::<BTreeMap<_, _>>();
    let local = state.service_core_id();
    let mut claims = BTreeMap::new();
    for welcome in welcomes {
        verify_welcome_proof(welcome, producer_method, producer_key)?;
        if welcome.realm_id != event.realm_id
            || welcome.effective_scope != event.scope_ref
            || welcome.commit_event_ref != event.event_id
        {
            return Err(failed_precondition(
                "the Welcome does not name the exact Commit Event",
            ));
        }
        let recipient_account = welcome
            .recipient_actor_id
            .as_account_id()
            .ok_or_else(|| failed_precondition("a Welcome recipient is an Account actor"))?;
        if recipient_account.station_id != local {
            continue;
        }
        let (claim, record) = resolve_claim(state, event, welcome).await?;
        let leaf = arkret_mls::author_leaf_from_key_package_bytes(
            &arkret_canonical::base64url_decode(&record.keypackage).map_err(schema)?,
            0,
        )
        .map_err(|error| schema(format!("claimed KeyPackage is invalid: {error}")))?;
        let signature_key = arkret_canonical::base64url_encode(&leaf.signature_key);
        let Some(added) = unmatched.remove(&signature_key) else {
            return Err(failed_precondition(
                "the Welcome's claimed KeyPackage is not a leaf the Commit adds",
            ));
        };
        if added.actor_id != welcome.recipient_actor_id {
            return Err(failed_precondition(
                "the added leaf belongs to another actor than the Welcome recipient",
            ));
        }
        claims.insert(welcome.welcome_id.clone(), claim);
    }
    let mut verified = Vec::with_capacity(welcomes.len());
    for welcome in welcomes {
        let claim = claims.remove(&welcome.welcome_id);
        if claim.is_none() {
            let Some(key) = unmatched
                .iter()
                .find(|(_, leaf)| leaf.actor_id == welcome.recipient_actor_id)
                .map(|(key, _)| key.clone())
            else {
                return Err(failed_precondition(
                    "no leaf the Commit adds belongs to the remote Welcome recipient",
                ));
            };
            unmatched.remove(&key);
        }
        verified.push(VerifiedMlsWelcome {
            delivery: welcome.clone(),
            claim,
            roster_witness: None,
        });
    }
    Ok(verified)
}

/// §2.6.1: the producer proof seals the exact delivery minus the proof, under
/// the method that verified the Commit Event's own producer proof.
fn verify_welcome_proof(
    welcome: &MlsWelcomeDelivery,
    producer_method: &arkret_wire::DidUrl,
    producer_key: &arkret_signatures::PublicKeyMaterial,
) -> ServiceResult<()> {
    if &welcome.producer_proof.verification_method != producer_method {
        return Err(ServiceError::protocol(
            arkret_wire::ErrorCode::SignatureInvalid,
            "the Welcome is not sealed by the Commit producer's method",
        ));
    }
    let mut unsigned = serde_json::to_value(welcome).map_err(schema)?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| schema("a Welcome delivery is a JSON object"))?
        .remove("producer_proof");
    arkret_signatures::detached_object::verify_detached_object_signature(
        &welcome.producer_proof,
        &unsigned,
        DetachedSignatureContext::MlsWelcomeDelivery,
        producer_key,
    )
    .map_err(|error| {
        ServiceError::protocol(
            arkret_wire::ErrorCode::SignatureInvalid,
            format!("the Welcome producer proof does not verify: {error}"),
        )
    })
}

/// device-lifecycle.md claim ledger rules: resolve `keypackage_claim_ref` to
/// the exact durable ledger row, verify its destination-signed receipt and
/// bind every coordinate it covers to the Welcome and its Commit. The claim
/// destination runs it: the governance Station for a recipient it hosts, the
/// recipient's Account Station for a replicated Welcome (§9.2.3).
pub(super) async fn resolve_claim(
    state: &AppState,
    event: &Event,
    welcome: &MlsWelcomeDelivery,
) -> ServiceResult<(MlsWelcomeClaimLedgerKey, KeyPackageClaimRecord)> {
    let local = state.service_core_id();
    let recipient_account = welcome
        .recipient_actor_id
        .as_account_id()
        .ok_or_else(|| failed_precondition("a Welcome recipient is an Account actor"))?;
    let row = state
        .mls_key_packages()
        .peer_claim_by_claim_id(welcome.keypackage_claim_ref.as_str())
        .await?
        .ok_or_else(|| {
            failed_precondition("the Welcome's KeyPackage claim is not in the ledger")
        })?;
    if !matches!(row.state.as_str(), "claimed" | "last_resort_claimed") {
        return Err(failed_precondition(
            "the Welcome's KeyPackage claim is no longer live",
        ));
    }
    let outcome: PeerKeyPackagesClaimOutcome = row
        .outcome
        .clone()
        .ok_or_else(|| failed_precondition("the claim ledger row holds no success outcome"))
        .and_then(|outcome| serde_json::from_value(outcome).map_err(schema))?;
    let receipt = &outcome.claim_receipt;
    if receipt.destination_id != local
        || receipt.source_id.as_str() != row.source_id
        || receipt.claim_request_id.as_str() != row.claim_request_id
        || receipt.request_digest.as_str() != row.request_digest
    {
        return Err(failed_precondition(
            "the stored claim receipt does not bind its ledger row",
        ));
    }
    let transcript = arkret_models_crypto::peer_keypackage_claim_receipt_signing_bytes(receipt)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let signature = arkret_canonical::base64url_decode(receipt.signature.sig.as_str())
        .ok()
        .and_then(|bytes| ed25519_dalek::Signature::from_slice(&bytes).ok())
        .ok_or_else(|| failed_precondition("the stored claim receipt signature is malformed"))?;
    state
        .notary_signing_key()
        .verifying_key()
        .verify_strict(&transcript, &signature)
        .map_err(|_| failed_precondition("the stored claim receipt signature does not verify"))?;
    let request = &receipt.request;
    let group_id = event.scope_ref.canonical_mls_group_id().map_err(schema)?;
    let target_matches = match (
        &welcome.recipient_endpoint,
        &request.target_account_id,
        &request.target_agent_id,
    ) {
        (MlsWelcomeRecipientEndpoint::Device { .. }, Some(account), None) => {
            account == recipient_account
        }
        (MlsWelcomeRecipientEndpoint::AgentRuntime { .. }, None, Some(agent_id)) => {
            agent_id == &recipient_account.principal_id
        }
        _ => false,
    };
    if request.intended_realm_id != event.realm_id
        || request.mls_group_id != group_id
        || request.requester_account_id.as_ref() != event.actor_id.as_account_id()
        || !target_matches
    {
        return Err(failed_precondition(
            "the claim was not made by this committer for this recipient, Realm and group",
        ));
    }
    let record = outcome
        .claims
        .into_iter()
        .find(|record| record.claim_id == welcome.keypackage_claim_ref.as_str())
        .ok_or_else(|| failed_precondition("the claim outcome does not hold the claim id"))?;
    let endpoint_matches = match &welcome.recipient_endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => {
            record.device_id.as_ref() == Some(device_id)
                && record.agent_verification_method.is_none()
        }
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => {
            record.agent_verification_method.as_ref() == Some(verification_method)
                && record.device_id.is_none()
        }
    };
    let keypackage = arkret_canonical::base64url_decode(&record.keypackage).map_err(schema)?;
    if record.actor_id != welcome.recipient_actor_id
        || !endpoint_matches
        || arkret_canonical::sha256_digest(&keypackage) != record.keypackage_ref
    {
        return Err(failed_precondition(
            "the claimed KeyPackage is not the Welcome recipient's endpoint package",
        ));
    }
    Ok((
        MlsWelcomeClaimLedgerKey {
            source_id: row.source_id,
            claim_request_id: row.claim_request_id,
            request_digest: row.request_digest,
        },
        record,
    ))
}

fn ciphersuite_is_active(canonical_id: &str) -> bool {
    arkret_wire::MLS_CIPHERSUITES
        .iter()
        .any(|suite| suite.canonical_id == canonical_id && suite.status == "active")
}

/// Read one public MLS Blob and prove it is the exact content its ref
/// addresses.
async fn public_blob(state: &AppState, blob_ref: &str) -> ServiceResult<Vec<u8>> {
    let bytes = crate::routing::mls::load_mls_public_blob(
        state,
        blob_ref,
        arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES
            as usize,
    )
    .await
    .map_err(|_| failed_precondition(format!("MLS public Blob {blob_ref} is unavailable")))?;
    let digest = blob_ref
        .strip_prefix("ak:blob:")
        .ok_or_else(|| schema("MLS public Blob ref is not an ak:blob ref"))?;
    arkret_canonical::verify_digest(&bytes, digest).map_err(|_| {
        schema(format!(
            "MLS public Blob {blob_ref} does not address its bytes"
        ))
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity};
    use arkret_models_crypto::{MlsGovernanceBindingPayload, MlsKeyPackageState};
    use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId, EventId, MlsGroupCurrent, RealmId};
    use coland_storage::MlsGroupCurrentRecord;

    use super::*;

    const REALM: &str = "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT";
    const CREATOR: &str = "ak:did_core:web:mls-creator.example";
    const MEMBER: &str = "ak:did_core:web:mls-member.example";

    fn actor(principal: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:mls-unit-station.example").unwrap(),
        ))
    }

    fn identity(principal: &str, device: &str) -> ArkretMlsIdentity {
        ArkretMlsIdentity::new_test_human_device(actor(principal), DeviceId::new(device).unwrap())
            .unwrap()
    }

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new(REALM).unwrap(),
        }
    }

    fn test_state() -> AppState {
        AppState::new(
            crate::config::AppConfig {
                seed_demo_data: false,
                ..crate::config::AppConfig::test_default()
            },
            coland_storage_postgres::Db { pool: None },
        )
    }

    fn event_ref(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    /// The creator's accepted epoch-0 group, installed as the scope's
    /// current `mls_group` with the public tracker its Genesis verified into.
    async fn accepted_genesis(state: &AppState) -> (ArkretMlsGroup, EventId) {
        accepted_genesis_in_scope(
            state,
            realm_scope(),
            MlsGovernanceBindingPayload::realm(RealmId::new(REALM).unwrap(), None, 0, 0, 0)
                .unwrap(),
        )
        .await
    }

    async fn accepted_genesis_in_scope(
        state: &AppState,
        scope: ScopeRef,
        genesis_binding: MlsGovernanceBindingPayload,
    ) -> (ArkretMlsGroup, EventId) {
        let group = identity(CREATOR, "ak:device:01904100-0000-7000-8000-000000000081")
            .create_group_with_governance_binding(&scope, &genesis_binding)
            .unwrap();
        let (group_info, tree) = group.public_group_state_bytes().unwrap();
        let tracker =
            MlsPublicGroupTracker::from_external(&group_info, &tree, group.group_id().as_str(), 0)
                .unwrap();
        let genesis = event_ref(0x71);
        state
            .mls_groups()
            .seed_test_current(&MlsGroupCurrentRecord {
                realm_id: RealmId::new(REALM).unwrap(),
                value: MlsGroupCurrent {
                    effective_scope: scope,
                    genesis_event_ref: genesis.clone(),
                    cipher_suite: arkret_wire::NonEmptyString::new(
                        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                    )
                    .unwrap(),
                    current_mls_commit_event_ref: genesis.clone(),
                    epoch: 0,
                    current_key_access_revision: 0,
                    covered_key_access_revision: 0,
                    public_tree_ref: arkret_wire::BlobRef::new(format!(
                        "ak:blob:{}",
                        arkret_canonical::sha256_digest(&tree)
                    ))
                    .unwrap(),
                },
                current_commit_id: arkret_wire::RealmCommitId::from_digest([0x72; 32]),
                current_stream_position: 9,
                public_state: tracker.export_state().unwrap(),
            })
            .await
            .unwrap();
        (group, genesis)
    }

    fn commit_event(actor: ActorId, payload: &MlsCommitPayload) -> Event {
        let scope = payload.governance_binding().effective_scope().clone();
        let serde_json::Value::Object(payload) = serde_json::to_value(payload).unwrap() else {
            unreachable!("an MLS Commit payload is an object")
        };
        Event {
            event_id: event_ref(0x73),
            kind: EventKind::MlsCommit,
            realm_id: RealmId::new(REALM).unwrap(),
            scope_ref: scope,
            actor_id: actor,
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: payload.into_iter().collect(),
            producer_proof: None,
        }
    }

    /// The creator adds the member under `binding`; the returned payload is
    /// the exact `ak.mls.commit` payload a client submits.
    fn add_member(
        group: &mut ArkretMlsGroup,
        base: &EventId,
        binding: &MlsGovernanceBindingPayload,
    ) -> MlsCommitPayload {
        let mut keypackage = identity(MEMBER, "ak:device:01904100-0000-7000-8000-000000000082")
            .key_package_record()
            .unwrap();
        keypackage.state = MlsKeyPackageState::Claimed;
        keypackage.claim_id =
            Some("ak:keypackage_claim:01904100-0000-7000-8000-000000000083".to_owned());
        let added = group
            .add_member_with_governance_binding(&keypackage, binding)
            .unwrap();
        MlsCommitPayload::new(
            base.clone(),
            binding.key_access_revision(),
            &added.commit,
            binding.clone(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn an_inline_add_commit_is_verified_against_the_current_group() {
        let state = test_state();
        let (mut group, genesis) = accepted_genesis(&state).await;
        let binding = MlsGovernanceBindingPayload::realm(
            RealmId::new(REALM).unwrap(),
            Some(genesis.clone()),
            0,
            1,
            0,
        )
        .unwrap();
        let payload = add_member(&mut group, &genesis, &binding);
        let (installation, added) = verify_commit(&state, &commit_event(actor(CREATOR), &payload))
            .await
            .unwrap();
        assert_eq!(installation.epoch, 1);
        assert_eq!(
            installation.base,
            Some(MlsInstalledBase {
                current_mls_commit_event_ref: genesis,
                epoch: 0,
            })
        );
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].actor_id, actor(MEMBER));
        let tracker = MlsPublicGroupTracker::restore(
            &installation.public_state,
            group.group_id().as_str(),
            1,
        )
        .expect("the installed public state is the tracker at the new epoch");
        let tree = tracker.ratchet_tree_bytes().unwrap();
        assert_eq!(installation.public_blobs.len(), 1);
        let blob = &installation.public_blobs[0];
        carried_blob_addresses(&blob.blob_ref, &tree).unwrap();
        assert_eq!(blob.size_bytes, tree.len() as i64);
        assert_eq!(
            format!("sha256:{}", blob.sha256),
            arkret_canonical::sha256_digest(&tree)
        );
        let previous = state
            .mls_groups()
            .current(&installation.effective_scope)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(blob.blob_ref, previous.value.public_tree_ref);

        let error = verify_commit(&state, &commit_event(actor(MEMBER), &payload))
            .await
            .unwrap_err();
        assert_eq!(error.conflict_code(), Some(ConflictCode::CapabilityDenied));
    }

    #[tokio::test]
    async fn a_sidecar_add_verifies_its_actual_transition_and_exact_signed_binding() {
        let state = test_state();
        let sidecar_id =
            arkret_wire::SidecarId::new("ak:sidecar:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT")
                .unwrap();
        let scope = ScopeRef::Sidecar {
            realm_id: RealmId::new(REALM).unwrap(),
            sidecar_id: sidecar_id.clone(),
        };
        let binding_for = |base, previous, next| {
            MlsGovernanceBindingPayload::sidecar(
                RealmId::new(REALM).unwrap(),
                sidecar_id.clone(),
                base,
                previous,
                next,
                0,
                arkret_wire::Hash::new(arkret_canonical::sha256_digest([0x81])).unwrap(),
                vec![event_ref(0x82)],
            )
            .unwrap()
        };
        let (mut group, genesis) =
            accepted_genesis_in_scope(&state, scope.clone(), binding_for(None, 0, 0)).await;
        let binding = binding_for(Some(genesis.clone()), 0, 1);
        let payload = add_member(&mut group, &genesis, &binding);
        let event = commit_event(actor(CREATOR), &payload);
        let (installation, added) = verify_commit(&state, &event).await.unwrap();
        assert_eq!(installation.effective_scope, scope);
        assert_eq!(installation.epoch, 1);
        assert_eq!(added[0].actor_id, actor(MEMBER));
        let tracker = MlsPublicGroupTracker::restore(
            &installation.public_state,
            group.group_id().as_str(),
            1,
        )
        .unwrap();
        assert_eq!(tracker.governance_binding().unwrap(), binding);
        assert!(installation.consumed_proposals.iter().any(|p| {
            p.target_after
                .as_ref()
                .is_some_and(|leaf| leaf.actor_id == actor(MEMBER))
        }));

        let mut wrong_binding = event.clone();
        wrong_binding.payload.get_mut("governance_binding").unwrap()["participant_authority_digest"] =
            serde_json::json!(arkret_canonical::sha256_digest([0x83]));
        let error = verify_commit(&state, &wrong_binding).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(ConflictCode::GovernanceBindingMismatch)
        );

        let error = verify_commit(&state, &commit_event(actor(MEMBER), &payload))
            .await
            .unwrap_err();
        assert_eq!(error.conflict_code(), Some(ConflictCode::CapabilityDenied));
        let mut corrupted = event;
        let mut bytes = arkret_canonical::base64url_decode(payload.commit_bytes_b64()).unwrap();
        bytes[20] ^= 1;
        corrupted.payload.insert(
            "commit_bytes_b64".to_owned(),
            serde_json::json!(arkret_canonical::base64url_encode(&bytes)),
        );
        assert!(verify_commit(&state, &corrupted).await.is_err());
        let current = state.mls_groups().current(&scope).await.unwrap().unwrap();
        assert_eq!(current.value.epoch, 0);
        assert_eq!(current.value.current_mls_commit_event_ref, genesis);
    }

    #[tokio::test]
    async fn a_commit_binding_other_than_the_current_group_is_governance_binding_mismatch() {
        let state = test_state();
        let (mut group, genesis) = accepted_genesis(&state).await;
        let stale_revision = MlsGovernanceBindingPayload::realm(
            RealmId::new(REALM).unwrap(),
            Some(genesis.clone()),
            0,
            1,
            3,
        )
        .unwrap();
        let payload = add_member(&mut group, &genesis, &stale_revision);
        let event = commit_event(actor(CREATOR), &payload);
        let prepared = prepare_commit(&state, &event).await.unwrap();
        let PreparedCommit::KeyAccessRefused(leaves) = prepared else {
            panic!("a revision mismatch must not produce an installable state");
        };
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].actor_id, actor(MEMBER));
        let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: vec![0x44; 32],
        };
        assert!(
            verify_welcomes(&state, &event, &[], &leaves, &key)
                .await
                .is_err()
        );
        let mut inconsistent_payload = event.clone();
        inconsistent_payload
            .payload
            .get_mut("governance_binding")
            .unwrap()["key_access_revision"] = serde_json::json!(4);
        assert!(prepare_commit(&state, &inconsistent_payload).await.is_err());
        let error = verify_commit(&state, &event).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(ConflictCode::GovernanceBindingMismatch),
            "{error}"
        );
    }

    #[test]
    fn a_welcome_is_sealed_by_the_commit_producer_method_only() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        let method = arkret_wire::DidUrl::new("did:web:mls-creator.example#device").unwrap();
        let mut delivery = MlsWelcomeDelivery {
            welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(
                "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000084".to_owned(),
            )
            .unwrap(),
            realm_id: RealmId::new(REALM).unwrap(),
            effective_scope: realm_scope(),
            commit_event_ref: event_ref(0x73),
            recipient_actor_id: actor(MEMBER),
            recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000082").unwrap(),
            },
            keypackage_claim_ref: arkret_wire::KeypackageClaimId::new(
                "ak:keypackage_claim:01904100-0000-7000-8000-000000000083".to_owned(),
            )
            .unwrap(),
            ciphertext_b64: arkret_wire::Base64UrlString::new("V2VsY29tZQ".to_owned()).unwrap(),
            producer_proof: arkret_wire::DetachedObjectSignature {
                context: DetachedSignatureContext::MlsWelcomeDelivery,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: method.clone(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
                    .unwrap(),
                created_at: chrono::Utc::now(),
                sig: arkret_wire::Base64UrlString::new("AA".to_owned()).unwrap(),
            },
        };
        let mut unsigned = serde_json::to_value(&delivery).unwrap();
        unsigned.as_object_mut().unwrap().remove("producer_proof");
        delivery.producer_proof = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            DetachedSignatureContext::MlsWelcomeDelivery,
            method.clone(),
            arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            &signing_key,
        )
        .unwrap();
        verify_welcome_proof(&delivery, &method, &key).unwrap();

        let other = arkret_wire::DidUrl::new("did:web:mls-creator.example#other").unwrap();
        assert_eq!(
            verify_welcome_proof(&delivery, &other, &key)
                .unwrap_err()
                .conflict_code(),
            Some(ConflictCode::SignatureInvalid)
        );
        let mut tampered = delivery.clone();
        tampered.ciphertext_b64 = arkret_wire::Base64UrlString::new("VGFtcGVy".to_owned()).unwrap();
        assert_eq!(
            verify_welcome_proof(&tampered, &method, &key)
                .unwrap_err()
                .conflict_code(),
            Some(ConflictCode::SignatureInvalid)
        );
    }
}
