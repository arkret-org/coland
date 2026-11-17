//! Existing peer ingress for the Organization native one-create unit.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;
use arkret_models_identity::service_identity::ServiceDidEndpoint;
use arkret_wire::{ActorId, AuthoritySubmitResponseBody, Did, DidUrl, ErrorCode};
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

fn unavailable(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::protocol(ErrorCode::TemporarilyUnavailable, error)
}
fn invalid(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::protocol(ErrorCode::FailedPrecondition, error)
}

pub(super) async fn native_history(
    state: &AppState,
    did: &Did,
) -> ServiceResult<(arkret_identity::VerifiedDidWebvhLog, Vec<serde_json::Value>)> {
    // A retained foreign prefix is historical evidence, not a fresh origin
    // observation. Fetch the standard method origin before any PG unit lock;
    // the existing DID owner then rejects rollback below its durable head.
    let (history, witness_records) =
        super::did_resolver_chain::build_coland_did_resolver(state.config())
            .fetch_retained_webvh_history(did)
            .await
            .map_err(unavailable)?;
    let document: arkret_identity::DidDocument =
        serde_json::from_value(history.head_state.clone()).map_err(invalid)?;
    let method_evidence = arkret_identity::build_webvh_method_history_evidence(
        &document,
        history.raw_entries.clone(),
        witness_records.clone(),
    )
    .map_err(invalid)?;
    let current = state.dids().document(did.as_str()).await?;
    let head = arkret_canonical::canonical_sha256(
        history
            .raw_entries
            .last()
            .ok_or_else(|| invalid("origin history is empty"))?,
    )
    .map_err(invalid)?;
    if current.as_ref().is_some_and(|record| {
        record.key_log_head.as_deref() == Some(head.as_str())
            && record.sequence == history.raw_entries.len() as u64
            && record.did_document == history.head_state
    }) {
        // A real fresh origin read may confirm an unchanged durable head.
        // Do not manufacture a new freshness/witness timestamp by rewriting it.
        return Ok((history, witness_records));
    }
    let previous = current.and_then(|record| record.key_log_head);
    let at = chrono::Utc::now();
    let retained = coland_services::identity::DidDocumentState {
        did: document.id.to_string(),
        did_document: history.head_state.clone(),
        key_log_head: Some(
            arkret_canonical::canonical_sha256(
                history
                    .raw_entries
                    .last()
                    .ok_or_else(|| invalid("origin history is empty"))?,
            )
            .map_err(invalid)?,
        ),
        sequence: history.raw_entries.len() as u64,
        method_evidence: serde_json::to_value(method_evidence).map_err(invalid)?,
        // These are existing storage freshness hints, not witness observations
        // or proof that no unknown remote suffix exists.
        fetched_at: at,
        expires_at: at + chrono::Duration::minutes(15),
        updated_at: at,
    };
    match state
        .dids()
        .ingest_verified_history(previous, retained)
        .await?
    {
        coland_services::identity::DidLogCommitResult::Accepted
        | coland_services::identity::DidLogCommitResult::Duplicate => {
            Ok((history, witness_records))
        }
        coland_services::identity::DidLogCommitResult::Conflict => Err(unavailable(
            "native origin history changed or rolls back the durable head",
        )),
    }
}

pub(super) async fn governor_signer(
    state: &AppState,
) -> ServiceResult<(DidUrl, std::sync::Arc<ed25519_dalek::SigningKey>)> {
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(unavailable)?;
    let document = &resolution.normalized_did_document;
    let signing_key = state.notary_signing_key();
    let expected = signing_key.verifying_key().to_bytes();
    document
        .verification_methods
        .keys()
        .filter_map(|id| DidUrl::new(id).ok())
        .find(|method| {
            arkret_identity::validate_verification_method_relationship(
                document,
                method,
                &document.id,
                arkret_identity::DidVerificationRelationship::AssertionMethod,
            )
            .is_ok()
                && arkret_identity::public_key_material_from_document(document, method)
                    .ok()
                    .and_then(|key| key.ed25519_bytes().ok())
                    == Some(expected)
        })
        .ok_or_else(|| {
            unavailable(
                "governor has no current published assertion method for its held notary key",
            )
        })
        .map(|method| (method, signing_key))
}

pub(super) async fn producer_service_resolution(
    state: &AppState,
    event: &arkret_wire::Event,
) -> ServiceResult<Option<arkret_models_identity::AuthenticatedServiceResolution>> {
    Ok(
        if let ActorId::Service { service_id } = event.actual_signer() {
            let method = event
                .producer_proof
                .as_ref()
                .ok_or_else(|| invalid("producer proof missing"))?
                .verification_method
                .as_str();
            let did = Did::new(
                method
                    .split_once('#')
                    .ok_or_else(|| invalid("producer method fragment missing"))?
                    .0,
            )
            .map_err(invalid)?;
            if arkret_wire::project_did_to_core_id(&did).map_err(invalid)? != *service_id {
                return Err(invalid(
                    "Service proof controller differs from actual executor",
                ));
            }
            let (history, witnesses) = native_history(state, &did).await?;
            let endpoint = history
                .head_state
                .get("service")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|row| serde_json::from_value::<ServiceDidEndpoint>(row.clone()).ok())
                .find(|endpoint| endpoint.endpoint_type == "ArkretService")
                .ok_or_else(|| invalid("Service executor has no registered Service identity"))?;
            Some(
                arkret_identity::build_authenticated_webvh_service_resolution(
                    service_id.clone(),
                    endpoint.service_kind.as_str().to_owned(),
                    serde_json::from_value(history.head_state).map_err(invalid)?,
                    history.raw_entries,
                    witnesses,
                    chrono::Utc::now(),
                )
                .map_err(invalid)?,
            )
        } else {
            None
        },
    )
}

pub(super) async fn admit_forwarded(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerAuthorityForwardEventRequestBody,
) -> ServiceResult<AuthoritySubmitResponseBody> {
    request.validate().map_err(invalid)?;
    let event = &request.event_submission.event;
    if !request.is_organization_pcr_genesis_candidate()
        || event
            .actor_id
            .as_account_id()
            .is_none_or(|holder| holder.station_id != peer.source_service_id)
    {
        return Err(invalid(
            "Organization hosting Account differs from authenticated peer source",
        ));
    }
    if let Some(original) = state
        .persistence()
        .organization_pcr_genesis_original(&request, &peer.source_service_id)
        .await?
    {
        return Ok(original);
    }
    let genesis = event.as_realm_create().map_err(invalid)?.object;
    if genesis.governance_station_id != state.service_core_id()
        || genesis.trust_domain.as_str() != state.config().trust_domain.as_str()
    {
        return Err(invalid(
            "Organization genesis targets another governor or trust domain",
        ));
    }
    let initial = genesis
        .initial_resolution
        .as_ref()
        .ok_or_else(|| invalid("initial resolution is missing"))?;
    let (organization, organization_witness_records) = native_history(state, &initial.did).await?;
    let producer_service_resolution = producer_service_resolution(state, event).await?;
    let (method, signing_key) = governor_signer(state).await?;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let (_, fact) =
        arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
            &request,
            &peer.source_service_id,
            &organization.raw_entries,
            &organization_witness_records,
            producer_service_resolution.as_ref(),
            at,
        )
        .map_err(invalid)?;
    let fact = arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::OrganizationGenesis(fact);
    let transaction = state
        .authority_commits()
        .prepare_genesis_transaction_with_signer_fact(
            event,
            &state.service_core_id(),
            method,
            signing_key.as_ref(),
            at,
            Some(&fact),
        )?;
    state
        .persistence()
        .admit_organization_pcr_genesis(coland_storage::OrganizationPcrGenesisAdmissionWrite {
            transaction,
            request,
            source_service_id: peer.source_service_id.clone(),
            organization_log_entries: organization.raw_entries,
            organization_witness_records,
            producer_service_resolution,
            queued_at: at,
        })
        .await
        .map_err(ServiceError::from)
}

#[cfg(test)]
mod tests;
