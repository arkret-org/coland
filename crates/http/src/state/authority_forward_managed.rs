//! Independent governor verification of private native managed first-forward originals.
use arkret_identity::RealmAuthorityKeyMap;
use arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest;
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

fn invalid(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("signature_invalid: {error}"))
}
fn identity_refusal(error: arkret_identity::IdentityError) -> ServiceError {
    ServiceError::protocol(
        error
            .error_code()
            .unwrap_or(arkret_wire::ErrorCode::SignatureInvalid),
        error,
    )
}
fn unavailable(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!("temporarily_unavailable: {error}"))
}

async fn require_non_managed_branch(
    state: &AppState,
    event: &arkret_wire::Event,
    now: chrono::DateTime<chrono::Utc>,
) -> ServiceResult<()> {
    // A known native PCR cannot be reclassified as Human when its sibling is absent.
    if state
        .persistence()
        .applet_managed_event_producer(event, now)
        .await?
        .is_some()
    {
        return Err(invalid(
            "managed producer is missing producer_managed_provenance",
        ));
    }
    Ok(())
}

pub(super) fn verify<'a>(
    state: &'a AppState,
    peer: &'a AuthenticatedPeerContext,
    request: &'a PeerAuthoritySubmitRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> impl std::future::Future<
    Output = ServiceResult<Option<coland_storage::ForwardedProducerDeviceEvidence>>,
> + Send
+ 'a {
    crate::boxed_future(move || verify_inner(state, peer, request, now))
}

async fn verify_inner(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: &PeerAuthoritySubmitRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> ServiceResult<Option<coland_storage::ForwardedProducerDeviceEvidence>> {
    let (source, device, event, digest) = match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => {
            match &v.producer_managed_provenance {
                None => {
                    require_non_managed_branch(state, &v.event_submission.event, now).await?;
                    return Ok(None);
                }
                Some(source) => (
                    source,
                    v.producer_device_evidence.as_ref(),
                    &v.event_submission.event,
                    arkret_models_collaboration::authority_commit::authority_forward_body_digest(v)
                        .map_err(invalid)?,
                ),
            }
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => {
            match &v.producer_managed_provenance {
                None => {
                    require_non_managed_branch(state, &v.mls_submission.commit_event, now).await?;
                    return Ok(None);
                }
                Some(source) => (
                    source,
                    v.producer_device_evidence.as_ref(),
                    &v.mls_submission.commit_event,
                    arkret_models_collaboration::authority_commit::authority_forward_body_digest(v)
                        .map_err(invalid)?,
                ),
            }
        }
        _ => return Ok(None),
    };
    let device = device.ok_or_else(|| invalid("managed source has no original Device evidence"))?;
    source
        .validate()
        .map_err(super::authority_forward::wire_refusal)?;
    let fact = arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
        device, event, &peer.source_service_id, &state.service_core_id(), &digest,
        event.realm_id.digest_suite_code().digest_suite(), now,
    ).map_err(identity_refusal)?.into_fact();
    // The Device source supplies a native identity carrier, never a Realm role.
    // Resolve current history and Describe through the existing verified route contract.
    let projection = device.service_resolution.projection().map_err(invalid)?;
    let base = arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(
        &projection.base_url,
    )
    .map_err(invalid)?;
    // Historical proof remains bound to the carried history. Fetch the current route
    // separately so a later legal Service rotation does not replace that historical proof.
    let carrier = arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
        resolution_url: format!(
            "{}{}",
            base,
            arkret_models_identity::canonical_service_resolution_path(&peer.source_service_id)
                .trim_start_matches('/')
        ),
    };
    state
        .service_route_resolver()
        .map_err(unavailable)?
        .resolve_carrier(&carrier, &peer.source_service_id, "station", now)
        .await
        .map_err(unavailable)?;
    let applet = event
        .applet_id
        .as_ref()
        .ok_or_else(|| invalid("managed producer has no Applet"))?;
    let record = crate::routing::extensions::applet_bridge::record::applet_record(
        state,
        applet.as_str(),
        &event.scope_ref,
    )
    .await
    .map_err(|e| unavailable(e.message))?
    .ok_or_else(|| invalid("actual Applet installation is absent"))?;
    let registration: arkret_models_integration::AppletRegistrationPayload =
        serde_json::from_value(
            serde_json::to_value(&record.registration_event.payload).map_err(invalid)?,
        )
        .map_err(invalid)?;
    let epoch = crate::routing::extensions::applet_bridge::registration_epoch_evidence_from_event(
        &record.registration_event,
    )
    .map_err(invalid)?;
    let document = crate::jws_verify::resolve_did_document_async(state, &epoch.did)
        .await
        .map_err(unavailable)?;
    epoch
        .validate_against_did_document(&document)
        .map_err(invalid)?;
    let mut authorities = std::collections::BTreeMap::new();
    let mut keys = RealmAuthorityKeyMap::new();
    for commit in [
        &source.current.profile.commit,
        &source.current.accountability.commit,
    ] {
        if authorities.contains_key(&commit.realm_id) {
            continue;
        }
        let hint = state
            .authority_commits()
            .current_authority(&commit.realm_id)
            .await?
            .map(|v| v.service_id)
            .unwrap_or_else(|| peer.source_service_id.clone());
        let nonce =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<
                [u8; 32],
            >()))
            .map_err(invalid)?;
        let candidates=[arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidate {
            service_kind:arkret_models_collaboration::governance::realm_join_intake::RealmJoinCandidateServiceKind::Station,
            service_id:hint,endpoint_url:None,source:arkret_models_collaboration::governance::realm_join_intake::AuthorityLocatorSource::Cache,
        }];
        let located = crate::routing::realm_join::resolve_verified_authority(
            state,
            &commit.realm_id,
            &candidates,
            &nonce,
        )
        .await
        .map_err(|e| unavailable(e.message))?;
        for current in [
            &source.current.profile.commit,
            &source.current.accountability.commit,
        ] {
            if current.realm_id == commit.realm_id {
                crate::routing::realm_join::insert_historical_method_key(
                    state,
                    &mut keys,
                    &current.signature.verification_method,
                    current.signature.created_at,
                )
                .await
                .map_err(|e| unavailable(e.message))?;
            }
        }
        authorities.insert(commit.realm_id.clone(), located.authority);
    }
    let context = arkret_identity::managed_actor_provenance::ManagedForwardVerificationContext {
        source_service_id: &peer.source_service_id,
        destination_service_id: &state.service_core_id(),
        applet_id: applet,
        applet_service_id: &registration.service_id,
        digest_suite: event.realm_id.digest_suite_code().digest_suite(),
        now,
        authorities: &authorities,
        authority_keys: &keys,
    };
    let verified = match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => {
            arkret_identity::verify_forwarded_managed_event_request(v, &context)
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => {
            arkret_identity::verify_forwarded_managed_mls_request(v, &context)
        }
        _ => unreachable!("checked forward branch"),
    }
    .map_err(identity_refusal)?;
    let mut retained = coland_storage::ForwardedProducerDeviceEvidence::new(device.clone(), fact)?;
    retained.managed = Some(Box::new(coland_storage::ForwardedManagedActorSource::new(
        verified, event, document,
    )?));
    Ok(Some(retained))
}
