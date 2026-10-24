//! Deliver frozen recipient Add proofs through the registered peer operation.

use arkret_models_collaboration::mls_roster_authority::{
    MlsAttestAddRequestBody, MlsAttestAddResponseBody,
};

use crate::state::AppState;

pub(super) async fn dispatch(state: &AppState) -> Result<(), String> {
    let requests = state
        .authority_commits()
        .pending_mls_recipient_attestations(32)
        .await
        .map_err(|error| error.to_string())?;
    for request in requests {
        if let Err(error) = deliver(state, &request).await {
            tracing::warn!(commit_event_ref=%request.attestation.commit_event_ref,
                welcome_id=%request.attestation.welcome_id, %error,
                "recipient MLS Add proof remains pending for retry");
        }
    }
    Ok(())
}

async fn deliver(state: &AppState, request: &MlsAttestAddRequestBody) -> Result<(), String> {
    request
        .validate_claim_binding()
        .map_err(|error| error.to_string())?;
    if request.attestation.attestor_station_id != state.service_core_id() {
        return Err("recipient proof belongs to another Station".into());
    }
    let authority = state
        .authority_commits()
        .current_authority(&request.attestation.realm_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("recipient proof has no current Realm authority")?;
    let outcome = if authority.service_id == state.service_core_id() {
        let resolution =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|error| error.to_string())?;
        let claim_issuer_resolution =
            if request.claim_outcome.claim_receipt.destination_id == state.service_core_id() {
                resolution.clone()
            } else {
                crate::routing::identity::agents::evidence::fetch_service_resolution(
                    state,
                    &request.claim_outcome.claim_receipt.destination_id,
                    None,
                )
                .await
                .map_err(|error| format!("{error:?}"))?
            };
        arkret::verify_mls_attest_add_request(request, &claim_issuer_resolution, &resolution)
            .map_err(|error| format!("{error:?}"))?;
        state
            .authority_commits()
            .install_mls_add_authority_attestation(
                &coland_storage::VerifiedMlsAddAuthorityAttestation {
                    source_station_id: state.service_core_id(),
                    request: request.clone(),
                    attestor_resolution: resolution,
                    claim_issuer_resolution,
                },
                &state.service_core_id(),
            )
            .await
            .map_err(|error| error.to_string())?
    } else {
        crate::routing::realm_join::resolve_verified_authority_of_service(
            state,
            &request.attestation.realm_id,
            &authority.service_id,
        )
        .await
        .map_err(|error| error.to_string())?;
        let body =
            arkret_canonical::canonical_json_bytes(request).map_err(|error| error.to_string())?;
        let response = super::outbox::signed_peer_request(
            state,
            authority.service_id.as_str(),
            arkret_wire::PATH_PEER_MLS_ATTEST_ADD,
            &body,
            16 * 1024,
        )
        .await?;
        if response.status != 200 {
            return Err(format!(
                "recipient proof ingress returned {}",
                response.status
            ));
        }
        serde_json::from_slice::<MlsAttestAddResponseBody>(&response.body)
            .map_err(|error| error.to_string())?
    };
    state
        .authority_commits()
        .acknowledge_mls_recipient_attestation(
            request,
            &outcome.attestation_digest,
            crate::wire::now(),
        )
        .await
        .map_err(|error| error.to_string())
}
