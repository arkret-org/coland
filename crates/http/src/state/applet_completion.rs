//! At-least-once delivery of the exact accepted Applet authoring context.

use arkret_http_client::{Client, HttpMessageSigner, RetryConfig};
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, AppletManagedActorCommittedRequest,
    AppletTransactionRequestBody, AppletTransactionStatus,
};
use coland_storage::AppletAuthoringCompletion;

use super::AppState;

/// Start immediately on process startup so a failed request or process exit
/// never loses the completion written by the accepting transaction.
pub fn spawn_pending_applet_completion_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = deliver_pending_applet_completions(&state).await {
                tracing::warn!(%error,"Applet completion delivery remains pending");
            }
        }
    })
}

/// One bounded sweep. Acknowledgements follow successful registered HTTP
/// responses only; any transport, validation or storage failure is retried.
pub async fn deliver_pending_applet_completions(state: &AppState) -> Result<usize, String> {
    let pending = state
        .event_queries()
        .pending_applet_authoring_completions(16)
        .await
        .map_err(|error| error.to_string())?;
    let mut delivered = 0;
    for completion in pending {
        match deliver_one(state, &completion).await {
            Ok(()) => {
                state
                    .event_queries()
                    .acknowledge_applet_authoring_completion(
                        &completion.applet_id,
                        &completion.request_digest,
                        chrono::Utc::now(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                delivered += 1;
            }
            Err(error) => {
                tracing::warn!(%error,applet_id=%completion.applet_id,request_digest=%completion.request_digest,"accepted Applet completion retained for retry")
            }
        }
    }
    Ok(delivered)
}

async fn deliver_one(
    state: &AppState,
    completion: &AppletAuthoringCompletion,
) -> Result<(), String> {
    completion
        .context
        .validate()
        .map_err(|error| error.to_string())?;
    let request = match &completion.context.committed_request {
        AppletManagedActorCommittedRequest::Bot(request) => &request.authoring_request,
        AppletManagedActorCommittedRequest::Ghost(request) => &request.authoring_request,
    };
    let applet_id = match &request.basis {
        arkret_models_integration::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => {
            &basis.applet_id
        }
        arkret_models_integration::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => {
            &basis.applet_id
        }
    };
    if completion.source_id != state.service_core_id()
        || request.basis.target_station_id() != &completion.source_id
        || request.basis.service_id() != &completion.destination_id
        || applet_id != &completion.applet_id
        || completion.idempotency_key.is_empty()
    {
        return Err(
            "accepted Applet completion has inconsistent service or request identity".to_owned(),
        );
    }
    let attestation = &completion.projection_attestation;
    let evidence = &completion
        .context
        .managed_actor_signer_evidence
        .attester_signer_evidence;
    if attestation.attestation.account_id.station_id != completion.source_id
        || attestation.attestation.account_id.principal_id
            != completion
                .context
                .managed_actor_signer_evidence
                .authenticated_signer_evidence
                .subject_id
        || evidence.subject_id != completion.source_id
        || evidence.authority_commit_id != completion.context.principal_control_commit.commit_id
        || attestation.proof.verification_method != evidence.verification_method
        || attestation.proof.created_at != attestation.attestation.issued_at
        || attestation.attestation.issued_at >= attestation.attestation.expires_at
    {
        return Err(
            "accepted Applet completion attestation differs from its frozen signer root".to_owned(),
        );
    }
    let jwk = evidence.public_key_jwk.as_map();
    if jwk.get("kty").and_then(serde_json::Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(serde_json::Value::as_str) != Some("Ed25519")
    {
        return Err("accepted Applet completion attester is not an Ed25519 key".to_owned());
    }
    let key = arkret_canonical::base64url_decode(
        jwk.get("x")
            .and_then(serde_json::Value::as_str)
            .ok_or("accepted completion has no attester key")?,
    )
    .map_err(|error| error.to_string())?;
    if key.len() != 32 {
        return Err("accepted Applet completion attester key has invalid size".to_owned());
    }
    // Verify the frozen historic proof; transport signs with the current key.
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &attestation.proof.jws,
            &attestation
                .proof_signing_bytes()
                .map_err(|error| error.to_string())?,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: key },
        )
        .map_err(|error| error.to_string())?;
    let method = state.service_verification_method("notary-key")?;
    let (base, transport) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &completion.endpoint,
        "Applet authoring completion",
        state.config().development_mode,
        std::time::Duration::from_secs(15),
    )?;
    let mut builder = Client::builder(base)
        .http_client(transport)
        .retry(RetryConfig::disabled())
        .http_message_signer(HttpMessageSigner::new(
            method.to_string(),
            state.notary_signing_key().as_ref().clone(),
        ));
    if state.config().development_mode {
        builder = builder.allow_insecure_localhost();
    }
    let client = builder.build().map_err(|error| error.to_string())?;
    let body =
        AppletTransactionRequestBody::Authoring(Box::new(AppletAuthoringTransactionRequestBody {
            applet_id: completion.applet_id.clone(),
            source_id: completion.source_id.clone(),
            authoring_context: completion.context.clone(),
        }));
    // Authoring returns accepted context; this branch publishes no new originals.
    let body = arkret_identity::VerifiedSubmission::from_verified_events(body, &[])
        .map_err(|error| error.to_string())?;
    let outcome = client
        .applet_transaction_from_service(
            &completion.idempotency_key,
            &body,
            &completion.source_id,
            &completion.destination_id,
        )
        .await
        .map_err(|error| error.to_string())?;
    if outcome.status() != AppletTransactionStatus::Accepted
        || !outcome.rejections().is_empty()
        || outcome.retry_after_ms().is_some()
    {
        return Err(
            "Applet did not acknowledge the complete accepted authoring context".to_owned(),
        );
    }
    Ok(())
}
