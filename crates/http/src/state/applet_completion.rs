//! At-least-once delivery of the exact accepted Applet authoring context.

use arkret_http_client::{Client, HttpMessageSigner, RetryConfig};
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, AppletTransactionRequestBody, AppletTransactionStatus,
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
            Ok(delivery_key) => {
                state
                    .event_queries()
                    .acknowledge_applet_authoring_completion(
                        &completion.applet_id,
                        &completion.request_digest,
                        &delivery_key,
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
) -> Result<String, String> {
    let method = state.service_verification_method("notary-key")?;
    let completion = state
        .authority_commits()
        .prepare_applet_authoring_completion(
            completion,
            &state.service_core_id(),
            &method,
            state.notary_signing_key().as_ref(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let context = completion
        .context
        .as_ref()
        .ok_or("creation completion has no signed material")?;
    context.validate().map_err(|error| error.to_string())?;
    let material = &context.material;
    if completion.source_id != state.service_core_id()
        || material.requester_actor_id
            != arkret_wire::ActorId::service(completion.destination_id.clone())
        || completion.idempotency_key.is_empty()
    {
        return Err("accepted Applet completion has inconsistent service identity".into());
    }
    let authority = state
        .authority_commits()
        .current_authority(&material.realm_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("Realm authority unavailable")?;
    if authority.service_id != completion.source_id
        || authority.generation != material.governance_generation
        || authority.authority_ref != material.authority_ref
    {
        return Err("accepted Applet completion must be refreshed at current governance".into());
    }
    let resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .map_err(|error| error.to_string())?;
    let document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &completion.source_id,
        material.issued_at,
    )
    .map_err(|error| error.to_string())?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &material.signature.verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| error.to_string())?;
    let key = arkret_identity::public_key_material_from_document(
        &document,
        &material.signature.verification_method,
    )
    .map_err(|error| error.to_string())?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &material.signature,
        &arkret_canonical::unsigned_value(material, &["signature"])
            .map_err(|error| error.to_string())?,
        arkret_wire::DetachedSignatureContext::RealmActorMaterial,
        &key,
    )
    .map_err(|error| error.to_string())?;
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
            authoring_context: context.clone(),
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
    Ok(completion.idempotency_key)
}
