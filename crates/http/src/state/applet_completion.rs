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
        .pending_applet_authoring_completions(&state.service_core_id(), 16)
        .await
        .map_err(|error| error.to_string())?;
    let mut delivered = 0;
    for completion in pending {
        match deliver_one(state, &completion).await {
            Ok(delivery_digest) => {
                state
                    .event_queries()
                    .acknowledge_applet_authoring_completion(
                        &completion.applet_id,
                        &completion.request_digest,
                        &state.service_core_id(),
                        &delivery_digest,
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
) -> Result<arkret_wire::Hash, String> {
    let governor = state.service_core_id();
    let registration = &completion.recipient_package;
    if registration.service_id != completion.destination_id {
        return Err("original completion recipient differs".into());
    }
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let resolution = crate::routing::identity::agents::evidence::fetch_service_resolution(
        state,
        &completion.destination_id,
        Some(&registration.base_url),
    )
    .await
    .map_err(|e| format!("Service resolution unavailable: {e:?}"))?;
    let document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &completion.destination_id,
        now,
    )
    .map_err(|e| e.to_string())?;
    let (verification_method, public_key) =
        std::iter::once(registration.webhook_auth.key_ref.to_string())
            .chain(document.verification_methods.keys().cloned())
            .filter_map(|method| arkret_wire::DidUrl::new(method).ok())
            .find_map(|method| {
                arkret_identity::validate_verification_method_relationship(
                    &document,
                    &method,
                    &document.id,
                    arkret_identity::DidVerificationRelationship::AssertionMethod,
                )
                .ok()?;
                let key = arkret_identity::public_key_material_from_document(&document, &method)
                    .ok()?
                    .ed25519_bytes()
                    .ok()?;
                Some((method, key))
            })
            .ok_or("completion recipient has no current assertion key")?;
    let caller = coland_storage::RealmActorMaterialCaller::Service {
        service_id: completion.destination_id.clone(),
        verification_method,
        public_key,
        expires_at: now + chrono::Duration::seconds(60),
    };
    let method = state.service_verification_method("notary-key")?;
    let sign = |body: &arkret_models_integration::RealmActorMaterialUnsigned| {
        let signature = arkret_signatures::detached_object::sign_detached_object(
            body,
            arkret_wire::DetachedSignatureContext::RealmActorMaterial,
            method.clone(),
            body.issued_at,
            state.notary_signing_key().as_ref(),
        )
        .map_err(coland_storage::PersistenceError::database)?;
        Ok(body.clone().into_signed(signature))
    };
    let delivery = state
        .persistence()
        .prepare_applet_authoring_delivery(completion, &governor, &caller, &sign)
        .await
        .map_err(|e| e.to_string())?;
    let delivery_digest = arkret_wire::Hash::new(
        arkret_canonical::canonical_sha256(&delivery).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let method = state.service_verification_method("notary-key")?;
    let (base, transport) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &delivery.endpoint,
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
            source_id: delivery.source_id.clone(),
            authoring_context: delivery.context.clone(),
        }));
    // Authoring returns accepted context; this branch publishes no new originals.
    let body = arkret_identity::VerifiedSubmission::from_verified_events(body, &[])
        .map_err(|error| error.to_string())?;
    let outcome = client
        .applet_transaction_from_service(
            &delivery.idempotency_key,
            &body,
            &delivery.source_id,
            &delivery.destination_id,
        )
        .await
        .map_err(|error| error.to_string())?;
    if outcome.status() != AppletTransactionStatus::Accepted
        || !outcome.committed_event_refs().is_empty()
        || !outcome.rejections().is_empty()
        || outcome.retry_after_ms().is_some()
    {
        return Err(
            "Applet did not acknowledge the complete accepted authoring context".to_owned(),
        );
    }
    Ok(delivery_digest)
}
