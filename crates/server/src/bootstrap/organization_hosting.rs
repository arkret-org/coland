//! Explicit local H acceptance, using the configured runtime and durable keys.
use std::path::Path;

use anyhow::Context as _;
use coland_http::config::AppConfig;
use coland_http::state::organization_hosting;
use coland_storage_postgres::Db;

pub async fn accept(config: &AppConfig, db: Db, input: &str) -> anyhow::Result<serde_json::Value> {
    let bytes = std::fs::read(Path::new(input))
        .context("read the local canonical Organization peer request")?;
    let request = organization_hosting::read_request(&bytes)?;
    let (state, store) = super::operator::load_existing_state(config, db).await?;
    let hosting = state.service_core_id();
    let previous = store
        .organization_hosting_intent(&request, &hosting)
        .await?;
    let outcome = match previous {
        Some(Some(original)) => original,
        pending => {
            // Only a positive independently verified bundle can recover the
            // one fixed Org result. An unavailable read leaves the existing
            // choice unknown; it never releases it or grants C permission.
            let certificate = if pending.is_some() {
                organization_hosting::certificate(&state, &request)
                    .await
                    .ok()
            } else {
                None
            };
            if let Some((bundle, freshness, keys)) = certificate {
                store
                    .recover_organization_hosting(&request, &hosting, &bundle, &freshness, &keys)
                    .await?
            } else {
                // Even an existing unknown choice must issue C's source anew.
                // E(C) cannot reach this actual send branch through stale evidence.
                let (entries, witnesses, producer) =
                    organization_hosting::current_sources(&state, &request).await?;
                let fresh = organization_hosting::fresh_request(&state, &request).await?;
                let frozen = store
                    .prepare_organization_hosting(
                        &fresh,
                        &hosting,
                        &entries,
                        &witnesses,
                        producer.as_ref(),
                    )
                    .await?;
                let (outcome, bundle, freshness, keys) =
                    organization_hosting::submit_original(&state, &frozen).await?;
                store
                    .complete_organization_hosting(
                        &request, &hosting, &outcome, &bundle, &freshness, &keys,
                    )
                    .await?
            }
        }
    };
    // This stdout is a local operator report, not a new protocol response.
    Ok(serde_json::json!({
        "holder_account_id": request.event.actor_id.as_account_id(),
        "realm_id": request.event.realm_id,
        "outcome": outcome,
    }))
}

pub async fn inspect_consent(
    config: &AppConfig,
    db: Db,
    input: &str,
) -> anyhow::Result<arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody> {
    let bytes =
        std::fs::read(Path::new(input)).context("read the local Consent current request")?;
    let request: arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody =
        serde_json::from_slice(&bytes)?;
    request.validate()?;
    let (state, _) = super::operator::load_existing_state(config, db).await?;
    Ok(organization_hosting::inspect_consent(&state, &request).await?)
}
