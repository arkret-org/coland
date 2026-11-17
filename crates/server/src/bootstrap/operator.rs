//! Load an accepted local runtime for explicit operator commands.
use anyhow::{Context as _, ensure};
use coland_http::config::AppConfig;
use coland_storage_postgres::{Db, PgAuthorityCommitStore};

pub(super) async fn load_existing_state(
    config: &AppConfig,
    db: Db,
) -> anyhow::Result<(coland_http::state::AppState, PgAuthorityCommitStore)> {
    let pool = db
        .pool
        .as_ref()
        .context("operator command requires PostgreSQL")?
        .clone();
    let native = load_existing_runtime(config, &db).await?;
    let resolution = native
        .resolution_commitment
        .clone()
        .context("local Service has no accepted resolution")?;
    ensure!(
        native.state.identity().is_some(),
        "local Service has no loadable serving identity"
    );
    let mut state = crate::runtime::build_operator_app_state(
        config.clone(),
        db,
        native.persistence,
        native.state,
        resolution,
        native.signing_seed,
    )?;
    if let Some(keys) = native.key_store {
        state = state.with_verifier_private_keystore(keys);
    }
    // No listener, worker, hydration/demo account creation or new Service key.
    let store = PgAuthorityCommitStore { pool };
    Ok((state, store))
}

/// Local operator work may load this deployment's accepted identity, never
/// provision, restore, rotate, migrate or repair it as a side effect.
async fn load_existing_runtime(
    config: &AppConfig,
    db: &Db,
) -> anyhow::Result<super::ServiceIdentityBootstrap> {
    use std::sync::Arc;

    use coland_services::persistence::PersistenceHandle;
    use coland_storage_postgres::PgPersistenceStore;

    let pool = db
        .pool
        .as_ref()
        .context("operator command requires the existing local database")?;
    let persistence = PersistenceHandle::new(Arc::new(PgPersistenceStore::new(pool.clone())));
    let keys: Option<Arc<dyn arkret_keystore::KeyStore>> = config
        .key_store
        .open(super::SERVICE_IDENTITY_KEYSTORE_APP)?
        .map(Arc::from);
    let stored = persistence
        .stored_service_identity()
        .await?
        .context("operator command requires an existing accepted local Service identity")?;
    ensure!(
        stored.identity.registration_key == super::registration_key(config)?,
        "configured base differs from the accepted local Service identity"
    );
    super::validate_stored_service_identity(&persistence, config, keys.as_deref(), &stored).await?;
    // This operation uses H's accepted native identity, not an AA session or
    // a new AA delegation. Do not discover, authorize or refresh an issuer.
    let signing_seed = super::load_signing_seed(
        config,
        keys.as_deref(),
        &stored.identity.active_signing_key_ref,
    )?;
    let resolution_commitment = Some(arkret_models_identity::ResolutionCommitment {
        did: stored.identity.did.clone(),
        method_history_head: stored.registration_receipt.log_head_digest.clone(),
        version_id: stored.identity.version_id.clone(),
    });
    Ok(super::ServiceIdentityBootstrap {
        persistence,
        key_store: keys,
        state: arkret_identity::service_identity::DidCoreIdentityState::Ready {
            identity: stored.identity,
        },
        resolution_commitment,
        signing_seed,
    })
}
