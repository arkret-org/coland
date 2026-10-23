//! Explicit, control-key-signed relocation of this deployment's public base.
use super::*;

fn target_did(current: &Did, base: &CanonicalServiceUrl) -> anyhow::Result<Did> {
    let url = url::Url::parse(base.as_str())?;
    let (mut authority, _) = arkret_signatures::webvh::webvh_authority_pair(
        url.host_str()
            .ok_or_else(|| anyhow::anyhow!("target base has no host"))?,
        url.port(),
    );
    for segment in url
        .path()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
    {
        authority.push(':');
        authority.push_str(&segment.replace(':', "%3A"));
    }
    let scid = current
        .as_str()
        .split(':')
        .nth(2)
        .ok_or_else(|| anyhow::anyhow!("stored DID has no SCID"))?;
    let local = current
        .as_str()
        .rsplit_once(":webvh:")
        .map(|p| p.1)
        .ok_or_else(|| anyhow::anyhow!("stored DID has no hosting local id"))?;
    Ok(arkret_signatures::webvh::format_webvh_did(&authority, scid, local).parse()?)
}

fn relocated_document(
    stored: &StoredDidCoreIdentity,
    did: &Did,
    base: &CanonicalServiceUrl,
) -> anyhow::Result<Value> {
    let mut state = serde_json::to_value(&stored.did_document)?;
    fn replace(value: &mut Value, old: &str, new: &str) {
        match value {
            Value::String(text) if text == old || text.starts_with(&format!("{old}#")) => {
                *text = text.replacen(old, new, 1)
            }
            Value::Array(values) => values.iter_mut().for_each(|v| replace(v, old, new)),
            Value::Object(values) => values
                .iter_mut()
                .filter(|(key, _)| key.as_str() != "alsoKnownAs")
                .for_each(|(_, v)| replace(v, old, new)),
            _ => {}
        }
    }
    replace(&mut state, stored.identity.did.as_str(), did.as_str());
    if did != &stored.identity.did {
        let aliases = state
            .as_object_mut()
            .unwrap()
            .entry("alsoKnownAs")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid service aliases"))?;
        if !aliases
            .iter()
            .any(|a| a.as_str() == Some(stored.identity.did.as_str()))
        {
            aliases.push(json!(stored.identity.did));
        }
    }
    let service = state
        .get_mut("service")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("service document omits endpoints"))?;
    let mut entries = service
        .iter_mut()
        .filter(|s| s["type"] == "ArkretService" && s["serviceKind"] == "station");
    let endpoint = entries
        .next()
        .ok_or_else(|| anyhow::anyhow!("Station endpoint is missing"))?;
    if entries.next().is_some() {
        anyhow::bail!("Station endpoint is ambiguous")
    }
    endpoint["serviceEndpoint"] = json!(base.as_str());
    Ok(state)
}

/// Local operator choices, independent of the signed wire contract.
pub struct MigrationOptions {
    pub preflight: bool,
    pub preserve_did_host: bool,
}

pub async fn migrate(
    config: &AppConfig,
    db: &Db,
    from: &str,
    to: &str,
    options: MigrationOptions,
) -> anyhow::Result<Value> {
    let pool = db
        .pool
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("migration requires PostgreSQL"))?;
    let persistence = PersistenceHandle::new(Arc::new(PgPersistenceStore::new(pool.clone())));
    let keys = config
        .key_store
        .open(SERVICE_IDENTITY_KEYSTORE_APP)?
        .ok_or_else(|| {
            anyhow::anyhow!("migration requires the durable service control KeyStore")
        })?;
    let backend = config
        .service_identity_bundle_dir
        .clone()
        .map(FileIdentityBundleBackend::new);
    migrate_with_storage(
        &persistence,
        config,
        keys.as_ref(),
        backend.as_ref().map(|b| b as &dyn IdentityBundleBackend),
        from,
        to,
        options,
    )
    .await
}

pub(super) async fn migrate_with_storage(
    persistence: &PersistenceHandle,
    config: &AppConfig,
    keys: &dyn KeyStore,
    backend: Option<&dyn IdentityBundleBackend>,
    from: &str,
    to: &str,
    options: MigrationOptions,
) -> anyhow::Result<Value> {
    let MigrationOptions {
        preflight,
        preserve_did_host,
    } = options;
    let from = CanonicalServiceUrl::canonicalize(from)?;
    from.require_https()?;
    let to = CanonicalServiceUrl::canonicalize(to)?;
    to.require_https()?;
    if from == to {
        anyhow::bail!("migration requires a different target public base")
    }
    if config.external_webvh_registration_bearer.is_some() {
        anyhow::bail!(
            "this command requires the self-hosted Provider; use the external Provider's signed successor publication"
        )
    }
    let stored = persistence
        .stored_service_identity()
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("migration requires an existing accepted service identity")
        })?;
    let stored = if preflight {
        stored
    } else {
        reconcile_pending_local_rotation(persistence, config, Some(keys), stored).await?
    };
    validate_stored_service_identity(persistence, config, Some(keys), &stored).await?;
    if stored.identity.registration_key.public_base_url() == &to {
        if !preflight {
            ensure_identity_bundle(persistence, backend, &stored).await?;
        }
        return Ok(
            json!({"status":"already_current","service_id":stored.identity.service_id,"did":stored.identity.did,
            "public_base_url":to,"method_history_head":stored.registration_receipt.log_head_digest,"version_id":stored.identity.version_id}),
        );
    }
    if stored.identity.registration_key.public_base_url() != &from {
        anyhow::bail!("migration source differs from the accepted current registration key")
    }
    if let Some(backend) = backend {
        if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
            anyhow::bail!("bundle backend unavailable: {error}")
        }
        if !preflight {
            ensure_identity_bundle(persistence, Some(backend), &stored).await?;
        }
    }
    let did = if preserve_did_host {
        stored.identity.did.clone()
    } else {
        target_did(&stored.identity.did, &to)?
    };
    if arkret_wire::project_did_to_core_id(&did)? != stored.identity.service_id {
        anyhow::bail!("migration changes the service identity")
    }
    let key = ServiceRegistrationKey::new(ServiceKind::Station, to.clone())?;
    if let Some(occupied) = persistence.service_registration(&key).await? {
        if occupied.registration_receipt.service_id != stored.identity.service_id {
            anyhow::bail!("target registration key belongs to another service identity")
        }
    }
    let history = persistence
        .webvh_history(stored.identity.did.as_str())
        .await?;
    let head = history
        .last()
        .ok_or_else(|| anyhow::anyhow!("service history unavailable"))?;
    let next_ref = next_control_key_ref(&stored.identity.control_key_ref)?;
    let seed = load_seed(keys, &next_ref)?;
    let public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
    );
    let hash = arkret_signatures::webvh::webvh_next_key_hash(&public)?;
    let committed = head
        .operation
        .pointer("/parameters/nextKeyHashes")
        .and_then(Value::as_array)
        .is_some_and(|hashes| hashes.len() == 1 && hashes[0] == hash);
    if !committed {
        anyhow::bail!("next control key does not match the accepted native precommitment")
    }
    let state = relocated_document(&stored, &did, &to)?;
    let plan = json!({"status":"preflight","service_id":stored.identity.service_id,"from_public_base_url":from,"to_public_base_url":to,
        "current_did":stored.identity.did,"target_did":did,"expected_method_history_head":stored.registration_receipt.log_head_digest,
        "expected_version_id":stored.identity.version_id,"next_update_public_key_multibase":public,"target_state":state});
    if preflight {
        return Ok(plan);
    }
    let mut desired = config.clone();
    desired.public_base_url = to.to_string();
    let updated = publish_service_document_successor_impl(
        persistence,
        &desired,
        Some(keys),
        stored,
        state,
        None,
        Some(key),
    )
    .await?;
    // A cut already accepted before a bundle-write failure is repaired by an
    // exact retry or normal startup using the prior native registration key.
    ensure_identity_bundle(persistence, backend, &updated).await?;
    Ok(
        json!({"status":"migrated","service_id":updated.identity.service_id,"did":updated.identity.did,
        "public_base_url":to,"method_history_head":updated.registration_receipt.log_head_digest,"version_id":updated.identity.version_id}),
    )
}
