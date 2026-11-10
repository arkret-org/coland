//! Native publication-time proof for recovery's permanent old-key exclusion.

use arkret_models_crypto::ContentEndpoint;
use arkret_wire::{EventId, MlsWelcomeRecipientEndpoint};
use coland_storage::{MlsKeyPackageRow, PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use horme::RunQueryDsl as _;

use crate::AsyncPgConnection;

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "revision_unavailable: KeyPackage signing history {detail}"
    ))
}

/// The caller already qualified the actual native publication endpoint. Only
/// verified RFC bytes supply the signing key; a declared public key is never
/// inserted into this set. Capture and publication commit or roll back together.
pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    record: &MlsKeyPackageRow,
) -> PersistenceResult<()> {
    if record.owner_actor_id.as_account_id().is_none() {
        return Ok(());
    }
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(&record.key_package_bytes, 0)
        .map_err(unavailable)?;
    let arkret_mls::AuthorLeafCredential::Basic { identity } = leaf.credential else {
        return Err(unavailable("has no registered Actor credential"));
    };
    if arkret_mls::decode_leaf_credential(&identity).map_err(unavailable)? != record.owner_actor_id
        || arkret_canonical::sha256_digest(&record.key_package_bytes) != record.keypackage_digest
    {
        return Err(unavailable(
            "differs from its verified Actor or original bytes",
        ));
    }
    let (endpoint, authorization) = match (
        &record.device_id,
        &record.device_authorize_event_id,
        &record.endpoint_verification_method,
        &record.agent_key_authorize_event_id,
    ) {
        (Some(device), Some(authorization), None, None) => (
            MlsWelcomeRecipientEndpoint::Device {
                device_id: device.parse().map_err(unavailable)?,
            },
            authorization,
        ),
        (None, None, Some(method), Some(authorization)) => (
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: arkret_wire::DidUrl::new(method.clone())
                    .map_err(unavailable)?,
            },
            authorization,
        ),
        _ => return Err(unavailable("has no exact original native endpoint")),
    };
    let binding = ContentEndpoint {
        actor_id: record.owner_actor_id.clone(),
        endpoint,
        authorization_event_ref: EventId::new(authorization.clone()).map_err(unavailable)?,
        signature_key_base64url: arkret_canonical::base64url_encode(leaf.signature_key),
    };
    binding.validate().map_err(unavailable)?;
    sql_query("INSERT INTO content_keypackage_signature_history(keypackage_id,publication_digest,binding,admitted_at) VALUES($1,$2,$3,$4)")
        .bind::<Text,_>(&record.id).bind::<Text,_>(&record.keypackage_digest)
        .bind::<Jsonb,_>(serde_json::to_value(binding).map_err(unavailable)?)
        .bind::<Timestamptz,_>(chrono::Utc::now())
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
