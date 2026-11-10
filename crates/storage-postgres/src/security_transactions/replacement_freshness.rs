//! Exclude every verified old daily/MLS signing key before replacement admission.

use std::collections::BTreeMap;

use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_crypto::ContentEndpoint;
use arkret_wire::{ActorId, DeviceId, EventId, MlsWelcomeRecipientEndpoint};
use coland_storage::{PersistenceError, PersistenceResult, RecoveryUnitCommitWrite};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::RunQueryDsl as _;

use crate::{AsyncPgConnection, JsonPayloadRow};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "revision_unavailable: replacement signing-key exclusion {detail}"
    ))
}

fn reused() -> PersistenceError {
    PersistenceError::Conflict(
        "failed_precondition: replacement signing key was already used by an old endpoint".into(),
    )
}

#[derive(QueryableByName)]
struct Publication {
    #[diesel(sql_type = Text)]
    keypackage_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    publication_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    binding: Option<serde_json::Value>,
}

fn check_binding(
    binding: &ContentEndpoint,
    actor: &ActorId,
    authorizations: &BTreeMap<EventId, DeviceId>,
    new_key: &str,
) -> PersistenceResult<()> {
    binding.validate().map_err(unavailable)?;
    let MlsWelcomeRecipientEndpoint::Device { device_id } = &binding.endpoint else {
        return Err(unavailable("Human source has another endpoint class"));
    };
    if &binding.actor_id != actor
        || authorizations.get(&binding.authorization_event_ref) != Some(device_id)
    {
        return Err(unavailable(
            "MLS key has no exact original Human authorization",
        ));
    }
    if binding.signature_key_base64url == new_key {
        return Err(reused());
    }
    Ok(())
}

/// The caller holds the PCR authority lock before either replacement Event is
/// inserted. Publication and endpoint writers share that lock/fence boundary.
pub(super) async fn require_fresh(
    conn: &mut AsyncPgConnection,
    write: &RecoveryUnitCommitWrite,
) -> PersistenceResult<()> {
    let account = &write.transaction.resource.account_id;
    let actor = ActorId::account(account.clone());
    let actor_json = serde_json::to_value(&actor).map_err(unavailable)?;
    let authorize: DeviceAuthorizePayload = serde_json::from_value(
        serde_json::to_value(&write.commits[1].event.payload).map_err(unavailable)?,
    )
    .map_err(unavailable)?;
    arkret_signatures::verify_device_authorize_possession(&authorize, account)
        .map_err(unavailable)?;
    let decode = |payload: &DeviceAuthorizePayload| -> PersistenceResult<String> {
        let multibase = payload
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| unavailable("Device key is not did:key"))?;
        Ok(arkret_canonical::base64url_encode(
            arkret_canonical::decode_ed25519_multibase(multibase).map_err(unavailable)?,
        ))
    };
    let new_key = decode(&authorize)?;
    let rows = sql_query("SELECT e.envelope AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.state='committed' AND c.realm_id=$1 AND e.kind='ak.device.authorize' AND e.envelope->'actor_id'=$2 ORDER BY c.stream_position")
        .bind::<Text,_>(write.commits[1].event.realm_id.as_str()).bind::<Jsonb,_>(&actor_json)
        .get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut authorizations = BTreeMap::new();
    for row in rows {
        let event: arkret_wire::Event = serde_json::from_value(row.payload).map_err(unavailable)?;
        let payload: DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(unavailable)?)
                .map_err(unavailable)?;
        arkret_signatures::verify_device_authorize_possession(&payload, account)
            .map_err(unavailable)?;
        if decode(&payload)? == new_key {
            return Err(reused());
        }
        authorizations.insert(event.event_id, payload.device_id);
    }
    if authorizations.is_empty() {
        return Err(unavailable("has no original Device authorizations"));
    }
    let history = sql_query("SELECT binding AS payload FROM content_endpoint_admission_history WHERE binding->'actor_id'=$1")
        .bind::<Jsonb,_>(&actor_json).get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in history {
        let binding: ContentEndpoint = serde_json::from_value(row.payload).map_err(unavailable)?;
        check_binding(&binding, &actor, &authorizations, &new_key)?;
    }
    let published = sql_query("SELECT p.keypackage_digest,h.publication_digest,h.binding FROM mls_key_packages p LEFT JOIN content_keypackage_signature_history h ON h.keypackage_id=p.id WHERE p.owner_actor_id=$1 FOR SHARE OF p")
        .bind::<Jsonb,_>(&actor_json).get_results::<Publication>(conn).await.map_err(PersistenceError::database)?;
    for publication in published {
        if publication.publication_digest.as_deref() != Some(publication.keypackage_digest.as_str())
        {
            return Err(unavailable(
                "published KeyPackage has no original verified signature fact",
            ));
        }
        let binding: ContentEndpoint = serde_json::from_value(
            publication
                .binding
                .ok_or_else(|| unavailable("published KeyPackage signing fact is absent"))?,
        )
        .map_err(unavailable)?;
        check_binding(&binding, &actor, &authorizations, &new_key)?;
    }
    Ok(())
}
