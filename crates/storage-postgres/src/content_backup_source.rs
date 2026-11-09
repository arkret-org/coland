//! Native owning-Station root custody before publishing a Service source.
//! The target governor independently admits the original and its physical blobs.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::ContentBackupSourceDraft;
use arkret_wire::{DidCoreId, DidUrl, Event};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel_async::AsyncConnection as _;

use crate::{PgPool, PgTransactionError};

fn unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: content backup source {detail}"
    ))
}

pub(crate) async fn prepare(
    pool: &PgPool,
    event: &Event,
    issuer: &DidCoreId,
    destination: &DidCoreId,
    verification_method: &DidUrl,
) -> PersistenceResult<ContentBackupSourceDraft> {
    if event
        .event_content_envelopes()
        .map_err(PersistenceError::database)?
        .is_empty()
    {
        return Err(unavailable("requires registered encrypted original slots"));
    }
    let account = event
        .actual_signer()
        .as_account_id()
        .ok_or_else(|| unavailable("requires an actual Account producer"))?;
    if &account.station_id != issuer || issuer == destination {
        return Err(unavailable("issuer is not the owning forwarding Station"));
    }
    if event
        .account_device_producer()
        .map_err(PersistenceError::database)?
        .is_none()
    {
        return Err(unavailable(
            "native Agent custody issuer is not yet qualified",
        ));
    }
    let mut conn = crate::pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        crate::managed_forward_source::lock_source(conn, event).await?;
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let producer =
            crate::account_device_signer_evidence::forward_source::prepare_context_in_connection(
                conn, event, at,
            )
            .await?
            .ok_or_else(|| unavailable("has no native current producer source"))?;
        let current = crate::content_dependencies::current_group_in_connection(conn, event).await?;
        let fact = producer.fact.into();
        let endpoint = crate::content_endpoint_bindings::current_producer_from_fact_in_connection(
            conn,
            event,
            &fact,
            &current.group,
        )
        .await?;
        let roots = crate::content_dependencies::local_original_dependencies_in_connection(
            conn, event, &current, &endpoint,
        )
        .await?;
        let attested_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let expires_at = (attested_at + chrono::Duration::seconds(300))
            .min(producer.expires_at)
            .min(roots.source_valid_until);
        let draft = ContentBackupSourceDraft {
            event_ref: event.event_id.clone(),
            event_original_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(event).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?,
            producer: endpoint,
            effective_scope: event.scope_ref.clone(),
            destination_service_id: destination.clone(),
            protections_digest: event
                .event_content_protections_digest()
                .map_err(PersistenceError::database)?,
            verification_method: verification_method.clone(),
            attested_at,
            expires_at,
        };
        draft.validate().map_err(PersistenceError::database)?;
        // The exact signed original and its validated physical root custody
        // become durable together; this is neither a target Commit nor a send.
        crate::authority_commit::queue_event_in_connection(conn, event, attested_at).await?;
        Ok(draft)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
