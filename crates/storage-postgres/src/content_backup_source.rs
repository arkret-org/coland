//! Native owning-Station root custody before publishing a Service source.
//! The target governor independently admits the original and its physical blobs.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact;
use arkret_models_crypto::{ContentBackupSourceDraft, ContentEndpoint};
use arkret_wire::{CurrentState, DidCoreId, DidUrl, Event, MlsWelcomeRecipientEndpoint};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text};
use diesel_async::AsyncConnection as _;
use horme::RunQueryDsl as _;

use crate::content_dependencies::NativeContentGroup;
use crate::{PgPool, PgTransactionError};

fn unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: content backup source {detail}"
    ))
}

fn source_cut_unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: content backup source {detail}",
        coland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
    ))
}

/// A Direct replica holds a verified public MLS replay and native local Add
/// provenance. It does not have, or create, a governor's admission projection.
async fn replica_direct_source(
    conn: &mut crate::AsyncPgConnection,
    event: &Event,
    destination: &DidCoreId,
    producer: &AccountDeviceHistoricalSignerFact,
) -> PersistenceResult<Option<(NativeContentGroup, ContentEndpoint)>> {
    let Some(input) = crate::replica_direct_mls::input_in_connection(
        conn,
        &event.realm_id,
        event.actual_signer(),
    )
    .await?
    else {
        return Ok(None);
    };
    let CurrentState::Value { value, .. } = input.current;
    let group: arkret_wire::MlsGroupValue =
        serde_json::from_value(value).map_err(PersistenceError::database)?;
    let Some(base) = input.base.filter(|base| {
        input.complete
            && input.history.is_empty()
            && input.service_id == *destination
            && group.effective_scope == event.scope_ref
            && base.current_event_ref == group.current_mls_commit_event_ref
            && base.epoch == group.epoch
            && base.covered_revision == group.covered_key_access_revision
            && base.covered_revision == group.current_key_access_revision
    }) else {
        return Err(unavailable("has no covered Direct replica MLS result"));
    };
    let group_id = group
        .effective_scope
        .canonical_mls_group_id()
        .map_err(PersistenceError::database)?;
    let tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &base.public_state,
        group_id.as_str(),
        group.epoch,
    )
    .map_err(PersistenceError::database)?;
    let endpoint = replica_endpoint(conn, event, producer, &group, &tracker).await?;
    Ok(Some((
        NativeContentGroup {
            group,
            public_state: base.public_state,
            realm_declaration: None,
        },
        endpoint,
    )))
}

async fn replica_endpoint(
    conn: &mut crate::AsyncPgConnection,
    event: &Event,
    producer: &AccountDeviceHistoricalSignerFact,
    group: &arkret_wire::MlsGroupValue,
    tracker: &arkret_mls::MlsPublicGroupTracker,
) -> PersistenceResult<ContentEndpoint> {
    let leaves = tracker.leaves().map_err(PersistenceError::database)?;
    let actor = event.actual_signer();
    let rows = sql_query(
        "SELECT binding AS payload FROM content_endpoint_admission_history \
         WHERE effective_scope=$1 AND genesis_event_ref=$2 AND binding->'actor_id'=$3",
    )
    .bind::<Jsonb, _>(
        serde_json::to_value(&group.effective_scope).map_err(PersistenceError::database)?,
    )
    .bind::<Text, _>(group.genesis_event_ref.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(actor).map_err(PersistenceError::database)?)
    .get_results::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let bindings = rows
        .into_iter()
        .map(|row| serde_json::from_value::<ContentEndpoint>(row.payload))
        .collect::<Result<Vec<_>, _>>()
        .map_err(PersistenceError::database)?;
    let mut current = bindings.iter().filter(|binding| {
        leaves
            .iter()
            .filter(|leaf| {
                &leaf.actor_id == actor
                    && leaf.signature_key.as_str() == binding.signature_key_base64url
            })
            .count()
            == 1
    });
    let expected = MlsWelcomeRecipientEndpoint::Device {
        device_id: producer.device_id.clone(),
    };
    let endpoint = current
        .find(|binding| {
            binding.endpoint == expected
                && binding.authorization_event_ref == producer.key.authorization_ref.event_id
        })
        .ok_or_else(|| unavailable("has no current locally admitted Device leaf"))?;
    if bindings.iter().any(|binding| {
        binding != endpoint && binding.signature_key_base64url == endpoint.signature_key_base64url
    }) {
        return Err(unavailable("Device leaf has conflicting native provenance"));
    }
    endpoint.validate().map_err(PersistenceError::database)?;
    Ok(endpoint.clone())
}

/// Network reads finish before the native transaction. Rebind their public
/// result to the current verified replica, accepted original and local Device
/// provenance under the same authorization lock used for root custody.
async fn replica_public_source(
    conn: &mut crate::AsyncPgConnection,
    event: &Event,
    destination: &DidCoreId,
    producer: &AccountDeviceHistoricalSignerFact,
    evidence: &coland_storage::ContentBackupSourcePublicEvidence,
) -> Result<(NativeContentGroup, ContentEndpoint), PgTransactionError> {
    let authority = crate::authority_commit::locked_authority(conn, &event.realm_id).await?;
    if authority.as_ref() != Some(&evidence.expected_authority)
        || &evidence.expected_authority.service_id != destination
    {
        return Err(source_cut_unavailable("public material authority changed").into());
    }
    let group = crate::mls_group_current_states::held_current_value_in_connection(
        conn,
        &event.scope_ref,
        None,
    )
    .await?
    .ok_or_else(|| source_cut_unavailable("has no verified current group"))?;
    if group != evidence.group {
        return Err(source_cut_unavailable("public material group cut changed").into());
    }
    let envelopes = event
        .event_content_envelopes()
        .map_err(PersistenceError::database)?;
    let envelopes = envelopes
        .iter()
        .map(|slot| &slot.envelope)
        .collect::<Vec<_>>();
    coland_storage::decide_mls_send_gate(Some(&group), &event.scope_ref, Some(&envelopes))
        .map_err(coland_storage::MlsSendGateRefusal::into_conflict)?;
    let request = &evidence.request;
    if request.realm_id != event.realm_id
        || request.effective_scope != event.scope_ref
        || &request.caller_actor_id != event.actual_signer()
        || request.epoch != group.epoch
        || request.target_epoch != group.epoch
        || request.group_state_event_id != group.current_mls_commit_event_ref
        || request.target_commit_event_ref != group.current_mls_commit_event_ref
        || request.mls_group_id
            != event
                .scope_ref
                .canonical_mls_group_id()
                .map_err(PersistenceError::database)?
    {
        return Err(unavailable("public material selectors differ from the original cut").into());
    }
    let selector = crate::mls_group_state_material_read::MemberMlsTargetSelector {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        group_state_event_id: Some(request.group_state_event_id.clone()),
        group_state_epoch: Some(request.epoch),
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
    };
    let issuer = event
        .actual_signer()
        .as_account_id()
        .ok_or_else(|| unavailable("public material requires an actual Account"))?;
    if !matches!(
        crate::mls_group_state_material_read::read_in_connection(
            conn,
            &selector,
            &issuer.station_id,
            None
        )
        .await?,
        coland_storage::MlsMemberGroupStateMaterialRead::Authorized { .. }
    ) {
        return Err(
            unavailable("public material reader lost its current or target eligibility").into(),
        );
    }
    let original =
        crate::content_dependencies::original_event(conn, &group.current_mls_commit_event_ref)
            .await?;
    if original.scope_ref != event.scope_ref || original.realm_id != event.realm_id {
        return Err(unavailable("public material has no exact scope original").into());
    }
    let material = evidence
        .material
        .validate_for_request(&request.as_peer_request())
        .map_err(PersistenceError::database)?;
    let publication =
        arkret_models_collaboration::authority_commit::MlsGroupStateMaterial::from_bytes(
            &material.group_info_bytes,
            &material.ratchet_tree_bytes,
        );
    let (info, tree) = publication
        .decode_for_event(&original)
        .map_err(PersistenceError::database)?;
    let tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &info,
        &tree,
        request.mls_group_id.as_str(),
        group.epoch,
    )
    .map_err(PersistenceError::database)?;
    tracker
        .verify_publication(&info, &tree)
        .map_err(PersistenceError::database)?;
    if tracker
        .ciphersuite_canonical_id()
        .map_err(PersistenceError::database)?
        != group.cipher_suite.as_str()
    {
        return Err(unavailable("public material cipher suite differs").into());
    }
    let declaration = &evidence.realm_declaration;
    declaration
        .verify_event_id_matches_content_with_digest_suite(
            event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(PersistenceError::database)?;
    if declaration.realm_id != event.realm_id
        || arkret_wire::RealmId::from_event_id(&declaration.event_id) != event.realm_id
        || declaration.kind != arkret_wire::EventKind::RealmCreate
    {
        return Err(unavailable("has no verified original Realm strategy").into());
    }
    let endpoint = replica_endpoint(conn, event, producer, &group, &tracker).await?;
    Ok((
        NativeContentGroup {
            group,
            public_state: tracker.export_state().map_err(PersistenceError::database)?,
            realm_declaration: Some(declaration.clone()),
        },
        endpoint,
    ))
}

pub(crate) async fn prepare(
    pool: &PgPool,
    event: &Event,
    issuer: &DidCoreId,
    destination: &DidCoreId,
    verification_method: &DidUrl,
    public_evidence: Option<&coland_storage::ContentBackupSourcePublicEvidence>,
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
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
        crate::managed_forward_source::lock_source(conn, event).await?;
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let producer =
            crate::account_device_signer_evidence::forward_source::prepare_context_in_connection(
                conn, event, at,
            )
            .await?
            .ok_or_else(|| unavailable("has no native current producer source"))?;
        let (current, endpoint) = if let Some(evidence) = public_evidence {
            replica_public_source(conn, event, destination, &producer.fact, evidence).await?
        } else if let Some(replica) =
            replica_direct_source(conn, event, destination, &producer.fact).await?
        {
            replica
        } else {
            let current =
                crate::content_dependencies::current_group_in_connection(conn, event).await?;
            let endpoint =
                crate::content_endpoint_bindings::current_producer_from_fact_in_connection(
                    conn,
                    event,
                    &producer.fact.into(),
                    &current.group,
                )
                .await?;
            (current, endpoint)
        };
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
