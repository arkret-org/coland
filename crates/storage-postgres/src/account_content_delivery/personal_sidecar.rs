//! Native Agent handoff of exact private originals and endpoint-bound Welcomes.
use arkret_wire::{CommitStreamRef, MlsWelcomeRecipientEndpoint, ScopeRef};
use coland_storage::AccountContentDeliveryInput;

use super::*;

pub(super) fn requested(input: &AccountContentDeliveryInput) -> bool {
    input
        .stream_scans
        .iter()
        .any(|(r, _)| matches!(r.stream_ref, CommitStreamRef::Sidecar { .. }))
        || input
            .committed_events
            .iter()
            .any(|r| matches!(r.commit().stream_ref, CommitStreamRef::Sidecar { .. }))
        || input
            .future_materials
            .iter()
            .any(|w| matches!(w.effective_scope, ScopeRef::Sidecar { .. }))
}

pub(super) async fn acquire(
    mut guard: Box<DeliveryGuard>,
    account: &AccountId,
    station: &DidCoreId,
    input: &AccountContentDeliveryInput,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    let denied = || unavailable("current private Sidecar delivery authority is unavailable");
    let endpoint = input.agent_endpoint.as_ref().ok_or_else(denied)?;
    let owner = &input
        .qualified_agent_scope_evidence
        .as_ref()
        .ok_or_else(denied)?
        .accepted_binding()
        .controller_account;
    let expiry = input.credential_expires_at.ok_or_else(denied)?;
    if &account.station_id != station || &owner.station_id != station || account == owner {
        return Err(denied());
    }
    if input.agent_membership_list.is_some()
        || input.native_blob_upload.is_some()
        || input.realm_actor_material.is_some()
        || !input.keypackage_claims.is_empty()
        || !input.mls_group_material_reads.is_empty()
        || !input.mls_roster_reads.is_empty()
        || !input.current_views.is_empty()
        || !input.projection_lists.is_empty()
        || !input.morph_lists.is_empty()
        || !input.morph_documents.is_empty()
        || !input.morph_absences.is_empty()
        || !input.account_status_observations.is_empty()
        || !input.realm_lifecycle_reads.is_empty()
        || !input.realm_link_reads.is_empty()
        || !input.realm_exports.is_empty()
        || !input.snapshots.is_empty()
        || !input.notifications.is_empty()
        || !input.exact_reads.is_empty()
        || !input.watch_reads.is_empty()
        || input.remote_watch_read.is_some()
        || input.audited_watch_read.is_some()
        || !input.blobs.is_empty()
        || input.applet_endpoint.is_some()
        || !input.unresolved_content_realms.is_empty()
    {
        return Err(denied());
    }
    let home =
        crate::morph_projection_reads::human_realm_in_connection(guard.connection(), owner).await?;
    if input.realms.iter().any(|realm| realm != &home) {
        return Err(denied());
    }
    let actor = ActorId::account(account.clone());
    let mut scopes = std::collections::BTreeSet::new();
    for scope in input
        .stream_scans
        .iter()
        .map(|(r, _)| r.stream_ref.scope_ref())
        .chain(
            input
                .committed_events
                .iter()
                .map(|r| r.commit().stream_ref.scope_ref()),
        )
        .chain(
            input
                .future_materials
                .iter()
                .map(|w| w.effective_scope.clone()),
        )
    {
        let ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } = scope
        else {
            return Err(denied());
        };
        if realm_id != home {
            return Err(denied());
        }
        scopes.insert(sidecar_id);
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(guard.connection(), &home).await?;
    let mut ready = std::collections::BTreeSet::new();
    for id in scopes {
        let cut = crate::sidecar_authority_cut::locked_in_connection(
            guard.connection(),
            &home,
            &id,
            owner,
        )
        .await?
        .ok_or_else(denied)?;
        if !crate::sidecar_access::desired_participant(&cut, &actor) {
            return Err(denied());
        }
        if crate::sidecar_effective_access::effective_agents_for_endpoint_in_connection(
            guard.connection(),
            &cut,
            Some((&endpoint.agent_id, &endpoint.verification_method, Some(&endpoint.authorization_ref.event_id))),
        )
        .await?
        .contains(&endpoint.agent_id)
        {
            ready.insert(id);
        }
    }
    validate_private_delivery_credentials(
        &mut guard,
        account,
        station,
        input,
        arkret_wire::WireResourceSelector::realm(home),
        Default::default(),
        CapabilityActionId::EventRead,
        expiry,
    )
    .await?;
    let physical = MlsWelcomeRecipientEndpoint::AgentRuntime {
        verification_method: endpoint.verification_method.clone(),
    };
    for (request, page) in &input.stream_scans {
        let live = crate::account_stream_scan::scan_stream_for_account_in_connection(
            guard.connection(),
            request,
            account,
            station,
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
        if !matches!(live, coland_storage::AccountStreamScan::Page(ref current) if current == page)
        {
            return Err(denied());
        }
    }
    for row in input.committed_events.iter().chain(
        input
            .stream_scans
            .iter()
            .flat_map(|(_, page)| page.committed_events.iter()),
    ) {
        let CommitStreamRef::Sidecar { sidecar_id, .. } = &row.commit().stream_ref else {
            return Err(denied());
        };
        let live = crate::account_stream_scan::committed_event_for_member_in_connection(
            guard.connection(),
            &row.commit().event_ref,
            &actor,
            station,
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
        if !matches!(live, coland_storage::MemberCommittedEventRead::Read(ref current) if current.as_ref() == row)
        {
            return Err(denied());
        }
        if !ready.contains(sidecar_id)
            && let Some(event) = row.reducer_input()
            && !crate::sidecar_access::handshake_event_in_connection(
                guard.connection(),
                event,
                &actor,
            )
            .await?
        {
            return Err(denied());
        }
    }
    for welcome in &input.future_materials {
        if welcome.recipient_actor_id != actor || welcome.recipient_endpoint != physical {
            return Err(denied());
        }
        let full = crate::committed_disclosure::accepted_full_event_in_connection(
            guard.connection(),
            &welcome.commit_event_ref,
        )
        .await?
        .ok_or_else(denied)?;
        if full.event.scope_ref != welcome.effective_scope
            || !crate::sidecar_access::handshake_event_in_connection(
                guard.connection(),
                &full.event,
                &actor,
            )
            .await?
        {
            return Err(denied());
        }
        let queued = sql_query("SELECT EXISTS(SELECT 1 FROM mls_welcome_deliveries WHERE welcome_id=$1 AND state='queued' AND delivery_json=$2) AS present")
            .bind::<Text,_>(welcome.welcome_id.as_str()).bind::<diesel::sql_types::Jsonb,_>(serde_json::json!(welcome))
            .get_result::<crate::query_rows::ExistsRow>(guard.connection()).await.map_err(PersistenceError::database)?.present;
        if !queued {
            return Err(denied());
        }
    }
    if !guard.permits_handoff() {
        return Err(denied());
    }
    Ok(Some(guard))
}
