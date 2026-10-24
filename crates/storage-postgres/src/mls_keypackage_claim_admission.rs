//! Native claim inputs stay bound to the original SDK command and one real cut.
use arkret_models_crypto::{PeerKeyPackageClaimPurpose, PeerKeyPackageRequesterAuthorization};
use arkret_wire::{ActorId, ScopeRef};

use super::*;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

pub(crate) async fn lock_cuts(
    conn: &mut AsyncPgConnection,
    endpoints: &[&AppletManagedDeviceScopeGuard],
    counterparts: &[crate::mls_keypackage_claim_endpoints::ClaimEndpoint],
) -> PersistenceResult<()> {
    let mut realms = Vec::new();
    for endpoint in endpoints {
        realms.push((
            endpoint.authority.realm_id.clone(),
            endpoint.authority.governance_service_id.clone(),
        ));
        realms.push((
            endpoint.effective_scope.realm_id().clone(),
            endpoint.authority.governance_service_id.clone(),
        ));
    }
    let station = &endpoints[0].authority.governance_service_id;
    realms.extend(
        counterparts
            .iter()
            .map(|endpoint| (endpoint.realm().clone(), station.clone())),
    );
    realms.sort();
    realms.dedup();
    for (realm, station) in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
        crate::realm_management_archive::require_unfrozen(conn, &realm).await?;
        let owner = sql_query(
            "SELECT to_jsonb(service_id) AS payload FROM realm_authorities WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if owner.payload.as_str() != Some(station.as_str()) {
            return Err(PersistenceError::Conflict(
                "temporarily_unavailable: native claim has no local current scope barrier".into(),
            ));
        }
    }
    Ok(())
}

fn matches_scope(
    request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    scope: &ScopeRef,
) -> PersistenceResult<()> {
    if request.intended_realm_id != *scope.realm_id()
        || request.mls_group_id != scope.canonical_mls_group_id().map_err(denied)?
    {
        return Err(denied(
            "claim differs from its actual original scope and group",
        ));
    }
    Ok(())
}

fn claim_participants(
    request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
) -> PersistenceResult<(ActorId, ActorId)> {
    let requester = match (
        &request.requester_account_id,
        &request.requester_authorization,
    ) {
        (Some(account), PeerKeyPackageRequesterAuthorization::Device { .. }) => {
            ActorId::account(account.clone())
        }
        (
            None,
            PeerKeyPackageRequesterAuthorization::Agent {
                requester_agent_id, ..
            },
        ) => ActorId::account(arkret_wire::AccountId::new(
            requester_agent_id.clone(),
            request.service_binding.source_id.clone(),
        )),
        (None, PeerKeyPackageRequesterAuthorization::RealmDevice { .. }) => request
            .requester_actor_id
            .clone()
            .ok_or_else(|| denied("Realm requester is absent"))?,
        _ => return Err(denied("claim requester routing branch is incomplete")),
    };
    let target = match (
        &request.target_account_id,
        &request.target_agent_id,
        &request.target_actor_id,
    ) {
        (Some(account), None, None) => ActorId::account(account.clone()),
        (None, Some(agent), None) => ActorId::account(arkret_wire::AccountId::new(
            agent.clone(),
            request.service_binding.destination_id.clone(),
        )),
        (None, None, Some(actor)) => actor.clone(),
        _ => return Err(denied("claim target routing branch is incomplete")),
    };
    Ok((requester, target))
}

/// Follow the native sorted endpoint lock order, including the room Realm.
/// Preparing all endpoints before locking avoids room/PCR lock inversion.
pub(crate) async fn lock_mimi_cut(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    room: &arkret_wire::MimiRoomUri,
    outcome: &arkret_models_crypto::KeyPackagesClaimResponseBody,
) -> PersistenceResult<()> {
    let counterparts = crate::boxed_future(|| {
        crate::mls_keypackage_claim_endpoints::prepare(
            conn,
            outcome,
            Some(request),
            &request.service_binding.destination_id,
            &[],
        )
    })
    .await?;
    let mut realms = counterparts
        .iter()
        .map(|endpoint| endpoint.realm().clone())
        .collect::<Vec<_>>();
    realms.push(request.intended_realm_id.clone());
    realms.sort();
    realms.dedup();
    for realm in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
        crate::realm_management_archive::require_unfrozen(conn, &realm).await?;
    }
    require_mimi_room(conn, request, room).await?;
    for endpoint in &counterparts {
        crate::boxed_future(|| endpoint.require_current(conn)).await?;
    }
    if request.service_binding.source_id == request.service_binding.destination_id {
        crate::boxed_future(|| {
            crate::mls_keypackage_claim_endpoints::require_local_requester_signature(conn, request)
        })
        .await?;
    }
    Ok(())
}

/// Resolve the signed room locator at the same current cut as native claim CAS.
/// It is an additional selector constraint, never a second claim identity.
pub(crate) async fn require_mimi_room(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    room: &arkret_wire::MimiRoomUri,
) -> PersistenceResult<ScopeRef> {
    use arkret_models_collaboration::events_payloads::mimi::{
        MimiRoomBindingPayload, MimiRoomBindingStatus,
    };
    request.validate_shape().map_err(denied)?;
    if request.last_resort_allowed == Some(true)
        || !request
            .required_capabilities
            .iter()
            .any(|capability| capability.as_str() == "mimi.content.v1")
    {
        return Err(denied("MIMI requires ordinary single-use content packages"));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &request.intended_realm_id)
        .await?;
    crate::realm_management_archive::require_unfrozen(conn, &request.intended_realm_id).await?;
    let row = sql_query("SELECT value AS payload FROM mimi_room_binding_current_states WHERE mimi_room_uri=$1 AND realm_id=$2 FOR SHARE")
        .bind::<Text,_>(room.as_str()).bind::<Text,_>(request.intended_realm_id.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("current MIMI room is unavailable"))?;
    let binding: MimiRoomBindingPayload = serde_json::from_value(row.payload).map_err(denied)?;
    binding.validate_shape().map_err(denied)?;
    if binding.mimi_room_uri != *room
        || binding.binding_scope.realm_id != request.intended_realm_id
        || binding.status != MimiRoomBindingStatus::Accepted
        || binding.mls_group_id.as_ref() != Some(&request.mls_group_id)
        || request
            .strand_id
            .as_ref()
            .is_some_and(|strand| strand != &binding.binding_scope.strand_id)
    {
        return Err(denied("MIMI room differs from the native claim target"));
    }
    let scope = crate::strand_current_states::locked_active_strand_scope(
        conn,
        &request.intended_realm_id,
        &binding.binding_scope.strand_id,
    )
    .await?;
    matches_scope(request, &scope)?;
    crate::mls_keypackage_publication::require_existing_group(conn, &scope).await?;
    if Utc::now() >= request.expires_at {
        return Err(denied("fresh MIMI claim expired"));
    }
    if request.claim_purpose == PeerKeyPackageClaimPurpose::RealmMembership {
        let (requester, target) = claim_participants(request)?;
        member(conn, &scope, &requester).await?;
        member(conn, &scope, &target).await?;
    }
    Ok(scope)
}

async fn member(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    actor: &ActorId,
) -> PersistenceResult<()> {
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, scope.realm_id(), actor)
            .await?;
    cut.require_open_content_read()?;
    if !cut.actor_is_joined() {
        return Err(denied("claim endpoint is not a current Realm member"));
    }
    if let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = scope
    {
        let basis =
            crate::circle_current_states::locked_circle_basis(conn, realm_id, circle_id).await?;
        if basis["value"]["state"] != "active"
            || !crate::circle_current_states::effective_member_in_connection(
                conn, realm_id, circle_id, actor,
            )
            .await?
        {
            return Err(denied(
                "claim endpoint has no active exact Circle membership",
            ));
        }
    }
    Ok(())
}

/// Persist only the original command, not an invented remote result. The
/// caller can query or retry these exact bytes after a lost response.
pub(crate) async fn prepare_source(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    source: &AppletManagedDeviceScopeGuard,
    deadline: chrono::DateTime<Utc>,
) -> PersistenceResult<bool> {
    request.validate_shape().map_err(denied)?;
    matches_scope(request, &source.effective_scope)?;
    lock_cuts(conn, &[source], &[]).await?;
    let PeerKeyPackageRequesterAuthorization::RealmDevice {
        verification_method,
        requester_device_id,
        device_authorize_event_id,
        signed_at,
        signature,
    } = &request.requester_authorization
    else {
        return Err(denied(
            "outbound Realm claim needs its native Device signature",
        ));
    };
    if request.requester_actor_id.as_ref() != Some(&source.authority.actor_id)
        || requester_device_id != &source.authority.device_id
        || device_authorize_event_id != &source.authority.authorization_ref.event_id
        || verification_method.as_str()
            != format!(
                "{}#{}",
                source.authority.native_did, source.authority.device_id
            )
    {
        return Err(denied(
            "outbound claim differs from its current native Device",
        ));
    }
    let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .map_err(denied)?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &source.authority.public_key,
        verification_method.as_str(),
        &input,
        signature,
    )
    .map_err(denied)?;
    crate::boxed_future(|| {
        crate::applet_content_delivery::require_mls_scope_read(
            conn,
            source,
            deadline,
            request.strand_id.as_ref(),
        )
    })
    .await?;
    crate::mls_keypackage_publication::require_existing_group(conn, &source.effective_scope)
        .await?;
    member(conn, &source.effective_scope, &source.authority.actor_id).await?;
    let target = match (
        &request.target_actor_id,
        &request.target_account_id,
        &request.target_agent_id,
    ) {
        (Some(actor), None, None) => actor.clone(),
        (None, Some(account), None) => ActorId::account(account.clone()),
        (None, None, Some(agent)) => ActorId::account(arkret_wire::AccountId::new(
            agent.clone(),
            request.service_binding.destination_id.clone(),
        )),
        _ => return Err(denied("outbound claim target is incomplete")),
    };
    member(conn, &source.effective_scope, &target).await?;
    let source_id = request.service_binding.source_id.as_str();
    let digest = arkret_canonical::canonical_sha256(request).map_err(denied)?;
    let body = serde_json::to_value(request).map_err(denied)?;
    let prior = sql_query("SELECT jsonb_build_object('digest',request_digest,'body',request_body,'realm',governing_realm_id) AS payload FROM realm_keypackage_claim_sources WHERE source_id=$1 AND claim_request_id=$2")
        .bind::<Text,_>(source_id).bind::<Text,_>(request.claim_request_id.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(prior) = prior {
        if prior.payload["digest"].as_str() != Some(&digest)
            || prior.payload["body"] != body
            || prior.payload["realm"].as_str() != Some(source.authority.realm_id.as_str())
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: outbound claim original differs".into(),
            ));
        }
        crate::realm_management_history::require_issuer(
            conn,
            &source.authority.realm_id,
            &request.service_binding.source_id,
            None,
            *signed_at,
        )
        .await?;
        if Utc::now() >= deadline {
            return Err(denied("outbound recovery credential expired"));
        }
        return Ok(false);
    }
    let at = Utc::now();
    if request.service_binding.source_id != source.authority.governance_service_id
        || at >= deadline
        || at >= request.expires_at
        || *signed_at > at + chrono::Duration::seconds(60)
        || request.expires_at <= *signed_at
        || request.expires_at - *signed_at > chrono::Duration::minutes(5)
    {
        return Err(denied(
            "fresh outbound claim has no current issuing tenure and time window",
        ));
    }
    sql_query("INSERT INTO realm_keypackage_claim_sources(source_id,claim_request_id,request_digest,request_body,governing_realm_id) VALUES($1,$2,$3,$4,$5)")
        .bind::<Text,_>(source_id).bind::<Text,_>(request.claim_request_id.as_str())
        .bind::<Text,_>(digest).bind::<Jsonb,_>(body)
        .bind::<Text,_>(source.authority.realm_id.as_str())
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(true)
}

/// Checks local native requester facts, while remote participant key facts
/// remain the authenticated origin Station's responsibility under section9.2.
pub(crate) async fn require_admission(
    conn: &mut AsyncPgConnection,
    attempt: &PeerKeyPackageClaimAttempt<'_>,
) -> PersistenceResult<()> {
    let Some(admission) = &attempt.admission else {
        if attempt.applet_device_scope_guard.is_some() {
            return Err(denied("native claim needs its original signed command"));
        }
        return Ok(());
    };
    let request = &admission.request;
    request.validate_shape().map_err(denied)?;
    if request.claim_request_id.as_str() != attempt.ledger.claim_request_id
        || request.service_binding.source_id.as_str() != attempt.ledger.source_id
        || request.mls_group_id.as_str() != attempt.mls_group_id
        || request.expires_at.timestamp_millis() != attempt.claim_expires_at_unix_ms
        || arkret_canonical::canonical_sha256(request).map_err(denied)?
            != attempt.ledger.request_digest
    {
        return Err(denied(
            "claim admission differs from the exact signed command",
        ));
    }
    if let Some(room) = &admission.mimi_room_uri {
        let outcome: arkret_models_crypto::KeyPackagesClaimResponseBody = serde_json::from_value(
            attempt
                .ledger
                .outcome
                .clone()
                .ok_or_else(|| denied("claim outcome missing"))?,
        )
        .map_err(denied)?;
        crate::boxed_future(|| lock_mimi_cut(conn, request, room, &outcome)).await?;
    }
    let mut endpoints = Vec::new();
    if let Some((source, _)) = &admission.requester {
        endpoints.push(source);
    }
    if let Some(target) = &attempt.applet_device_scope_guard {
        endpoints.push(target);
    }
    if endpoints.is_empty() {
        return Ok(());
    }
    let outcome: arkret_models_crypto::KeyPackagesClaimResponseBody = serde_json::from_value(
        attempt
            .ledger
            .outcome
            .clone()
            .ok_or_else(|| denied("claim outcome missing"))?,
    )
    .map_err(denied)?;
    let counterparts = crate::boxed_future(|| {
        crate::mls_keypackage_claim_endpoints::prepare(
            conn,
            &outcome,
            Some(request),
            &endpoints[0].authority.governance_service_id,
            &[],
        )
    })
    .await?;
    lock_cuts(conn, &endpoints, &counterparts).await?;
    for endpoint in &counterparts {
        crate::boxed_future(|| endpoint.require_current(conn)).await?;
    }

    for endpoint in &endpoints {
        matches_scope(request, &endpoint.effective_scope)?;
    }
    let scope = &endpoints[0].effective_scope;
    crate::mls_keypackage_publication::require_existing_group(conn, scope).await?;
    let at = Utc::now();
    if at >= request.expires_at {
        return Err(denied("new claim command expired"));
    }
    if let Some((source, deadline)) = &admission.requester {
        let PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            signature,
        } = &request.requester_authorization
        else {
            return Err(denied("native requester must use its true Device branch"));
        };
        if request.requester_actor_id.as_ref() != Some(&source.authority.actor_id)
            || request.service_binding.source_id != source.authority.governance_service_id
            || requester_device_id != &source.authority.device_id
            || device_authorize_event_id != &source.authority.authorization_ref.event_id
            || verification_method.as_str()
                != format!(
                    "{}#{}",
                    source.authority.native_did, source.authority.device_id
                )
            || signature.kid.as_str() != verification_method.as_str()
            || *signed_at > at + chrono::Duration::seconds(60)
            || request.expires_at <= *signed_at
            || request.expires_at - *signed_at > chrono::Duration::minutes(5)
            || at >= *deadline
        {
            return Err(denied(
                "native requester differs from its original current Device intent",
            ));
        }
        let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
            &request.unsigned_request(),
            &request.service_binding,
            &request.requester_authorization,
        )
        .map_err(denied)?;
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &source.authority.public_key,
            verification_method.as_str(),
            &input,
            signature,
        )
        .map_err(denied)?;
        crate::boxed_future(|| {
            crate::applet_content_delivery::require_mls_scope_read(
                conn,
                source,
                (*deadline).min(request.expires_at),
                request.strand_id.as_ref(),
            )
        })
        .await?;
    }
    if let Some(target) = &attempt.applet_device_scope_guard {
        if request.target_actor_id.as_ref() != Some(&target.authority.actor_id)
            || request.service_binding.destination_id != target.authority.governance_service_id
            || (!request.target_device_ids.is_empty()
                && !request
                    .target_device_ids
                    .contains(&target.authority.device_id))
        {
            return Err(denied(
                "native target differs from signed Account and Device selectors",
            ));
        }
        crate::boxed_future(|| {
            crate::applet_content_delivery::require_mls_scope_read(
                conn,
                target,
                request.expires_at,
                request.strand_id.as_ref(),
            )
        })
        .await?;
    }
    let (requester, target) = claim_participants(request)?;
    // Managed Device scopes are actual existing Realm/Circle scopes. Direct
    // founding without their current installation never becomes a shortcut.
    if request.claim_purpose == PeerKeyPackageClaimPurpose::RealmMembership || !endpoints.is_empty()
    {
        member(conn, scope, &requester).await?;
        member(conn, scope, &target).await?;
    }
    let final_at = Utc::now();
    if final_at >= request.expires_at
        || admission
            .requester
            .as_ref()
            .is_some_and(|(_, deadline)| final_at >= *deadline)
        || counterparts
            .iter()
            .any(|endpoint| !endpoint.window().permits_at(final_at))
    {
        return Err(denied("claim authority expired before finalization"));
    }

    Ok(())
}

/// Existing native publication is eligible for new material only at its real
/// read/deliver cut. Upload's Execute/control exception is not claim permission.
pub(crate) async fn require_target(
    conn: &mut AsyncPgConnection,
    row: &MlsKeyPackageRow,
    guard: &AppletManagedDeviceScopeGuard,
    deadline: chrono::DateTime<Utc>,
) -> PersistenceResult<()> {
    if row.effective_scope.as_ref() != Some(&guard.effective_scope)
        || row.owner_actor_id != guard.authority.actor_id
        || row.actor_id != guard.authority.actor_id.signing_principal_id().as_str()
        || row.device_id.as_deref() != Some(guard.authority.device_id.as_str())
        || row.device_authorize_event_id.as_deref()
            != Some(guard.authority.authorization_ref.event_id.as_str())
        || row.agent_key_authorize_event_id.is_some()
        || row.endpoint_verification_method.is_some()
    {
        return Err(denied(
            "claim package differs from its true original Account Device",
        ));
    }
    lock_cuts(conn, &[guard], &[]).await?;
    crate::boxed_future(|| {
        crate::applet_content_delivery::require_mls_scope_read(conn, guard, deadline, None)
    })
    .await?;
    crate::mls_keypackage_publication::require_existing_group(conn, &guard.effective_scope).await?;
    let leaf = arkret_mls::author_leaf_from_key_package_bytes(&row.key_package_bytes, 0)
        .map_err(denied)?;
    let actor = row.owner_actor_id.clone();
    let credential = arkret_models_crypto::mls_basic_credential_identity(&actor).map_err(denied)?;
    if !matches!(leaf.credential,arkret_mls::AuthorLeafCredential::Basic{identity} if identity==credential)
        || leaf.signature_key.as_slice() != guard.authority.public_key.as_slice()
        || arkret_canonical::sha256_digest(&row.key_package_bytes) != row.keypackage_digest
        || row.keypackage_ref != row.keypackage_digest
        || arkret_canonical::canonical_sha256(&row.capabilities).map_err(denied)?
            != row.capabilities_digest
    {
        return Err(denied(
            "native claim leaf differs from original key and credential",
        ));
    }
    arkret_mls::validate_keypackage_capability_binding(&row.key_package_bytes, &row.capabilities)
        .map_err(denied)?;
    let at = Utc::now();
    if at >= deadline
        || at >= guard.authority.expires_at
        || at.timestamp() < row.lifetime_not_before
        || at.timestamp() >= row.lifetime_not_after
    {
        return Err(denied("native claim window expired"));
    }
    Ok(())
}

fn outcome_matches_row(
    outcome: &arkret_models_crypto::KeyPackagesClaimResponseBody,
    row: &MlsKeyPackageRow,
) -> PersistenceResult<()> {
    outcome.validate_shape().map_err(denied)?;
    let [claim] = outcome.claims.as_slice() else {
        return Err(denied("one candidate must bind one exact outcome"));
    };
    // Agent publications retain their accountable controller as the private
    // storage owner; their MLS recipient remains the Agent's complete Account.
    let recipient = if row.agent_key_authorize_event_id.is_some() {
        let controller = row
            .owner_actor_id
            .as_account_id()
            .ok_or_else(|| denied("Agent publication has no full controller Account"))?;
        ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(row.actor_id.clone()).map_err(denied)?,
            controller.station_id.clone(),
        ))
    } else {
        row.owner_actor_id.clone()
    };
    if claim.keypackage_ref != row.keypackage_ref
        || claim.principal_id.as_str() != row.actor_id
        || claim.actor_id != recipient
        || claim.device_id.as_ref().map(|id| id.as_str()) != row.device_id.as_deref()
        || claim
            .device_authorize_event_id
            .as_ref()
            .map(|id| id.as_str())
            != row.device_authorize_event_id.as_deref()
        || claim
            .agent_key_authorize_event_id
            .as_ref()
            .map(|id| id.as_str())
            != row.agent_key_authorize_event_id.as_deref()
        || claim
            .agent_verification_method
            .as_ref()
            .map(|id| id.as_str())
            != row.endpoint_verification_method.as_deref()
        || claim.keypackage != arkret_canonical::base64url_encode(&row.key_package_bytes)
        || claim.capabilities != row.capabilities
        || claim.last_resort.unwrap_or(false) != row.last_resort
        || claim.expires_at.timestamp_millis()
            != if row.last_resort {
                row.lifetime_not_after * 1000
            } else {
                outcome.claim_receipt.expires_at.timestamp_millis()
            }
    {
        return Err(denied(
            "claim response differs from its actual durable publication",
        ));
    }
    if row.device_id.is_some() && claim.actor_id != row.owner_actor_id {
        return Err(denied("claim response has another full owner Account"));
    }
    Ok(())
}

pub(crate) fn require_outcome(
    attempt: &PeerKeyPackageClaimAttempt<'_>,
    row: &MlsKeyPackageRow,
) -> PersistenceResult<()> {
    let Some(admission) = &attempt.admission else {
        return Ok(());
    };
    let outcome: arkret_models_crypto::KeyPackagesClaimResponseBody = serde_json::from_value(
        attempt
            .ledger
            .outcome
            .clone()
            .ok_or_else(|| denied("claim outcome missing"))?,
    )
    .map_err(denied)?;
    outcome_matches_row(&outcome, row)?;
    if outcome.claim_receipt.request_digest.as_str() != attempt.ledger.request_digest
        || outcome.claim_request_id != admission.request.claim_request_id
        || outcome.claim_receipt.source_id != admission.request.service_binding.source_id
        || outcome.claim_receipt.destination_id != admission.request.service_binding.destination_id
        || arkret_canonical::canonical_json_bytes(&outcome.claim_receipt.request).map_err(denied)?
            != arkret_canonical::canonical_json_bytes(&admission.request.unsigned_request())
                .map_err(denied)?
    {
        return Err(denied("claim receipt differs from original exact command"));
    }
    Ok(())
}

/// Immutable original outcome is re-read under the delivery transaction. Its
/// lifecycle may advance; current native material permission is independent.
pub(crate) async fn require_stored_outcome(
    conn: &mut AsyncPgConnection,
    operation: arkret_wire::ServiceOperationId,
    outcome: &arkret_models_crypto::KeyPackagesClaimResponseBody,
    endpoints: &[AppletManagedDeviceScopeGuard],
    remote_devices: &[coland_storage::MlsClaimRemoteDeviceEvidence],
) -> PersistenceResult<chrono::DateTime<Utc>> {
    use arkret_wire::ServiceOperationId;
    // Peer command/query recover the original signed result and its closed
    // ledger state after the original intent expires (section 9.2.3). Self
    // consumers deliver current material; neither mode changes the outcome.
    let material_read = match operation {
        ServiceOperationId::SelfKeysKeypackagesReadClaimV1
        | ServiceOperationId::SelfKeysKeypackagesCommandClaimV1 => true,
        ServiceOperationId::PeerKeysKeypackagesReadClaimV1
        | ServiceOperationId::PeerKeysKeypackagesCommandClaimV1 => false,
        _ => return Err(denied("claim delivery has no mounted consumer")),
    };
    outcome.validate_shape().map_err(denied)?;
    #[derive(QueryableByName)]
    struct DeliveryLedger {
        #[diesel(sql_type=Jsonb)]
        payload: Value,
        #[diesel(sql_type=Text)]
        state: String,
        #[diesel(sql_type=BigInt)]
        expires_at: i64,
        #[diesel(sql_type=Nullable<BigInt>)]
        claim_expires_at_unix_ms: Option<i64>,
    }
    let source = (operation == ServiceOperationId::SelfKeysKeypackagesCommandClaimV1)
        .then(|| {
            endpoints.iter().find(|endpoint| {
                outcome.claim_receipt.request.requester_actor_id.as_ref()
                    == Some(&endpoint.authority.actor_id)
            })
        })
        .flatten();
    let ledger = if let Some(source) = source {
        use arkret_models_crypto::PeerKeyPackagesClaimQueryState;
        let locked = sql_query("SELECT request_body AS payload FROM realm_keypackage_claim_sources WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3 FOR SHARE NOWAIT")
            .bind::<Text,_>(outcome.claim_receipt.source_id.as_str())
            .bind::<Text,_>(outcome.claim_request_id.as_str())
            .bind::<Text,_>(outcome.claim_receipt.request_digest.as_str())
            .get_result::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let stored = crate::realm_claim_source::read(
            conn,
            outcome.claim_receipt.source_id.as_str(),
            outcome.claim_request_id.as_str(),
        )
        .await?
        .ok_or_else(|| denied("Realm source ledger absent"))?;
        if arkret_canonical::canonical_json_bytes(&stored.request).map_err(denied)?
            != arkret_canonical::canonical_json_bytes(&locked.payload).map_err(denied)?
        {
            return Err(denied("Realm source ledger changed"));
        }
        let query = stored
            .result
            .ok_or_else(|| denied("Realm source has no original result"))?;
        let state = match query.state {
            PeerKeyPackagesClaimQueryState::Claimed => "claimed",
            PeerKeyPackagesClaimQueryState::Consumed => "consumed",
            _ => return Err(denied("Realm source material is terminally unavailable")),
        };
        let original = query
            .claim_outcome
            .ok_or_else(|| denied("Realm source claim absent"))?;
        member(conn, &source.effective_scope, &source.authority.actor_id).await?;
        for claim in &outcome.claims {
            member(conn, &source.effective_scope, &claim.actor_id).await?;
        }
        DeliveryLedger {
            payload: serde_json::to_value(&original).map_err(denied)?,
            state: state.into(),
            expires_at: (stored.request.expires_at + chrono::Duration::minutes(10)).timestamp(),
            claim_expires_at_unix_ms: Some(original.claim_receipt.expires_at.timestamp_millis()),
        }
    } else {
        sql_query("SELECT outcome AS payload,state,expires_at,claim_expires_at_unix_ms FROM peer_keypackage_claims WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3 FOR SHARE NOWAIT")
        .bind::<Text,_>(outcome.claim_receipt.source_id.as_str())
        .bind::<Text,_>(outcome.claim_request_id.as_str())
        .bind::<Text,_>(outcome.claim_receipt.request_digest.as_str())
        .get_result::<DeliveryLedger>(&mut *conn).await.map_err(PersistenceError::database)?
    };
    if arkret_canonical::canonical_json_bytes(&ledger.payload).map_err(denied)?
        != arkret_canonical::canonical_json_bytes(outcome).map_err(denied)?
    {
        return Err(denied("claim delivery differs from immutable ledger"));
    }
    let mut deadline = chrono::DateTime::from_timestamp(ledger.expires_at, 0)
        .ok_or_else(|| denied("claim retention window is invalid"))?;
    if material_read {
        match ledger.state.as_str() {
            "claimed" | "last_resort_claimed" => {
                let claim_deadline = ledger
                    .claim_expires_at_unix_ms
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .ok_or_else(|| denied("claim material window is unavailable"))?;
                deadline = deadline.min(claim_deadline);
            }
            "consumed" => {}
            _ => {
                return Err(denied(
                    "claim is terminally unavailable for material delivery",
                ));
            }
        }
    }
    for claim in &outcome.claims {
        if source.is_some_and(|source| {
            claim
                .actor_id
                .fixed_route_service_id()
                .is_some_and(|station| station != &source.authority.governance_service_id)
        }) {
            crate::mls_keypackage_claim_endpoints::remote_device_window(claim, remote_devices)?;
            continue;
        }
        let row = crate::mls::key_package_for_delivery(conn, &claim.keypackage_ref)
            .await?
            .ok_or_else(|| denied("original claim package is unavailable"))?;
        if let Some(scope) = &row.effective_scope {
            if material_read {
                let lifecycle = row.lifecycle().map_err(denied)?;
                if matches!(
                    lifecycle.claim_state,
                    coland_storage::PersistedKeyPackageClaimState::Revoked
                        | coland_storage::PersistedKeyPackageClaimState::Retired
                ) || (matches!(
                    lifecycle.claim_state,
                    coland_storage::PersistedKeyPackageClaimState::Available
                ) && !row.last_resort)
                    || Utc::now().timestamp() < row.lifetime_not_before
                {
                    return Err(denied(
                        "original native package is not available for delivery",
                    ));
                }
                deadline = deadline.min(
                    chrono::DateTime::from_timestamp(row.lifetime_not_after, 0)
                        .ok_or_else(|| denied("original package window is invalid"))?,
                );
            }
            let guard = endpoints
                .iter()
                .find(|endpoint| {
                    claim.actor_id == endpoint.authority.actor_id
                        && claim.device_id.as_ref() == Some(&endpoint.authority.device_id)
                })
                .ok_or_else(|| denied("claim omits its true native target proof"))?;
            if &guard.effective_scope != scope
                || claim.device_authorize_event_id.as_ref()
                    != Some(&guard.authority.authorization_ref.event_id)
            {
                return Err(denied(
                    "claim target authorization instance or scope changed",
                ));
            }
        }
    }
    for endpoint in endpoints {
        let actor = endpoint.authority.actor_id.clone();
        let request = &outcome.claim_receipt.request;
        if request.requester_actor_id.as_ref() != Some(&endpoint.authority.actor_id)
            && !outcome.claims.iter().any(|claim| {
                claim.actor_id == actor
                    && claim.device_id.as_ref() == Some(&endpoint.authority.device_id)
            })
        {
            return Err(denied(
                "claim delivery endpoint is unrelated to original request",
            ));
        }
    }
    if Utc::now() >= deadline {
        return Err(denied("original claim material window ended"));
    }
    Ok(deadline)
}
