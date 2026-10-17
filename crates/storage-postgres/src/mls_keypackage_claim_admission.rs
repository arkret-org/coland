//! Native claim inputs stay bound to the original SDK command and one real cut.
use arkret_models_crypto::{PeerKeyPackageClaimPurpose, PeerKeyPackageRequesterAuthorization};
use arkret_wire::{ActorId, ScopeRef};

use super::*;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

async fn lock_cuts(
    conn: &mut AsyncPgConnection,
    endpoints: &[&AppletManagedDeviceScopeGuard],
    counterparts: &[crate::mls_keypackage_claim_endpoints::ClaimEndpoint],
) -> PersistenceResult<()> {
    let mut realms = Vec::new();
    for endpoint in endpoints {
        realms.push((
            endpoint.authority.pcr_realm_id.clone(),
            endpoint.authority.account_id.station_id.clone(),
        ));
        realms.push((
            endpoint.effective_scope.realm_id().clone(),
            endpoint.authority.account_id.station_id.clone(),
        ));
    }
    let station = &endpoints[0].authority.account_id.station_id;
    realms.extend(
        counterparts
            .iter()
            .map(|endpoint| (endpoint.realm().clone(), station.clone())),
    );
    realms.sort();
    realms.dedup();
    for (realm, station) in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
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
    request: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
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
            crate::circle_current_results::locked_circle_basis(conn, realm_id, circle_id).await?;
        if basis["value"]["state"] != "active"
            || !crate::circle_current_results::effective_member_in_connection(
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
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome = serde_json::from_value(
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
            &endpoints[0].authority.account_id.station_id,
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
        let PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            signature,
        } = &request.requester_authorization
        else {
            return Err(denied("native requester must use its true Device branch"));
        };
        if request.requester_account_id.as_ref() != Some(&source.authority.account_id)
            || request.service_binding.source_id != source.authority.account_id.station_id
            || requester_device_id != &source.authority.device_id
            || device_authorize_event_id != &source.authority.selector.authorization_ref.event_id
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
        if request.target_account_id.as_ref() != Some(&target.authority.account_id)
            || request.service_binding.destination_id != target.authority.account_id.station_id
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
        _ => return Err(denied("claim requester routing branch is incomplete")),
    };
    let target = match (&request.target_account_id, &request.target_agent_id) {
        (Some(account), None) => ActorId::account(account.clone()),
        (None, Some(agent)) => ActorId::account(arkret_wire::AccountId::new(
            agent.clone(),
            request.service_binding.destination_id.clone(),
        )),
        _ => return Err(denied("claim target routing branch is incomplete")),
    };
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
        || row.owner_account_id != guard.authority.account_id
        || row.actor_id != guard.authority.account_id.principal_id.as_str()
        || row.device_id.as_deref() != Some(guard.authority.device_id.as_str())
        || row.device_authorize_event_id.as_deref()
            != Some(guard.authority.selector.authorization_ref.event_id.as_str())
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
    let actor = ActorId::account(row.owner_account_id.clone());
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
    outcome: &arkret_models_crypto::PeerKeyPackagesClaimOutcome,
    row: &MlsKeyPackageRow,
) -> PersistenceResult<()> {
    outcome.validate_shape().map_err(denied)?;
    let [claim] = outcome.claims.as_slice() else {
        return Err(denied("one candidate must bind one exact outcome"));
    };
    if claim.keypackage_ref != row.keypackage_ref
        || claim.principal_id.as_str() != row.actor_id
        || claim.actor_id.route_service_id() != &row.owner_account_id.station_id
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
    if row.device_id.is_some() && claim.actor_id.as_account_id() != Some(&row.owner_account_id) {
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
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome = serde_json::from_value(
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
    outcome: &arkret_models_crypto::PeerKeyPackagesClaimOutcome,
    endpoints: &[AppletManagedDeviceScopeGuard],
) -> PersistenceResult<()> {
    outcome.validate_shape().map_err(denied)?;
    let ledger=sql_query("SELECT outcome AS payload FROM peer_keypackage_claims WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3 FOR SHARE NOWAIT")
        .bind::<Text,_>(outcome.claim_receipt.source_id.as_str())
        .bind::<Text,_>(outcome.claim_request_id.as_str())
        .bind::<Text,_>(outcome.claim_receipt.request_digest.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if arkret_canonical::canonical_json_bytes(&ledger.payload).map_err(denied)?
        != arkret_canonical::canonical_json_bytes(outcome).map_err(denied)?
    {
        return Err(denied("claim delivery differs from immutable ledger"));
    }
    for claim in &outcome.claims {
        let row=sql_query("SELECT to_jsonb(k) AS payload FROM mls_key_packages k WHERE keypackage_ref=$1 FOR SHARE NOWAIT")
            .bind::<Text,_>(&claim.keypackage_ref).get_result::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        // Device and scope are immutable original publication fields. Parse
        // using the SDK scope/Account models; SQL bytea is not a wire object.
        let scope: Option<ScopeRef> =
            serde_json::from_value(row.payload["effective_scope"].clone()).map_err(denied)?;
        if let Some(scope) = scope {
            let guard = endpoints
                .iter()
                .find(|endpoint| {
                    claim.actor_id.as_account_id() == Some(&endpoint.authority.account_id)
                        && claim.device_id.as_ref() == Some(&endpoint.authority.device_id)
                })
                .ok_or_else(|| denied("claim omits its true native target proof"))?;
            if guard.effective_scope != scope
                || claim.device_authorize_event_id.as_ref()
                    != Some(&guard.authority.selector.authorization_ref.event_id)
            {
                return Err(denied(
                    "claim target authorization instance or scope changed",
                ));
            }
        }
    }
    for endpoint in endpoints {
        let actor = ActorId::account(endpoint.authority.account_id.clone());
        let request = &outcome.claim_receipt.request;
        if request.requester_account_id.as_ref() != Some(&endpoint.authority.account_id)
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
    Ok(())
}
