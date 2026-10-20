use crate::state::AppState;

fn snapshot_unavailable(message: &'static str) -> coland_http::error::AppError {
    crate::app_error!(RealmStateSnapshotUnavailable, message,)
}

fn map_issue_error(
    realm_id: &arkret_wire::RealmId,
    error: coland_services::ServiceError,
) -> coland_http::error::AppError {
    if error.conflict_code() == Some(coland_storage::ConflictCode::SnapshotCapacityExceeded) {
        return crate::app_error!(
            PayloadTooLarge,
            "complete Realm State Snapshot exceeds the 8 MiB inline response limit",
        )
        .with_wire_code("payload_too_large");
    }
    if error.conflict_code() == Some(coland_storage::ConflictCode::TemporarilyUnavailable) {
        // The entire transaction rolled back. A signature may have been
        // computed, but no issuance was committed or returned. Serialization
        // alone cannot distinguish a handoff from an issuance-row race.
        tracing::warn!(
            operation_stage = "snapshot_issuance_transaction",
            conflict_code = "temporarily_unavailable",
            "snapshot issuance transaction unavailable",
        );
        return snapshot_unavailable("a concurrent write prevented snapshot issuance");
    }
    match error {
        coland_services::ServiceError::SchemaViolation(_) => {
            tracing::warn!(%error, realm_id=%realm_id, "snapshot disclosure gate rejected material");
            snapshot_unavailable("complete Account disclosure cannot be proved at this cut")
        }
        other => coland_http::error::AppError::internal(other.to_string()),
    }
}

/// Whether `account` is a currently joined member of the Realm on the
/// governing Station's typed `member_state` current (the same membership the
/// Snapshot gate, the stream scan and the stream list prove), so a non-member
/// gets the non-enumerating refusal before any disclosure is attempted.
pub(crate) async fn account_is_joined_member(
    state: &AppState,
    realm_id: &str,
    account: &arkret_wire::AccountId,
) -> Result<bool, coland_http::error::AppError> {
    let Ok(realm_id) = arkret_wire::RealmId::new(realm_id.to_owned()) else {
        return Ok(false);
    };
    match state
        .authority_commits()
        .list_realm_streams_for_account(&realm_id, account, &state.service_core_id())
        .await
    {
        Ok(coland_storage::AccountRealmStreamList::NotVisible) => Ok(false),
        Ok(_) => Ok(true),
        Err(error) => Err(coland_http::error::AppError::internal(error.to_string())),
    }
}

/// Issue the one closed, inline v1 snapshot from a single durable cut that
/// also proves this Station's current governing tenure and persists the exact
/// signed object for later by-ref reads. No chunk, cursor, or partial
/// fallback exists.
pub(crate) async fn realm_state_snapshot_manifest_for_realm(
    state: &AppState,
    realm_id: &str,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, coland_http::error::AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|_| coland_http::error::AppError::param_invalid("invalid realm_id"))?;
    if state
        .authority_commits()
        .current_authority(&realm_id)
        .await
        .map_err(|error| coland_http::error::AppError::internal(error.to_string()))?
        .is_some_and(|authority| authority.service_id != state.service_core_id())
    {
        return crate::state::refresh_account_snapshot(state, &realm_id, account)
            .await.map_err(|reason| {
                tracing::warn!(%reason, realm_id=%realm_id, "member Account Snapshot refresh unavailable");
                snapshot_unavailable("the complete governing Snapshot is not installed at the member cut")
            });
    }
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(coland_http::error::AppError::internal)?;
    let signing_key = state.notary_signing_key();
    state
        .authority_commits()
        .issue_realm_state_snapshot_for_account(
            &realm_id,
            account,
            &state.service_core_id(),
            &verification_method,
            signing_key.as_ref(),
            crate::wire::now(),
        )
        .await
        .map_err(|error| map_issue_error(&realm_id, error))?
        .ok_or_else(|| coland_http::error::AppError::not_found("not found"))
}

/// Return exactly the original object previously issued to this Account,
/// after the store re-proves its disclosure at the read cut. A missing or no
/// longer disclosable reference is unavailable; `/head` never substitutes.
pub(crate) async fn issued_realm_state_snapshot_for_account(
    state: &AppState,
    realm_id: &str,
    snapshot_id: &arkret_wire::RealmSnapshotId,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, coland_http::error::AppError> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())
        .map_err(|_| coland_http::error::AppError::param_invalid("invalid realm_id"))?;
    match state
        .authority_commits()
        .issued_realm_state_snapshot(&realm_id, account, snapshot_id, &state.service_core_id())
        .await
    {
        Ok(Some(snapshot)) => Ok(snapshot),
        Ok(None) => Err(snapshot_unavailable(
            "the exact snapshot was not issued to this Account",
        )),
        Err(coland_services::ServiceError::SchemaViolation(reason)) => {
            tracing::warn!(%reason, realm_id=%realm_id, "issued snapshot disclosure recheck failed");
            Err(snapshot_unavailable(
                "the exact snapshot is no longer safely disclosable",
            ))
        }
        Err(error) => Err(coland_http::error::AppError::internal(error.to_string())),
    }
}

/// Native snapshots use the existing closed object and Account archive. Only
/// a locally governed exact scope is signed; a foreign object is never clipped
/// and resigned by its receiving Account Station.
pub(crate) async fn native_snapshot(
    state: &AppState,
    device: &crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice,
    realm: &str,
    reference: Option<&arkret_wire::RealmSnapshotId>,
) -> coland_http::result::GuardedJsonResult<arkret_wire::RealmStateSnapshot> {
    use crate::routing::identity::applet_managed_device;
    let denied = || {
        coland_http::error::AppError::capability_denied(
            "the Realm snapshot is not readable by this caller",
        )
    };
    let hidden = || {
        if reference.is_some() {
            denied()
        } else {
            coland_http::error::AppError::not_found("not found")
        }
    };
    let realm_id = arkret_wire::RealmId::new(realm.to_owned()).map_err(|_| hidden())?;
    let operation = if reference.is_some() {
        "ak.self.realm_state_snapshot.read.by_ref.v1"
    } else {
        "ak.self.realm_state_snapshot.read.manifest_head.v1"
    };
    if device.operation.as_str() != operation
        || device.authority.governance_service_id != state.service_core_id()
        || device.metadata.effective_scope.realm_id() != &realm_id
        || crate::routing::spaces::space::is_realm_deleted(state, realm_id.as_str()).await
    {
        return Err(hidden());
    }
    let endpoint = applet_managed_device::scope_guard(state, device).await?;
    let issuer = state.service_core_id();
    let snapshot = if let Some(reference) = reference {
        state
            .authority_commits()
            .issued_realm_state_snapshot_for_actor(
                &realm_id,
                &device.authority.actor_id,
                reference,
                &issuer,
            )
            .await
            .map_err(|error| map_issue_error(&realm_id, error))?
            .ok_or_else(hidden)?
    } else {
        let method = state
            .service_verification_method("notary-key")
            .map_err(coland_http::error::AppError::internal)?;
        let key = state.notary_signing_key();
        state
            .authority_commits()
            .issue_realm_state_snapshot_for_applet_device(
                &endpoint,
                &issuer,
                device.transport_expires_at,
                &method,
                key.as_ref(),
                crate::wire::now(),
            )
            .await
            .map_err(|error| {
                if error.conflict_code() == Some(coland_storage::ConflictCode::CapabilityDenied) {
                    hidden()
                } else {
                    map_issue_error(&realm_id, error)
                }
            })?
            .ok_or_else(hidden)?
    };
    let input = coland_storage::AccountContentDeliveryInput::snapshot(&snapshot);
    let guard = applet_managed_device::content_delivery_guard_for_input(state, device, input)
        .await
        .map_err(|error| if reference.is_some() { denied() } else { error })?;
    coland_http::result::guarded_json_ok(snapshot, Some(guard))
}

#[cfg(test)]
mod issue_error_tests {
    use super::*;

    fn realm() -> arkret_wire::RealmId {
        arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x5a; 32],
        ))
    }

    #[test]
    fn snapshot_transaction_race_is_the_registered_snapshot_unavailability() {
        let raced = map_issue_error(
            &realm(),
            coland_services::ServiceError::Conflict(format!(
                "{}: the snapshot transaction lost a concurrent write race: could not serialize access",
                coland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
            )),
        );
        assert_eq!(raced.wire_code(), "realm_state_snapshot_unavailable");
        assert_eq!(raced.http_status().as_u16(), 503);

        // An unclassified storage fault stays internal rather than being
        // guessed into a caller-facing reason.
        let fault = map_issue_error(
            &realm(),
            coland_services::ServiceError::Database("connection reset".to_owned()),
        );
        assert_eq!(fault.http_status().as_u16(), 500);
    }
}
