//! Current governing invite cut held through a delegated provider's side effect.
use coland_storage::{
    ThirdPartyInviteProviderLivenessGuard, ThirdPartyInviteProviderLivenessRequest,
};

use super::*;

type Connection = diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>;

struct ProviderGuard {
    connection: Option<Connection>,
    observed_at: chrono::DateTime<chrono::Utc>,
    runtime: tokio::runtime::Handle,
}

impl ProviderGuard {
    fn connection(&mut self) -> &mut AsyncPgConnection {
        self.connection.as_mut().expect("provider cut is held")
    }
}

#[async_trait::async_trait]
impl ThirdPartyInviteProviderLivenessGuard for ProviderGuard {
    fn observed_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.observed_at
    }

    async fn finish(mut self: Box<Self>) -> PersistenceResult<()> {
        // No governing state was changed. A rolled-back, unlocked session may
        // return to the pool only after the provider completed its private unit.
        diesel::sql_query("ROLLBACK")
            .execute(self.connection())
            .await
            .map_err(PersistenceError::database)?;
        drop(self.connection.take());
        Ok(())
    }
}

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            let connection = Connection::take(connection);
            let cancel = connection.cancel_token();
            drop(connection);
            // A backend waiting on a lock may not observe socket EOF yet.
            self.runtime.spawn(async move {
                let _ = cancel.cancel_query(tokio_postgres::NoTls).await;
            });
        }
    }
}

pub(super) async fn acquire(
    pool: &crate::PgPool,
    request: &ThirdPartyInviteProviderLivenessRequest,
    station: &arkret_wire::DidCoreId,
    observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
) -> PersistenceResult<Box<dyn ThirdPartyInviteProviderLivenessGuard>> {
    // Only an explicitly delegated provider of this governing Station can hold
    // a local database cut. A remote verifier needs its own registered mechanism.
    if request.third_party_invite.verification_id != *station {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: provider has no current governing invite cut".into(),
        ));
    }
    let mut guard = Box::new(ProviderGuard {
        connection: Some(crate::pg_conn(pool).await?),
        observed_at: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        runtime: tokio::runtime::Handle::current(),
    });
    // This transaction performs no writes, but FOR UPDATE on the governing
    // row is required to serialize it with accepted governance writers.
    diesel::sql_query("BEGIN")
        .execute(guard.connection())
        .await
        .map_err(PersistenceError::database)?;
    let evidence = acceptance_attestation::pending_invite_evidence(
        guard.connection(),
        &request.realm_id,
        &request.invite_id,
        &request.inviter_account_id,
        station,
        &request.third_party_invite.verification_id,
        observe,
    )
    .await?;
    if evidence.material.third_party_invite != request.third_party_invite
        || evidence.material.expires_at != request.expires_at
    {
        return Err(PersistenceError::NotFound(
            "third-party invite unavailable".into(),
        ));
    }
    let join_rule = diesel::sql_query(
        "SELECT b.value FROM realm_bootstrap_current_states b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.state_family='realm_join_rule' AND c.realm_id=b.realm_id \
         AND c.stream_position=b.current_stream_position AND c.stream_ref->>'kind'='realm'",
    )
    .bind::<Text, _>(request.realm_id.as_str())
    .get_result::<ValueRow>(guard.connection())
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Conflict("revision_unavailable: current join rule unavailable".into())
    })?;
    if !join_rule
        .value
        .as_str()
        .is_some_and(|rule| matches!(rule, "invite" | "restricted"))
    {
        return Err(PersistenceError::Conflict(
            "unsupported_join_rule: 3PID claim requires invite or restricted".into(),
        ));
    }
    guard.observed_at = evidence.observed_at;
    Ok(guard)
}

#[derive(diesel::QueryableByName)]
struct InviterPrincipal {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    did: String,
}

#[derive(diesel::QueryableByName)]
struct Present {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

fn invalid_provision_proof() -> PersistenceError {
    PersistenceError::Conflict("signature_invalid: inviter proof is unavailable".into())
}

pub(super) async fn acquire_provision_device(
    pool: &crate::PgPool,
    request: &arkret_models_collaboration::governance::third_party_invite::ThirdPartyInviteProvisionRequestBody,
    station: &arkret_wire::DidCoreId,
    observe: &(dyn Fn() -> chrono::DateTime<chrono::Utc> + Send + Sync),
) -> PersistenceResult<Box<dyn ThirdPartyInviteProviderLivenessGuard>> {
    request
        .validate_for_service(station)
        .map_err(|_| invalid_provision_proof())?;
    let account = &request.inviter_account_id;
    if account.station_id != *station {
        return Err(invalid_provision_proof());
    }
    let (did, fragment) = request
        .signature
        .verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(invalid_provision_proof)?;
    let device = arkret_wire::DeviceId::new(fragment).map_err(|_| invalid_provision_proof())?;
    let native = arkret_wire::Did::new(did).map_err(|_| invalid_provision_proof())?;
    if arkret_wire::project_did_to_core_id(&native).map_err(|_| invalid_provision_proof())?
        != account.principal_id
    {
        return Err(invalid_provision_proof());
    }
    let mut guard = Box::new(ProviderGuard {
        connection: Some(crate::pg_conn(pool).await?),
        observed_at: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        runtime: tokio::runtime::Handle::current(),
    });
    diesel::sql_query("BEGIN")
        .execute(guard.connection())
        .await
        .map_err(PersistenceError::database)?;
    let principal = diesel::sql_query(
        "SELECT pcr_realm_id,value->>'did' AS did FROM principal_resolution_current_states \
         WHERE principal_id=$1 AND station_id=$2",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<InviterPrincipal>(guard.connection())
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(invalid_provision_proof)?;
    if principal.did != did {
        return Err(invalid_provision_proof());
    }
    let pcr = arkret_wire::RealmId::new(principal.pcr_realm_id).map_err(corrupt)?;
    lock_realm_authorization_cut(guard.connection(), &pcr).await?;
    let principal = diesel::sql_query(
        "SELECT pcr_realm_id,value->>'did' AS did FROM principal_resolution_current_states \
         WHERE principal_id=$1 AND station_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<InviterPrincipal>(guard.connection())
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(invalid_provision_proof)?;
    // Accepted PCR authority is the identity source. A product account row is
    // optional, but its deactivation writer must serialize with this guard.
    diesel::sql_query(
        "SELECT TRUE AS present FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .load::<Present>(guard.connection())
    .await
    .map_err(PersistenceError::database)?;
    let active = diesel::sql_query(
        "SELECT NOT EXISTS(SELECT 1 FROM accounts a \
         JOIN account_lifecycle l ON l.account_pk=a.pk \
         WHERE a.principal_id=$1 AND a.station_id=$2 \
         AND l.state<>'active') AS present",
    )
    .bind::<Text, _>(account.principal_id.as_str())
    .bind::<Text, _>(account.station_id.as_str())
    .get_result::<Present>(guard.connection())
    .await
    .map_err(PersistenceError::database)?
    .present;
    let governor = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_authorities WHERE realm_id=$1 AND service_id=$2) AS present",
    )
    .bind::<Text, _>(pcr.as_str())
    .bind::<Text, _>(station.as_str())
    .get_result::<Present>(guard.connection())
    .await
    .map_err(PersistenceError::database)?
    .present;
    if principal.did != did || principal.pcr_realm_id != pcr.as_str() || !active || !governor {
        return Err(invalid_provision_proof());
    }
    let selector = crate::device_revocations::current_device_binding_in_transaction(
        guard.connection(),
        &account.principal_id,
        &account.station_id,
        device.as_str(),
    )
    .await?
    .ok_or_else(invalid_provision_proof)?;
    crate::device_revocations::lock_artifact_devices_in_transaction(
        guard.connection(),
        &[&selector],
    )
    .await?;
    let at = observe();
    request
        .validate_proof_freshness(at)
        .map_err(|_| invalid_provision_proof())?;
    let current = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        guard.connection(),
        account,
        &device,
        at,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    .ok_or_else(invalid_provision_proof)?;
    if current.admission().error_code().is_some() {
        return Err(invalid_provision_proof());
    }
    crate::device_revocations::ensure_gate_allowed_in_transaction(guard.connection(), &selector)
        .await?;
    let authorization = current
        .authority
        .authorization
        .ok_or_else(invalid_provision_proof)?;
    if current.authority.realm_id != pcr
        || authorization.event_id != selector.authorization_ref.event_id
        || authorization.source_commit_id != selector.authorization_ref.commit_id
        || Some(authorization.payload.authorized_generation_ref)
            != current.authority.current_generation
    {
        return Err(invalid_provision_proof());
    }
    let multibase = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(invalid_provision_proof)?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: multibase.to_owned(),
    };
    let transcript = request
        .proof_binding_bytes()
        .map_err(|_| invalid_provision_proof())?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &request.signature,
        &transcript,
        &key,
    )
    .map_err(|_| invalid_provision_proof())?;
    guard.observed_at = at;
    Ok(guard)
}
