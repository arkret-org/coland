//! Narrow own-Device cleanup, serialized with its original PCR authority.
use arkret_models_crypto::{KeyPackagesRevokeOutcome, KeyPackagesRevokeRequestBody};
use arkret_wire::ScopeRef;

use super::*;
use crate::mls::{MlsKeyPackagePgRow, validated_keypackage_row};

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}

/// Package locks always precede claim-ledger locks, as on claim and consume.
/// Consumed audit rows and the original signed outcome are never rewritten.
pub(crate) async fn close_claims(
    conn: &mut AsyncPgConnection,
    id: &str,
    at: i64,
) -> PersistenceResult<()> {
    sql_query("UPDATE peer_keypackage_claims SET state='revoked', updated_at=$2 WHERE keypackage_id=$1 AND state IN ('claimed','last_resort_claimed')")
        .bind::<Text,_>(id).bind::<BigInt,_>(at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

fn failure(reference: &str, code: &str) -> arkret_models_crypto::artifacts_keys::Failure {
    arkret_models_crypto::artifacts_keys::Failure {
        keypackage_ref: Some(reference.to_owned()),
        device_id: None,
        reason_code: arkret_wire::ReasonCode::from_wire(code),
        retry_after_ms: None,
    }
}

pub(crate) async fn revoke(
    pool: &PgPool,
    body: &KeyPackagesRevokeRequestBody,
    authority: &AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    expires_at: chrono::DateTime<Utc>,
) -> PersistenceResult<MlsKeyPackageRevocation> {
    if body.device_id != authority.device_id
        || !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. })
        || !authority.scopes.contains_scope(scope)
    {
        return Err(denied("revoke differs from original Device scope"));
    }
    let refs = body
        .key_package_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if refs.is_empty() || refs.len() != body.key_package_refs.len() {
        return Err(PersistenceError::SchemaViolation(
            "KeyPackage revoke refs must be nonempty and unique".into(),
        ));
    }
    let input = arkret_models_crypto::keypackages_revoke_signing_input(&body.unsigned())
        .map_err(PersistenceError::database)?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &authority.public_key,
        body.signature.kid.as_str(),
        &input,
        &body.signature,
    )
    .map_err(|_| denied("invalid original Device revoke signature"))?;
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &authority.realm_id).await?;
        let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        if at >= expires_at {
            return Err(denied("revoke request expired").into());
        }
        let current = crate::realm_actor_device_authority::current_in_connection(
            conn, &authority.actor_id, &authority.device_id, at,
        ).await?.ok_or_else(||denied("revoke Device is unavailable"))?;
        if current != *authority {
            return Err(denied("revoke Device authorization instance changed").into());
        }
        // Lock in stable order, then preflight the entire batch. A valid own
        // package at another signed scope must not cause partial cleanup.
        let mut rows = BTreeMap::new();
        for reference in refs {
            let row = sql_query("SELECT id,keypackage_ref,keypackage_digest,owner_account_id,effective_scope,actor_id,device_id,endpoint_verification_method,key_package_bytes,capabilities,capabilities_digest,last_resort,last_resort_realm_id,lifetime_not_before,lifetime_not_after,claimed_by_mls_group_id,device_authorize_event_id,agent_key_authorize_event_id,claimed_at,claim_expires_at_unix_ms,consumed_at,created_at FROM mls_key_packages WHERE keypackage_ref=$1 FOR UPDATE")
                .bind::<Text,_>(&reference).get_result::<MlsKeyPackagePgRow>(&mut *conn).await.optional()?
                .map(validated_keypackage_row).transpose()?;
            let own = row.filter(|row| row.owner_actor_id == authority.actor_id
                && row.actor_id == authority.actor_id.signing_principal_id().as_str()
                && row.device_id.as_deref() == Some(authority.device_id.as_str())
                && row.device_authorize_event_id.as_deref() == Some(authority.authorization_ref.event_id.as_str())
                && row.agent_key_authorize_event_id.is_none()
                && row.endpoint_verification_method.is_none());
            if own.as_ref().is_some_and(|row|row.effective_scope.as_ref() != Some(scope)) {
                return Err(denied("revoke package differs from exact scope").into());
            }
            rows.insert(reference, own);
        }
        let commit_at = Utc::now();
        if commit_at >= expires_at || commit_at >= authority.expires_at {
            return Err(denied("revoke authority expired while waiting for package locks").into());
        }
        let mut outcome = KeyPackagesRevokeOutcome { revoked: vec![], failures: vec![] };
        let mut records = vec![];
        for reference in &body.key_package_refs {
            let Some(row) = rows.remove(reference).flatten() else {
                outcome.failures.push(failure(reference, arkret_wire::ErrorCode::KEYPACKAGE_UNKNOWN));
                continue;
            };
            if row.consumed_at.is_some() || row.claimed_by_mls_group_id.as_deref() == Some("retired") {
                outcome.failures.push(failure(reference, arkret_wire::ErrorCode::KEYPACKAGE_ALREADY_CONSUMED));
                continue;
            }
            let next = if row.claimed_by_mls_group_id.as_deref() == Some("revoked") {
                row
            } else {
                let claim = MlsKeyPackageClaim {
                    applet_device_scope_guard: None,
                    id: &row.id,
                    target: MlsKeyPackageClaimTarget::Revoke,
                    intended_realm_id: None,
                    device_authorize_event_id: Some(authority.authorization_ref.event_id.as_str()),
                    agent_key_authorize_event_id: None,
                    device_revocation_gate: None,
                    claimed_at: at.timestamp(),
                    claim_expires_at_unix_ms: None,
                };
                let next = apply_key_package_claim(&row, &claim)
                    .ok_or_else(||PersistenceError::Internal("locked own KeyPackage cannot revoke".into()))?;
                let count = sql_query("UPDATE mls_key_packages SET claimed_by_mls_group_id='revoked', claimed_at=NULL, claim_expires_at_unix_ms=NULL WHERE id=$1 AND consumed_at IS NULL")
                    .bind::<Text,_>(&row.id).execute(&mut *conn).await?;
                if count != 1 {
                    return Err(PersistenceError::Internal("locked own KeyPackage disappeared".into()).into());
                }
                close_claims(conn, &row.id, at.timestamp()).await?;
                next
            };
            outcome.revoked.push(reference.clone());
            records.push(next);
        }
        Ok(MlsKeyPackageRevocation { outcome, records })
    }).await.map_err(PgTransactionError::into_persistence)
}
