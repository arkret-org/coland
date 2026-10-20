use diesel_async::AsyncConnection;

use super::{
    BigInt, Binary, Bool, Jsonb, MlsKeyPackageClaim, MlsKeyPackageClaimTarget, MlsKeyPackageRow,
    MlsKeyPackageStore, Nullable, OptionalExtension, PeerClaimTerminalTransition,
    PeerKeyPackageClaimAttempt, PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord,
    PeerKeyPackageClaimLedgerWriteResult, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, Value, apply_key_package_claim,
    async_trait, ids, json_string_array, pg_conn, sql_query,
};

/// Encode a key package's trust-binding Event reference for storage.
///
/// These columns hold the same 33-octet token `canonical_events.id` does, so a
/// malformed wire id is rejected here rather than stored and found on read.
fn parse_authorize_event_id(event_id: Option<&str>) -> PersistenceResult<Option<Vec<u8>>> {
    event_id
        .map(|value| {
            ids::event_token_part_or_schema_violation(value, "event").map(|token| token.to_vec())
        })
        .transpose()
}

fn format_authorize_event_id(token: &[u8]) -> String {
    ids::format_event_id(
        &<[u8; ids::EVENT_ID_BYTES]>::try_from(token)
            .expect("mls_key_packages authorize Event id is a 33-octet Event id"),
    )
}
pub(super) async fn key_package_for_delivery(
    conn: &mut diesel_async::AsyncPgConnection,
    reference: &str,
) -> PersistenceResult<Option<MlsKeyPackageRow>> {
    sql_query(
        "SELECT id,keypackage_ref,keypackage_digest,owner_actor_id,effective_scope,actor_id,device_id,endpoint_verification_method, \
         key_package_bytes,capabilities,capabilities_digest,last_resort,last_resort_realm_id,lifetime_not_before,lifetime_not_after, \
         claimed_by_mls_group_id,device_authorize_event_id,agent_key_authorize_event_id,claimed_at,claim_expires_at_unix_ms,consumed_at,created_at \
         FROM mls_key_packages WHERE keypackage_ref=$1 FOR SHARE NOWAIT",
    )
    .bind::<Text,_>(reference).get_result::<MlsKeyPackagePgRow>(conn).await.optional()
    .map_err(PersistenceError::database)?.map(validated_keypackage_row).transpose()
}

// Serialize native authority before the row lock, using the same lock order
// as publication and MLS admission. Recheck the immutable row after the CAS.
async fn claim_candidate(
    conn: &mut diesel_async::AsyncPgConnection,
    id: &str,
    group: &str,
    deadline: Option<i64>,
    guard: Option<&coland_storage::AppletManagedDeviceScopeGuard>,
) -> PersistenceResult<Option<MlsKeyPackageRow>> {
    let candidate=sql_query("SELECT id,keypackage_ref,keypackage_digest,owner_actor_id,effective_scope,actor_id,device_id,endpoint_verification_method,key_package_bytes,capabilities,capabilities_digest,last_resort,last_resort_realm_id,lifetime_not_before,lifetime_not_after,claimed_by_mls_group_id,device_authorize_event_id,agent_key_authorize_event_id,claimed_at,claim_expires_at_unix_ms,consumed_at,created_at FROM mls_key_packages WHERE id=$1")
        .bind::<Text,_>(id).get_result::<MlsKeyPackagePgRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .map(validated_keypackage_row).transpose()?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    match (&candidate.effective_scope, guard) {
        (Some(scope), Some(guard)) => {
            if scope
                .canonical_mls_group_id()
                .map_err(PersistenceError::database)?
                .as_str()
                != group
            {
                return Ok(None);
            }
            let Some(expires_at) = deadline.and_then(chrono::DateTime::from_timestamp_millis)
            else {
                return Ok(None);
            };
            crate::boxed_future(|| {
                crate::mls_keypackage_publication::require_native(
                    conn, &candidate, guard, expires_at,
                )
            })
            .await?;
        }
        (None, None) => {}
        _ => return Ok(None),
    }
    Ok(Some(candidate))
}

pub struct PgMlsKeyPackageStore {
    pub pool: PgPool,
}
impl PgMlsKeyPackageStore {
    async fn put_guarded(
        &self,
        record: &MlsKeyPackageRow,
        native: Option<(
            &coland_storage::AppletManagedDeviceScopeGuard,
            chrono::DateTime<chrono::Utc>,
            &arkret_models_crypto::KeyPackagesUploadRequestBody,
        )>,
    ) -> PersistenceResult<bool> {
        match (&record.device_id, &record.device_authorize_event_id, &record.agent_key_authorize_event_id) {
            (Some(_), Some(_), None) | (None, None, Some(_)) | (None, None, None) => {}
            _ => return Err(PersistenceError::SchemaViolation(
                "KeyPackage producer must bind one Account Device authorization or a non-device endpoint".into(),
            )),
        }
        record.lifecycle().map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "invalid MLS KeyPackage lifecycle before insert: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        if let Some((guard, expires_at, body)) = native {
            crate::mls_keypackage_publication::require_native_publication(conn, record, guard, expires_at, body).await?;
        } else if record.effective_scope.is_some() {
            return Err(PersistenceError::Conflict("capability_denied: scoped Device publication requires its native guard".into()).into());
        }
        // An exact existing id cannot publish new material. Do not relabel it
        // with a successor authorization merely because a retry arrived later.
        if sql_query("SELECT to_jsonb(id) AS payload FROM mls_key_packages WHERE id=$1")
            .bind::<Text,_>(&record.id).get_result::<super::JsonPayloadRow>(&mut *conn).await.optional()?.is_some() {
            return Ok(false);
        }
        if native.is_none() {
            let account = record.owner_actor_id.as_account_id().ok_or_else(|| PersistenceError::Conflict("Realm KeyPackage requires its native authority guard".into()))?;
            #[derive(QueryableByName)]
            struct Owner { #[diesel(sql_type=Text)] principal_id: String, #[diesel(sql_type=Text)] station_id: String }
            let owner=sql_query("SELECT principal_id,station_id FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR SHARE")
                .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
                .get_result::<Owner>(&mut *conn).await.optional()?.ok_or_else(||PersistenceError::Conflict("KeyPackage Account owner is unavailable".into()))?;
            if let Some(original_authorize) = &record.device_authorize_event_id {
                let device = record.device_id.as_deref().ok_or_else(||PersistenceError::SchemaViolation("Account Device KeyPackage omits device".into()))?;
                let binding = crate::device_revocations::local_device_binding_in_transaction(conn,&record.actor_id,device).await?
                    .ok_or_else(||PersistenceError::Conflict("device_unauthorized".into()))?;
                if binding.authorization_ref.event_id.as_str() != original_authorize || owner.principal_id != binding.principal_id.as_str() || owner.station_id != binding.station_id.as_str() {
                    return Err(PersistenceError::Conflict("KeyPackage Account differs from its original device authorization".into()).into());
                }
                crate::ensure_gate_allowed_in_transaction(conn,&binding).await?;
            }
        }
        let inserted = sql_query(
            "INSERT INTO mls_key_packages \
             (id, keypackage_ref, keypackage_digest, owner_actor_id, actor_id, device_id, endpoint_verification_method, key_package_bytes, \
              capabilities, capabilities_digest, last_resort, \
              last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
              claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
              claim_expires_at_unix_ms, consumed_at, created_at, effective_scope) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<Text, _>(&record.id)
        .bind::<Text, _>(&record.keypackage_ref)
        .bind::<Text, _>(&record.keypackage_digest)
        .bind::<Jsonb, _>(serde_json::json!(record.owner_actor_id))
        .bind::<Text, _>(&record.actor_id)
        .bind::<Nullable<Text>, _>(&record.device_id)
        .bind::<Nullable<Text>, _>(&record.endpoint_verification_method)
        .bind::<Binary, _>(&record.key_package_bytes)
        .bind::<Jsonb, _>(serde_json::json!(record.capabilities))
        .bind::<Text, _>(&record.capabilities_digest)
        .bind::<Bool, _>(record.last_resort)
        .bind::<Nullable<Text>, _>(&record.last_resort_realm_id)
        .bind::<BigInt, _>(record.lifetime_not_before)
        .bind::<BigInt, _>(record.lifetime_not_after)
        .bind::<Nullable<Text>, _>(&record.claimed_by_mls_group_id)
        .bind::<Nullable<Binary>, _>(parse_authorize_event_id(
            record.device_authorize_event_id.as_deref(),
        )?)
        .bind::<Nullable<Binary>, _>(parse_authorize_event_id(
            record.agent_key_authorize_event_id.as_deref(),
        )?)
        .bind::<Nullable<BigInt>, _>(record.claimed_at)
        .bind::<Nullable<BigInt>, _>(record.claim_expires_at_unix_ms)
        .bind::<Nullable<BigInt>, _>(record.consumed_at)
        .bind::<BigInt, _>(record.created_at)
        .bind::<Nullable<Jsonb>, _>(record.effective_scope.as_ref().map(serde_json::to_value).transpose().map_err(PersistenceError::database)?)
        .execute(&mut *conn)
        .await.map_err(PersistenceError::database)?;
        Ok(inserted > 0)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
#[async_trait]
impl MlsKeyPackageStore for PgMlsKeyPackageStore {
    async fn prepare_realm_claim_source(
        &self,
        request: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
        source: &coland_storage::AppletManagedDeviceScopeGuard,
        transport_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            Ok(crate::mls_keypackage_claim_admission::prepare_source(
                conn,
                request,
                source,
                transport_expires_at,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn peer_claim_original(
        &self,
        claim_request_id: &str,
        request_digest: &str,
    ) -> PersistenceResult<Option<arkret_models_crypto::PeerKeyPackagesClaimRequestBody>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::realm_claim_history::original(&mut conn, claim_request_id, request_digest).await
    }
    async fn realm_claim_issuer_resolution(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<arkret_models_identity::AuthenticatedServiceResolution>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::realm_claim_history::read(&mut conn, source_id, claim_request_id).await
    }

    async fn consume_for_applet_device(
        &self,
        command: coland_storage::AppletDeviceKeyPackageConsume<'_>,
    ) -> PersistenceResult<coland_storage::MlsKeyPackageConsumption> {
        crate::mls_keypackage_consume::consume(&self.pool, command).await
    }
    async fn peer_claim_candidates(
        &self,
        body: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        body.validate_shape().map_err(|error| {
            PersistenceError::SchemaViolation(format!("claim candidate command: {error}"))
        })?;
        let principal = body
            .unsigned_request()
            .target_principal_id()
            .ok_or_else(|| {
                PersistenceError::SchemaViolation("claim target identity is incomplete".into())
            })?;
        let owner = body
            .target_account_id
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(PersistenceError::database)?;
        let devices = body
            .target_device_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let reference = body
            .target_keypackage_ref
            .as_ref()
            .map(|value| value.as_str());
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // A Device belongs to the complete Account, whereas an Agent has its
        // own principal and stores its package under its controller Account.
        // An exact-reference command cannot fall back to another package.
        sql_query(
            "SELECT id,keypackage_ref,keypackage_digest,owner_actor_id,effective_scope,actor_id,device_id,endpoint_verification_method, \
             key_package_bytes,capabilities,capabilities_digest,last_resort,last_resort_realm_id,lifetime_not_before,lifetime_not_after, \
             claimed_by_mls_group_id,device_authorize_event_id,agent_key_authorize_event_id,claimed_at,claim_expires_at_unix_ms,consumed_at,created_at \
             FROM mls_key_packages WHERE actor_id=$1 AND ($2::jsonb IS NULL OR owner_actor_id=$2) \
             AND (($2::jsonb IS NOT NULL AND device_id IS NOT NULL AND agent_key_authorize_event_id IS NULL) \
                  OR ($2::jsonb IS NULL AND device_id IS NULL AND agent_key_authorize_event_id IS NOT NULL)) \
             AND (cardinality($3::text[])=0 OR device_id=ANY($3)) \
             AND ($4::text IS NULL OR keypackage_ref=$4) \
             AND claimed_by_mls_group_id IS NULL AND consumed_at IS NULL \
             ORDER BY created_at ASC,id ASC",
        )
        .bind::<Text,_>(principal.as_str())
        .bind::<Nullable<Jsonb>,_>(owner)
        .bind::<diesel::sql_types::Array<Text>,_>(devices)
        .bind::<Nullable<Text>,_>(reference)
        .load::<MlsKeyPackagePgRow>(&mut *conn).await.map_err(PersistenceError::database)?
        .into_iter().map(validated_keypackage_row).collect()
    }
    async fn put(&self, record: &MlsKeyPackageRow) -> PersistenceResult<bool> {
        self.put_guarded(record, None).await
    }
    async fn put_for_applet_device(
        &self,
        record: &MlsKeyPackageRow,
        guard: &coland_storage::AppletManagedDeviceScopeGuard,
        expires_at: chrono::DateTime<chrono::Utc>,
        body: &arkret_models_crypto::KeyPackagesUploadRequestBody,
    ) -> PersistenceResult<bool> {
        self.put_guarded(record, Some((guard, expires_at, body)))
            .await
    }

    async fn revoke_for_applet_device(
        &self,
        body: &arkret_models_crypto::KeyPackagesRevokeRequestBody,
        authority: &coland_storage::AppletManagedDeviceAuthority,
        scope: &arkret_wire::ScopeRef,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::MlsKeyPackageRevocation> {
        crate::mls_keypackage_revocation::revoke(&self.pool, body, authority, scope, expires_at)
            .await
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
             "SELECT id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
             key_package_bytes, capabilities, capabilities_digest, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages WHERE id = $1",
        )
        .bind::<Text, _>(id)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(validated_keypackage_row)
        .transpose()
    }

    async fn get_by_ref(
        &self,
        keypackage_ref: &str,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
             "SELECT id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
             key_package_bytes, capabilities, capabilities_digest, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages WHERE keypackage_ref = $1",
        )
        .bind::<Text, _>(keypackage_ref)
        .get_result::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(validated_keypackage_row)
        .transpose()
    }

    async fn try_claim(
        &self,
        claim: MlsKeyPackageClaim<'_>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let gate_required = matches!(claim.target, MlsKeyPackageClaimTarget::Group(_))
            && claim.device_authorize_event_id.is_some();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Preserve the adapter boundary's strict wire-id validation even
            // though the shared transition compares canonical strings.
            parse_authorize_event_id(claim.device_authorize_event_id)?;
            parse_authorize_event_id(claim.agent_key_authorize_event_id)?;
            let candidate = match claim.target {
                MlsKeyPackageClaimTarget::Group(group) => claim_candidate(conn,claim.id,group,claim.claim_expires_at_unix_ms,claim.applet_device_scope_guard.as_ref()).await?,
                _ => None,
            };
            if matches!(claim.target,MlsKeyPackageClaimTarget::Group(_)) && candidate.is_none() {return Ok(None);}
            if gate_required && claim.applet_device_scope_guard.is_none() {
                let selector = claim.device_revocation_gate.as_ref().ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "device KeyPackage claim is missing revocation selector".to_owned(),
                    )
                })?;
                crate::ensure_gate_allowed_in_transaction(conn, selector).await?;
            }
            let existing = sql_query(
                "SELECT id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
                 key_package_bytes, capabilities, capabilities_digest, \
                 last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
                 claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
                 claim_expires_at_unix_ms, consumed_at, created_at \
                 FROM mls_key_packages WHERE id = $1 FOR UPDATE",
            )
            .bind::<Text, _>(claim.id)
            .get_result::<MlsKeyPackagePgRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(validated_keypackage_row)
            .transpose()?;
            let Some(existing) = existing else {
                return Ok(None);
            };
            if candidate.as_ref().is_some_and(|candidate|!candidate.same_publication(&existing)) {return Ok(None);}
            let Some(next) = apply_key_package_claim(&existing, &claim) else {
                return Ok(None);
            };
            let updated = sql_query(
                "UPDATE mls_key_packages \
                 SET claimed_by_mls_group_id = $2, last_resort_realm_id = $3, \
                     claimed_at = $4, claim_expires_at_unix_ms = $5, consumed_at = $6 \
                 WHERE id = $1",
            )
            .bind::<Text, _>(claim.id)
            .bind::<Nullable<Text>, _>(&next.claimed_by_mls_group_id)
            .bind::<Nullable<Text>, _>(&next.last_resort_realm_id)
            .bind::<Nullable<BigInt>, _>(next.claimed_at)
            .bind::<Nullable<BigInt>, _>(next.claim_expires_at_unix_ms)
            .bind::<Nullable<BigInt>, _>(next.consumed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if updated != 1 {
                return Err(PersistenceError::Internal(
                    "locked MLS KeyPackage row disappeared during claim".to_owned(),
                )
                .into());
            }
            if matches!(claim.target, MlsKeyPackageClaimTarget::Revoke) {
                crate::mls_keypackage_revocation::close_claims(conn, &next.id, claim.claimed_at).await?;
            }
            Ok::<Option<MlsKeyPackageRow>, PgTransactionError>(Some(next))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn consume_claim(
        &self,
        id: &str,
        mls_group_id: &str,
        now_unix_ms: i64,
        consumption: Option<coland_storage::MlsKeyPackageConsumeEvidence<'_>>,
    ) -> PersistenceResult<Option<MlsKeyPackageRow>> {
        let consume_digest = consumption
            .map(|evidence| evidence.request_digest())
            .transpose()?;
        if consumption.is_some_and(|evidence| {
            evidence
                .request
                .recipient_durable_receipt
                .mls_group_id
                .as_str()
                != mls_group_id
        }) {
            return Err(PersistenceError::SchemaViolation(
                "consume group differs from its original command".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let row = sql_query(
                "UPDATE mls_key_packages \
             SET consumed_at = $3 / 1000 \
             WHERE id = $1 AND NOT last_resort AND owner_actor_id->>'kind'<>'realm' \
               AND claimed_by_mls_group_id = $2 \
               AND consumed_at IS NULL \
               AND claim_expires_at_unix_ms > $3 \
             RETURNING id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
             key_package_bytes, capabilities, capabilities_digest, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at",
                )
                .bind::<Text, _>(id)
                .bind::<Text, _>(mls_group_id)
                .bind::<BigInt, _>(now_unix_ms)
                .get_result::<MlsKeyPackagePgRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
            let Some(row) = row else {
                let revoked = sql_query(
                    "UPDATE mls_key_packages \
                     SET claimed_by_mls_group_id = 'revoked', claimed_at = NULL, \
                         claim_expires_at_unix_ms = NULL, consumed_at = NULL \
                     WHERE id = $1 AND NOT last_resort AND owner_actor_id->>'kind'<>'realm' \
                       AND claimed_by_mls_group_id = $2 \
                       AND consumed_at IS NULL \
                       AND claim_expires_at_unix_ms <= $3",
                )
                .bind::<Text, _>(id)
                .bind::<Text, _>(mls_group_id)
                .bind::<BigInt, _>(now_unix_ms)
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if revoked == 1 {
                    let updated = sql_query(
                        "UPDATE peer_keypackage_claims \
                         SET state = 'revoked', updated_at = $2 / 1000 \
                         WHERE key_package_use = 'single_use' AND keypackage_id = $1 \
                           AND state = 'claimed'",
                    )
                    .bind::<Text, _>(id)
                    .bind::<BigInt, _>(now_unix_ms)
                    .execute(conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    if updated > 1 {
                        return Err(PersistenceError::Internal(
                            "multiple peer claim ledgers reference one KeyPackage".to_owned(),
                        )
                        .into());
                    }
                }
                return Ok(None);
            };
            if let Some(consumption) = consumption {
                let receipt = serde_json::to_value(consumption.receipt).map_err(PersistenceError::database)?;
                let updated = sql_query(
                    "UPDATE peer_keypackage_claims p \
                     SET state = 'consumed', consume_receipt = $2, consume_request_digest = $4, updated_at = $3 / 1000 \
                     WHERE key_package_use = 'single_use' AND keypackage_id = $1 AND state = 'claimed' \
                     AND EXISTS (SELECT 1 FROM keypackage_claim_welcome_bindings b \
                         WHERE b.source_id=p.source_id AND b.claim_request_id=p.claim_request_id \
                         AND b.claim_id=$5 AND b.welcome_id=$6 AND b.welcome_digest=$7)",
                )
                .bind::<Text, _>(id)
                .bind::<Jsonb, _>(&receipt)
                .bind::<BigInt, _>(now_unix_ms)
                .bind::<Text, _>(consume_digest.as_ref().unwrap())
                .bind::<Text, _>(consumption.request.claim_id.as_str())
                .bind::<Text, _>(consumption.request.recipient_durable_receipt.welcome_ref.as_str())
                .bind::<Text, _>(consumption.request.recipient_durable_receipt.welcome_digest.as_str())
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
                if updated != 1 {
                    return Err(PersistenceError::Conflict(
                        "consume has no unique original claim and Welcome binding".to_owned(),
                    )
                    .into());
                }
            }
            Ok(Some(validated_keypackage_row(row)?))
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn record_peer_claim_attempt(
        &self,
        body: &arkret_models_crypto::PeerKeyPackagesClaimRequestBody,
    ) -> PersistenceResult<coland_storage::PeerKeyPackageClaimRateDecision> {
        crate::mls_keypackage_claim_budget::record_attempt(&self.pool, body).await
    }
    async fn prune_peer_claim_attempts(&self) -> PersistenceResult<usize> {
        crate::mls_keypackage_claim_budget::prune(&self.pool).await
    }
    async fn get_peer_claim(
        &self,
        source_id: &str,
        claim_request_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        load_peer_claim(&mut conn, source_id, claim_request_id).await
    }

    async fn get_peer_claim_by_claim_id(
        &self,
        claim_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at \
             FROM peer_keypackage_claims \
             WHERE outcome->'claims' @> jsonb_build_array(jsonb_build_object('claim_id', $1::text)) \
             LIMIT 2",
        )
        .bind::<Text, _>(claim_id)
        .load::<PeerKeyPackageClaimPgRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        match <[PeerKeyPackageClaimPgRow; 1]>::try_from(rows) {
            Ok([row]) => Ok(Some(PeerKeyPackageClaimLedgerRecord::from(row))),
            Err(rows) if rows.is_empty() => Ok(None),
            Err(_) => Err(PersistenceError::Conflict(
                "one KeypackageClaimId names more than one claim ledger row".to_owned(),
            )),
        }
    }

    async fn get_claim_welcome_binding(
        &self,
        claim_id: &str,
    ) -> PersistenceResult<Option<coland_storage::MlsWelcomeClaimBinding>> {
        #[derive(QueryableByName)]
        struct BindingRow {
            #[diesel(sql_type = Text)]
            claim_id: String,
            #[diesel(sql_type = Text)]
            source_id: String,
            #[diesel(sql_type = Text)]
            claim_request_id: String,
            #[diesel(sql_type = Text)]
            welcome_id: String,
            #[diesel(sql_type = Text)]
            welcome_digest: String,
            #[diesel(sql_type = Text)]
            commit_event_ref: String,
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        Ok(sql_query(
            "SELECT claim_id,source_id,claim_request_id,welcome_id,welcome_digest,commit_event_ref \
             FROM keypackage_claim_welcome_bindings WHERE claim_id=$1",
        )
        .bind::<Text, _>(claim_id)
        .get_result::<BindingRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| coland_storage::MlsWelcomeClaimBinding {
            claim_id: row.claim_id,
            source_id: row.source_id,
            claim_request_id: row.claim_request_id,
            welcome_id: row.welcome_id,
            welcome_digest: row.welcome_digest,
            commit_event_ref: row.commit_event_ref,
        }))
    }

    async fn get_peer_claim_by_keypackage_id(
        &self,
        keypackage_id: &str,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at \
             FROM peer_keypackage_claims WHERE key_package_use = 'single_use' AND keypackage_id = $1",
        )
        .bind::<Text, _>(keypackage_id)
        .get_result::<PeerKeyPackageClaimPgRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn try_claim_peer(
        &self,
        attempt: PeerKeyPackageClaimAttempt<'_>,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let source_id = attempt.ledger.source_id.clone();
        let claim_request_id = attempt.ledger.claim_request_id.clone();
        let result = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                if let Some(existing) = load_peer_claim(
                    conn,
                    &attempt.ledger.source_id,
                    &attempt.ledger.claim_request_id,
                )
                .await?
                {
                    return Ok(PeerKeyPackageClaimAttemptResult::Existing(Box::new(existing)));
                }
                crate::boxed_future(|| crate::mls_keypackage_claim_admission::require_admission(conn, &attempt)).await?;
                let Some(candidate)=claim_candidate(conn,attempt.keypackage_id,attempt.mls_group_id,Some(attempt.claim_expires_at_unix_ms),attempt.applet_device_scope_guard.as_ref()).await? else {
                    return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                };
                if attempt.applet_device_scope_guard.is_some() && attempt.device_authorize_event_id != candidate.device_authorize_event_id.as_deref() {
                    return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                }
                if attempt.device_authorize_event_id.is_some() && attempt.applet_device_scope_guard.is_none() {
                    let selector = attempt.device_revocation_gate.as_ref().ok_or_else(|| {
                        PersistenceError::SchemaViolation(
                            "peer device KeyPackage claim is missing revocation selector"
                                .to_owned(),
                        )
                    })?;
                    match crate::gate_status_in_transaction(conn, selector).await? {
                        coland_storage::DeviceRevocationGateStatus::Active => {}
                        coland_storage::DeviceRevocationGateStatus::Revoked { .. }
                        | coland_storage::DeviceRevocationGateStatus::AuthorityMismatch
                        | coland_storage::DeviceRevocationGateStatus::GenerationMismatch => {
                            return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                        }
                    }
                }
                if attempt.ledger.key_package_use == "last_resort" {
                    if attempt.ledger.state != "last_resort_claimed"
                        || attempt.ledger.claim_expires_at_unix_ms
                            != Some(attempt.claim_expires_at_unix_ms)
                    {
                        return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                    }
                    let realm=attempt.admission.as_ref().map(|a|a.request.intended_realm_id.as_str()).or(candidate.last_resort_realm_id.as_deref()).ok_or_else(||PersistenceError::SchemaViolation("last-resort claim omits intended Realm".into()))?;
                    let claimed = sql_query(
                        "UPDATE mls_key_packages SET last_resort_realm_id=COALESCE(last_resort_realm_id,$6) \
                         WHERE id = $1 AND last_resort AND claimed_by_mls_group_id IS NULL AND (last_resort_realm_id IS NULL OR last_resort_realm_id=$6) \
                           AND ($2 IS NULL OR device_authorize_event_id = $2) \
                           AND ($3 IS NULL OR agent_key_authorize_event_id = $3) \
                           AND lifetime_not_after * 1000 > $4 \
                           AND $5 > $4 AND $5 <= lifetime_not_after * 1000 \
                         RETURNING id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
                         key_package_bytes, capabilities, capabilities_digest, \
                         last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
                         claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
                         claim_expires_at_unix_ms, consumed_at, created_at",
                    )
                    .bind::<Text, _>(attempt.keypackage_id)
                    .bind::<Nullable<Binary>, _>(parse_authorize_event_id(
                        attempt.device_authorize_event_id,
                    )?)
                    .bind::<Nullable<Binary>, _>(parse_authorize_event_id(
                        attempt.agent_key_authorize_event_id,
                    )?)
                    .bind::<BigInt, _>(attempt.claimed_at_unix_ms)
                    .bind::<BigInt, _>(attempt.claim_expires_at_unix_ms)
                    .bind::<Text, _>(realm)
                    .get_result::<MlsKeyPackagePgRow>(conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::database)?;
                    let Some(claimed) = claimed else {
                        return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                    };
                    let claimed=validated_keypackage_row(claimed)?;
                    if !candidate.same_publication(&claimed) {return Err(PersistenceError::Conflict("duplicate_conflict: KeyPackage original changed during claim".into()).into());}
                    crate::mls_keypackage_claim_admission::require_outcome(&attempt,&claimed)?;
                    crate::boxed_future(||crate::mls_keypackage_claim_admission::require_admission(conn,&attempt)).await?;
                    if let Some(guard)=&attempt.applet_device_scope_guard {
                        let deadline=chrono::DateTime::from_timestamp_millis(attempt.claim_expires_at_unix_ms).ok_or_else(||PersistenceError::SchemaViolation("invalid claim expiry".into()))?;
                        crate::boxed_future(||crate::mls_keypackage_claim_admission::require_target(conn,&claimed,guard,deadline)).await?;
                    }
                    insert_peer_claim_strict(conn, attempt.ledger).await?;
                    crate::realm_claim_history::retain(conn,&attempt).await?;
                    crate::boxed_future(||crate::mls_keypackage_claim_admission::require_admission(conn,&attempt)).await?;
                    return Ok(PeerKeyPackageClaimAttemptResult::Claimed(Box::new(claimed)));
                }
                if attempt.ledger.key_package_use != "single_use"
                    || attempt.ledger.claim_expires_at_unix_ms
                        != Some(attempt.claim_expires_at_unix_ms)
                {
                    return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                }
                let claimed = sql_query(
                    "UPDATE mls_key_packages \
                 SET claimed_by_mls_group_id = $2, claimed_at = $5 / 1000, claim_expires_at_unix_ms = $6, consumed_at = NULL \
                 WHERE id = $1 \
                   AND NOT last_resort \
                   AND claimed_by_mls_group_id IS NULL \
                   AND ($3 IS NULL OR device_authorize_event_id = $3) \
                   AND ($4 IS NULL OR agent_key_authorize_event_id = $4) \
                   AND lifetime_not_after * 1000 > $5 \
                   AND $6 > $5 AND $6 <= lifetime_not_after * 1000 \
             RETURNING id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
             key_package_bytes, capabilities, capabilities_digest, \
                 last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
                 claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
                 claim_expires_at_unix_ms, consumed_at, created_at",
                )
                .bind::<Text, _>(attempt.keypackage_id)
                .bind::<Text, _>(attempt.mls_group_id)
                .bind::<Nullable<Binary>, _>(parse_authorize_event_id(
                    attempt.device_authorize_event_id,
                )?)
                .bind::<Nullable<Binary>, _>(parse_authorize_event_id(
                    attempt.agent_key_authorize_event_id,
                )?)
                .bind::<BigInt, _>(attempt.claimed_at_unix_ms)
                .bind::<BigInt, _>(attempt.claim_expires_at_unix_ms)
                .get_result::<MlsKeyPackagePgRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                let Some(claimed) = claimed else {
                    return Ok(PeerKeyPackageClaimAttemptResult::KeyPackageUnavailable);
                };
                let claimed=validated_keypackage_row(claimed)?;
                if !candidate.same_publication(&claimed) {return Err(PersistenceError::Conflict("duplicate_conflict: KeyPackage original changed during claim".into()).into());}
                crate::mls_keypackage_claim_admission::require_outcome(&attempt,&claimed)?;
                crate::boxed_future(||crate::mls_keypackage_claim_admission::require_admission(conn,&attempt)).await?;
                if let Some(guard)=&attempt.applet_device_scope_guard {
                    let deadline=chrono::DateTime::from_timestamp_millis(attempt.claim_expires_at_unix_ms).ok_or_else(||PersistenceError::SchemaViolation("invalid claim expiry".into()))?;
                        crate::boxed_future(||crate::mls_keypackage_claim_admission::require_target(conn,&claimed,guard,deadline)).await?;
                }
                insert_peer_claim_strict(conn, attempt.ledger).await?;
                    crate::realm_claim_history::retain(conn,&attempt).await?;
                    crate::boxed_future(||crate::mls_keypackage_claim_admission::require_admission(conn,&attempt)).await?;
                Ok(PeerKeyPackageClaimAttemptResult::Claimed(Box::new(claimed)))
            })
            .await;
        match result {
            Ok(result) => Ok(result),
            Err(error) => {
                if let Some(existing) = self.get_peer_claim(&source_id, &claim_request_id).await? {
                    Ok(PeerKeyPackageClaimAttemptResult::Existing(Box::new(
                        existing,
                    )))
                } else {
                    Err(error.into_persistence())
                }
            }
        }
    }

    async fn record_peer_claim_terminal(
        &self,
        record: &PeerKeyPackageClaimLedgerRecord,
    ) -> PersistenceResult<PeerKeyPackageClaimLedgerWriteResult> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            crate::realm_claim_history::lock_mutation(
                conn,
                &record.source_id,
                &record.claim_request_id,
            )
            .await?;
            let inserted = insert_peer_claim(&mut *conn, record)
                .await
                .map_err(PersistenceError::database)?;
            if inserted > 0 {
                return Ok(PeerKeyPackageClaimLedgerWriteResult::Inserted);
            }
            let existing = load_peer_claim(&mut *conn, &record.source_id, &record.claim_request_id)
                .await?
                .ok_or_else(|| {
                    PersistenceError::Internal(
                        "peer KeyPackage claim ledger conflict row disappeared".to_owned(),
                    )
                })?;
            Ok(PeerKeyPackageClaimLedgerWriteResult::Existing(Box::new(
                existing,
            )))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn attach_peer_claim_terminal_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        terminal_receipt: &Value,
        updated_at: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
        crate::realm_claim_history::lock_mutation(conn,source_id,claim_request_id).await?;
        let result=sql_query(
            "UPDATE peer_keypackage_claims \
             SET terminal_receipt = COALESCE(terminal_receipt, $4), \
                 updated_at = CASE WHEN terminal_receipt IS NULL THEN $5 ELSE updated_at END \
             WHERE source_id = $1 AND claim_request_id = $2 \
               AND request_digest = $3 AND state IN ('expired', 'revoked') \
             RETURNING source_id, claim_request_id, request_digest, key_package_use, keypackage_id, \
               outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, \
               expires_at, state, updated_at",
        )
        .bind::<Text, _>(source_id)
        .bind::<Text, _>(claim_request_id)
        .bind::<Text, _>(request_digest)
        .bind::<Jsonb, _>(terminal_receipt)
        .bind::<BigInt, _>(updated_at)
        .get_result::<PeerKeyPackageClaimPgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
        .map_err(PersistenceError::database)?;
        Ok(result)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn attach_peer_claim_consume_receipt(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        consume_receipt: &Value,
        now_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
        crate::realm_claim_history::lock_mutation(conn,source_id,claim_request_id).await?;
        let result=sql_query(
            "WITH expired_last_resort AS ( \
               UPDATE peer_keypackage_claims \
               SET state = 'expired', updated_at = $5 / 1000 \
               WHERE source_id = $1 AND claim_request_id = $2 AND request_digest = $3 \
                 AND state = 'last_resort_claimed' \
                 AND (claim_expires_at_unix_ms IS NULL OR claim_expires_at_unix_ms <= $5) \
               RETURNING claim_request_id \
             ) \
             UPDATE peer_keypackage_claims SET state = 'consumed', consume_receipt = $4, updated_at = $5 / 1000 \
             WHERE source_id = $1 AND claim_request_id = $2 AND request_digest = $3 \
               AND state IN ('claimed', 'last_resort_claimed') \
               AND claim_expires_at_unix_ms > $5 \
             RETURNING source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at",
        )
        .bind::<Text, _>(source_id)
        .bind::<Text, _>(claim_request_id)
        .bind::<Text, _>(request_digest)
        .bind::<Jsonb, _>(consume_receipt)
        .bind::<BigInt, _>(now_unix_ms)
        .get_result::<PeerKeyPackageClaimPgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
        .map_err(PersistenceError::database)?;
        Ok(result)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn transition_peer_claim_consumed(
        &self,
        source_id: &str,
        claim_request_id: &str,
        request_digest: &str,
        expected_outcome: &Value,
        consume_receipt: &Value,
        consumed_at_unix_ms: i64,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
        crate::realm_claim_history::lock_mutation(conn,source_id,claim_request_id).await?;
        let result=sql_query(
            "UPDATE peer_keypackage_claims \
             SET state = 'consumed', consume_receipt = $5, updated_at = $6 / 1000 \
             WHERE source_id = $1 AND claim_request_id = $2 \
               AND request_digest = $3 AND outcome = $4 \
               AND state IN ('claimed', 'last_resort_claimed', 'expired') \
               AND (state <> 'expired' OR terminal_receipt IS NULL) \
               AND claim_expires_at_unix_ms > $6 \
             RETURNING source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at",
        )
        .bind::<Text, _>(source_id)
        .bind::<Text, _>(claim_request_id)
        .bind::<Text, _>(request_digest)
        .bind::<Jsonb, _>(expected_outcome)
        .bind::<Jsonb, _>(consume_receipt)
        .bind::<BigInt, _>(consumed_at_unix_ms)
        .get_result::<PeerKeyPackageClaimPgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
        .map_err(PersistenceError::database)?;
        Ok(result)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn transition_peer_claim_terminal(
        &self,
        transition: PeerClaimTerminalTransition<'_>,
    ) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
        let PeerClaimTerminalTransition {
            source_id,
            claim_request_id,
            request_digest,
            expected_outcome,
            terminal_state,
            terminal_receipt,
            now_unix_ms,
        } = transition;
        if !matches!(terminal_state, "expired" | "revoked") {
            return Ok(None);
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async |conn| {
        crate::realm_claim_history::lock_mutation(conn,source_id,claim_request_id).await?;
        let result=sql_query(
            "UPDATE peer_keypackage_claims \
             SET state = $5, terminal_receipt = $6, updated_at = $7 / 1000 \
             WHERE source_id = $1 AND claim_request_id = $2 \
               AND request_digest = $3 AND outcome = $4 \
               AND (state IN ('claimed', 'last_resort_claimed') \
                    OR (state = $5 AND terminal_receipt IS NULL)) \
             RETURNING source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at",
        )
        .bind::<Text, _>(source_id)
        .bind::<Text, _>(claim_request_id)
        .bind::<Text, _>(request_digest)
        .bind::<Jsonb, _>(expected_outcome)
        .bind::<Text, _>(terminal_state)
        .bind::<Jsonb, _>(terminal_receipt)
        .bind::<BigInt, _>(now_unix_ms)
        .get_result::<PeerKeyPackageClaimPgRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
        .map_err(PersistenceError::database)?;
        Ok(result)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn revoke_expired_peer_claims(&self, now_unix_ms: i64) -> PersistenceResult<Vec<String>> {
        #[derive(QueryableByName)]
        struct RevokedKeyPackageId {
            #[diesel(sql_type = Text)]
            id: String,
        }

        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let candidates=sql_query("SELECT COALESCE(jsonb_agg(DISTINCT s.governing_realm_id) FILTER (WHERE s.governing_realm_id IS NOT NULL),'[]'::jsonb) AS payload FROM peer_keypackage_claims c JOIN keypackage_claim_sources s ON s.source_id=c.source_id AND s.claim_request_id=c.claim_request_id WHERE c.keypackage_id IS NOT NULL AND c.state IN ('claimed','last_resort_claimed') AND c.claim_expires_at_unix_ms<=$1")
                .bind::<BigInt,_>(now_unix_ms).get_result::<crate::JsonPayloadRow>(&mut *conn).await?;
            let realms:Vec<String>=serde_json::from_value(candidates.payload).map_err(PersistenceError::database)?;
            let mutable=crate::realm_management_archive::mutable_realms(conn,&realms).await?;

            sql_query(
                "UPDATE peer_keypackage_claims \
                 SET state = 'expired', updated_at = $1 / 1000 \
                 WHERE keypackage_id IS NOT NULL AND key_package_use = 'last_resort' \
                   AND state = 'last_resort_claimed' \
                   AND claim_expires_at_unix_ms <= $1 AND NOT EXISTS(SELECT 1 FROM keypackage_claim_sources s WHERE s.source_id=peer_keypackage_claims.source_id AND s.claim_request_id=peer_keypackage_claims.claim_request_id AND s.governing_realm_id IS NOT NULL AND NOT(s.governing_realm_id=ANY($2)))",
            )
            .bind::<BigInt, _>(now_unix_ms)
            .bind::<diesel::sql_types::Array<Text>,_>(&mutable)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            let rows = sql_query(
                "WITH expired AS ( \
                   SELECT source_id, claim_request_id, keypackage_id \
                   FROM peer_keypackage_claims \
                   WHERE key_package_use = 'single_use' \
                     AND state = 'claimed' AND claim_expires_at_unix_ms <= $1 AND NOT EXISTS(SELECT 1 FROM keypackage_claim_sources s WHERE s.source_id=peer_keypackage_claims.source_id AND s.claim_request_id=peer_keypackage_claims.claim_request_id AND s.governing_realm_id IS NOT NULL AND NOT(s.governing_realm_id=ANY($2))) \
                 ), revoked AS ( \
                   UPDATE mls_key_packages kp \
                   SET claimed_by_mls_group_id = 'revoked', \
                       claimed_at = NULL, \
                       claim_expires_at_unix_ms = NULL \
                   FROM expired e \
                   WHERE kp.id = e.keypackage_id AND kp.consumed_at IS NULL \
                     AND kp.claimed_by_mls_group_id <> 'revoked' \
                   RETURNING kp.id \
                 ) \
                 UPDATE peer_keypackage_claims ledger \
                 SET state = 'revoked', updated_at = $1 / 1000 \
                 FROM expired e, revoked r \
                 WHERE ledger.source_id = e.source_id \
                   AND ledger.claim_request_id = e.claim_request_id \
                   AND e.keypackage_id = r.id \
                 RETURNING r.id",
            )
            .bind::<BigInt, _>(now_unix_ms)
            .bind::<diesel::sql_types::Array<Text>,_>(&mutable)
            .load::<RevokedKeyPackageId>(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(rows.into_iter().map(|row| row.id).collect())
        })
        .await
        .map_err(|error| error.into_persistence())
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
             "SELECT id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
             key_package_bytes, capabilities, capabilities_digest, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages ORDER BY created_at ASC, id ASC",
        )
        .load::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(validated_keypackage_row)
        .collect()
    }

    async fn list_claimed_by_group(
        &self,
        mls_group_id: &str,
    ) -> PersistenceResult<Vec<MlsKeyPackageRow>> {
        if matches!(mls_group_id, "revoked" | "retired") {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
             "SELECT id, keypackage_ref, keypackage_digest, owner_actor_id, effective_scope, actor_id, device_id, endpoint_verification_method, \
             key_package_bytes, capabilities, capabilities_digest, \
             last_resort, last_resort_realm_id, lifetime_not_before, lifetime_not_after, \
             claimed_by_mls_group_id, device_authorize_event_id, agent_key_authorize_event_id, claimed_at, \
             claim_expires_at_unix_ms, consumed_at, created_at \
             FROM mls_key_packages WHERE claimed_by_mls_group_id = $1 \
             ORDER BY claimed_at ASC NULLS FIRST, id ASC",
        )
        .bind::<Text, _>(mls_group_id)
        .load::<MlsKeyPackagePgRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(validated_keypackage_row)
        .collect()
    }
}

async fn insert_peer_claim(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &PeerKeyPackageClaimLedgerRecord,
) -> Result<usize, diesel::result::Error> {
    sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (source_id, claim_request_id) DO NOTHING",
    )
    .bind::<Text, _>(&record.source_id)
    .bind::<Text, _>(&record.claim_request_id)
    .bind::<Text, _>(&record.request_digest)
    .bind::<Text, _>(&record.key_package_use)
    .bind::<Nullable<Text>, _>(&record.keypackage_id)
    .bind::<Nullable<Jsonb>, _>(&record.outcome)
    .bind::<Nullable<Jsonb>, _>(&record.terminal_receipt)
    .bind::<Nullable<Jsonb>, _>(&record.consume_receipt)
    .bind::<Nullable<BigInt>, _>(record.claim_expires_at_unix_ms)
    .bind::<BigInt, _>(record.expires_at)
    .bind::<Text, _>(&record.state)
    .bind::<BigInt, _>(record.updated_at)
    .execute(conn)
    .await
}

async fn insert_peer_claim_strict(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &PeerKeyPackageClaimLedgerRecord,
) -> Result<(), diesel::result::Error> {
    sql_query(
        "INSERT INTO peer_keypackage_claims \
         (source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind::<Text, _>(&record.source_id)
    .bind::<Text, _>(&record.claim_request_id)
    .bind::<Text, _>(&record.request_digest)
    .bind::<Text, _>(&record.key_package_use)
    .bind::<Nullable<Text>, _>(&record.keypackage_id)
    .bind::<Nullable<Jsonb>, _>(&record.outcome)
    .bind::<Nullable<Jsonb>, _>(&record.terminal_receipt)
    .bind::<Nullable<Jsonb>, _>(&record.consume_receipt)
    .bind::<Nullable<BigInt>, _>(record.claim_expires_at_unix_ms)
    .bind::<BigInt, _>(record.expires_at)
    .bind::<Text, _>(&record.state)
    .bind::<BigInt, _>(record.updated_at)
    .execute(conn)
    .await
    .map(|_| ())
}

async fn load_peer_claim(
    conn: &mut diesel_async::AsyncPgConnection,
    source_id: &str,
    claim_request_id: &str,
) -> PersistenceResult<Option<PeerKeyPackageClaimLedgerRecord>> {
    sql_query(
        "SELECT source_id, claim_request_id, request_digest, key_package_use, keypackage_id, outcome, terminal_receipt, consume_receipt, claim_expires_at_unix_ms, expires_at, state, updated_at \
         FROM peer_keypackage_claims \
         WHERE source_id = $1 AND claim_request_id = $2",
    )
    .bind::<Text, _>(source_id)
    .bind::<Text, _>(claim_request_id)
    .get_result::<PeerKeyPackageClaimPgRow>(conn)
    .await
    .optional()
    .map(|row| row.map(PeerKeyPackageClaimLedgerRecord::from))
    .map_err(PersistenceError::database)
}
#[derive(QueryableByName)]
pub(super) struct MlsKeyPackagePgRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    keypackage_ref: String,
    #[diesel(sql_type = Text)]
    keypackage_digest: String,
    #[diesel(sql_type = Jsonb)]
    owner_actor_id: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    effective_scope: Option<Value>,
    #[diesel(sql_type = Text)]
    actor_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    endpoint_verification_method: Option<String>,
    #[diesel(sql_type = Binary)]
    key_package_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    capabilities: Value,
    #[diesel(sql_type = Text)]
    capabilities_digest: String,
    #[diesel(sql_type = Bool)]
    last_resort: bool,
    #[diesel(sql_type = Nullable<Text>)]
    last_resort_realm_id: Option<String>,
    #[diesel(sql_type = BigInt)]
    lifetime_not_before: i64,
    #[diesel(sql_type = BigInt)]
    lifetime_not_after: i64,
    #[diesel(sql_type = Nullable<Text>)]
    claimed_by_mls_group_id: Option<String>,
    #[diesel(sql_type = Nullable<Binary>)]
    device_authorize_event_id: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Binary>)]
    agent_key_authorize_event_id: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<BigInt>)]
    claimed_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
}

#[derive(QueryableByName)]
pub(super) struct PeerKeyPackageClaimPgRow {
    #[diesel(sql_type = Text)]
    source_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    claim_request_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    key_package_use: String,
    #[diesel(sql_type = Nullable<Text>)]
    keypackage_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    terminal_receipt: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    consume_receipt: Option<Value>,
    #[diesel(sql_type = Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
    #[diesel(sql_type = BigInt)]
    expires_at: i64,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

impl From<PeerKeyPackageClaimPgRow> for PeerKeyPackageClaimLedgerRecord {
    fn from(row: PeerKeyPackageClaimPgRow) -> Self {
        Self {
            source_id: row.source_id.into_string(),
            claim_request_id: row.claim_request_id,
            request_digest: row.request_digest,
            key_package_use: row.key_package_use,
            keypackage_id: row.keypackage_id,
            outcome: row.outcome,
            terminal_receipt: row.terminal_receipt,
            consume_receipt: row.consume_receipt,
            claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
            expires_at: row.expires_at,
            state: row.state,
            updated_at: row.updated_at,
        }
    }
}
pub(super) fn validated_keypackage_row(
    row: MlsKeyPackagePgRow,
) -> PersistenceResult<MlsKeyPackageRow> {
    let row = MlsKeyPackageRow {
        id: row.id,
        keypackage_ref: row.keypackage_ref,
        keypackage_digest: row.keypackage_digest,
        owner_actor_id: serde_json::from_value(row.owner_actor_id)
            .map_err(PersistenceError::database)?,
        effective_scope: row
            .effective_scope
            .map(serde_json::from_value)
            .transpose()
            .map_err(PersistenceError::database)?,
        actor_id: row.actor_id.to_string(),
        device_id: row.device_id,
        endpoint_verification_method: row.endpoint_verification_method,
        key_package_bytes: row.key_package_bytes,
        capabilities: json_string_array(row.capabilities),
        capabilities_digest: row.capabilities_digest,
        last_resort: row.last_resort,
        last_resort_realm_id: row.last_resort_realm_id,
        lifetime_not_before: row.lifetime_not_before,
        lifetime_not_after: row.lifetime_not_after,
        claimed_by_mls_group_id: row.claimed_by_mls_group_id,
        device_authorize_event_id: row
            .device_authorize_event_id
            .as_deref()
            .map(format_authorize_event_id),
        agent_key_authorize_event_id: row
            .agent_key_authorize_event_id
            .as_deref()
            .map(format_authorize_event_id),
        claimed_at: row.claimed_at,
        claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
        consumed_at: row.consumed_at,
        created_at: row.created_at,
    };
    row.lifecycle().map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "stored MLS KeyPackage lifecycle is invalid: {error}"
        ))
    })?;
    Ok(row)
}
