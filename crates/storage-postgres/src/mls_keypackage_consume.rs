//! Original native receipt cleanup under one current Realm control and claim transaction.
use arkret_models_crypto::{
    KeyPackageConsumeReceipt, KeyPackagesConsumeOutcome, RecipientMlsDurableSigner,
};
use coland_storage::{AppletDeviceKeyPackageConsume, MlsKeyPackageConsumption};
use diesel_async::AsyncConnection;

use super::*;
use crate::mls::{MlsKeyPackagePgRow, PeerKeyPackageClaimPgRow, validated_keypackage_row};

fn conflict(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("conflict: {detail}"))
}
fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
fn same(a: &impl serde::Serialize, b: &impl serde::Serialize) -> PersistenceResult<bool> {
    Ok(
        arkret_canonical::canonical_json_bytes(a).map_err(PersistenceError::database)?
            == arkret_canonical::canonical_json_bytes(b).map_err(PersistenceError::database)?,
    )
}
#[derive(QueryableByName)]
struct Clock {
    #[diesel(sql_type=diesel::sql_types::Timestamptz)]
    at: chrono::DateTime<Utc>,
}
async fn clock(conn: &mut AsyncPgConnection) -> PersistenceResult<chrono::DateTime<Utc>> {
    let at = sql_query("SELECT clock_timestamp() AS at")
        .get_result::<Clock>(conn)
        .await
        .map_err(PersistenceError::database)?
        .at;
    Ok(arkret_canonical::normalize_timestamp_canonical(at))
}
#[derive(QueryableByName)]
struct Binding {
    #[diesel(sql_type=Text)]
    source_id: String,
    #[diesel(sql_type=Text)]
    claim_request_id: String,
    #[diesel(sql_type=Text)]
    welcome_id: String,
    #[diesel(sql_type=Text)]
    welcome_digest: String,
    #[diesel(sql_type=Text)]
    commit_event_ref: String,
}

pub(crate) async fn consume(
    pool: &PgPool,
    input: AppletDeviceKeyPackageConsume<'_>,
) -> PersistenceResult<MlsKeyPackageConsumption> {
    let AppletDeviceKeyPackageConsume {
        body,
        authority,
        effective_scope: scope,
        transport_expires_at,
        issue_receipt,
    } = input;
    body.validate_shape()
        .map_err(|error| PersistenceError::SchemaViolation(error.into()))?;
    let receipt = &body.recipient_durable_receipt;
    let RecipientMlsDurableSigner::RealmDevice {
        recipient_actor_id,
        recipient_device_id,
        device_verification_method,
    } = &receipt.recipient
    else {
        return Err(denied("native consume has no Device signer"));
    };
    if recipient_actor_id != &authority.actor_id
        || recipient_device_id != &authority.device_id
        || !matches!(
            scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        )
        || !authority.scopes.contains_scope(scope)
        || &receipt.realm_id != scope.realm_id()
        || receipt.mls_group_id
            != scope
                .canonical_mls_group_id()
                .map_err(PersistenceError::database)?
    {
        return Err(denied(
            "native consume differs from its original Realm Device and scope",
        ));
    }
    let method = device_verification_method.as_str();
    let key_did = format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key)
    );
    let controller = method.split(['#', '?']).next().unwrap_or("");
    let account_method = arkret_wire::Did::new(controller.to_owned())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        .is_ok_and(|core| &core == authority.actor_id.signing_principal_id());
    if !(method == key_did
        || method
            .strip_prefix(&key_did)
            .is_some_and(|rest| rest.starts_with('#') || rest.starts_with('?'))
        || account_method)
    {
        return Err(denied(
            "native consume method is not an original Device key alias",
        ));
    }
    for (signature, bytes) in [
        (
            &body.signature,
            arkret_models_crypto::keypackages_consume_signing_input(&body.unsigned())
                .map_err(PersistenceError::database)?,
        ),
        (
            &receipt.signature,
            receipt
                .canonical_signing_bytes()
                .map_err(PersistenceError::database)?,
        ),
    ] {
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &authority.public_key,
            method,
            &bytes,
            signature,
        )
        .map_err(|_| denied("native consume original Device signature is invalid"))?;
    }
    let digest = arkret_models_crypto::keypackages_consume_request_digest(body)
        .map_err(PersistenceError::database)?;
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        // The same order as own revoke: PCR, package, then exact claim ledger.
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn,&authority.realm_id).await?;
        let mut package=sql_query("SELECT id,keypackage_ref,keypackage_digest,owner_actor_id,effective_scope,actor_id,device_id,endpoint_verification_method,key_package_bytes,capabilities,capabilities_digest,last_resort,last_resort_realm_id,lifetime_not_before,lifetime_not_after,claimed_by_mls_group_id,device_authorize_event_id,agent_key_authorize_event_id,claimed_at,claim_expires_at_unix_ms,consumed_at,created_at FROM mls_key_packages WHERE keypackage_ref=$1 FOR UPDATE")
            .bind::<Text,_>(receipt.key_package_ref.as_str()).get_result::<MlsKeyPackagePgRow>(&mut *conn).await.optional()?.map(validated_keypackage_row).transpose()?
            .ok_or_else(||conflict("consume package is unavailable"))?;
        if package.owner_actor_id!=authority.actor_id
            || package.actor_id!=authority.actor_id.signing_principal_id().as_str()
            || package.device_id.as_deref()!=Some(authority.device_id.as_str())
            || package.device_authorize_event_id.as_deref()!=Some(authority.authorization_ref.event_id.as_str())
            || package.agent_key_authorize_event_id.is_some() || package.endpoint_verification_method.is_some()
            || package.effective_scope.as_ref()!=Some(scope) {
            return Err(conflict("consume package has another original endpoint or scope").into());
        }
        let ledger=sql_query("SELECT l.source_id,l.claim_request_id,l.request_digest,l.key_package_use,l.keypackage_id,l.outcome,l.terminal_receipt,l.consume_receipt,l.claim_expires_at_unix_ms,l.expires_at,l.state,l.updated_at FROM peer_keypackage_claims l JOIN keypackage_claim_welcome_bindings b ON b.source_id=l.source_id AND b.claim_request_id=l.claim_request_id WHERE b.claim_id=$1 FOR UPDATE OF l")
            .bind::<Text,_>(body.claim_id.as_str()).get_result::<PeerKeyPackageClaimPgRow>(&mut *conn).await.optional()?
            .map(PeerKeyPackageClaimLedgerRecord::from).ok_or_else(||conflict("consume claim has no accepted Welcome ledger"))?;
        let binding=sql_query("SELECT source_id,claim_request_id,welcome_id,welcome_digest,commit_event_ref FROM keypackage_claim_welcome_bindings WHERE claim_id=$1 AND source_id=$2 AND claim_request_id=$3 FOR SHARE")
            .bind::<Text,_>(body.claim_id.as_str()).bind::<Text,_>(&ledger.source_id).bind::<Text,_>(&ledger.claim_request_id)
            .get_result::<Binding>(&mut *conn).await.optional()?.ok_or_else(||conflict("the accepted Welcome binding changed"))?;
        let at=clock(conn).await?;
        let current=crate::boxed_future(||crate::realm_actor_device_authority::current_in_connection(conn,&authority.actor_id,&authority.device_id,at)).await?
            .ok_or_else(||denied("consume Device is unavailable"))?;
        if &current!=authority || at>=transport_expires_at || at>=authority.expires_at {
            return Err(denied("consume Device instance or credential window changed").into());
        }
        let outcome:arkret_models_crypto::PeerKeyPackagesClaimOutcome=serde_json::from_value(ledger.outcome.clone().ok_or_else(||conflict("consume has no original claim outcome"))?).map_err(PersistenceError::database)?;
        outcome.validate_shape().map_err(|_|conflict("original claim outcome is invalid"))?;
        let original_authority=outcome.claim_receipt.claim_authority_ref.as_ref()
            .ok_or_else(||conflict("Realm claim has no original authority reference"))?;
        crate::realm_management_history::require_issuer(conn,&authority.realm_id,
            &outcome.claim_receipt.destination_id,Some(original_authority),outcome.claim_receipt.claimed_at).await?;

        let claim=outcome.claims.iter().find(|claim|claim.claim_id==body.claim_id.as_str()).ok_or_else(||conflict("claim id is not in its original outcome"))?;
        if ledger.keypackage_id.as_deref()!=Some(package.id.as_str())
            || outcome.claim_request_id.as_str()!=ledger.claim_request_id
            || outcome.claim_receipt.source_id.as_str()!=ledger.source_id
            || outcome.claim_receipt.request_digest.as_str()!=ledger.request_digest
            || outcome.claim_receipt.destination_id!=receipt.recipient_id
            || receipt.claim_request_id!=outcome.claim_request_id
            || claim.actor_id!=authority.actor_id
            || claim.device_id.as_ref()!=Some(&authority.device_id)
            || claim.device_authorize_event_id.as_ref()!=Some(&authority.authorization_ref.event_id)
            || claim.agent_id.is_some() || claim.agent_verification_method.is_some() || claim.agent_key_authorize_event_id.is_some()
            || claim.keypackage_ref!=package.keypackage_ref
            || claim.keypackage!=arkret_canonical::base64url_encode(&package.key_package_bytes)
            || claim.capabilities!=package.capabilities || claim.last_resort.unwrap_or(false)!=package.last_resort
            || arkret_canonical::sha256_digest(&package.key_package_bytes)!=package.keypackage_ref
            || package.keypackage_digest!=package.keypackage_ref
            || receipt.realm_id!=outcome.claim_receipt.request.intended_realm_id
            || receipt.mls_group_id!=outcome.claim_receipt.request.mls_group_id
            || receipt.welcome_ref.as_str()!=binding.welcome_id || receipt.welcome_digest.as_str()!=binding.welcome_digest
            || ledger.claim_expires_at_unix_ms!=Some(outcome.claim_receipt.expires_at.timestamp_millis()) {
            return Err(conflict("consume differs from its exact original claim and delivery").into());
        }
        let token=ids::event_token_part_or_schema_violation(&binding.commit_event_ref,"event")?;
        let accepted=sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) AS payload FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
            .bind::<Binary,_>(token.to_vec()).get_result::<JsonPayloadRow>(&mut *conn).await.optional()?
            .ok_or_else(||conflict("Welcome winning Commit is unavailable"))?;
        let accepted:arkret_wire::CommittedEventFullView=serde_json::from_value(accepted.payload).map_err(PersistenceError::database)?;
        if accepted.event.kind!=arkret_wire::EventKind::MlsCommit
            || &accepted.event.scope_ref!=scope || accepted.event.realm_id!=receipt.realm_id
            || accepted.event.event_id.as_str()!=binding.commit_event_ref || accepted.commit.realm_id!=receipt.realm_id {
            return Err(conflict("consume differs from its accepted winning Add scope").into());
        }
        let payload:arkret_models_crypto::MlsCommitPayload=serde_json::from_value(serde_json::to_value(&accepted.event.payload).map_err(PersistenceError::database)?).map_err(PersistenceError::database)?;
        if payload.next_epoch()!=receipt.mls_epoch {
            return Err(conflict("consume epoch is not the accepted winning Add epoch").into());
        }
        let reusable=package.last_resort;
        if ledger.key_package_use!=if reusable {"last_resort"} else {"single_use"} {
            return Err(conflict("consume use class differs from its original package").into());
        }
        if ledger.state=="consumed" {
            let stored:KeyPackageConsumeReceipt=serde_json::from_value(ledger.consume_receipt.ok_or_else(||conflict("consumed claim has no receipt"))?).map_err(PersistenceError::database)?;
            stored.validate_shape().map_err(|_|conflict("stored consume receipt is invalid"))?;
            if stored.request_digest.as_str()!=digest || stored.claim_id!=body.claim_id || !same(&stored.recipient_durable_receipt,receipt)?
                || (!reusable && (package.consumed_at.is_none() || package.claimed_by_mls_group_id.as_deref()!=Some(receipt.mls_group_id.as_str()))) {
                return Err(conflict("consume retry differs from the first accepted signed command").into());
            }
            return Ok(MlsKeyPackageConsumption {outcome:KeyPackagesConsumeOutcome {consume_receipt:stored},record:package});
        }
        if ledger.state!=if reusable {"last_resort_claimed"} else {"claimed"}
            || ledger.claim_expires_at_unix_ms.is_none_or(|end|at.timestamp_millis()>=end)
            || ledger.expires_at<=at.timestamp() || package.lifetime_not_after<=at.timestamp()
            || (!reusable && (package.claimed_by_mls_group_id.as_deref()!=Some(receipt.mls_group_id.as_str()) || package.consumed_at.is_some()
                || package.claim_expires_at_unix_ms!=ledger.claim_expires_at_unix_ms))
            || (reusable && (package.claimed_by_mls_group_id.is_some() || package.consumed_at.is_some() || package.last_resort_realm_id.as_deref()!=Some(scope.realm_id().as_str()))) {
            return Err(conflict("consume has no live original claim").into());
        }
        if !reusable {
            let count=sql_query("UPDATE mls_key_packages SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL AND claimed_by_mls_group_id=$3 AND claim_expires_at_unix_ms>$4 AND NOT last_resort")
                .bind::<Text,_>(&package.id).bind::<BigInt,_>(at.timestamp()).bind::<Text,_>(receipt.mls_group_id.as_str()).bind::<BigInt,_>(at.timestamp_millis()).execute(&mut *conn).await?;
            if count!=1 {return Err(conflict("consume package CAS changed").into());}
            package.consumed_at=Some(at.timestamp());
        }
        // Issuance is not observable unless both transitions commit. Replays
        // above return the first receipt without invoking this issuer again.
        let signed=issue_receipt(body,at)?;
        signed.validate_shape().map_err(|_|conflict("consume issuer returned an invalid receipt"))?;
        if signed.request_digest.as_str()!=digest || signed.claim_id!=body.claim_id || signed.consumed_at!=at || !same(&signed.recipient_durable_receipt,receipt)? {
            return Err(conflict("consume issuer changed the original request").into());
        }
        let value=serde_json::to_value(&signed).map_err(PersistenceError::database)?;
        let count=sql_query("UPDATE peer_keypackage_claims SET state='consumed',consume_receipt=$3,consume_request_digest=$7,updated_at=$4 WHERE source_id=$1 AND claim_request_id=$2 AND state=$5 AND claim_expires_at_unix_ms>$6")
            .bind::<Text,_>(&binding.source_id).bind::<Text,_>(&binding.claim_request_id).bind::<Jsonb,_>(value).bind::<BigInt,_>(at.timestamp())
            .bind::<Text,_>(if reusable {"last_resort_claimed"}else{"claimed"}).bind::<BigInt,_>(at.timestamp_millis()).bind::<Text,_>(&digest).execute(&mut *conn).await?;
        if count!=1 {return Err(conflict("consume ledger CAS changed").into());}
        let final_at=clock(conn).await?;
        if final_at>=authority.expires_at {
            return Err(PersistenceError::Conflict(format!("{}: consume Device expired before finalization",coland_storage::ConflictCode::DeviceUnauthorized)).into());
        }
        if final_at>=transport_expires_at || ledger.claim_expires_at_unix_ms.is_none_or(|end|final_at.timestamp_millis()>=end) {
            return Err(denied("consume authority expired before finalization").into());
        }
        Ok(MlsKeyPackageConsumption {outcome:KeyPackagesConsumeOutcome {consume_receipt:signed},record:package})
    }).await.map_err(PgTransactionError::into_persistence)
}
