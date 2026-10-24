//! Realm-owned outbound recovery, separate from recipient allocation/consume.
use arkret_models_crypto::{
    KeyPackagesClaimRequestBody as Request, PeerKeyPackagesClaimQueryResponseBody as Outcome,
    PeerKeyPackagesClaimQueryState as State, RecipientMlsDurableSigner,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{DidCoreId, RealmId};
use coland_storage::{PersistenceError, PersistenceResult, RealmKeyPackageClaimSource};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: Realm claim source: {detail}"))
}
#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Text)]
    governing_realm_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_body: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    result: Option<Value>,
    #[diesel(sql_type = Jsonb)]
    issuer_histories: Value,
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    source: &str,
    id: &str,
) -> PersistenceResult<Option<RealmKeyPackageClaimSource>> {
    let row = sql_query("SELECT governing_realm_id,request_digest,request_body,result,issuer_histories FROM realm_keypackage_claim_sources WHERE source_id=$1 AND claim_request_id=$2")
        .bind::<Text,_>(source).bind::<Text,_>(id).get_result::<Row>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    let request: Request = serde_json::from_value(row.request_body).map_err(invalid)?;
    request.validate_shape().map_err(invalid)?;
    if request.service_binding.source_id.as_str() != source
        || request.claim_request_id.as_str() != id
        || request
            .requester_actor_id
            .as_ref()
            .and_then(|a| a.as_realm_actor_id())
            .is_none_or(|a| a.realm_id.as_str() != row.governing_realm_id)
        || request.intended_realm_id.as_str() != row.governing_realm_id
        || arkret_canonical::canonical_sha256(&request).map_err(invalid)? != row.request_digest
    {
        return Err(invalid("stored original identity or digest differs"));
    }
    let result: Option<Outcome> = row
        .result
        .map(serde_json::from_value)
        .transpose()
        .map_err(invalid)?;
    let histories: Vec<AuthenticatedServiceResolution> =
        serde_json::from_value(row.issuer_histories).map_err(invalid)?;
    if let Some(result) = &result {
        validate_result(conn, &request, result, &histories).await?;
    }
    Ok(Some(RealmKeyPackageClaimSource {
        request,
        result,
        issuer_histories: histories,
    }))
}

fn signer(signature: &arkret_models_crypto::KeyOperationSignature) -> PersistenceResult<DidCoreId> {
    let did = signature
        .kid
        .as_str()
        .split_once('#')
        .ok_or_else(|| invalid("missing signer method"))?
        .0;
    arkret_wire::Did::new(did)
        .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        .map_err(invalid)
}

async fn require_issuer(
    conn: &mut AsyncPgConnection,
    request: &Request,
    issuer: &DidCoreId,
    reference: Option<&arkret_wire::RealmCommitAuthorityRef>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if request.target_actor_id.is_some() {
        crate::realm_management_history::require_issuer(
            conn,
            &request.intended_realm_id,
            issuer,
            reference,
            at,
        )
        .await
    } else if issuer == &request.service_binding.destination_id {
        Ok(())
    } else {
        Err(invalid("ordinary recipient changed its Station"))
    }
}

/// Full frozen method histories are reverified on replay and export/import.
async fn validate_result(
    conn: &mut AsyncPgConnection,
    request: &Request,
    result: &Outcome,
    histories: &[AuthenticatedServiceResolution],
) -> PersistenceResult<()> {
    result.validate_shape().map_err(invalid)?;
    let digest = arkret_canonical::canonical_sha256(request).map_err(invalid)?;
    if result.claim_request_id != request.claim_request_id
        || matches!(result.state, State::Unknown | State::Pending)
    {
        return Err(invalid("unresolved or unrelated result"));
    }
    if let Some(outcome) = &result.claim_outcome {
        let receipt = &outcome.claim_receipt;
        if receipt.request != request.unsigned_request()
            || receipt.request_digest.as_str() != digest
            || receipt.source_id != request.service_binding.source_id
            || receipt.destination_id != request.service_binding.destination_id
            || !histories.iter().any(|history| {
                history.service_kind == "station"
                    && arkret::verify_peer_keypackage_claim_receipt_signature(receipt, history)
                        .is_ok()
            })
        {
            return Err(invalid("claim binding or historical signature differs"));
        }
        require_issuer(
            conn,
            request,
            &receipt.destination_id,
            receipt.claim_authority_ref.as_ref(),
            receipt.claimed_at,
        )
        .await?;
    }
    if let Some(consume) = &result.consume_receipt {
        let outcome = result
            .claim_outcome
            .as_ref()
            .ok_or_else(|| invalid("consume lost claim"))?;
        let [claim] = outcome.claims.as_slice() else {
            return Err(invalid("consume has no unique claim"));
        };
        let durable = &consume.recipient_durable_receipt;
        let recipient = match &durable.recipient {
            RecipientMlsDurableSigner::Device {
                recipient_account_id,
                recipient_device_id,
                ..
            } => {
                claim.actor_id.as_account_id() == Some(recipient_account_id)
                    && request.target_account_id.as_ref() == Some(recipient_account_id)
                    && claim.device_id.as_ref() == Some(recipient_device_id)
            }
            RecipientMlsDurableSigner::RealmDevice {
                recipient_actor_id,
                recipient_device_id,
                ..
            } => {
                &claim.actor_id == recipient_actor_id
                    && request.target_actor_id.as_ref() == Some(recipient_actor_id)
                    && claim.device_id.as_ref() == Some(recipient_device_id)
            }
            RecipientMlsDurableSigner::Agent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            } => {
                request.target_agent_id.as_ref() == Some(recipient_agent_id)
                    && claim.agent_id.as_ref() == Some(recipient_agent_id)
                    && claim.agent_verification_method.as_ref()
                        == Some(recipient_agent_verification_method)
                    && claim.agent_key_authorize_event_id.as_ref()
                        == Some(agent_key_authorize_event_id)
            }
        };
        let issuer = signer(&consume.signature)?;
        if !recipient
            || consume.claim_id.as_str() != claim.claim_id
            || durable.recipient_id != outcome.claim_receipt.destination_id
            || durable.keypackage_ref.as_str() != claim.keypackage_ref
            || durable.realm_id != request.intended_realm_id
            || durable.mls_group_id != request.mls_group_id
            || durable.durable_at > consume.consumed_at
            || consume.consumed_at < outcome.claim_receipt.claimed_at
            || consume.consumed_at >= request.expires_at
            || consume.consumed_at >= outcome.claim_receipt.expires_at
            || !histories.iter().any(|h| {
                arkret::verify_peer_keypackage_consume_receipt_signature(consume, &issuer, h)
                    .is_ok()
            })
        {
            return Err(invalid("consume binding or historical signature differs"));
        }
        require_issuer(conn, request, &issuer, None, consume.consumed_at).await?;
    }
    if let Some(terminal) = &result.terminal_receipt {
        let issuer = signer(&terminal.signature)?;
        if terminal.request_digest.as_str() != digest
            || terminal.source_id != request.service_binding.source_id
            || terminal.destination_id != issuer
            || !histories.iter().any(|h| {
                arkret::verify_peer_keypackage_terminal_receipt_signature(terminal, &issuer, h)
                    .is_ok()
            })
        {
            return Err(invalid("terminal binding or historical signature differs"));
        }
        require_issuer(conn, request, &issuer, None, terminal.terminal_at).await?;
        if let Some(outcome) = &result.claim_outcome {
            let expected = outcome
                .claims
                .iter()
                .map(|c| c.keypackage_ref.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let actual = terminal
                .keypackage_refs
                .as_ref()
                .ok_or_else(|| invalid("terminal package refs absent"))?
                .iter()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if actual != expected
                || terminal.terminal_at < outcome.claim_receipt.claimed_at
                || (result.state == State::Expired
                    && terminal.terminal_at < outcome.claim_receipt.expires_at)
            {
                return Err(invalid("terminal coordinates differ"));
            }
        }
    }
    Ok(())
}

pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    request: &Request,
    result: &Outcome,
    histories: &[AuthenticatedServiceResolution],
    governor: &DidCoreId,
) -> PersistenceResult<Outcome> {
    request.validate_shape().map_err(invalid)?;
    let realm = &request.intended_realm_id;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    crate::realm_management_archive::require_unfrozen(conn, realm).await?;
    let current = sql_query(
        "SELECT to_jsonb(service_id) AS payload FROM realm_authorities WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if current.payload != json!(governor) {
        return Err(invalid("source governor changed"));
    }
    let original = read(
        conn,
        request.service_binding.source_id.as_str(),
        request.claim_request_id.as_str(),
    )
    .await?
    .ok_or_else(|| invalid("original was not durably registered"))?;
    if json!(original.request) != json!(request) {
        return Err(invalid("original request differs"));
    }
    validate_result(conn, request, result, histories).await?;
    if let Some(prior) = &original.result {
        if json!(prior) == json!(result)
            || (result.state == State::Claimed
                && json!(prior.claim_outcome) == json!(result.claim_outcome))
        {
            return Ok(prior.clone());
        }
        if prior.state != State::Claimed
            || json!(prior.claim_outcome) != json!(result.claim_outcome)
        {
            return Err(invalid("first durable result cannot be replaced"));
        }
        if result.state == State::Claimed {
            return Err(invalid("claim original cannot change"));
        }
    }
    sql_query("UPDATE realm_keypackage_claim_sources SET result=$3,issuer_histories=$4 WHERE source_id=$1 AND claim_request_id=$2")
        .bind::<Text,_>(request.service_binding.source_id.as_str()).bind::<Text,_>(request.claim_request_id.as_str())
        .bind::<Jsonb,_>(json!(result)).bind::<Jsonb,_>(json!(histories)).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(result.clone())
}

pub(crate) async fn validate_archive(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<()> {
    let rows = sql_query("SELECT jsonb_build_object('source',source_id,'id',claim_request_id) AS payload FROM realm_keypackage_claim_sources WHERE governing_realm_id=$1")
        .bind::<Text,_>(realm.as_str()).load::<crate::JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        read(
            conn,
            row.payload["source"]
                .as_str()
                .ok_or_else(|| invalid("source absent"))?,
            row.payload["id"]
                .as_str()
                .ok_or_else(|| invalid("id absent"))?,
        )
        .await?
        .ok_or_else(|| invalid("source disappeared"))?;
    }
    Ok(())
}
