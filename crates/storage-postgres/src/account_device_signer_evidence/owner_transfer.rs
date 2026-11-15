//! Finite successor consent, sourced from the one native Human Device verifier.
use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizationScopes,
};
use arkret_models_crypto::realm_owner_transfer::RealmOwnerTransferAcceptance;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_wire::{ActorId, DidKey};
use chrono::{DateTime, Utc};

use super::*;

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "temporarily_unavailable: owner-transfer successor {detail}"
    ))
}
fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "device_unauthorized: owner-transfer successor {detail}"
    ))
}
fn now() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

fn permits(payload: &DeviceAuthorizePayload) -> bool {
    payload.authorization_binding_kind != DeviceAuthorizationBindingKind::RealmManagedDelegation
        && match &payload.scopes {
            None => true,
            Some(DeviceAuthorizationScopes::Ordinary(scopes)) => scopes.iter().any(|scope| {
                scope.as_str() == arkret_wire::CapabilityActionId::REALM_OWNER_TRANSFER
            }),
            Some(DeviceAuthorizationScopes::AppletManaged(_)) => false,
        }
}

#[derive(QueryableByName)]
struct StatusHead {
    #[diesel(sql_type=Jsonb)]
    record: Value,
    #[diesel(sql_type=Jsonb)]
    receipt: Value,
}

#[derive(QueryableByName)]
struct ProductLifecycle {
    #[diesel(sql_type = Text)]
    state: String,
}

/// The PCR is already locked. Take the existing status-writer shared fence,
/// then the native account row lock; neither an HTTP pre-read nor Device active
/// alone proves that this Human may consent to a new root role.
async fn lifecycle(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    pcr: &arkret_wire::RealmId,
) -> PersistenceResult<Option<DateTime<Utc>>> {
    sql_query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
        .bind::<Text, _>(format!("account-status:{}:{account}", account.station_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    crate::pcr_private_authority::require_active_human_account(conn, account).await?;
    let product=sql_query("SELECT l.state FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<ProductLifecycle>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if product.is_some_and(|row| !matches!(row.state.as_str(), "active" | "soft_logged_out")) {
        return Err(denied(
            "known native Account lifecycle does not admit new consent",
        ));
    }
    crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        pcr,
        &ActorId::account(account.clone()),
    )
    .await?
    .require_open_business_mutation()?;
    let row=sql_query("SELECT record,receipt FROM account_status_replica_records WHERE account_authority_id=$1 AND account_id=$2 ORDER BY status_sequence DESC LIMIT 1")
        .bind::<Text,_>(account.station_id.as_str()).bind::<Jsonb,_>(serde_json::json!(account))
        .get_result::<StatusHead>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        // The complete accepted local Human inception establishes the initial
        // lifecycle; an absent optional status publication is not an absence
        // proof for a foreign Account.
        return Ok(None);
    };
    let record: AccountStatusRecord = serde_json::from_value(row.record).map_err(unavailable)?;
    let receipt: AccountStatusReceipt = serde_json::from_value(row.receipt).map_err(unavailable)?;
    receipt.validate_for_record(&record).map_err(unavailable)?;
    if record.account_id != *account
        || record.account_authority_id != account.station_id
        || record.principal_control_realm_id != *pcr
        || receipt.receiver_id != account.station_id
    {
        return Err(unavailable(
            "lifecycle checkpoint differs from its native Account/PCR",
        ));
    }
    if !matches!(
        record.status,
        arkret_models_collaboration::objects::account_status::AccountStatus::Active
            | arkret_models_collaboration::objects::account_status::AccountStatus::SoftLoggedOut
    ) {
        return Err(denied("Account lifecycle does not admit new consent"));
    }
    Ok(record.expires_at)
}

async fn joined(
    conn: &mut AsyncPgConnection,
    component: &RealmOwnerTransferAcceptance,
) -> PersistenceResult<()> {
    let realm = &component
        .intent
        .payload_without_successor_acceptance
        .realm_id;
    for actor in [
        &component.intent.actor_id,
        &component
            .intent
            .payload_without_successor_acceptance
            .patch
            .controller_actor_id,
    ] {
        if !crate::authority_commit::accepted_current_member_joined_in_connection(
            conn, realm, actor,
        )
        .await?
        {
            return Err(unavailable(
                "does not have both exact current joined members",
            ));
        }
    }
    Ok(())
}

async fn source(
    conn: &mut AsyncPgConnection,
    component: &RealmOwnerTransferAcceptance,
    at: DateTime<Utc>,
    lifecycle_deadline: Option<DateTime<Utc>>,
) -> PersistenceResult<(DeviceProjectionAttestationCore, CommittedEventRef)> {
    component
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let account = component.intent.successor_account().map_err(unavailable)?;
    let device = component
        .intent
        .successor_device(&component.acceptance)
        .map_err(unavailable)?;
    let (source, payload) =
        crate::agent_producer_signer_keys::native_current_human_device_source_in_connection(
            conn, account, &device, at,
        )
        .await?;
    if !permits(&payload) {
        return Err(denied(
            "original Device scopes do not permit this finite purpose",
        ));
    }
    if component.acceptance.created_at < payload.not_before
        || payload
            .expires_at
            .flatten()
            .is_some_and(|expiry| component.acceptance.created_at >= expiry)
    {
        return Err(denied(
            "original signature is outside its native authorization window",
        ));
    }
    arkret_signatures::realm_owner_transfer::verify_realm_owner_transfer_acceptance(
        &component.intent,
        &component.acceptance,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(source.key.public_key_base64url.as_str())
                .map_err(unavailable)?,
        },
    )
    .map_err(|e| PersistenceError::Conflict(format!("signature_invalid: {e}")))?;
    let deadline = at
        .checked_add_signed(chrono::Duration::seconds(30))
        .ok_or_else(|| unavailable("deadline overflows"))?;
    let expires_at = deadline
        .min(
            payload
                .expires_at
                .flatten()
                .unwrap_or(DateTime::<Utc>::MAX_UTC),
        )
        .min(lifecycle_deadline.unwrap_or(DateTime::<Utc>::MAX_UTC));
    if expires_at <= at {
        return Err(denied("current source deadline elapsed"));
    }
    joined(conn, component).await?;
    Ok((
        DeviceProjectionAttestationCore {
            account_id: account.clone(),
            device_id: device,
            device_signing_key_did: DidKey::new(payload.device_public_key_did.to_string())
                .map_err(unavailable)?,
            hpke_key: payload.hpke_key,
            device_authorize_event_id: source.key.authorization_ref.event_id.clone(),
            authorized_generation_ref: payload.authorized_generation_ref,
            device_status: DeviceStatus::Active,
            attested_at: at,
            expires_at,
            authorization_window: DeviceAuthorizationWindow {
                not_before: payload.not_before,
                expires_at: payload.expires_at.flatten(),
            },
            owner_transfer_acceptance_intent_digest: Some(
                component.intent.digest().map_err(unavailable)?,
            ),
        },
        source.key.authorization_ref,
    ))
}

pub(super) async fn prepare(
    pool: &PgPool,
    component: &RealmOwnerTransferAcceptance,
) -> PersistenceResult<Option<(DeviceProjectionAttestationCore, CommittedEventRef)>> {
    component
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let account = component.intent.successor_account().map_err(unavailable)?;
    let mut conn = pg_conn(pool).await?;
    let result = conn
        .transaction::<_, PgTransactionError, _>(async |conn| {
            let holder =
                crate::pcr_private_authority::lock_holder(conn, account, Some(&account.station_id))
                    .await?;
            let deadline = lifecycle(conn, account, &holder.realm_id).await?;
            // Both actual lock waits precede the source instant. No network runs
            // inside this transaction and no Event/proof is manufactured.
            let at = now();
            let prepared = source(conn, component, at, deadline).await?;
            if prepared.1.stream_ref
                != (arkret_wire::CommitStreamRef::Realm {
                    realm_id: holder.realm_id,
                })
            {
                return Err(unavailable("native source moved away from its locked PCR").into());
            }
            Ok(Some(prepared))
        })
        .await;
    match result {
        // Directory absence does not disclose which native eligibility gate
        // failed. The origin caller requires a complete row and treats its
        // absence as dependency failure, never as consent.
        Err(PgTransactionError::Storage(PersistenceError::Conflict(_))) => Ok(None),
        other => other.map_err(retention_transaction_error),
    }
}

pub(super) async fn retain(
    pool: &PgPool,
    evidence: &AccountDeviceSignerEvidence,
    authorization: &CommittedEventRef,
    component: &RealmOwnerTransferAcceptance,
) -> PersistenceResult<SignerEvidenceRef> {
    let core = &evidence.device_projection_attestation.attestation;
    arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
        evidence,
        &component.intent,
        &component.acceptance,
        core.attested_at,
    )
    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let reference = evidence.signer_evidence_ref().map_err(unavailable)?;
    let body = serde_json::to_value(evidence).map_err(PersistenceError::database)?;
    let account = &core.account_id;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        let holder=crate::pcr_private_authority::lock_holder(conn,account,Some(&account.station_id)).await?;
        if authorization.stream_ref!=(arkret_wire::CommitStreamRef::Realm {realm_id:holder.realm_id.clone()}) {
            return Err(denied("original source differs from the locked PCR").into());
        }
        let deadline=lifecycle(conn,account,&holder.realm_id).await?;
        let (expected,exact)=source(conn,component,core.attested_at,deadline).await?;
        if &expected!=core || &exact!=authorization {
            return Err(denied("signed projection differs from its exact locked native source").into());
        }
        sql_query("INSERT INTO account_device_signer_evidence(evidence_ref,principal_id,station_id,device_id,authorization_event_id,authorization_commit_id,attested_at,evidence_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(evidence_ref) DO NOTHING")
            .bind::<Text,_>(reference.as_ref()).bind::<Text,_>(account.principal_id.as_str())
            .bind::<Text,_>(account.station_id.as_str()).bind::<Text,_>(core.device_id.as_str())
            .bind::<Text,_>(authorization.event_id.as_str()).bind::<Text,_>(authorization.commit_id.as_str())
            .bind::<Timestamptz,_>(core.attested_at).bind::<Jsonb,_>(&body)
            .execute(&mut *conn).await?;
        let stored=sql_query("SELECT evidence_json,authorization_commit_id FROM account_device_signer_evidence WHERE evidence_ref=$1 FOR SHARE")
            .bind::<Text,_>(reference.as_ref()).get_result::<ArchiveRow>(&mut *conn).await?;
        if stored.evidence_json!=body || stored.authorization_commit_id!=authorization.commit_id.as_str() {
            return Err(denied("immutable archive root conflicts").into());
        }
        // The immutable insert itself may have waited. Re-prove current
        // lineage and the physical deadline after every writer wait; failure
        // rolls the complete archive insert back.
        let final_at=now();
        let (_,final_source)=source(conn,component,final_at,deadline).await?;
        if final_source!=*authorization {
            return Err(denied("native authorization changed at the final writer").into());
        }
        arkret_identity::account_device_signer_evidence::verify_owner_transfer_successor_evidence(
            evidence,&component.intent,&component.acceptance,final_at,
        ).map_err(|e|denied(e.to_string()))?;
        Ok(())
    }).await.map_err(retention_transaction_error)?;
    Ok(reference)
}
