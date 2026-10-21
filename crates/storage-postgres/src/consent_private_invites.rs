//! Native Invite private acceptance under the caller's locked PCR cut.
use arkret_models_collaboration::consent_private::ConsentPrivateInviteDeliveryBody;
use arkret_models_collaboration::governance::invite_addressing::*;
use arkret_wire::{AccountDataKey, ActorId, InviteReceiveAction, NewSourceQuotaConstraints};
use coland_storage::{
    AccountDataCasResult, AccountDataRecord, NewSourceAdmission, PersistenceError,
    PersistenceResult, PreparedPrivateInviteDelivery,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};
fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("private Invite admission: {detail}"))
}
#[derive(diesel::QueryableByName)]
struct Cell {
    #[diesel(sql_type=BigInt)]
    revision: i64,
    #[diesel(sql_type=Jsonb)]
    content: Value,
}
#[derive(diesel::QueryableByName)]
struct Disabled {
    #[diesel(sql_type=Bool)]
    disabled: bool,
}
fn deferred(
    at: chrono::DateTime<chrono::Utc>,
    disclosed_outcome: Option<DisclosedOutcome>,
) -> InviteDeliveryOutcome {
    InviteDeliveryOutcome {
        status: InviteDeliveryOutcomeStatus::Deferred,
        disclosed_outcome,
        received_at: Some(at),
        retry_after_ms: None,
    }
}
async fn cell(
    conn: &mut AsyncPgConnection,
    holder: &arkret_wire::AccountId,
    key: &str,
) -> PersistenceResult<Option<Cell>> {
    sql_query("SELECT revision,payload AS content FROM account_datas WHERE actor_id=$1 AND account_data_key=$2 AND NOT tombstone AND account_data_source_current(actor_id,account_data_key) FOR UPDATE")
        .bind::<Text,_>(ActorId::account(holder.clone()).to_string()).bind::<Text,_>(key).get_result::<Cell>(conn).await.optional().map_err(PersistenceError::database)
}
async fn save(
    conn: &mut AsyncPgConnection,
    holder: &arkret_wire::AccountId,
    key: &str,
    previous: Option<Cell>,
    content: Value,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let expected = previous
        .as_ref()
        .map_or(Ok(0), |row| u64::try_from(row.revision).map_err(invalid))?;
    let record = AccountDataRecord {
        actor: ActorId::account(holder.clone()).to_string(),
        account_data_key: key.to_owned(),
        revision: expected
            .checked_add(1)
            .ok_or_else(|| invalid("private revision exhausted"))?,
        payload: content,
        tombstone: false,
        updated_at: at,
    };
    match crate::accounts::compare_account_data_in_transaction(conn, &record, expected, None)
        .await?
    {
        AccountDataCasResult::Applied(_) => {
            let authority = crate::pcr_private_authority::lock_holder(conn, holder, None).await?;
            crate::consent_private_effects::mark_pending(conn, holder, &authority.realm_id).await
        }
        AccountDataCasResult::Conflict(_) => Err(PersistenceError::Conflict(
            "temporarily_unavailable: private Invite cell raced the accepting cut".into(),
        )),
    }
}
pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    holder: &arkret_wire::AccountId,
    realm: &arkret_wire::RealmId,
    body: &ConsentPrivateInviteDeliveryBody,
    prepared: &PreparedPrivateInviteDelivery,
    quota: &NewSourceQuotaConstraints,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<InviteDeliveryOutcome, crate::PgTransactionError> {
    let delivery = &body.delivery;
    delivery.validate_minimal().map_err(invalid)?;
    if &delivery.invite_address.account_id != holder {
        return Err(invalid("delivery belongs to another holder").into());
    }
    let disabled=sql_query("SELECT (a.disabled_at IS NOT NULL OR COALESCE(l.state IN ('deactivated','erasure_pending'),FALSE)) AS disabled FROM accounts a LEFT JOIN account_lifecycle l ON l.account_pk=a.pk WHERE a.principal_id=$1 AND a.station_id=$2 FOR SHARE OF a")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).get_result::<Disabled>(&mut *conn).await?;
    if disabled.disabled {
        return Ok(deferred(at, None));
    }
    let policy = crate::consent_private_commands::policy_in_connection(conn, holder).await?;
    let inviter = delivery
        .invite_event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("Invite producer is not a human Account"))?;
    let records = crate::consent_current::records_in_connection(conn, holder, realm).await?;
    let consent = match &delivery.introduction_evidence {
        IntroductionEvidence::ConsentGrant { consent_grant_ref } => records
            .iter()
            .find(|record| record.event.event_id == *consent_grant_ref)
            .is_some_and(|record| {
                record.permits(
                    &delivery.invite_event.actor_id,
                    arkret_wire::ConsentScope::Invite,
                    at,
                )
            }),
        _ => false,
    };
    let decision = coland_domain::invite_receive::evaluate_resolved(
        prepared.constraints(),
        prepared.locator_verified(),
        at,
        &policy,
        &delivery.introduction_evidence,
        &delivery.invite_event.actor_id,
        holder.principal_id.as_str(),
        holder.station_id.as_str(),
        body.notification_source_service_id.as_str(),
        inviter.station_id == holder.station_id,
        consent,
    );
    if decision.action == InviteReceiveAction::Drop {
        return Ok(deferred(at, decision.disclosed_outcome));
    }
    let event_value = serde_json::to_value(&delivery.invite_event).map_err(invalid)?;
    let created = delivery.invite_event.created_at;
    let expires = event_value["payload"]
        .get("expires_at")
        .map(|value| {
            serde_json::from_value::<chrono::DateTime<chrono::Utc>>(value.clone()).map_err(invalid)
        })
        .transpose()?
        .unwrap_or(created + chrono::Duration::days(7));
    if expires <= at {
        return Ok(deferred(at, None));
    }
    if decision.action == InviteReceiveAction::Notify {
        let old = cell(conn, holder, AccountDataKey::ACCOUNT_INVITE_DELIVERY).await?;
        let mut value = old
            .as_ref()
            .map(|row| {
                serde_json::from_value::<InviteDelivery>(row.content.clone()).map_err(invalid)
            })
            .transpose()?
            .unwrap_or_else(|| InviteDelivery::new(at, Vec::new()));
        value.validate().map_err(invalid)?;
        let entry = InviteDeliveryEntry {
            invite_id: arkret_wire::InviteId::from_event_id(&delivery.invite_event.event_id),
            realm_id: delivery.invite_event.realm_id.clone(),
            inviter_account_id: inviter.clone(),
            authority_locator_hints: delivery.authority_locator_hints.clone(),
            received_at: at,
            expires_at: expires,
        };
        if value.delivery_entries.iter().any(|existing| {
            existing.invite_id == entry.invite_id
                && existing.realm_id == entry.realm_id
                && existing.inviter_account_id == entry.inviter_account_id
                && existing.authority_locator_hints == entry.authority_locator_hints
                && existing.expires_at == entry.expires_at
                && existing.expires_at > at
        }) {
            return Ok(InviteDeliveryOutcome {
                status: InviteDeliveryOutcomeStatus::Duplicate,
                disclosed_outcome: decision.disclosed_outcome,
                received_at: Some(at),
                retry_after_ms: None,
            });
        }
        value = coland_domain::invite_receive::merge_invite_delivery_cell(Some(value), entry, at)
            .map_err(invalid)?;
        save(
            conn,
            holder,
            AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            old,
            serde_json::to_value(value).map_err(invalid)?,
            at,
        )
        .await?;
        return Ok(InviteDeliveryOutcome {
            status: InviteDeliveryOutcomeStatus::Accepted,
            disclosed_outcome: decision.disclosed_outcome,
            received_at: Some(at),
            retry_after_ms: None,
        });
    }
    let old = cell(conn, holder, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE).await?;
    let mut value = old
        .as_ref()
        .map(|row| serde_json::from_value::<HolderQuarantine>(row.content.clone()).map_err(invalid))
        .transpose()?
        .unwrap_or_else(|| HolderQuarantine::new(at));
    value.validate_holder(holder).map_err(invalid)?;
    let entry_digest=arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&json!({"account_id":holder,"source_id":body.notification_source_service_id,"idempotency_key":delivery.idempotency_key,"invite_event_id":delivery.invite_event.event_id})).map_err(invalid)?).map_err(invalid)?;
    if value
        .quarantine_entries
        .iter()
        .any(|entry| entry.entry_digest == entry_digest && entry.expires_at > at)
    {
        return Ok(deferred(at, decision.disclosed_outcome));
    }
    let quota = quota
        .effective(policy.new_source_quota.as_ref())
        .map_err(invalid)?;
    let digest = crate::invite_new_source_ledger::source_digest_in_connection(
        conn,
        holder,
        &inviter.principal_id,
    )
    .await?;
    if crate::invite_new_source_ledger::admit_in_connection(conn, holder, &digest, at, &quota)
        .await?
        == NewSourceAdmission::Denied
    {
        return Ok(deferred(at, None));
    }
    let entry = HolderQuarantineEntry {
        entry_digest,
        account_id: holder.clone(),
        source_peer_actor_id: delivery.invite_event.actor_id.clone(),
        source_peer_principal_id: inviter.principal_id.clone(),
        source_id: body.notification_source_service_id.clone(),
        surface: HolderQuarantineSurface::InviteDelivery {
            consent_scope: HolderQuarantineInviteScope::Invite,
            introduction_kind: serde_json::from_value(json!(delivery.introduction_evidence.kind()))
                .map_err(invalid)?,
            effective_kind: serde_json::from_value(json!(decision.effective_kind))
                .map_err(invalid)?,
            trust_tier: match decision.trust_tier {
                coland_domain::invite_receive::TrustTier::High => InviteTrustTier::High,
                coland_domain::invite_receive::TrustTier::Discovery => InviteTrustTier::Discovery,
                coland_domain::invite_receive::TrustTier::Low => InviteTrustTier::Low,
            },
            invite_event_id: delivery.invite_event.event_id.clone(),
            request_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(delivery).map_err(invalid)?,
            )
            .map_err(invalid)?,
            idempotency_key_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                delivery.idempotency_key.as_bytes(),
            ))
            .map_err(invalid)?,
        },
        received_at: at,
        expires_at: at + chrono::Duration::days(30),
    };
    value
        .quarantine_entries
        .retain(|old| old.expires_at > at && old.entry_digest != entry.entry_digest);
    value.quarantine_entries.push(entry);
    value.quarantine_entries.sort_by(|a, b| {
        a.received_at
            .cmp(&b.received_at)
            .then_with(|| a.entry_digest.as_str().cmp(b.entry_digest.as_str()))
    });
    if value.quarantine_entries.len() > 200 {
        let excess = value.quarantine_entries.len() - 200;
        value.quarantine_entries.drain(..excess);
    }
    value.updated_at = at;
    value.validate_holder(holder).map_err(invalid)?;
    save(
        conn,
        holder,
        AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
        old,
        serde_json::to_value(value).map_err(invalid)?,
        at,
    )
    .await?;
    Ok(deferred(at, decision.disclosed_outcome))
}
