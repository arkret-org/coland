//! Closed holder-private commands, serialized with the accepting PCR authority.

use arkret_models_collaboration::consent_private::*;
use arkret_wire::{AccountId, ActorId, DidCoreId, NewSourceQuotaConstraints};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::PgTransactionError;

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "temporarily_unavailable: private PCR command {detail}"
    ))
}
fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}
#[derive(diesel::QueryableByName)]
struct Fence {
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type=Jsonb)]
    outcome: Value,
}
#[derive(diesel::QueryableByName)]
struct Cell {
    #[diesel(sql_type=BigInt)]
    revision: i64,
    #[diesel(sql_type=Jsonb)]
    content: Value,
}
async fn account_cell(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    key: &str,
) -> PersistenceResult<Option<Cell>> {
    sql_query("SELECT revision,payload AS content FROM account_datas WHERE actor_id=$1 AND account_data_key=$2 AND NOT tombstone AND account_data_source_current(actor_id,account_data_key)")
        .bind::<Text,_>(ActorId::account(holder.clone()).to_string()).bind::<Text,_>(key)
        .get_result::<Cell>(conn).await.optional().map_err(PersistenceError::database)
}
async fn policy_cell(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
) -> PersistenceResult<Option<Cell>> {
    sql_query("SELECT p.revision,p.policy_payload AS content FROM invite_receive_policies p JOIN accounts a ON a.pk=p.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
        .get_result::<Cell>(conn).await.optional().map_err(PersistenceError::database)
}
pub(crate) async fn policy_in_connection(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
) -> PersistenceResult<
    arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
> {
    let policy=policy_cell(conn,holder).await?.map(|cell|serde_json::from_value::<arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy>(cell.content).map_err(invalid)).transpose()?.unwrap_or_else(||arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::spec_default(holder.clone()));
    if policy.account_id!=*holder || policy.schema!=arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::SCHEMA {return Err(invalid("private receive policy schema or owner is invalid"));}
    Ok(policy)
}
fn revision(value: i64) -> PersistenceResult<u64> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| unavailable("has an invalid private revision"))
}
pub(crate) async fn effects(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
) -> PersistenceResult<ConsentPrivateEffects> {
    let holder_quarantine = account_cell(
        conn,
        holder,
        arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
    )
    .await?
    .map(|cell| -> PersistenceResult<_> {
        Ok(ConsentPrivateHolderQuarantineCell {
            revision: revision(cell.revision)?,
            content: serde_json::from_value(cell.content).map_err(invalid)?,
        })
    })
    .transpose()?;
    let invite_delivery = account_cell(
        conn,
        holder,
        arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
    )
    .await?
    .map(|cell| -> PersistenceResult<_> {
        Ok(ConsentPrivateInviteDeliveryCell {
            revision: revision(cell.revision)?,
            content: serde_json::from_value(cell.content).map_err(invalid)?,
        })
    })
    .transpose()?;
    let invite_receive_policy = policy_cell(conn, holder)
        .await?
        .map(|cell| -> PersistenceResult<_> {
            Ok(ConsentPrivateInviteReceivePolicyCell {
                revision: revision(cell.revision)?,
                content: serde_json::from_value(cell.content).map_err(invalid)?,
            })
        })
        .transpose()?;
    Ok(ConsentPrivateEffects {
        holder_quarantine,
        invite_delivery,
        invite_receive_policy,
    })
}

pub(crate) async fn execute(
    conn: &mut AsyncPgConnection,
    request: &ConsentPrivateProxyRequest,
    source: &DidCoreId,
    acceptor: &DidCoreId,
    quota: &NewSourceQuotaConstraints,
    prepared: Option<&coland_storage::PreparedPrivateInviteDelivery>,
) -> Result<ConsentPrivateProxyOutcome, PgTransactionError> {
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    request.validate_at(source, now).map_err(invalid)?;
    let cut =
        crate::pcr_private_authority::lock_holder(conn, &request.holder_account_id, Some(acceptor))
            .await?;
    crate::pcr_private_authority::require_transferable(conn, &cut.realm_id).await?;
    if cut.realm_id != request.realm_id || cut.generation != request.governance_generation {
        return Err(unavailable("request names an obsolete authority cut").into());
    }
    if let ConsentPrivateContext::HolderSession(context) = &request.context {
        let status =
            crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                conn,
                &request.holder_account_id,
                &context.device_id,
                now,
            )
            .await?;
        if !status.is_some_and(|s| {
            s.lifecycle == crate::pcr_device_status_fold::PcrDeviceLifecycle::Active
        }) {
            return Err(unavailable("holder Device is no longer active").into());
        }
    }
    let digest = request.digest().map_err(invalid)?;
    let holder = serde_json::to_value(&request.holder_account_id).map_err(invalid)?;
    let generation = i64::try_from(cut.generation).map_err(invalid)?;
    if request.command.writes_private_state() {
        let held=sql_query("SELECT request_digest,expires_at,outcome FROM consent_private_proxy_fences WHERE holder_account_id=$1 AND governance_generation=$2 AND nonce=$3")
            .bind::<Jsonb,_>(&holder).bind::<BigInt,_>(generation).bind::<Text,_>(&request.nonce)
            .get_result::<Fence>(&mut *conn).await.optional()?;
        if let Some(held) = held {
            if held.request_digest != digest || held.expires_at != request.expires_at {
                return Err(invalid("private command nonce was rebound").into());
            }
            let outcome: ConsentPrivateProxyOutcome =
                serde_json::from_value(held.outcome).map_err(invalid)?;
            outcome
                .validate_for_request(request, now)
                .map_err(invalid)?;
            return Ok(outcome);
        }
    }
    let prepared = prepared.filter(|material| material.matches(request));
    let outcome = apply_command(
        conn,
        &request.holder_account_id,
        &cut.realm_id,
        &request.command,
        acceptor,
        quota,
        prepared,
        now,
    )
    .await?;
    let outcome = ConsentPrivateProxyOutcome {
        request_digest: digest.clone(),
        realm_id: cut.realm_id,
        governance_generation: cut.generation,
        effective_stream_head: cut.head,
        evaluated_at: now,
        expires_at: request.expires_at,
        outcome,
    };
    if request.command.writes_private_state() {
        sql_query("INSERT INTO consent_private_proxy_fences(holder_account_id,realm_id,governance_generation,nonce,expires_at,request_digest,outcome) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind::<Jsonb,_>(&holder).bind::<Text,_>(outcome.realm_id.as_str()).bind::<BigInt,_>(generation)
            .bind::<Text,_>(&request.nonce).bind::<Timestamptz,_>(request.expires_at).bind::<Text,_>(&digest)
            .bind::<Jsonb,_>(serde_json::to_value(&outcome).map_err(invalid)?).execute(&mut *conn).await?;
    }
    Ok(outcome)
}

#[allow(
    clippy::too_many_arguments,
    reason = "The command transaction binds the holder, Realm, constraints and prepared delivery."
)]
async fn apply_command(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    realm: &arkret_wire::RealmId,
    command: &ConsentPrivateCommand,
    acceptor: &DidCoreId,
    quota: &NewSourceQuotaConstraints,
    prepared: Option<&coland_storage::PreparedPrivateInviteDelivery>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ConsentPrivateCommandOutcome, PgTransactionError> {
    Ok(match command {
        ConsentPrivateCommand::List(_) => {
            let records =
                crate::consent_current::records_in_connection(conn, holder, realm).await?;
            ConsentPrivateCommandOutcome::List(ConsentPrivateListOutcome {
                kind: ConsentPrivateListOutcomeKind::List,
                body: arkret_models_collaboration::consent_operations::ConsentList {
                    consents: records.into_iter().map(|r| r.view()).collect(),
                },
            })
        }
        ConsentPrivateCommand::Version(command) => {
            #[derive(diesel::QueryableByName)]
            struct Original {
                #[diesel(sql_type=Jsonb)]
                value: Value,
                #[diesel(sql_type=Jsonb)]
                commit_json: Value,
            }
            let row=sql_query("SELECT v.value,c.commit_json FROM consent_result_versions v JOIN realm_commits c ON c.commit_id=v.commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE v.commit_id=$1 AND c.realm_id=$2 AND e.envelope->'actor_id'=$3 AND v.peer_id=$4 AND e.envelope->>'event_id'=$5")
                .bind::<Text,_>(command.body.commit_id.as_str()).bind::<Text,_>(realm.as_str())
                .bind::<Jsonb,_>(serde_json::to_value(ActorId::account(holder.clone())).map_err(invalid)?).bind::<Jsonb,_>(serde_json::to_value(match &command.body.peer { arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {actor_id} => actor_id }).map_err(invalid)?).bind::<Text,_>(command.body.event_id.as_str())
                .get_result::<Original>(&mut *conn).await.optional()?.ok_or_else(||unavailable("exact original Consent version is missing"))?;
            let value: arkret_models_collaboration::consent_operations::ConsentValue =
                serde_json::from_value(row.value).map_err(invalid)?;
            let commit: arkret_wire::RealmCommit =
                serde_json::from_value(row.commit_json).map_err(invalid)?;
            ConsentPrivateCommandOutcome::Version(ConsentPrivateVersionOutcome {
                kind: ConsentPrivateVersionOutcomeKind::Version,
                body: arkret_models_collaboration::consent_operations::ConsentView {
                    peer: command.body.peer.clone(),
                    permission_scopes: value.permissions.iter().map(|p| p.consent_scope).collect(),
                    updated_at: commit.committed_at,
                    revision: arkret_wire::CurrentRevision {
                        commit_id: commit.commit_id,
                        stream_position: commit.stream_position,
                    },
                },
            })
        }
        ConsentPrivateCommand::Effects(_) => {
            ConsentPrivateCommandOutcome::Effects(ConsentPrivateEffectsOutcome {
                kind: ConsentPrivateEffectsOutcomeKind::Effects,
                body: effects(conn, holder).await?,
            })
        }
        ConsentPrivateCommand::InvitePolicy(command) => {
            let policy = &command.body;
            if policy.schema!=arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy::SCHEMA || policy.account_id!=*holder {
                return Err(invalid("private receive policy schema or holder mismatch").into());
            }
            quota
                .effective(policy.new_source_quota.as_ref())
                .map_err(invalid)?;
            let previous = policy_cell(conn, holder).await?.map(|cell| cell.revision);
            let cell=sql_query("INSERT INTO invite_receive_policies(account_pk,policy_payload) SELECT pk,$3 FROM accounts WHERE principal_id=$1 AND station_id=$2 ON CONFLICT(account_pk) DO UPDATE SET revision=invite_receive_policies.revision+CASE WHEN invite_receive_policies.policy_payload IS DISTINCT FROM EXCLUDED.policy_payload THEN 1 ELSE 0 END,policy_payload=EXCLUDED.policy_payload,updated_at=CASE WHEN invite_receive_policies.policy_payload IS DISTINCT FROM EXCLUDED.policy_payload THEN now() ELSE invite_receive_policies.updated_at END RETURNING revision,policy_payload AS content")
                .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
                .bind::<Jsonb,_>(serde_json::to_value(policy).map_err(invalid)?).get_result::<Cell>(&mut *conn).await?;
            if previous != Some(cell.revision) {
                crate::consent_private_effects::mark_pending(conn, holder, realm).await?;
            }
            ConsentPrivateCommandOutcome::InvitePolicy(ConsentPrivateInvitePolicyOutcome {
                kind: ConsentPrivateInvitePolicyOutcomeKind::InvitePolicy,
                body: ConsentPrivateInviteReceivePolicyCell {
                    revision: revision(cell.revision)?,
                    content: serde_json::from_value(cell.content).map_err(invalid)?,
                },
            })
        }
        ConsentPrivateCommand::Request(command) => {
            let requester = command
                .body
                .requester_actor_id
                .as_account_id()
                .ok_or_else(|| invalid("requester must be an Account"))?;
            crate::consent_request_quarantine::admit_in_connection(
                conn,
                &coland_storage::ConsentRequestQuarantineInput {
                    holder: holder.clone(),
                    acceptor_service_id: acceptor.clone(),
                    requester: requester.clone(),
                    consent_scope: command.body.request.consent_scope,
                    received_at: now,
                    quota_constraints: quota.clone(),
                },
            )
            .await?;
            ConsentPrivateCommandOutcome::Request(ConsentPrivateRequestOutcome {
                kind: ConsentPrivateRequestOutcomeKind::Request,
                body:
                    arkret_models_collaboration::consent_operations::ConsentRequestOutcome::accepted(
                    ),
            })
        }
        ConsentPrivateCommand::InviteDelivery(command) => {
            let verified = prepared.ok_or_else(|| {
                unavailable("original Invite receipt has not been independently verified")
            })?;
            let body = crate::consent_private_invites::admit(
                conn,
                holder,
                realm,
                &command.body,
                verified,
                quota,
                now,
            )
            .await?;
            ConsentPrivateCommandOutcome::InviteDelivery(ConsentPrivateInviteDeliveryOutcome {
                kind: ConsentPrivateInviteDeliveryOutcomeKind::InviteDelivery,
                body,
            })
        }
    })
}

pub(crate) async fn execute_native(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    context: &ConsentPrivateContext,
    command: &ConsentPrivateCommand,
    acceptor: &DidCoreId,
    quota: &NewSourceQuotaConstraints,
    prepared: Option<&coland_storage::PreparedPrivateInviteDelivery>,
) -> Result<ConsentPrivateCommandOutcome, PgTransactionError> {
    command
        .validate_context(holder, context, acceptor)
        .map_err(invalid)?;
    let cut = crate::pcr_private_authority::lock_holder(conn, holder, Some(acceptor)).await?;
    if !crate::pcr_private_authority::accepted_governance(conn, &cut.realm_id)
        .await?
        .is_human()
        || holder.station_id != *acceptor
    {
        return Err(invalid("native Human command requires its account Station").into());
    }
    crate::pcr_private_authority::require_active_human_account(conn, holder).await?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    if let ConsentPrivateContext::HolderSession(context) = context {
        let status =
            crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
                conn,
                holder,
                &context.device_id,
                now,
            )
            .await?;
        if !status.is_some_and(|s| {
            s.lifecycle == crate::pcr_device_status_fold::PcrDeviceLifecycle::Active
        }) {
            return Err(unavailable("holder Device is no longer active").into());
        }
    }
    let prepared = prepared.filter(|material| material.matches_native(holder, command));
    apply_command(
        conn,
        holder,
        &cut.realm_id,
        command,
        acceptor,
        quota,
        prepared,
        now,
    )
    .await
}
