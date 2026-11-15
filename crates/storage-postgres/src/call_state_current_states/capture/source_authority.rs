//! Read-only revalidation of a recording Start's actual authorization source.
//!
//! A ready artifact is not another capture Start. Its publisher has independent
//! admission; this module proves that the selected original source remains live
//! and that Start already paid its exact approval and quota obligations.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::call::{
    CallRecordingStartPayload, RecordingCaptureKind,
};
use arkret_models_collaboration::governance::grant_constraint::{CapabilityGrant, GrantConstraint};
use arkret_wire::{
    ApprovalContext, ApprovalSignature, CapabilityActionId, Event, EventKind, GrantId, RealmCommit,
};
use chrono::{DateTime, Utc};
use coland_storage::{
    ActorRealmAuthorization, GrantEvaluation, QuotaReservation, VerifiedGrantApproval,
};
use serde_json::Value;

use crate::{
    AsyncPgConnection, BigInt, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, Timestamptz, sql_query,
};

#[cfg(test)]
mod tests;

fn denied(reason: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: capture source {reason}"))
}

#[derive(QueryableByName)]
struct OriginalStart {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct ApprovalAudit {
    #[diesel(sql_type = Text)]
    event_digest: String,
    #[diesel(sql_type = Text)]
    accepted_commit_id: String,
    #[diesel(sql_type = Timestamptz)]
    accepted_at: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    approval_context: String,
    #[diesel(sql_type = Text)]
    approver_did: String,
    #[diesel(sql_type = Text)]
    nonce: String,
    #[diesel(sql_type = Jsonb)]
    evidence: Value,
    #[diesel(sql_type = Jsonb)]
    accepted_basis: Value,
}

#[derive(QueryableByName)]
struct Present {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

/// Called inside the result's already locked accepting transaction. It takes
/// the same Realm authorization lock itself as well, so no caller can turn a
/// stale snapshot into a current source. No counter, nonce or audit is written.
pub(super) async fn require_source(
    conn: &mut AsyncPgConnection,
    start: &Event,
    cited: &GrantId,
    now: DateTime<Utc>,
) -> PersistenceResult<CapabilityGrant> {
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &start.realm_id).await?;
    if start.kind != EventKind::CallRecordingStart
        || start.authorization_ref.as_ref().map(|value| value.as_str()) != Some(cited.as_str())
    {
        return Err(denied("is not the signed selected Start grant"));
    }
    let payload: CallRecordingStartPayload =
        serde_json::from_value(serde_json::json!(start.payload))
            .map_err(PersistenceError::database)?;
    payload.validate().map_err(PersistenceError::database)?;
    let action = match payload.capture_kind {
        RecordingCaptureKind::Recording => CapabilityActionId::CallRecord,
        RecordingCaptureKind::Transcript => CapabilityActionId::CallTranscribe,
    };
    let original = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.envelope->>'event_id'=$2 AND e.state='committed'")
        .bind::<Text,_>(start.realm_id.as_str()).bind::<Text,_>(start.event_id.as_str())
        .get_result::<OriginalStart>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("has no retained accepting Start Commit"))?;
    let original_event: Event =
        serde_json::from_value(original.envelope).map_err(PersistenceError::database)?;
    let commit: RealmCommit =
        serde_json::from_value(original.commit_json).map_err(PersistenceError::database)?;
    validate_original(start, &original_event, &commit, now)?;
    // This shared reader checks the exact Commit fact digest and verifies the
    // original producer signature using the frozen historical key source.
    if crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn, start, &commit,
    )
    .await?
    .is_none()
    {
        return Err(denied("has no frozen historical producer source"));
    }
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, start).await?;
    cut.require_open_lifecycle(start)?;
    cut.require_governed_member(&start.kind)?;
    let (target, mut facts) = cut.event_operation(start);
    cut.complete_event_facts_in_connection(conn, start, &mut facts)
        .await?;
    let current = cut
        .bounded_actor_authorization_in_connection(conn, now)
        .await?;
    let grant = current.current_positive_grant_source(cited, action.as_str(), &target)?;
    let approvals = read_accepted_approvals(conn, start, &commit, action, &current).await?;
    let actions = [action.as_str()];
    let live = current.evaluate_with_approvals_checked(&actions, &target, &facts, &approvals)?;
    let GrantEvaluation::Allowed(live_paths) = live else {
        return Err(denied("fails its current complete capture constraints"));
    };
    // Use the shared evaluator at the actual Start time to derive the original
    // reservation identities. Never copy quota key/window algorithms here.
    let past_paths =
        current.original_quota_reservation_paths(&commit, &actions, &target, &facts, &approvals)?;
    for live in live_paths.iter().filter(|path| &path.grant.id == cited) {
        for (_, past) in past_paths.iter().filter(|(id, _)| id == cited) {
            if reservation_bindings(&live.reservations) != reservation_bindings(past) {
                continue;
            }
            if consumed_for_start(conn, past, start).await? {
                return Ok(grant.clone());
            }
        }
    }
    Err(denied("has no exact durably fulfilled original quota path"))
}

fn validate_original(
    start: &Event,
    original: &Event,
    commit: &RealmCommit,
    now: DateTime<Utc>,
) -> PersistenceResult<()> {
    commit
        .validate_content_address()
        .map_err(PersistenceError::database)?;
    let stream = arkret_wire::CommitStreamRef::from_scope(&start.scope_ref, None)
        .map_err(PersistenceError::database)?;
    if arkret_canonical::canonical_json_bytes(start).map_err(PersistenceError::database)?
        != arkret_canonical::canonical_json_bytes(original).map_err(PersistenceError::database)?
        || commit.event_ref != start.event_id
        || commit.realm_id != start.realm_id
        || commit.stream_ref != stream
        || commit.committed_at > now
    {
        return Err(denied("differs from its exact immutable Start acceptance"));
    }
    Ok(())
}

fn reservation_bindings(reservations: &[QuotaReservation]) -> BTreeSet<(GrantId, String, String)> {
    reservations
        .iter()
        .map(|row| {
            (
                row.grant_id.clone(),
                row.constraint_key.clone(),
                row.counter_key.clone(),
            )
        })
        .collect()
}

async fn consumed_for_start(
    conn: &mut AsyncPgConnection,
    reservations: &[QuotaReservation],
    start: &Event,
) -> PersistenceResult<bool> {
    for reservation in reservations {
        let row = sql_query("SELECT EXISTS(SELECT 1 FROM capability_quota_consumptions WHERE grant_id=$1 AND constraint_key=$2 AND operation_identity=$3 AND counter_key=$4 AND window_id=$5) AS present")
            .bind::<Text,_>(reservation.grant_id.as_str()).bind::<Text,_>(&reservation.constraint_key)
            .bind::<Text,_>(start.event_id.as_str()).bind::<Text,_>(&reservation.counter_key)
            .bind::<BigInt,_>(reservation.window_id).get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?;
        if !row.present {
            return Ok(false);
        }
    }
    Ok(true)
}

struct ApprovalGroup {
    quorum: u64,
    roster: BTreeSet<arkret_wire::DidCoreId>,
    voters: BTreeSet<arkret_wire::DidCoreId>,
}

fn find_grant<'a>(
    authorization: &'a ActorRealmAuthorization,
    id: &GrantId,
) -> Option<&'a CapabilityGrant> {
    authorization.current_grant_record(id).or_else(|| {
        authorization
            .agent_ceiling
            .as_ref()
            .and_then(|ceiling| find_grant(&ceiling.controller, id))
    })
}

async fn read_accepted_approvals(
    conn: &mut AsyncPgConnection,
    start: &Event,
    commit: &RealmCommit,
    action: CapabilityActionId,
    authorization: &ActorRealmAuthorization,
) -> PersistenceResult<Vec<VerifiedGrantApproval>> {
    let audits = sql_query("SELECT event_digest,accepted_commit_id,accepted_at,approval_context,approver_did,nonce,evidence,accepted_basis FROM event_approval_private_audit WHERE realm_id=$1 AND event_id=$2")
        .bind::<Text,_>(start.realm_id.as_str()).bind::<Text,_>(start.event_id.as_str())
        .load::<ApprovalAudit>(&mut *conn).await.map_err(PersistenceError::database)?;
    accepted_approvals(start, commit, action, authorization, &audits)
}

fn accepted_approvals(
    start: &Event,
    commit: &RealmCommit,
    action: CapabilityActionId,
    authorization: &ActorRealmAuthorization,
    audits: &[ApprovalAudit],
) -> PersistenceResult<Vec<VerifiedGrantApproval>> {
    let digest = arkret_canonical::canonical_sha256(start).map_err(PersistenceError::database)?;
    let mut groups: BTreeMap<(GrantId, String), ApprovalGroup> = BTreeMap::new();
    for row in audits {
        if row.event_digest != digest
            || row.accepted_commit_id != commit.commit_id.as_str()
            || row.accepted_at != commit.committed_at
        {
            return Err(denied(
                "approval audit differs from the original accepted Event/Commit",
            ));
        }
        let vote: ApprovalSignature =
            serde_json::from_value(row.evidence.clone()).map_err(PersistenceError::database)?;
        vote.validate().map_err(PersistenceError::database)?;
        if row.approval_context
            != arkret_canonical::canonical_json_string(&vote.input.approval_context)
                .map_err(PersistenceError::database)?
            || row.approver_did != vote.input.approver_did.as_str()
            || row.nonce != vote.input.nonce
            || vote.input.realm_id != start.realm_id
            || vote.input.initiating_actor_id != start.actor_id
        {
            return Err(denied("approval audit changed its exact original vote"));
        }
        vote.input
            .validate_approved_at(commit.committed_at)
            .map_err(PersistenceError::database)?;
        if let arkret_wire::ApprovalTarget::Event { event_id } = &vote.input.approval_target {
            if event_id != &start.event_id || vote.input.request_canonical_digest.as_str() != digest
            {
                return Err(denied("approval signed another original Event"));
            }
        }
        // The private immutable audit is the original accepting transaction's
        // verified carrier/roster result. Its key is not taken from a ready
        // request. Recheck the actual signed vote bytes as well; an Operation
        // target retains its original carrier digest instead of inventing a
        // new request preimage from the ready Event.
        let public_key = row
            .accepted_basis
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| denied("approval has no frozen original public key"))?;
        if row
            .accepted_basis
            .get("historical_method")
            .and_then(Value::as_str)
            != Some(vote.proof.verification_method.as_str())
        {
            return Err(denied("approval original key method differs"));
        }
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &vote.proof.jws,
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)
                    .map_err(PersistenceError::database)?,
                &arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                    value: public_key.to_owned(),
                },
            )
            .map_err(PersistenceError::database)?;
        let ApprovalContext::Grant { grant_id } = &vote.input.approval_context else {
            continue;
        };
        if vote.input.action != action {
            continue;
        }
        let Some(grant) = find_grant(authorization, grant_id) else {
            continue;
        };
        let principal = arkret_wire::project_did_to_core_id(&vote.input.approver_did)
            .map_err(PersistenceError::database)?;
        let qualifications = row
            .accepted_basis
            .get("qualifications")
            .and_then(Value::as_array)
            .ok_or_else(|| denied("approval has no accepted qualifications"))?;
        for qualification in qualifications {
            let Some(requirement) = qualification.get("grant_requirement") else {
                continue;
            };
            if requirement.get("grant_id")
                != Some(&serde_json::to_value(grant_id).map_err(PersistenceError::database)?)
            {
                continue;
            }
            let constraint: GrantConstraint =
                serde_json::from_value(requirement["constraint"].clone())
                    .map_err(PersistenceError::database)?;
            let constraint_digest = arkret_canonical::canonical_sha256(&constraint)
                .map_err(PersistenceError::database)?;
            if requirement["constraint_digest"].as_str() != Some(constraint_digest.as_str())
                || !grant.constraints.contains(&constraint)
            {
                return Err(denied(
                    "approval does not name an immutable current grant constraint",
                ));
            }
            if !crate::grant_approval_admission::is_approval_constraint(&constraint)
                || (!constraint.applies_to_actions.is_empty()
                    && !constraint
                        .applies_to_actions
                        .iter()
                        .any(|applied| applied == action.as_str()))
            {
                return Err(denied(
                    "approval qualification names another action or family",
                ));
            }
            let timeout = match constraint.timeout.as_deref() {
                Some(value) => Some(
                    coland_storage::fixed_duration(value)
                        .filter(|duration| *duration > chrono::TimeDelta::zero())
                        .ok_or_else(|| denied("approval original timeout is unproved"))?,
                ),
                None => None,
            };
            if vote.input.approved_at < crate::grant_approval_admission::approval_not_before(grant)
                || !crate::grant_approval_admission::approval_deadline(
                    vote.input.approved_at,
                    commit.committed_at,
                    timeout,
                )
            {
                return Err(denied(
                    "approval was not valid for this constraint at original acceptance",
                ));
            }
            let mut roster = BTreeSet::new();
            for member in requirement["eligible_roster"]
                .as_array()
                .ok_or_else(|| denied("approval has no original eligible roster"))?
            {
                let member: arkret_wire::DidCoreId =
                    serde_json::from_value(member["principal"].clone())
                        .map_err(PersistenceError::database)?;
                if !roster.insert(member) {
                    return Err(denied("approval original roster repeats a principal"));
                }
            }
            let quorum = requirement["effective_approval_quorum"]
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or_else(|| denied("approval has no original quorum"))?;
            if constraint
                .approval_threshold
                .unwrap_or_default()
                .required_votes(roster.len() as u64)
                != Some(quorum)
                || !roster.contains(&principal)
            {
                return Err(denied(
                    "approval voter or quorum differs from the accepted roster",
                ));
            }
            let group = groups
                .entry((grant_id.clone(), constraint_digest))
                .or_insert_with(|| ApprovalGroup {
                    quorum,
                    roster: roster.clone(),
                    voters: BTreeSet::new(),
                });
            if group.quorum != quorum || group.roster != roster {
                return Err(denied("approval original cut has conflicting rosters"));
            }
            group.voters.insert(principal.clone());
        }
    }
    Ok(groups
        .into_iter()
        .filter_map(|((grant_id, constraint_digest), group)| {
            (group.voters.len() as u64 >= group.quorum).then_some(VerifiedGrantApproval {
                grant_id,
                constraint_digest,
                action,
            })
        })
        .collect())
}
