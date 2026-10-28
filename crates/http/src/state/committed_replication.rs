//! `committed_replication` on a non-governance member Station
//! (`federation.md` §3 and §4.1.1).
//!
//! Each item is judged in request order and stored or rejected on its own:
//! the producer proof must be self-consistent, the source RealmCommit must
//! verify under the Realm's current authority chain as served and verified
//! from the authenticated source Station, and the Commit must directly follow
//! the stream this Station holds. A human device of an Account this Station
//! hosts is still verified against local PCR. The only way to open a held
//! Realm stream is the verified join of a member this Station hosts, which
//! leaves it pending anchor: this Station then anchors it on the governing
//! Station's bootstrap snapshot, and fills any gap in front of a replica
//! that arrived before its predecessors, through the peer reads
//! ([`super::replica_anchor`]). Nothing is admitted, re-signed or fanned out
//! again.

use std::collections::BTreeMap;

use arkret_models_collaboration::authority_commit::{
    CommittedEventReplicationOutcome, CommittedEventSubmission, CommittedReplicationBranch,
    PeerCommittedReplicationRequestBody, PeerCommittedReplicationResponseBody,
};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_wire::{CommitStreamRef, ErrorCode, RealmId};
use coland_services::authority_commit::AuthenticatedPeerContext;
use coland_services::committed_receipt::{
    CommitContinuity, verify_committed_event_receipt_with_source,
};
use coland_services::{ServiceError, ServiceResult};
use coland_storage::{
    CommittedReplica, CommittedReplicaOutcome, CommittedReplicaRole, ConflictCode,
    VerifiedMlsWelcome,
};

use super::AppState;
use crate::routing::realm_join::LocatedRealmAuthority;

fn temporarily_unavailable(detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(format!(
        "{}: {detail}",
        ConflictCode::TemporarilyUnavailable
    ))
}

/// The reason one item was not stored. A local store or read fault is not a
/// judgement of the item, so it fails the whole request and the source
/// replays the exact body.
fn rejection_reason(error: ServiceError) -> ServiceResult<String> {
    match &error {
        ServiceError::SchemaViolation(_) => Ok(ErrorCode::SCHEMA_VIOLATION.to_owned()),
        ServiceError::UnsupportedEventKind(_) => Ok(ErrorCode::UNSUPPORTED_EVENT_KIND.to_owned()),
        ServiceError::NotFound(_) => Ok(ConflictCode::DependencyMissing.as_str().to_owned()),
        ServiceError::Conflict(detail) => {
            if error.conflict_code() == Some(ConflictCode::TemporarilyUnavailable) {
                return Err(error);
            }
            let token = detail
                .split_once(": ")
                .map_or(detail.as_str(), |(head, _)| head);
            let registered =
                ConflictCode::from_detail(token).is_some() || ErrorCode::from_wire(token).is_some();
            Ok(if registered {
                token.to_owned()
            } else {
                ErrorCode::FAILED_PRECONDITION.to_owned()
            })
        }
        ServiceError::Database(_) | ServiceError::Internal(_) => Err(error),
    }
}

/// The hosted member whose verified join the item is, the one Event that may
/// open its held Realm stream: the member's own `ak.member.state{join}` or
/// the directed invitee's `ak.invite.accept`, which is that invitee's join
/// (`governance-objects.md` §5.3).
pub(super) fn hosted_member_join(
    state: &AppState,
    event: &arkret_wire::Event,
    source_commit: &arkret_wire::RealmCommit,
) -> Option<arkret_wire::AccountId> {
    if source_commit.stream_ref
        != arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None).ok()?
    {
        return None;
    }
    hosted_member_join_event(state, event)
}

/// Classify an opening join without granting admission or replica authority.
pub(super) fn hosted_member_join_event(
    state: &AppState,
    event: &arkret_wire::Event,
) -> Option<arkret_wire::AccountId> {
    let member = match event.kind {
        arkret_wire::EventKind::MemberState => {
            let payload = serde_json::to_value(&event.payload)
                .and_then(serde_json::from_value::<MembershipPayload>)
                .ok()?;
            if payload.membership != MembershipPayloadState::Join
                || payload
                    .realm_id
                    .as_ref()
                    .is_some_and(|realm_id| realm_id != &event.realm_id)
            {
                return None;
            }
            payload.member_id
        }
        arkret_wire::EventKind::CircleMemberState => {
            let arkret_wire::ScopeRef::Circle { circle_id, .. } = &event.scope_ref else {
                return None;
            };
            if event
                .payload
                .get("circle_id")
                .and_then(serde_json::Value::as_str)
                != Some(circle_id.as_str())
                || event
                    .payload
                    .get("membership")
                    .and_then(serde_json::Value::as_str)
                    != Some("join")
            {
                return None;
            }
            let member: arkret_wire::ActorId =
                serde_json::from_value(event.payload.get("member_id")?.clone()).ok()?;
            if member != event.actor_id {
                return None;
            }
            member
        }
        arkret_wire::EventKind::InviteAccept | arkret_wire::EventKind::RealmInviteLinkAccept => {
            event.actor_id.clone()
        }
        _ => return None,
    };
    match member {
        arkret_wire::ActorId::Account { account_id }
            if account_id.station_id == state.service_core_id() =>
        {
            Some(account_id)
        }
        _ => None,
    }
}

/// encryption-and-audit.md §2.2 "跨站 recipient": the Welcomes of a
/// replicated `ak.mls.commit` whose recipients this Station hosts and whose
/// claims, as this Station's own claim destination, it re-verifies against
/// its ledger exactly as the governance Station verifies a local recipient's
/// claim (device-lifecycle.md §9.2.3). A Welcome that fails is dropped with a
/// restricted log line and never judges the Commit replica.
async fn verified_replicated_welcomes(
    state: &AppState,
    item: &CommittedEventSubmission,
) -> ServiceResult<Vec<VerifiedMlsWelcome>> {
    let event = &item.event_submission.event;
    let mut verified = Vec::new();
    for welcome in item.welcomes.iter().flatten() {
        let refused = |detail: &dyn std::fmt::Display| {
            tracing::warn!(
                welcome_id = %welcome.welcome_id.as_str(),
                %detail,
                "replicated MLS Welcome refused by its claim destination"
            );
        };
        if crate::routing::actor_delivery_station(state, &welcome.recipient_actor_id)
            .await
            .map_err(|error| {
                coland_services::ServiceError::Conflict(format!("temporarily_unavailable: {error}"))
            })?
            != state.service_core_id()
        {
            refused(&"the recipient is not hosted here");
            continue;
        }
        let preparation: ServiceResult<_> = async {
            let (claim, _) =
                super::authority_mls_unit::resolve_claim(state, event, welcome).await?;
            let guard = super::authority_mls_unit::native_welcome_target(state, welcome).await?;
            Ok((claim, guard))
        }
        .await;
        match preparation {
            Ok((claim, guard)) => {
                verified.push(VerifiedMlsWelcome {
                    delivery: welcome.clone(),
                    claim: Some(claim),
                    applet_device_scope_guard: guard,
                    roster_witness: None,
                });
            }
            Err(error @ (ServiceError::Database(_) | ServiceError::Internal(_))) => {
                return Err(error);
            }
            Err(error) => refused(&error),
        }
    }
    Ok(verified)
}

async fn prepare_replica_roster_witnesses(
    state: &AppState,
    item: &CommittedEventSubmission,
    welcomes: Vec<VerifiedMlsWelcome>,
) -> ServiceResult<Vec<VerifiedMlsWelcome>> {
    let mut prepared = Vec::with_capacity(welcomes.len());
    for mut welcome in welcomes {
        match super::authority_mls_unit::attach_replicated_roster_witnesses(
            state,
            item,
            std::slice::from_mut(&mut welcome),
        )
        .await
        {
            Ok(()) => prepared.push(welcome),
            Err(error @ (ServiceError::Database(_) | ServiceError::Internal(_))) => {
                return Err(error);
            }
            Err(error) => tracing::warn!(
                commit_event_ref = %item.event_submission.event.event_id,
                welcome_id = %welcome.delivery.welcome_id,
                %error, "replicated Welcome refused without rejecting its accepted Commit"
            ),
        }
    }
    Ok(prepared)
}

async fn prepare_or_replicate_one(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    authorities: &mut BTreeMap<RealmId, LocatedRealmAuthority>,
    item: &CommittedEventSubmission,
    receipt: Option<&coland_storage::IdempotencyRecord>,
    deferred: Option<&mut Vec<CommittedReplica>>,
) -> ServiceResult<(CommittedReplicaOutcome, bool)> {
    item.validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let event = &item.event_submission.event;
    super::authority_port::refuse_actor_private_event(&event.kind)?;
    let commit = &item.source_commit;
    if !matches!(
        commit.stream_ref,
        CommitStreamRef::Realm { .. }
            | CommitStreamRef::Circle { .. }
            | CommitStreamRef::Sidecar { .. }
    ) {
        return Err(ServiceError::UnsupportedEventKind(
            "Circle and Sidecar replicas need their own scope membership basis".to_owned(),
        ));
    }
    let current_authority = state
        .authority_commits()
        .current_authority(&event.realm_id)
        .await?;
    if current_authority
        .as_ref()
        .is_some_and(|authority| authority.service_id == state.service_core_id())
    {
        return Err(ServiceError::Conflict(format!(
            "{}: this Station governs the Realm and accepts no replica of it",
            ConflictCode::ForkQuarantine
        )));
    }
    if !authorities.contains_key(&event.realm_id) {
        let located = crate::routing::realm_join::resolve_verified_authority_of_service(
            state,
            &event.realm_id,
            &peer.source_service_id,
        )
        .await
        .map_err(|error| {
            if current_authority
                .as_ref()
                .is_some_and(|authority| authority.service_id != peer.source_service_id)
            {
                ServiceError::Conflict(
                    "capability_denied: the authenticated peer is not the Realm's current origin service"
                        .to_owned(),
                )
            } else {
                temporarily_unavailable(format!("source Realm authority: {error}"))
            }
        })?;
        authorities.insert(event.realm_id.clone(), located);
    }
    let located = authorities
        .get_mut(&event.realm_id)
        .ok_or_else(|| ServiceError::internal("verified Realm authority vanished"))?;
    let welcomes = verified_replicated_welcomes(state, item).await?;
    if let Some(existing) = state
        .authority_commits()
        .committed_event_by_commit_id(&commit.commit_id)
        .await?
        .filter(|_| deferred.is_none())
    {
        if existing.commit == *commit && existing.event == *event {
            let original_fact = state
                .authority_commits()
                .producer_signer_fact(event, commit)
                .await?;
            if original_fact != item.producer_signer_fact {
                return Err(ServiceError::Conflict(
                    "duplicate_conflict: original replicated Human source differs".into(),
                ));
            }
            if receipt.is_none()
                && welcomes.is_empty()
                && !matches!(
                    event.kind,
                    arkret_wire::EventKind::MlsGenesis
                        | arkret_wire::EventKind::MlsCommit
                        | arkret_wire::EventKind::RealmGovernanceStationChange
                )
            {
                return Ok((CommittedReplicaOutcome::Duplicate, false));
            }
            // A replay may retain exact Genesis provenance or queue outstanding
            // Welcomes only after re-proving this authenticated peer's origin.
            if receipt.is_none() {
                let welcomes = prepare_replica_roster_witnesses(state, item, welcomes).await?;
                return state
                    .authority_commits()
                    .queue_replicated_welcomes(
                        event,
                        commit,
                        item.genesis_event_ref.as_ref(),
                        &welcomes,
                        crate::wire::now(),
                    )
                    .await
                    .map(|outcome| (outcome, false));
            }
        } else {
            return Err(ServiceError::Conflict(format!(
                "{}: the Commit id is held with different content",
                ConflictCode::DuplicateConflict
            )));
        }
    }
    if matches!(
        event.kind,
        arkret_wire::EventKind::SelfModerationReport
            | arkret_wire::EventKind::ModerationFrankingProof
    ) {
        let realm_stream = CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        };
        let cached = state
            .authority_commits()
            .replica_authorization_head(&realm_stream)
            .await?;
        let latest = &located.bundle.realm_stream_head;
        let current = cached.as_ref().is_some_and(|head| {
            head == latest
                || (commit.stream_ref == realm_stream
                    && latest.commit_id == commit.commit_id
                    && latest.stream_position == commit.stream_position
                    && commit.previous_commit_ref.as_ref() == Some(&head.commit_id)
                    && commit.stream_position == head.stream_position + 1)
        });
        if !current {
            return Err(ServiceError::Conflict(format!(
                "{}: a fresh signed authorization snapshot is required",
                ConflictCode::DependencyMissing
            )));
        }
    }
    if arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
        &located.keys,
        &commit.signature.verification_method,
        commit.signature.created_at,
    )
    .is_none()
    {
        crate::routing::realm_join::insert_historical_method_key(
            state,
            &mut located.keys,
            &commit.signature.verification_method,
            commit.signature.created_at,
            &located.bundle,
        )
        .await
        .map_err(|error| temporarily_unavailable(format!("RealmCommit signing key: {error}")))?;
    }
    // The locked installation proves exact replay or direct succession.
    // An unlocked head can advance after the duplicate lookup and wrongly
    // reject the same Commit concurrently delivered by another peer request.
    // Receipt verification still checks every signature and Event binding.
    let role = hosted_member_join(state, event, commit)
        .map_or(CommittedReplicaRole::HeldStream, |member_account_id| {
            CommittedReplicaRole::OpeningJoin { member_account_id }
        });
    verify_committed_event_receipt_with_source(
        state.persistence(),
        event,
        commit,
        CommitContinuity::Standalone,
        &located.authority,
        &located.keys,
        &state.service_core_id(),
        state
            .projections()
            .realm_digest_suite(event.realm_id.as_str()),
        item.producer_signer_fact.as_ref(),
    )
    .await?;
    let welcomes = prepare_replica_roster_witnesses(state, item, welcomes).await?;
    let replica = CommittedReplica {
        local_service_id: state.service_core_id(),
        authority: located.current_authority(),
        historical_commit: (commit.governance_generation < located.authority.current_generation())
            .then(|| {
                located
                    .authority
                    .verify_historical_commit(commit, &located.keys)
            })
            .transpose()
            .map_err(temporarily_unavailable)?,
        event: event.clone(),
        commit: commit.clone(),
        producer_signer_fact: item.producer_signer_fact.clone(),
        genesis_event_ref: item.genesis_event_ref.clone(),
        role,
        received_at: crate::wire::now(),
        welcomes,
    };
    if let Some(deferred) = deferred {
        deferred.push(replica);
        return Ok((CommittedReplicaOutcome::Stored, false));
    }
    let (outcome, fresh) = if let Some(receipt) = receipt {
        state
            .authority_commits()
            .install_committed_peer_replica(&replica, receipt)
            .await?
    } else {
        let outcome = state
            .authority_commits()
            .install_committed_replica(&replica)
            .await?;
        (outcome, matches!(outcome, CommittedReplicaOutcome::Stored))
    };
    if fresh {
        crate::routing::events::notify::dispatch_committed_event_notifications(state, event).await;
    }
    Ok((outcome, fresh))
}

async fn replicate_one(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    authorities: &mut BTreeMap<RealmId, LocatedRealmAuthority>,
    item: &CommittedEventSubmission,
    receipt: Option<&coland_storage::IdempotencyRecord>,
) -> ServiceResult<(CommittedReplicaOutcome, bool)> {
    prepare_or_replicate_one(state, peer, authorities, item, receipt, None).await
}

pub(super) async fn receive_audit_pair(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: arkret_models_collaboration::authority_commit::AuditPairedEventFederationSubmission,
) -> ServiceResult<arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome>
{
    request
        .validate()
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
    let mut authorities = BTreeMap::new();
    let mut prepared = Vec::with_capacity(2);
    for slot in &request.committed_events {
        prepare_or_replicate_one(
            state,
            peer,
            &mut authorities,
            slot,
            None,
            Some(&mut prepared),
        )
        .await?;
    }
    let replicas: [CommittedReplica; 2] = prepared
        .try_into()
        .map_err(|_| ServiceError::internal("audit pair replica preparation omitted a slot"))?;
    let status = state
        .authority_commits()
        .install_committed_audit_pair(&request, &replicas)
        .await?;
    if status == arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed
    {
        for slot in &request.committed_events {
            crate::routing::events::notify::dispatch_committed_event_notifications(
                state,
                &slot.event_submission.event,
            )
            .await;
        }
    }
    Ok(
        arkret_models_collaboration::authority_commit::AuditPairedEventAcceptanceOutcome {
            unit_kind: request.unit_kind,
            status,
            commits: request
                .committed_events
                .each_ref()
                .map(|slot| slot.source_commit.clone()),
        },
    )
}

/// Judge every item of one `committed_replication` request in order.
pub(super) async fn receive(
    state: &AppState,
    peer: &AuthenticatedPeerContext,
    request: PeerCommittedReplicationRequestBody,
) -> ServiceResult<PeerCommittedReplicationResponseBody> {
    let mut authorities = BTreeMap::new();
    let mut replication_outcomes = Vec::with_capacity(request.replications.len());
    let mut converge = std::collections::BTreeSet::new();
    for (index, item) in request.replications.iter().enumerate() {
        let receipt = peer
            .replay_receipt
            .as_ref()
            .map(|base| -> ServiceResult<_> {
                let mut receipt = base.clone();
                receipt.idempotency_key = arkret_canonical::sha256_digest(
                    &arkret_canonical::canonical_json_bytes(&(
                        base.idempotency_key.as_str(),
                        index,
                    ))
                    .map_err(|error| ServiceError::Internal(error.to_string()))?,
                )
                .as_str()
                .to_owned();
                Ok(receipt)
            })
            .transpose()?;
        let record =
            match replicate_one(state, peer, &mut authorities, item, receipt.as_ref()).await {
                Ok((CommittedReplicaOutcome::Stored, fresh)) => {
                    // A stored join that opened the stream leaves it pending
                    // anchor; anchoring it is this Station's next step.
                    if fresh {
                        converge.insert(item.source_commit.stream_ref.clone());
                    }
                    CommittedEventReplicationOutcome::Stored {}
                }
                Ok((CommittedReplicaOutcome::Duplicate, _)) => {
                    CommittedEventReplicationOutcome::Duplicate {}
                }
                Err(error) => {
                    let reason_code = rejection_reason(error)?;
                    // A pending anchor or a gap in front of the item: pull the
                    // missing prefix so the sender's retry can be stored.
                    if reason_code == ConflictCode::DependencyMissing.as_str() {
                        converge.insert(item.source_commit.stream_ref.clone());
                    }
                    CommittedEventReplicationOutcome::Rejected { reason_code }
                }
            };
        replication_outcomes.push(record);
    }
    for stream in converge {
        super::replica_anchor::spawn_converge_stream(state, stream);
    }
    Ok(PeerCommittedReplicationResponseBody {
        branch: CommittedReplicationBranch::CommittedReplication,
        replication_outcomes,
    })
}
