//! The member Station side of a held Realm replica stream
//! (`federation.md` §4.1.1): bootstrap anchoring and gap filling.
//!
//! A hosted member's own join opens the held stream pending anchor. This
//! Station then asks the governing Station for
//! `ak.peer.realm_join.read.bootstrap.v1` with that join's Commit, verifies
//! the authority bundle, the snapshot signature and generation, that the
//! snapshot's Realm stream floor is the join position and that its head is
//! not below it -- the prefix evidence -- and installs the snapshot's typed
//! current anchored at its head. It then pulls every Commit after its held
//! head through `ak.peer.committed_event.read.scan.v1` up to the advertised
//! head: a full row is stored exactly like a replica, a withheld row as a
//! continuity-only chain node. The same scan fills the gap in front of any
//! replica the sender delivered before its predecessors, so the sender's
//! retry of that replica is stored. Nothing here admits, re-signs or fans
//! out; a failed attempt leaves the stream as it was for the next one.

use std::collections::BTreeSet;
use std::sync::{LazyLock, Mutex};

use arkret_models_collaboration::governance::realm_join_bootstrap::RealmJoinBootstrapAssembly;
use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody,
};
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventView, DidCoreId, RealmCommit, RealmId,
    RequestId, StreamScanDirection, StreamScanRequest,
};
use coland_services::committed_receipt::{
    CommitContinuity, verify_committed_event_receipt_with_source,
};
use coland_storage::{
    CommittedChainNode, CommittedReplica, CommittedReplicaRole, ReplicaAnchorInstall,
    ReplicaStreamAnchor,
};

use super::AppState;
use crate::routing::realm_join::LocatedRealmAuthority;

const BOOTSTRAP_PATH: &str = "/_arkret/peer/realm-joins/bootstrap";
const SCAN_PATH: &str = "/_arkret/peer/streams/scan";
/// A signed snapshot is held to 8 MiB inline; the bundle and heads ride along.
const BOOTSTRAP_MAX_BYTES: usize = 12 * 1024 * 1024;
const SCAN_MAX_BYTES: usize = 16 * 1024 * 1024;
const SCAN_PAGE_LIMIT: u16 = 128;
/// How often the pending anchors a restart or an unreachable governing
/// Station left behind are retried.
const PENDING_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

static IN_FLIGHT: LazyLock<Mutex<BTreeSet<(String, String)>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

pub(crate) fn spawn_converge_stream(state: &AppState, stream: CommitStreamRef) {
    let key = (
        state.service_id().to_owned(),
        arkret_canonical::canonical_json_string(&stream).unwrap_or_default(),
    );
    {
        let Ok(mut in_flight) = IN_FLIGHT.lock() else {
            return;
        };
        if !in_flight.insert(key.clone()) {
            return;
        }
    }
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(reason) = converge(&state, &stream).await {
            tracing::warn!(?stream, %reason, "held replica did not converge");
        }
        if let Ok(mut in_flight) = IN_FLIGHT.lock() {
            in_flight.remove(&key);
        }
    });
}

/// Retry every pending anchor periodically. Needs outbound federation.
pub fn spawn_pending_anchor_sweeper(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    if !state.config().federation_outbound_enabled {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PENDING_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match state.authority_commits().pending_replica_streams().await {
                Ok(pending) => {
                    for stream in pending {
                        spawn_converge_stream(&state, stream);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "pending replica anchors are unreadable");
                }
            }
        }
    }))
}

async fn converge(state: &AppState, stream: &CommitStreamRef) -> Result<(), String> {
    let realm_id = stream.realm_id();
    let commits = state.authority_commits();
    let Some(anchor) = commits
        .replica_anchor_for_stream(stream)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let authority = commits
        .current_authority(realm_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("the held Realm has no recorded governing Station")?;
    let governance = authority.service_id;
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        realm_id,
        &governance,
    )
    .await
    .map_err(|error| error.message)?;
    // An installed anchor is verified durable prefix evidence. Requiring a
    // new join bootstrap for every gap would prevent consuming the terminal
    // membership Commit after that member's current join has ended.
    let anchored = match &anchor.anchored_head {
        Some(head) => head.clone(),
        None => anchor_stream(state, &anchor, &governance, &mut located).await?,
    };
    fill_to_head(state, realm_id, &governance, &anchored, &mut located).await?;
    // Grant and policy replicas invalidate the previous authorization cut.
    // Holding their Commit chain cannot reconstruct the governing inputs
    // deliberately omitted from a member bootstrap. Refresh the signed cut
    // through the same nonce-bound, exact-opening-join bootstrap verifier.
    // Fill first so a terminal membership Commit is still held even when a
    // fresh bootstrap correctly refuses the no-longer-current opening join.
    if commits
        .replica_authorization_head(stream)
        .await
        .map_err(temporary)?
        .is_none()
    {
        let readers = commits
            .replica_bootstrap_readers(stream, &state.service_core_id())
            .await
            .map_err(temporary)?;
        // The original anchor is durable prefix evidence, not a permanent
        // reader lease. Another hosted current join can authorize refresh.
        let mut failure = None;
        for (member_account_id, join_commit) in readers {
            let reader = ReplicaStreamAnchor {
                realm_id: realm_id.clone(),
                member_account_id,
                join_commit,
                anchored_head: anchor.anchored_head.clone(),
            };
            match anchor_stream(state, &reader, &governance, &mut located).await {
                Ok(refreshed) => {
                    return fill_to_head(state, realm_id, &governance, &refreshed, &mut located)
                        .await;
                }
                Err(error) => failure = Some(error),
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
    }
    Ok(())
}

fn temporary(detail: impl std::fmt::Display) -> String {
    detail.to_string()
}

/// Refresh a hosted Account's exact original governing Snapshot. Native
/// replica folding remains the only source of local current state: this read
/// archives no object until that complete cut already matches the peer.
pub(crate) async fn refresh_account_snapshot(
    state: &AppState,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, String> {
    use arkret_wire::{CurrentSelector, TypedCurrentRow};

    if account.station_id != state.service_core_id() {
        return Err("the Account is not hosted by this member Station".to_owned());
    }
    let commits = state.authority_commits();
    let material = commits
        .realm_state_snapshot_material_for_account(realm_id, account)
        .await
        .map_err(temporary)?
        .ok_or("the Account has no disclosed current cut")?;
    let actor = arkret_wire::ActorId::account(account.clone());
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let own_join = material.current_state_entries.iter().find(|row| matches!(row,
        TypedCurrentRow::Value {
            selector: CurrentSelector::MemberState { actor_id }, source_stream_ref, value, ..
        } if actor_id == &actor && source_stream_ref == &realm_stream
            && serde_json::from_value::<arkret_wire::MemberStateCurrent>(value.clone())
                .is_ok_and(|member| member.membership == arkret_wire::MembershipState::Join)
    )).ok_or("the hosted Account has no accepted current opening join")?;
    let TypedCurrentRow::Value { revision, .. } = own_join;
    let governance = commits
        .current_authority(realm_id)
        .await
        .map_err(temporary)?
        .ok_or("the Realm has no governing authority")?
        .service_id;
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        realm_id,
        &governance,
    )
    .await
    .map_err(|error| error.message)?;
    let request = PeerRealmJoinBootstrapRequestBody {
        request_id: RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .map_err(temporary)?,
        realm_id: realm_id.clone(),
        member_account_id: account.clone(),
        membership_commit_id: revision.commit_id.clone(),
    };
    let body = post_peer(
        state,
        &governance,
        BOOTSTRAP_PATH,
        &request,
        BOOTSTRAP_MAX_BYTES,
    )
    .await?;
    let outcome: PeerRealmJoinBootstrapOutcome =
        serde_json::from_slice(&body).map_err(temporary)?;
    if outcome.request_id != request.request_id || outcome.snapshot.realm_id != *realm_id {
        return Err("bootstrap answer does not bind the Account Snapshot request".to_owned());
    }
    let nonce = crate::routing::realm_join::nonce_for_request(&request.request_id)
        .map_err(|error| error.message)?;
    let served = crate::routing::realm_join::verify_served_bundle(
        state,
        outcome.authority_bundle.clone(),
        &nonce,
    )
    .await
    .map_err(|error| error.message)?;
    if served.authority.current_service_id() != &governance
        || served.authority.current_generation() != located.authority.current_generation()
    {
        return Err("bootstrap bundle names another governing tenure".to_owned());
    }
    located = served;
    RealmJoinBootstrapAssembly::new(outcome.clone()).map_err(temporary)?;
    let snapshot = outcome.snapshot;
    verify_snapshot(state, &mut located, &snapshot).await?;
    let expected_floor = commits
        .member_station_bootstrap_floor(realm_id, account, &revision.commit_id)
        .await
        .map_err(temporary)?
        .ok_or("the hosted opening join has no provable bootstrap floor")?;
    if !snapshot.current_state_entries.contains(own_join)
        || snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| floor.stream_ref == realm_stream)
            .is_none_or(|floor| floor.oldest_position != expected_floor)
        || snapshot
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == realm_stream)
            .is_none_or(|head| {
                head.stream_position < revision.stream_position
                    || (head.stream_position == revision.stream_position
                        && head.commit_id != revision.commit_id)
            })
    {
        return Err(
            "the governing Snapshot does not bind the hosted Account's current join".to_owned(),
        );
    }
    if let Err(error) = commits
        .install_verified_account_snapshot(account, &state.service_core_id(), &snapshot)
        .await
    {
        spawn_converge_stream(
            state,
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
        );
        return Err(temporary(error));
    }
    Ok(snapshot)
}

async fn post_peer<T: serde::Serialize>(
    state: &AppState,
    governance: &DidCoreId,
    path: &str,
    request: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let body = arkret_canonical::canonical_json_bytes(request).map_err(temporary)?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        governance.as_str(),
        path,
        &body,
        max_bytes,
    )
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(format!("{path} answered HTTP {}", response.status));
    }
    Ok(response.body)
}

async fn ensure_method_key(
    state: &AppState,
    located: &mut LocatedRealmAuthority,
    method: &arkret_wire::DidUrl,
) -> Result<(), String> {
    if arkret_identity::RealmAuthorityKeyDirectory::public_key(&located.keys, method).is_none() {
        crate::routing::realm_join::insert_method_key(state, &mut located.keys, method)
            .await
            .map_err(|error| error.message)?;
    }
    Ok(())
}

async fn ensure_historical_method_key(
    state: &AppState,
    located: &mut LocatedRealmAuthority,
    signature: &arkret_wire::DetachedObjectSignature,
) -> Result<(), String> {
    if arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
        &located.keys,
        &signature.verification_method,
        signature.created_at,
    )
    .is_none()
    {
        crate::routing::realm_join::insert_historical_method_key(
            state,
            &mut located.keys,
            &signature.verification_method,
            signature.created_at,
        )
        .await
        .map_err(|error| error.message)?;
    }
    Ok(())
}

/// Verify the snapshot identity and signature under the verified authority
/// chain: the signer is the governing Station of the snapshot's generation,
/// and that generation is the current one.
async fn verify_snapshot(
    state: &AppState,
    located: &mut LocatedRealmAuthority,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> Result<(), String> {
    if snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
        || snapshot.governance_generation != located.authority.current_generation()
    {
        return Err("bootstrap snapshot context or generation is not current".to_owned());
    }
    let identity = arkret_canonical::unsigned_value(snapshot, &["signature", "snapshot_id"])
        .map_err(temporary)?;
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity).map_err(temporary)?;
    if snapshot.snapshot_id
        != arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
            &identity_bytes,
        ))
    {
        return Err("bootstrap snapshot id differs from its identity body".to_owned());
    }
    let signer_did =
        arkret_identity::verification_method_did(snapshot.signature.verification_method.as_str())
            .map_err(temporary)?;
    let signer = arkret_wire::project_did_to_core_id(&signer_did).map_err(temporary)?;
    if located
        .authority
        .authority_service_at(snapshot.governance_generation)
        != Some(&signer)
    {
        return Err("bootstrap snapshot signer is not the governing Station".to_owned());
    }
    ensure_method_key(state, located, &snapshot.signature.verification_method).await?;
    let key = arkret_identity::RealmAuthorityKeyDirectory::public_key(
        &located.keys,
        &snapshot.signature.verification_method,
    )
    .ok_or("bootstrap snapshot signing method has no verified key")?;
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"]).map_err(temporary)?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )
    .map_err(temporary)
}

/// Anchor a pending held stream on the governing Station's bootstrap
/// snapshot and return the anchored head.
async fn anchor_stream(
    state: &AppState,
    anchor: &ReplicaStreamAnchor,
    governance: &DidCoreId,
    located: &mut LocatedRealmAuthority,
) -> Result<CommitStreamHead, String> {
    anchor_stream_with_forward_source(state, anchor, governance, located, None).await
}

async fn anchor_stream_with_forward_source(
    state: &AppState,
    anchor: &ReplicaStreamAnchor,
    governance: &DidCoreId,
    located: &mut LocatedRealmAuthority,
    forward_source: Option<(
        &coland_services::identity::SessionIdentityState,
        &arkret_wire::Event,
    )>,
) -> Result<CommitStreamHead, String> {
    let realm_id = &anchor.realm_id;
    let join = &anchor.join_commit;
    let request = PeerRealmJoinBootstrapRequestBody {
        request_id: RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .map_err(temporary)?,
        realm_id: realm_id.clone(),
        member_account_id: anchor.member_account_id.clone(),
        membership_commit_id: join.commit_id.clone(),
    };
    let body = post_peer(
        state,
        governance,
        BOOTSTRAP_PATH,
        &request,
        BOOTSTRAP_MAX_BYTES,
    )
    .await?;
    if let Some((session, event)) = forward_source {
        require_forward_source(state, session, event, located).await?;
    }
    let outcome: PeerRealmJoinBootstrapOutcome =
        serde_json::from_slice(&body).map_err(temporary)?;
    if outcome.request_id != request.request_id || outcome.snapshot.realm_id != *realm_id {
        return Err("bootstrap answer does not bind the request".to_owned());
    }
    let nonce = crate::routing::realm_join::nonce_for_request(&request.request_id)
        .map_err(|error| error.message)?;
    let served = crate::routing::realm_join::verify_served_bundle(
        state,
        outcome.authority_bundle.clone(),
        &nonce,
    )
    .await
    .map_err(|error| error.message)?;
    if served.authority.current_service_id() != governance
        || served.authority.current_generation() != located.authority.current_generation()
    {
        return Err("bootstrap bundle names another governing tenure".to_owned());
    }
    *located = served;
    RealmJoinBootstrapAssembly::new(outcome.clone()).map_err(temporary)?;
    let snapshot = &outcome.snapshot;
    verify_snapshot(state, located, snapshot).await?;
    let realm_stream = join.stream_ref.clone();
    // A single opening join anchors at itself; a held registered founding
    // unit proves its position-zero floor. The head must cover the join.
    let floor = snapshot
        .retention_and_history_floor
        .stream_floors
        .iter()
        .find(|floor| floor.stream_ref == realm_stream)
        .ok_or("bootstrap snapshot has no Realm stream floor")?;
    let expected_floor = state
        .authority_commits()
        .member_station_bootstrap_floor(realm_id, &anchor.member_account_id, &join.commit_id)
        .await
        .map_err(temporary)?
        .ok_or("bootstrap opening join has no provable floor")?;
    if floor.oldest_position != expected_floor {
        return Err("bootstrap snapshot floor differs from its exact opening unit".to_owned());
    }
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == realm_stream)
        .ok_or("bootstrap snapshot has no Realm stream head")?
        .clone();
    if head.stream_position < join.stream_position
        || (head.stream_position == join.stream_position && head.commit_id != join.commit_id)
    {
        return Err("bootstrap snapshot head does not cover the join".to_owned());
    }
    if let Some((session, event)) = forward_source {
        require_forward_source(state, session, event, located).await?;
    }
    state
        .authority_commits()
        .install_replica_anchor(&ReplicaAnchorInstall {
            realm_id: realm_id.clone(),
            join_commit_id: join.commit_id.clone(),
            governance_generation: snapshot.governance_generation,
            snapshot_head: head.clone(),
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
            verified_snapshot: snapshot.clone(),
        })
        .await
        .map_err(temporary)?;
    tracing::info!(%realm_id, anchor_position = head.stream_position,
        "held Realm replica anchored on its bootstrap snapshot");
    Ok(head)
}

/// Pull every Commit after the held head from the governing Station and
/// store it in order, until the peer scan reports no more.
async fn fill_to_head(
    state: &AppState,
    realm_id: &RealmId,
    governance: &DidCoreId,
    anchored: &CommitStreamHead,
    located: &mut LocatedRealmAuthority,
) -> Result<(), String> {
    let realm_stream = anchored.stream_ref.clone();
    loop {
        let mut held = state
            .authority_commits()
            .held_stream_head_commit(&realm_stream)
            .await
            .map_err(temporary)?
            .ok_or("the held Realm stream has no head")?;
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: realm_stream.clone(),
            direction: StreamScanDirection::After(Some(held.stream_position)),
            limit: SCAN_PAGE_LIMIT,
        };
        let body = post_peer(state, governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
        let page: arkret_models_collaboration::authority_commit::PeerStreamScanOutcome =
            serde_json::from_slice(&body).map_err(temporary)?;
        page.validate_for_request(&request).map_err(temporary)?;
        if page.committed_events.is_empty() {
            return Ok(());
        }
        for item in &page.committed_events {
            let fact = page
                .producer_signer_facts
                .iter()
                .find(|entry| entry.target.commit_id == item.commit().commit_id)
                .map(|entry| &entry.producer_signer_fact);
            store_scanned(
                state,
                realm_id,
                anchored,
                located,
                &held,
                item,
                ScannedItemEvidence {
                    producer_signer_fact: fact,
                    exact_self_result_account: None,
                },
            )
            .await?;
            held = item.commit().clone();
        }
        if !page.truncated {
            return Ok(());
        }
    }
}

/// Resolve only one frozen submission through an already authorized held stream.
/// The acknowledgement is not a replay floor or an installed current cut.
/// A bounded attempt may retain valid predecessors; it never installs a withheld target.
pub(crate) async fn ensure_forwarded_target(
    state: &AppState,
    governance: &DidCoreId,
    event: &arkret_wire::Event,
    expected: Option<&RealmCommit>,
    located: &mut LocatedRealmAuthority,
    session: &coland_services::identity::SessionIdentityState,
) -> Result<Option<RealmCommit>, String> {
    const MAX_PAGES: usize = 16;
    const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
    let stream = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
        .map_err(temporary)?;
    if located.authority.realm_id() != &event.realm_id
        || located.authority.current_service_id() != governance
    {
        return Err("forward recovery names another governing authority".into());
    }
    let commits = state.authority_commits();
    // The original Accepted is not a replica. Only the host's own opening join
    // may acquire its original through the governor's existing member scan.
    let mut total_bytes = 0usize;
    let mut pages_left = MAX_PAGES;
    let anchor = match commits
        .replica_anchor_for_stream(&stream)
        .await
        .map_err(temporary)?
    {
        Some(anchor) if anchor.anchored_head.is_some() => {
            let accepted_own_join = expected.is_some_and(|commit| {
                commit != &anchor.join_commit
                    && super::committed_replication::hosted_member_join(state, event, commit)
                        .is_some_and(|member| {
                            event.actor_id.as_account_id() == Some(&member)
                                && session
                                    .session_grant
                                    .as_ref()
                                    .map(|grant| &grant.account_id)
                                    == Some(&member)
                        })
            });
            if accepted_own_join {
                // A rejoin may reopen after all hosted members left. Acquire
                // its exact authorized Full, then let the locked installer
                // decide whether this is an opening or a direct successor.
                open_forwarded_join(
                    state,
                    governance,
                    event,
                    expected,
                    located,
                    session,
                    Some(anchor),
                    &mut pages_left,
                    &mut total_bytes,
                    MAX_TOTAL_BYTES,
                )
                .await?
            } else {
                anchor
            }
        }
        prior => {
            open_forwarded_join(
                state,
                governance,
                event,
                expected,
                located,
                session,
                prior,
                &mut pages_left,
                &mut total_bytes,
                MAX_TOTAL_BYTES,
            )
            .await?
        }
    };
    let anchored = anchor
        .anchored_head
        .as_ref()
        .ok_or("forward recovery replica anchor is not installed")?;
    if anchored.stream_ref != stream
        || anchor.member_account_id.station_id != state.service_core_id()
    {
        return Err("forward recovery anchor is not hosted on this exact stream".into());
    }
    for attempt in 0..=pages_left {
        require_forward_source(state, session, event, located).await?;
        if let Some(original) = commits
            .committed_event(&event.event_id)
            .await
            .map_err(temporary)?
        {
            if original.event != *event || expected.is_some_and(|c| c != &original.commit) {
                return Err("forward recovery conflicts with the exact accepted original".into());
            }
            let held = commits
                .held_stream_head_commit(&stream)
                .await
                .map_err(temporary)?
                .ok_or("forward recovery has no held head")?;
            if held.stream_position < original.commit.stream_position
                || (held.stream_position == original.commit.stream_position
                    && held.commit_id != original.commit.commit_id)
            {
                return Err("forward recovery original is not covered by the held prefix".into());
            }
            let fact = commits
                .producer_signer_fact(&original.event, &original.commit)
                .await
                .map_err(temporary)?;
            ensure_historical_method_key(state, located, &original.commit.signature).await?;
            verify_committed_event_receipt_with_source(
                state.persistence(),
                &original.event,
                &original.commit,
                CommitContinuity::Standalone,
                &located.authority,
                &located.keys,
                &state.service_core_id(),
                state
                    .projections()
                    .realm_digest_suite(event.realm_id.as_str()),
                fact.as_ref(),
            )
            .await
            .map_err(temporary)?;
            require_forward_source(state, session, event, located).await?;
            require_forward_bound_result_visibility(
                state,
                event,
                &original.commit,
                expected,
                session,
            )
            .await?;
            require_forward_source(state, session, event, located).await?;
            return Ok(Some(original.commit));
        }
        let mut held = commits
            .held_stream_head_commit(&stream)
            .await
            .map_err(temporary)?
            .ok_or("forward recovery has no held head")?;
        if expected.is_some_and(|target| held.stream_position >= target.stream_position) {
            // A snapshot may cover the position without containing its Full original.
            return Err("forward target Full is absent below the held head".into());
        }
        if attempt == pages_left {
            return Err("forward recovery page budget exhausted".into());
        }
        let request = StreamScanRequest {
            realm_id: event.realm_id.clone(),
            stream_ref: stream.clone(),
            direction: StreamScanDirection::After(Some(held.stream_position)),
            limit: SCAN_PAGE_LIMIT,
        };
        let body = post_peer(state, governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
        require_forward_source(state, session, event, located).await?;
        total_bytes = total_bytes
            .checked_add(body.len())
            .ok_or("forward recovery byte budget overflow")?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err("forward recovery byte budget exhausted".into());
        }
        let page: arkret_models_collaboration::authority_commit::PeerStreamScanOutcome =
            serde_json::from_slice(&body).map_err(temporary)?;
        page.validate_for_request(&request).map_err(temporary)?;
        for item in &page.committed_events {
            let commit = item.commit();
            if expected.is_some_and(|target| commit.stream_position > target.stream_position) {
                return Err("forward target is absent from the authorized prefix".into());
            }
            let fact = page
                .producer_signer_facts
                .iter()
                .find(|entry| entry.target.commit_id == commit.commit_id)
                .map(|entry| &entry.producer_signer_fact);
            let is_target = validate_forward_scan_target(item, event, expected)?;
            if is_target {
                let CommittedEventView::Full(full) = item else {
                    unreachable!("the target validator requires Full");
                };
                ensure_historical_method_key(state, located, &commit.signature).await?;
                verify_committed_event_receipt_with_source(
                    state.persistence(),
                    &full.event,
                    commit,
                    CommitContinuity::After(&held),
                    &located.authority,
                    &located.keys,
                    &state.service_core_id(),
                    state
                        .projections()
                        .realm_digest_suite(event.realm_id.as_str()),
                    fact,
                )
                .await
                .map_err(temporary)?;
                require_forward_source(state, session, event, located).await?;
                // Retain the original acknowledgement before installing its Full.
                commits
                    .retain_forwarded_acceptance(event, commit, crate::wire::now())
                    .await
                    .map_err(temporary)?;
            }
            require_forward_source(state, session, event, located).await?;
            let own_circle_leave = if is_target
                && expected == Some(commit)
                && event.kind == arkret_wire::EventKind::CircleMemberState
            {
                let payload: arkret_models_collaboration::events_payloads::CircleMemberStatePayload =
                    serde_json::from_value(serde_json::to_value(&event.payload).map_err(temporary)?)
                        .map_err(temporary)?;
                session.session_grant.as_ref().filter(|_| {
                    payload.membership == arkret_models_collaboration::governance::circle::CircleMembership::Leave
                        && payload.member_id == event.actor_id
                }).map(|grant| &grant.account_id)
                    .filter(|account| event.actor_id.as_account_id() == Some(*account))
            } else {
                None
            };
            store_scanned(
                state,
                &event.realm_id,
                anchored,
                located,
                &held,
                item,
                ScannedItemEvidence {
                    producer_signer_fact: fact,
                    exact_self_result_account: own_circle_leave,
                },
            )
            .await?;
            require_forward_source(state, session, event, located).await?;
            held = commit.clone();
            if is_target {
                require_forward_bound_result_visibility(state, event, commit, expected, session)
                    .await?;
                require_forward_source(state, session, event, located).await?;
                return Ok(Some(commit.clone()));
            }
        }
        if !page.truncated {
            return if expected.is_some() {
                Err("accepted forward target is not available at this authorized cut".into())
            } else {
                Ok(None)
            };
        }
    }
    Err("forward recovery page budget exhausted".into())
}

/// Acquire only an already Accepted, exact own opening join. No acknowledgement
/// becomes a Full row: the existing governor scan must disclose that original
/// and its immutable fact. Other page items are never installed here.
async fn open_forwarded_join(
    state: &AppState,
    governance: &DidCoreId,
    event: &arkret_wire::Event,
    expected: Option<&RealmCommit>,
    located: &mut LocatedRealmAuthority,
    session: &coland_services::identity::SessionIdentityState,
    prior: Option<ReplicaStreamAnchor>,
    pages_left: &mut usize,
    total_bytes: &mut usize,
    max_total_bytes: usize,
) -> Result<ReplicaStreamAnchor, String> {
    let commit = expected.ok_or("forward recovery has no authorized replica anchor")?;
    // The same hosted opening-join classifier used by committed replication
    // includes Circle joins. Their parent Realm revision is rechecked by the
    // transactional OpeningJoin installer before it can create an anchor.
    let member = super::committed_replication::hosted_member_join(state, event, commit)
        .ok_or("forward recovery is not a hosted opening join")?;
    if event.actor_id.as_account_id() != Some(&member)
        || session
            .session_grant
            .as_ref()
            .map(|grant| &grant.account_id)
            != Some(&member)
    {
        return Err("forward opening join does not bind the exact session Account".into());
    }
    require_forward_source(state, session, event, located).await?;
    let commits = state.authority_commits();
    let held_fallback = prior
        .as_ref()
        .filter(|anchor| {
            anchor.join_commit != *commit
                && anchor.join_commit.stream_ref == commit.stream_ref
                && anchor.member_account_id.station_id == state.service_core_id()
                && anchor
                    .anchored_head
                    .as_ref()
                    .is_some_and(|head| head.stream_ref == commit.stream_ref)
        })
        .cloned();
    let anchor = if let Some(anchor) = prior.filter(|_| held_fallback.is_none()) {
        if anchor.member_account_id != member || anchor.join_commit != *commit {
            return Err("forward opening join differs from the pending anchor".into());
        }
        let original = commits
            .committed_event(&event.event_id)
            .await
            .map_err(temporary)?
            .ok_or("pending opening join has no Full original")?;
        if original.event != *event || original.commit != *commit {
            return Err("pending opening join differs from its frozen Full".into());
        }
        let fact = commits
            .producer_signer_fact(&original.event, &original.commit)
            .await
            .map_err(temporary)?;
        ensure_historical_method_key(state, located, &commit.signature).await?;
        verify_committed_event_receipt_with_source(
            state.persistence(),
            &original.event,
            &original.commit,
            CommitContinuity::Standalone,
            &located.authority,
            &located.keys,
            &state.service_core_id(),
            state
                .projections()
                .realm_digest_suite(event.realm_id.as_str()),
            fact.as_ref(),
        )
        .await
        .map_err(temporary)?;
        require_forward_source(state, session, event, located).await?;
        anchor
    } else {
        // A rejoin can follow an interval this peer could never read. Seek the
        // exact accepted join through the registered authorized scan; this
        // selector is not a replay floor. The locked installer still decides
        // whether it may open a new interval or requires direct succession.
        if *pages_left == 0 {
            return Err("forward recovery page budget exhausted".into());
        }
        *pages_left -= 1;
        let mut original = None;
        {
            let request = StreamScanRequest {
                realm_id: event.realm_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                direction: StreamScanDirection::Before(Some(
                    commit
                        .stream_position
                        .checked_add(1)
                        .ok_or("opening target position overflow")?,
                )),
                limit: 1,
            };
            let body = post_peer(state, governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
            require_forward_source(state, session, event, located).await?;
            *total_bytes = total_bytes
                .checked_add(body.len())
                .ok_or("forward recovery byte budget overflow")?;
            if *total_bytes > max_total_bytes {
                return Err("forward recovery byte budget exhausted".into());
            }
            let page: arkret_models_collaboration::authority_commit::PeerStreamScanOutcome =
                serde_json::from_slice(&body).map_err(temporary)?;
            page.validate_for_request(&request).map_err(temporary)?;
            for item in &page.committed_events {
                if item.commit().stream_position > commit.stream_position {
                    return Err("opening target is absent from the authorized page".into());
                }
                if validate_forward_scan_target(item, event, Some(commit))? {
                    let CommittedEventView::Full(full) = item else {
                        unreachable!("exact target must be Full");
                    };
                    let fact = page
                        .producer_signer_facts
                        .iter()
                        .find(|entry| entry.target.commit_id == commit.commit_id)
                        .map(|entry| entry.producer_signer_fact.clone());
                    ensure_historical_method_key(state, located, &commit.signature).await?;
                    require_forward_source(state, session, event, located).await?;
                    verify_committed_event_receipt_with_source(
                        state.persistence(),
                        &full.event,
                        &full.commit,
                        CommitContinuity::Standalone,
                        &located.authority,
                        &located.keys,
                        &state.service_core_id(),
                        state
                            .projections()
                            .realm_digest_suite(event.realm_id.as_str()),
                        fact.as_ref(),
                    )
                    .await
                    .map_err(temporary)?;
                    require_forward_source(state, session, event, located).await?;
                    original = Some((full.clone(), fact));
                    break;
                }
            }
        }
        let (full, fact) = original.ok_or("opening target is absent from the authorized page")?;
        require_forward_source(state, session, event, located).await?;
        let installed = commits
            .install_committed_replica(&CommittedReplica {
                local_service_id: state.service_core_id(),
                authority: located.current_authority(),
                event: full.event,
                commit: full.commit,
                producer_signer_fact: fact,
                genesis_event_ref: None,
                role: CommittedReplicaRole::OpeningJoin {
                    member_account_id: member.clone(),
                },
                received_at: crate::wire::now(),
                welcomes: Vec::new(),
            })
            .await;
        if let Err(error) = installed {
            if error.conflict_code() == Some(coland_storage::ConflictCode::DependencyMissing)
                && let Some(anchor) = held_fallback
            {
                // Another hosted member may still authorize the old interval.
                // The failed transaction wrote nothing; continue through the
                // ordinary contiguous scan rather than skipping its gap.
                require_forward_source(state, session, event, located).await?;
                return Ok(anchor);
            }
            return Err(temporary(error));
        }
        require_forward_source(state, session, event, located).await?;
        let anchor = commits
            .replica_anchor_for_stream(&commit.stream_ref)
            .await
            .map_err(temporary)?
            .ok_or("verified opening join created no pending anchor")?;
        // The installer may retain the existing anchor when another hosted
        // member is still joined. In that case it required direct succession
        // rather than opening a new interval; the ordinary held-prefix and
        // exact target checks below remain mandatory.
        anchor
    };
    require_forward_source(state, session, event, located).await?;
    // Preserve the existing nonce-bound bundle, Snapshot/floor/head/current
    // validator. A failed bootstrap leaves only the legitimate pending join.
    if anchor.anchored_head.is_none() {
        anchor_stream_with_forward_source(
            state,
            &anchor,
            governance,
            located,
            Some((session, event)),
        )
        .await?;
        require_forward_source(state, session, event, located).await?;
    }
    commits
        .replica_anchor_for_stream(&commit.stream_ref)
        .await
        .map_err(temporary)?
        .ok_or_else(|| "verified opening join lost its anchor".into())
}

/// Coordinate and original-content gate only. Cryptographic and disclosure
/// checks remain mandatory before the caller can retain or install the target.
pub(super) fn validate_forward_scan_target(
    item: &CommittedEventView,
    event: &arkret_wire::Event,
    expected: Option<&RealmCommit>,
) -> Result<bool, String> {
    let commit = item.commit();
    if expected
        .is_some_and(|target| target.stream_position == commit.stream_position && target != commit)
    {
        return Err("forward target coordinate conflicts with its accepted acknowledgement".into());
    }
    if commit.event_ref != event.event_id {
        return Ok(false);
    }
    let CommittedEventView::Full(full) = item else {
        return Err("forward target is withheld at the authorized cut".into());
    };
    if full.event != *event || expected.is_some_and(|target| target != commit) {
        return Err("forward target differs from the frozen original".into());
    }
    Ok(true)
}

async fn require_forward_source(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    event: &arkret_wire::Event,
    located: &LocatedRealmAuthority,
) -> Result<(), String> {
    super::authority_forward::validate_recovery_caller(state, session, event)
        .await
        .map_err(temporary)?;
    require_forward_authority(state, located).await
}

async fn require_forward_authority(
    state: &AppState,
    located: &LocatedRealmAuthority,
) -> Result<(), String> {
    let current = state
        .authority_commits()
        .current_authority(located.authority.realm_id())
        .await
        .map_err(temporary)?;
    if current.as_ref() != Some(&located.current_authority()) {
        return Err("forward recovery governing tenure changed".into());
    }
    Ok(())
}

/// A terminal own submission remains a bound write outcome. Installing its
/// leave must not demand the ordinary joined-member read it just terminated.
/// This is not a scan/get/key-query authorization exception.
async fn require_forward_bound_result_visibility(
    state: &AppState,
    event: &arkret_wire::Event,
    commit: &RealmCommit,
    expected: Option<&RealmCommit>,
    session: &coland_services::identity::SessionIdentityState,
) -> Result<(), String> {
    super::authority_forward::validate_recovery_caller(state, session, event)
        .await
        .map_err(temporary)?;
    if expected == Some(commit) {
        let account = &session
            .session_grant
            .as_ref()
            .ok_or("bound leave recovery lacks an authenticated grant")?
            .account_id;
        if state
            .authority_commits()
            .accepted_own_leave_bound_result(event, commit, account, &state.service_core_id())
            .await
            .map_err(temporary)?
        {
            super::authority_forward::validate_recovery_caller(state, session, event)
                .await
                .map_err(temporary)?;
            return Ok(());
        }
    }
    require_forward_visibility(state, event, commit).await
}

async fn require_forward_visibility(
    state: &AppState,
    event: &arkret_wire::Event,
    commit: &RealmCommit,
) -> Result<(), String> {
    let account = event
        .actor_id
        .as_account_id()
        .ok_or("forward recovery producer is not a full Account")?;
    if account.station_id != state.service_core_id() {
        return Err("forward recovery producer is not hosted here".into());
    }
    let request = StreamScanRequest {
        realm_id: event.realm_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        direction: StreamScanDirection::Before(Some(
            commit
                .stream_position
                .checked_add(1)
                .ok_or("forward target position overflow")?,
        )),
        limit: 1,
    };
    match state
        .authority_commits()
        .scan_stream_for_account(&request, account, &state.service_core_id())
        .await
        .map_err(temporary)?
    {
        coland_storage::AccountStreamScan::Page(page) if page.committed_events.len() == 1 => {
            match &page.committed_events[0] {
                CommittedEventView::Full(full)
                    if full.event == *event && full.commit == *commit =>
                {
                    Ok(())
                }
                _ => Err("forward target is not exactly visible to its original Account".into()),
            }
        }
        _ => Err("forward target visibility is not available to its original Account".into()),
    }
}

struct ScannedItemEvidence<'a> {
    producer_signer_fact:
        Option<&'a arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
    exact_self_result_account: Option<&'a arkret_wire::AccountId>,
}

async fn store_scanned(
    state: &AppState,
    realm_id: &RealmId,
    anchored: &CommitStreamHead,
    located: &mut LocatedRealmAuthority,
    held: &RealmCommit,
    item: &CommittedEventView,
    evidence: ScannedItemEvidence<'_>,
) -> Result<(), String> {
    let fact = evidence.producer_signer_fact;
    let commit = item.commit();
    ensure_historical_method_key(state, located, &commit.signature).await?;
    let commits = state.authority_commits();
    match item {
        CommittedEventView::Full(view) => {
            verify_committed_event_receipt_with_source(
                state.persistence(),
                &view.event,
                commit,
                CommitContinuity::After(held),
                &located.authority,
                &located.keys,
                &state.service_core_id(),
                state.projections().realm_digest_suite(realm_id.as_str()),
                fact,
            )
            .await
            .map_err(temporary)?;
            let outcome = commits
                .install_committed_replica(&CommittedReplica {
                    local_service_id: state.service_core_id(),
                    authority: located.current_authority(),
                    event: view.event.clone(),
                    commit: commit.clone(),
                    producer_signer_fact: fact.cloned(),
                    genesis_event_ref: None,
                    role: evidence.exact_self_result_account.map_or(
                        CommittedReplicaRole::HeldStream,
                        |account| CommittedReplicaRole::AcceptedOwnCircleLeave {
                            member_account_id: account.clone(),
                        },
                    ),
                    received_at: crate::wire::now(),
                    // A scanned item carries no Welcome; its item's
                    // committed replication queues them.
                    welcomes: Vec::new(),
                })
                .await
                .map_err(temporary)?;
            // The prefix up to the anchor snapshot is history that precedes
            // this Station's hosted join; only a Commit after the anchor is
            // a live source Event for its accounts' notifications.
            if matches!(outcome, coland_storage::CommittedReplicaOutcome::Stored)
                && commit.stream_position > anchored.stream_position
            {
                crate::routing::events::notify::dispatch_committed_event_notifications(
                    state,
                    &view.event,
                )
                .await;
            }
        }
        CommittedEventView::Withheld(_) => {
            located
                .authority
                .verify_commit(commit, &located.keys)
                .map_err(temporary)?;
            commit.validate_successor_of(held).map_err(temporary)?;
            commits
                .install_committed_chain_node(&CommittedChainNode {
                    local_service_id: state.service_core_id(),
                    authority: located.current_authority(),
                    commit: commit.clone(),
                })
                .await
                .map_err(temporary)?;
        }
    }
    tracing::debug!(%realm_id, position = commit.stream_position,
        prefix = commit.stream_position <= anchored.stream_position,
        "held Realm replica filled one position");
    Ok(())
}
