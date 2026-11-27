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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use arkret_models_collaboration::governance::realm_join_bootstrap::RealmJoinBootstrapAssembly;
use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapRequestBody, PeerRealmJoinBootstrapResponseBody,
};
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventView, DidCoreId, RealmCommit, RealmId,
    RequestId, StreamScanDirection, StreamScanRequestBody,
};
use coland_services::committed_receipt::{
    CommitContinuity, ReceivedProducer, verify_committed_event_receipt_with_source,
};
use coland_storage::{
    CommittedChainNode, CommittedReplica, CommittedReplicaRole, ReplicaAnchorInstall,
    ReplicaStreamAnchor,
};

use super::AppState;
use crate::routing::realm_join::LocatedRealmAuthority;

async fn verify_native_genesis_producer(
    state: &AppState,
    original: &arkret_wire::CommittedEventFullView,
) -> Result<(), String> {
    use arkret_models_identity::{
        HistoricalSignerKeyQuerySender, SignerKeyQuerySelector, SignerKeyResolution,
    };
    let event = &original.event;
    let unavailable = "bootstrap native Genesis producer authorization is unavailable";
    if event.actual_signer().as_account_id().is_none() {
        return Err(unavailable.to_owned());
    }
    let proof = event.producer_proof.as_ref().ok_or(unavailable)?;
    let selector = SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::Agent {
            actor: event.actual_signer().clone(),
            verification_method: proof.verification_method.clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: original.commit.commit_id.clone(),
                stream_ref: original.commit.stream_ref.clone(),
                stream_position: original.commit.stream_position,
            },
        },
    };
    // Only an immutable native source retained at this exact accepted target
    // may supply authorization. Current keys and projections are not sources.
    let resolution = state
        .authority_commits()
        .historical_producer_signer_key(&event.realm_id, &selector)
        .await
        .map_err(temporary)?
        .ok_or(unavailable)?;
    if resolution.selector() != &selector {
        return Err(unavailable.to_owned());
    }
    resolution.validate(&event.realm_id).map_err(temporary)?;
    let SignerKeyResolution::HistoricalResolved { key, .. } = resolution else {
        return Err(unavailable.to_owned());
    };
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(key.public_key_base64url.as_str())
            .map_err(temporary)?,
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(temporary)?,
        &event.actor_id,
        &material,
        event.realm_id.digest_suite_code().digest_suite(),
    )
    .map_err(temporary)
}

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
type ConvergenceGate = tokio::sync::Mutex<()>;
static REALM_CONVERGENCE: LazyLock<Mutex<BTreeMap<(String, String), Weak<ConvergenceGate>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn realm_convergence_gate(
    state: &AppState,
    stream: &CommitStreamRef,
) -> Option<Arc<ConvergenceGate>> {
    let mut gates = REALM_CONVERGENCE.lock().ok()?;
    gates.retain(|_, gate| gate.strong_count() > 0);
    let key = (state.service_id().to_owned(), stream.realm_id().to_string());
    if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
        return Some(gate);
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    gates.insert(key, Arc::downgrade(&gate));
    Some(gate)
}

struct ConvergenceInFlight((String, String));

impl Drop for ConvergenceInFlight {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = IN_FLIGHT.lock() {
            in_flight.remove(&self.0);
        }
    }
}

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
    let in_flight = ConvergenceInFlight(key);
    let state = state.clone();
    tokio::spawn(async move {
        let _in_flight = in_flight;
        if let Err(reason) = converge(&state, &stream).await {
            tracing::warn!(?stream, %reason, "held replica did not converge");
        }
    });
}

/// Let live tests settle replication before measuring another delivery rail.
#[cfg(test)]
pub(super) async fn wait_for_converge_stream(state: &AppState, stream: &CommitStreamRef) {
    let key = (
        state.service_id().to_owned(),
        arkret_canonical::canonical_json_string(stream).unwrap(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if !IN_FLIGHT.lock().unwrap().contains(&key) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("replica convergence must settle before the receipt-only snapshot");
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
    fill_to_head(state, realm_id, &governance, &anchored, &mut located, None).await?;
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
                    return fill_to_head(
                        state,
                        realm_id,
                        &governance,
                        &refreshed,
                        &mut located,
                        None,
                    )
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
/// replica folding remains the only source of local current state. The read
/// binds its known heads before the network round trip, then rechecks the
/// original disclosure against the current durable replica cut.
pub(crate) async fn refresh_account_snapshot(
    state: &AppState,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> Result<arkret_wire::RealmStateSnapshot, String> {
    let (snapshot, mut located, material, genesis_original) =
        verified_account_snapshot(state, realm_id, account).await?;
    let refresh = async {
        complete_snapshot_tails(state, &snapshot, &material, &mut located).await?;
        state
            .authority_commits()
            .install_verified_account_bootstrap_snapshot(
                account,
                &state.service_core_id(),
                &snapshot,
                &material,
                &genesis_original,
            )
            .await
            .map_err(temporary)
    }
    .await;
    let issued = match refresh {
        Ok(issued) => issued,
        Err(error) => {
            for head in &snapshot.visible_stream_heads {
                if matches!(head.stream_ref, CommitStreamRef::Realm { .. })
                    || !material.visible_stream_heads.contains(head)
                {
                    spawn_converge_stream(state, head.stream_ref.clone());
                }
            }
            return Err(temporary(error));
        }
    };
    // Same-cut issuance may retain an earlier signed original. Verify that
    // actual object under this read's fresh authority before emitting its ID.
    verify_snapshot(state, &mut located, &issued).await?;
    spawn_history_originals(
        state,
        account,
        &issued,
        &material,
        located.authority.current_service_id(),
    );
    Ok(issued)
}

/// Recover missing Reaction current from the exact held reader's current
/// governing Snapshot. This is a native Station baseline install, not a
/// history scan and not an ordinary client's Event reducer.
pub(crate) async fn refresh_reaction_current_baseline(
    state: &AppState,
    required: &arkret_wire::RealmCommit,
) -> Result<(), String> {
    let commits = state.authority_commits();
    let anchor = commits
        .replica_anchor_for_stream(&required.stream_ref)
        .await
        .map_err(temporary)?
        .ok_or("Reaction current has no held reader anchor")?;
    if anchor.realm_id != required.realm_id
        || anchor.member_account_id.station_id != state.service_core_id()
    {
        return Err("Reaction baseline reader does not bind this hosted Realm".into());
    }
    let readers = commits
        .replica_bootstrap_readers(&required.stream_ref, &state.service_core_id())
        .await
        .map_err(temporary)?;
    if !readers.iter().any(|(account, join)| {
        account == &anchor.member_account_id && join.commit_id == anchor.join_commit.commit_id
    }) {
        return Err("Reaction baseline's exact hosted opening join is no longer current".into());
    }
    let governance = commits
        .current_authority(&required.realm_id)
        .await
        .map_err(temporary)?
        .ok_or("Reaction baseline has no governing authority")?
        .service_id;
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &required.realm_id,
        &governance,
    )
    .await
    .map_err(|error| error.message)?;
    // The existing bootstrap validates this exact Account's membership,
    // scope, floors, authority tenure and whole original before atomically
    // installing current plus its stream cut. It does not first replay the
    // unknown reaction whose current is precisely what needs recovery.
    anchor_stream(state, &anchor, &governance, &mut located).await?;
    let head = commits
        .replica_authorization_head(&required.stream_ref)
        .await
        .map_err(temporary)?
        .ok_or("Reaction complete Snapshot did not establish this stream's current cut")?;
    if head.stream_position < required.stream_position
        || (head.stream_position == required.stream_position
            && head.commit_id != required.commit_id)
    {
        return Err(
            "Reaction complete Snapshot does not cover the required accepted Commit".into(),
        );
    }
    Ok(())
}

/// Optional history preparation must not delay a valid full recovery response.
/// Coalesce by complete Account and Realm; later reads may retry a failed cut.
fn spawn_history_originals(
    state: &AppState,
    account: &arkret_wire::AccountId,
    issued: &arkret_wire::RealmStateSnapshot,
    material: &coland_storage::RealmStateSnapshotMaterial,
    governor: &DidCoreId,
) {
    let key = (
        state.service_id().to_owned(),
        arkret_canonical::canonical_json_string(&("history", account, &issued.realm_id))
            .unwrap_or_default(),
    );
    {
        let Ok(mut in_flight) = IN_FLIGHT.lock() else {
            return;
        };
        if !in_flight.insert(key.clone()) {
            return;
        }
    }
    let in_flight = ConvergenceInFlight(key);
    let (state, account, issued, material, governor) = (
        state.clone(),
        account.clone(),
        issued.clone(),
        material.clone(),
        governor.clone(),
    );
    tokio::spawn(async move {
        let _in_flight = in_flight;
        prepare_history_originals(&state, &account, &issued, &material, governor).await;
    });
}

async fn prepare_history_originals(
    state: &AppState,
    account: &arkret_wire::AccountId,
    issued: &arkret_wire::RealmStateSnapshot,
    material: &coland_storage::RealmStateSnapshotMaterial,
    governor: DidCoreId,
) {
    for head in &issued.visible_stream_heads {
        if let Err(reason) =
            prepare_history_original(state, account, issued, material, &governor, head).await
        {
            tracing::debug!(%reason, realm_id=%issued.realm_id, "history original not prepared; full recovery retained");
        }
    }
}

async fn prepare_history_original(
    state: &AppState,
    account: &arkret_wire::AccountId,
    issued: &arkret_wire::RealmStateSnapshot,
    material: &coland_storage::RealmStateSnapshotMaterial,
    governor: &DidCoreId,
    head: &CommitStreamHead,
) -> Result<(), String> {
    let realm_id = &issued.realm_id;
    let membership_commit_id = material
        .current_state_entries
        .iter()
        .find_map(|row| {
            let arkret_wire::CurrentState::Value {
                selector, revision, ..
            } = row;
            match selector {
                arkret_wire::CurrentSelector::MemberState { actor_id }
                    if actor_id.as_account_id() == Some(account) =>
                {
                    Some(revision.commit_id.clone())
                }
                _ => None,
            }
        })
        .ok_or("missing current member join")?;
    let request = PeerRealmJoinBootstrapRequestBody {
        request_id: RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .map_err(temporary)?,
        realm_id: realm_id.clone(),
        member_account_id: account.clone(),
        membership_commit_id,
        content_intent: None,
        history_stream_ref: Some(head.stream_ref.clone()),
    };
    let body = post_peer(
        state,
        governor,
        BOOTSTRAP_PATH,
        &request,
        BOOTSTRAP_MAX_BYTES,
    )
    .await?;
    let outcome: PeerRealmJoinBootstrapResponseBody =
        serde_json::from_slice(&body).map_err(temporary)?;
    let history = &outcome.snapshot;
    request
        .validate_history_snapshot(history)
        .map_err(temporary)?;
    if outcome.request_id != request.request_id
        || outcome.visible_stream_heads != history.visible_stream_heads
    {
        return Err("history response differs from requested coverage".into());
    }
    if history.governance_generation != issued.governance_generation
        || history
            .visible_stream_heads
            .iter()
            .any(|h| !issued.visible_stream_heads.contains(h))
    {
        return Ok::<(), String>(());
    }
    let nonce = crate::routing::realm_join::nonce_for_request(&request.request_id)
        .map_err(|e| e.message)?;
    let mut served = crate::routing::realm_join::verify_served_bundle(
        state,
        outcome.authority_bundle.clone(),
        &nonce,
    )
    .await
    .map_err(|e| e.message)?;
    let genesis_original = (
        verify_bootstrap_genesis(state, &outcome, &mut served).await?,
        outcome.producer_signer_fact.clone(),
    );
    verify_snapshot(state, &mut served, history).await?;
    complete_snapshot_tails(state, history, material, &mut served).await?;
    state
        .authority_commits()
        .install_verified_account_bootstrap_snapshot(
            account,
            &state.service_core_id(),
            history,
            material,
            &genesis_original,
        )
        .await
        .map_err(temporary)?;
    Ok(())
}

/// Pull only the missing tails of this already verified original. Re-fetching
/// a newer Snapshot after every replica lag can starve a continuously busy
/// stream. This retains real authenticated chain nodes, never invented heads.
#[inline(never)]
fn complete_snapshot_tails<'a>(
    state: &'a AppState,
    snapshot: &'a arkret_wire::RealmStateSnapshot,
    minimum: &'a coland_storage::RealmStateSnapshotMaterial,
    located: &'a mut LocatedRealmAuthority,
) -> std::pin::Pin<Box<impl std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let governance = located.authority.current_service_id().clone();
        for target in &snapshot.visible_stream_heads {
            if minimum.visible_stream_heads.contains(target) {
                continue;
            }
            let anchor = state
                .authority_commits()
                .replica_anchor_for_stream(&target.stream_ref)
                .await
                .map_err(temporary)?
                .and_then(|anchor| anchor.anchored_head)
                .ok_or("the disclosed stream has no installed replica anchor")?;
            fill_to_head(
                state,
                &snapshot.realm_id,
                &governance,
                &anchor,
                located,
                Some(target),
            )
            .await?;
        }
        Ok(())
    })
}

/// Verify the current disclosure without archiving or installing its cut.
async fn verified_account_snapshot(
    state: &AppState,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
) -> Result<
    (
        arkret_wire::RealmStateSnapshot,
        LocatedRealmAuthority,
        coland_storage::RealmStateSnapshotMaterial,
        (
            arkret_wire::CommittedEventFullView,
            Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
        ),
    ),
    String,
> {
    use arkret_wire::{CurrentSelector, CurrentState};

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
        CurrentState::Value {
            selector: CurrentSelector::MemberState { actor_id }, source_stream_ref, value, ..
        } if actor_id == &actor && source_stream_ref == &realm_stream
            && serde_json::from_value::<arkret_wire::MemberStateValue>(value.clone())
                .is_ok_and(|member| member.membership == arkret_wire::MembershipState::Join)
    )).ok_or("the hosted Account has no accepted current opening join")?;
    let CurrentState::Value { revision, .. } = own_join;
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
        content_intent: None,
        history_stream_ref: None,
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
    let outcome: PeerRealmJoinBootstrapResponseBody =
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
    let genesis_original = (
        verify_bootstrap_genesis(state, &outcome, &mut located).await?,
        outcome.producer_signer_fact.clone(),
    );
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
    Ok((snapshot, located, material, genesis_original))
}

/// Prove recoverable lag through the current governor, without installing a
/// snapshot, predecessor, notification, or cursor. A low head alone is not proof.
pub(crate) async fn account_continuation_recoverable(
    state: &AppState,
    realm_id: &RealmId,
    account: &arkret_wire::AccountId,
    minimum_heads: &[CommitStreamHead],
) -> Result<bool, String> {
    const MAX_PAGES: usize = 16;
    const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
    let (snapshot, mut located, original_material, _genesis_original) =
        verified_account_snapshot(state, realm_id, account).await?;
    let governance = located.authority.current_service_id().clone();
    if governance == state.service_core_id() {
        return Err("a governor cannot prove lost history from its own incomplete store".into());
    }
    let commits = state.authority_commits();
    let mut pages_left = MAX_PAGES;
    let mut total_bytes = 0usize;
    let mut lag = false;
    let mut original_heads = Vec::new();
    for required in minimum_heads {
        let remote = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == required.stream_ref)
            .ok_or("the required stream is not currently disclosed")?;
        let floor = snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .find(|floor| floor.stream_ref == required.stream_ref)
            .ok_or("the required stream has no authenticated readable floor")?;
        let mut held = commits
            .held_stream_head_commit(&required.stream_ref)
            .await
            .map_err(temporary)?
            .ok_or("the required stream has no verified local prefix")?;
        if required.stream_ref.realm_id() != realm_id
            || remote.stream_position < required.stream_position
            || held.stream_position < floor.oldest_position
            || held.stream_position > remote.stream_position
            || (held.stream_position == remote.stream_position
                && held.commit_id != remote.commit_id)
        {
            return Err("the continuation is outside a provable recoverable prefix".into());
        }
        ensure_historical_method_key(state, &mut located, &held.signature).await?;
        located
            .authority
            .verify_commit(&held, &located.keys)
            .map_err(temporary)?;
        original_heads.push(held.clone());
        if held.stream_position >= required.stream_position {
            if !commits
                .account_continuation_heads_covered(
                    realm_id,
                    account,
                    std::slice::from_ref(required),
                )
                .await
                .map_err(temporary)?
            {
                return Err("the local continuation identity is missing or inconsistent".into());
            }
            continue;
        }
        lag = true;
        let mut target_verified = false;
        while held.stream_position < remote.stream_position {
            if pages_left == 0 {
                return Err("continuation recovery page budget exhausted".into());
            }
            pages_left -= 1;
            let request = StreamScanRequestBody {
                realm_id: realm_id.clone(),
                stream_ref: required.stream_ref.clone(),
                direction: StreamScanDirection::After(Some(held.stream_position)),
                limit: SCAN_PAGE_LIMIT,
            };
            let body = post_peer(state, &governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
            total_bytes = total_bytes
                .checked_add(body.len())
                .ok_or("continuation recovery byte budget overflow")?;
            if total_bytes > MAX_TOTAL_BYTES {
                return Err("continuation recovery byte budget exhausted".into());
            }
            let page: arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody =
                serde_json::from_slice(&body).map_err(temporary)?;
            page.validate_for_request(&request).map_err(temporary)?;
            if page.committed_events.is_empty() {
                return Err("the governor did not supply the recoverable tail".into());
            }
            for item in &page.committed_events {
                let commit = item.commit();
                if commit.stream_position > remote.stream_position {
                    break;
                }
                let fact = page
                    .producer_signer_facts
                    .iter()
                    .find(|entry| entry.target.commit_id == commit.commit_id)
                    .map(|entry| &entry.producer_signer_fact);
                ensure_historical_method_key(state, &mut located, &commit.signature).await?;
                match item {
                    CommittedEventView::Full(view) => {
                        verify_committed_event_receipt_with_source(
                            state.persistence(),
                            &view.event,
                            commit,
                            CommitContinuity::After(&held),
                            &located.authority,
                            &located.keys,
                            &state.service_core_id(),
                            state.projections().realm_digest_suite(realm_id.as_str()),
                            fact,
                        )
                        .await
                        .map_err(temporary)?;
                    }
                    CommittedEventView::Withheld(_) => {
                        located
                            .authority
                            .verify_commit(commit, &located.keys)
                            .map_err(temporary)?;
                        commit.validate_successor_of(&held).map_err(temporary)?;
                    }
                }
                if commit.stream_position == required.stream_position {
                    if commit.commit_id != required.commit_id {
                        return Err("the requested position belongs to another Commit".into());
                    }
                    target_verified = true;
                }
                held = commit.clone();
            }
            if !page.truncated && held.stream_position < remote.stream_position {
                return Err("the recoverable tail ended before the signed disclosure head".into());
            }
        }
        if !target_verified || held.commit_id != remote.commit_id {
            return Err(
                "the verified prefix does not reach both continuation and current cut".into(),
            );
        }
    }
    // Reject a tenure or held-prefix replacement during network verification.
    if commits
        .current_authority(realm_id)
        .await
        .map_err(temporary)?
        .as_ref()
        != Some(&located.current_authority())
    {
        return Err("the local authority changed during continuation verification".into());
    }
    for original in original_heads {
        if commits
            .held_stream_head_commit(&original.stream_ref)
            .await
            .map_err(temporary)?
            .as_ref()
            != Some(&original)
        {
            return Err("the local prefix changed during continuation verification".into());
        }
    }
    if commits
        .realm_state_snapshot_material_for_account(realm_id, account)
        .await
        .map_err(temporary)?
        .as_ref()
        != Some(&original_material)
    {
        return Err("the Account disclosure cut changed during continuation verification".into());
    }
    Ok(lag)
}

/// Intersect an issuer's home-qualified actions with fresh, exact group
/// replies. No result is retained for a later issuance, publication or page.
pub(crate) async fn foreign_content_ceiling(
    state: &AppState,
    issue: &coland_storage::AgentSessionAuthorityRequest,
    home: &coland_storage::HomeContentQueries,
) -> Result<coland_storage::AgentSessionAuthorityView, String> {
    use arkret_models_collaboration::governance::realm_join_intake::OwnedAgentContentResponse;
    let located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        &home.realm,
        &home.governor,
    )
    .await
    .map_err(|e| e.message)?;
    if located.authority.current_generation() != home.generation
        || located.authority.current_service_id() != &home.governor
    {
        return Err("hosted Realm tenure changed".into());
    }
    let mut view = coland_storage::AgentSessionAuthorityView {
        binding: issue.clone(),
        granted_scope: home.service_operations.clone(),
        approval_required: false,
        realm_ids: vec![],
        strand_ids: vec![],
        allowed_tracks: vec![],
        allowed_data_labels: vec![],
        allowed_endpoints: vec![],
        capability_grant_refs: vec![],
        policy_refs: vec![],
    };
    for intent in &home.intents {
        let query = PeerRealmJoinBootstrapRequestBody {
            request_id: RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
                .map_err(temporary)?,
            realm_id: home.realm.clone(),
            member_account_id: issue.agent_account_id.clone(),
            membership_commit_id: home.membership.clone(),
            history_stream_ref: None,
            content_intent: Some(intent.clone()),
        };
        let bytes = post_peer(
            state,
            &home.governor,
            BOOTSTRAP_PATH,
            &query,
            BOOTSTRAP_MAX_BYTES,
        )
        .await?;
        let reply: OwnedAgentContentResponse = serde_json::from_slice(&bytes).map_err(temporary)?;
        reply.validate_binding(&query).map_err(temporary)?;
        let d = reply.scope_details;
        if d.resources.realm_ids != issue.resource_scope.realm_ids
            || d.resources.strand_ids != issue.resource_scope.strand_ids
            || d.realm_ids != d.resources.realm_ids
            || d.strand_ids != d.resources.strand_ids
            || !d.constraints.allowed_tracks.is_empty()
            || !d.constraints.allowed_data_labels.is_empty()
            || !d.constraints.allowed_endpoints.is_empty()
            || d.constraints
                .allowed_strand_ids
                .as_ref()
                .is_some_and(|ids| ids != &d.strand_ids)
            || d.participations.is_some()
        {
            continue;
        }
        let refs = d
            .capability_grant_refs
            .into_iter()
            .map(arkret_wire::GrantId::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(temporary)?;
        // The flat issuer carrier cannot correlate distinct grant sets to individual actions.
        if (!view.realm_ids.is_empty() || !view.strand_ids.is_empty())
            && (view.capability_grant_refs != refs || view.policy_refs != d.policy_refs)
        {
            continue;
        }
        let action = serde_json::to_value(intent.action).map_err(temporary)?;
        view.granted_scope.push(
            action
                .as_str()
                .ok_or("content action is not a string")?
                .to_owned(),
        );
        view.realm_ids = d.realm_ids;
        view.strand_ids = d.strand_ids;
        view.capability_grant_refs = refs;
        view.policy_refs = d.policy_refs;
    }
    let current = state
        .persistence()
        .home_content_queries(issue)
        .await
        .map_err(temporary)?;
    if current.as_ref() != Some(home) {
        return Err("home authority changed during content issue".into());
    }
    Ok(view)
}

/// The caller owns the native delivery guard. A narrow bootstrap establishes
/// the member generation's floor. Only the subsequent live scan supplies bytes.
pub(crate) async fn verify_foreign_project_history(
    state: &AppState,
    governor: &DidCoreId,
    session: &coland_services::identity::SessionIdentityState,
    local_secret: &str,
    query: &arkret_models_collaboration::authority_commit::OwnedAgentStreamScanRequestBody,
    guard: &mut dyn coland_storage::HostedAgentHistoryRead,
    archived: Option<&arkret_wire::RealmStateSnapshot>,
) -> Result<LocatedRealmAuthority, crate::error::AppError> {
    let unavailable = || {
        crate::error::AppError::new(
            arkret_wire::ErrorCode::TemporarilyUnavailable,
            "governing history proof is unavailable",
        )
    };
    let denied = || crate::error::AppError::capability_denied("Agent history is unavailable");
    let request = PeerRealmJoinBootstrapRequestBody {
        realm_id: query.scan.realm_id.clone(),
        request_id: RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .map_err(|_| unavailable())?,
        member_account_id: query.member_account_id.clone(),
        membership_commit_id: query.membership_commit_id.clone(),
        content_intent: None,
        history_stream_ref: Some(query.scan.stream_ref.clone()),
    };
    if !guard.permits_request().await {
        tracing::warn!("hosted project history authorization changed before bootstrap");
        return Err(denied());
    }
    crate::routing::identity::auth::revalidate_current_read_session(
        state,
        session,
        Some(local_secret),
    )
    .await
    .map_err(|cause| {
        tracing::warn!(
            status = cause.0.as_u16(),
            code = cause.1,
            "hosted project history session changed before bootstrap"
        );
        denied()
    })?;
    let body = post_history_request(
        state,
        governor,
        BOOTSTRAP_PATH,
        &request,
        BOOTSTRAP_MAX_BYTES,
    )
    .await?;
    let outcome: PeerRealmJoinBootstrapResponseBody =
        serde_json::from_slice(&body).map_err(|_| unavailable())?;
    if outcome.request_id != request.request_id
        || outcome.visible_stream_heads != outcome.snapshot.visible_stream_heads
    {
        return Err(unavailable());
    }
    request
        .validate_history_snapshot(&outcome.snapshot)
        .map_err(|_| unavailable())?;
    let nonce = crate::routing::realm_join::nonce_for_request(&request.request_id)
        .map_err(|_| unavailable())?;
    let mut served = crate::routing::realm_join::verify_served_bundle(
        state,
        outcome.authority_bundle.clone(),
        &nonce,
    )
    .await
    .map_err(|_| unavailable())?;
    if served.authority.current_service_id() != governor
        || served.bundle.realm_id != request.realm_id
    {
        return Err(unavailable());
    }
    verify_bootstrap_genesis(state, &outcome, &mut served)
        .await
        .map_err(|_| unavailable())?;
    verify_snapshot(state, &mut served, &outcome.snapshot)
        .await
        .map_err(|_| unavailable())?;
    guard
        .accept_history(&outcome.snapshot)
        .await
        .map_err(|cause| {
            tracing::warn!(%cause, "home Station rejected the signed project history cut");
            unavailable()
        })?;
    if let Some(original) = archived {
        guard
            .qualify_archived_history(original)
            .await
            .map_err(|_| denied())?;
        let current = &outcome.snapshot;
        let member = arkret_wire::ActorId::account(query.member_account_id.clone());
        let still_covered = original.history_basis.as_ref().is_some_and(|basis| {
            basis.account_id == query.member_account_id && basis.stream_ref == query.scan.stream_ref
        }) && original.active_realm_member_revision(&member) == current.active_realm_member_revision(&member) && original.visible_stream_heads.iter().all(|old| {
            current.visible_stream_heads.iter().any(|new| {
                new.stream_ref == old.stream_ref
                    && (new.stream_position > old.stream_position || new == old)
            })
        }) && original
            .retention_and_history_floor
            .stream_floors
            .iter()
            .all(|old| {
                current
                    .retention_and_history_floor
                    .stream_floors
                    .iter()
                    .any(|new| {
                        new.stream_ref == old.stream_ref
                            && new.oldest_position <= old.oldest_position
                    })
            })
            && original
                .current_state_entries
                .iter()
                .all(|row| current.current_state_entries.contains(row));
        if !still_covered {
            // A changed value requires historical source disclosure checks at the current cut.
            let rechecked = state
                .authority_commits()
                .issued_realm_state_snapshot(
                    &query.scan.realm_id,
                    &query.member_account_id,
                    &original.snapshot_id,
                    &state.service_core_id(),
                )
                .await
                .map_err(|_| unavailable())?;
            if rechecked.as_ref() != Some(original) {
                return Err(unavailable());
            }
        }
    }
    Ok(served)
}

pub(crate) async fn read_foreign_project_page(
    state: &AppState,
    governor: &DidCoreId,
    session: &coland_services::identity::SessionIdentityState,
    local_secret: &str,
    query: &arkret_models_collaboration::authority_commit::OwnedAgentStreamScanRequestBody,
    guard: &mut dyn coland_storage::HostedAgentHistoryRead,
    archived: Option<&arkret_wire::RealmStateSnapshot>,
) -> Result<arkret_wire::StreamScanResponseBody, crate::error::AppError> {
    let unavailable = || {
        crate::error::AppError::new(
            arkret_wire::ErrorCode::TemporarilyUnavailable,
            "governing history proof is unavailable",
        )
    };
    let denied = || crate::error::AppError::capability_denied("Agent history is unavailable");
    let mut served = verify_foreign_project_history(
        state,
        governor,
        session,
        local_secret,
        query,
        guard,
        archived,
    )
    .await?;
    if !guard.permits_request().await
        || crate::routing::identity::auth::revalidate_current_read_session(
            state,
            session,
            Some(local_secret),
        )
        .await
        .is_err()
    {
        return Err(denied());
    }
    let body = post_history_request(state, governor, SCAN_PATH, query, SCAN_MAX_BYTES).await?;
    let page: arkret_wire::StreamScanResponseBody =
        serde_json::from_slice(&body).map_err(|_| unavailable())?;
    page.validate_for_request(&query.scan)
        .map_err(|_| unavailable())?;
    for row in &page.committed_events {
        let commit = row.commit();
        ensure_historical_method_key(state, &mut served, &commit.signature)
            .await
            .map_err(|_| unavailable())?;
        match row {
            CommittedEventView::Full(full) => {
                // The Event ID omits its producer proof. Verify that proof as
                // well as the governor's signature on this disclosed original.
                let fact = state
                    .authority_commits()
                    .producer_signer_fact(&full.event, commit)
                    .await
                    .map_err(|_| unavailable())?;
                verify_committed_event_receipt_with_source(
                    state.persistence(),
                    &full.event,
                    commit,
                    CommitContinuity::Standalone,
                    &served.authority,
                    &served.keys,
                    &state.service_core_id(),
                    commit.realm_id.digest_suite_code().digest_suite(),
                    fact.as_ref(),
                )
                .await
                .map_err(|_| unavailable())?;
            }
            CommittedEventView::Withheld(_) => served
                .authority
                .verify_commit(commit, &served.keys)
                .map_err(|_| unavailable())?,
        }
    }
    guard.accept_page(&page).await.map_err(|cause| {
        tracing::warn!(%cause, "home Station rejected the project history page");
        denied()
    })?;
    Ok(page)
}

async fn post_history_request<T: serde::Serialize>(
    state: &AppState,
    governor: &DidCoreId,
    path: &str,
    request: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, crate::error::AppError> {
    let unavailable = || {
        crate::error::AppError::new(
            arkret_wire::ErrorCode::TemporarilyUnavailable,
            "governing history is unavailable",
        )
    };
    let body = arkret_canonical::canonical_json_bytes(request).map_err(|_| unavailable())?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        governor.as_str(),
        path,
        &body,
        max_bytes,
    )
    .await
    .map_err(|_| unavailable())?;
    match response.status {
        200 => Ok(response.body),
        401 | 403 | 404 => {
            tracing::warn!(
                status = response.status,
                path,
                "governing Station refused project history"
            );
            Err(crate::error::AppError::capability_denied(
                "Agent history is unavailable",
            ))
        }
        _ => Err(unavailable()),
    }
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
            &located.bundle,
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
    ensure_historical_method_key(state, located, &snapshot.signature).await?;
    let key = arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
        &located.keys,
        &snapshot.signature.verification_method,
        snapshot.signature.created_at,
    )
    .ok_or("bootstrap snapshot signing method has no verified key")?;
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"]).map_err(temporary)?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )
    .map_err(temporary)?;
    for commit in arkret_models_collaboration::events_payloads::call::call_current_source_commits(
        &snapshot.current_state_entries,
    )
    .map_err(temporary)?
    {
        if commit.governance_generation > snapshot.governance_generation {
            return Err("Call source is from a future governance generation".into());
        }
        ensure_historical_method_key(state, located, &commit.signature).await?;
        located
            .authority
            .verify_commit(&commit, &located.keys)
            .map_err(temporary)?;
    }
    for row in &snapshot.current_state_entries {
        let arkret_wire::CurrentState::Value {
            selector: arkret_wire::CurrentSelector::CallRoster { call_id },
            value,
            ..
        } = row
        else {
            continue;
        };
        let roster: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
            serde_json::from_value(value.clone()).map_err(temporary)?;
        arkret_signatures::media::verify_call_roster_bindings(&snapshot.realm_id, call_id, &roster)
            .map_err(temporary)?;
        for entry in &roster.entries {
            let arkret_models_collaboration::events_payloads::call::CallRosterDelta::Join {
                participant,
            } = &entry.value
            else {
                continue;
            };
            if let Some(binding) = &participant.participant_binding {
                ensure_call_issuer_history(state, &binding.issuer_kid).await?;
            }
        }
    }
    Ok(())
}

/// Cache an independently authenticated native issuer history before the
/// database installer selects its key at the original join Commit time.
async fn ensure_call_issuer_history(
    state: &AppState,
    kid: &arkret_wire::DidUrl,
) -> Result<(), String> {
    let did = arkret_identity::verification_method_did(kid.as_str()).map_err(temporary)?;
    if did.method() == "key" {
        return Ok(());
    }
    let issuer = arkret_wire::project_did_to_core_id(&did).map_err(temporary)?;
    if issuer == state.service_core_id() {
        // A held Realm can contain a join signed by this Station itself.
        // Retain its complete native history through the same independently
        // verified durable floor instead of looking for ourselves as a peer.
        let evidence =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                state,
            )
            .await
            .map_err(|error| temporary(error.message))?;
        let projection = evidence.projection().map_err(temporary)?;
        if projection.service_id != issuer || projection.did != did {
            return Err("local media issuer history has a different identity".into());
        }
        let route =
            arkret_models_identity::VerifiedServiceRoute::new(projection, chrono::Utc::now());
        return match coland_storage::ServiceRouteStore::publish_route_cache(
            state.persistence(),
            evidence,
            route,
        )
        .await
        .map_err(temporary)?
        {
            coland_storage::MonotonicRouteWrite::Applied
            | coland_storage::MonotonicRouteWrite::Replay => Ok(()),
            _ => Err("local media issuer native history is stale or conflicting".into()),
        };
    }
    match crate::routing::federation::resolved_peer_route(state, issuer.as_str(), "station", true)
        .await
    {
        Ok(_) => Ok(()),
        Err(_) => crate::routing::federation::resolved_peer_route(
            state,
            issuer.as_str(),
            "media_service",
            true,
        )
        .await
        .map(|_| ())
        .map_err(temporary),
    }
}

/// Anchor a pending held stream on the governing Station's bootstrap
/// snapshot and return the anchored head.
async fn anchor_stream(
    state: &AppState,
    anchor: &ReplicaStreamAnchor,
    governance: &DidCoreId,
    located: &mut LocatedRealmAuthority,
) -> Result<CommitStreamHead, String> {
    // Only bootstrap replaces a Realm's complete current cut. Queue those
    // background operations before acquiring a database connection, while
    // independent stream tails and ordinary command writers remain free.
    let gate = realm_convergence_gate(state, &anchor.join_commit.stream_ref)
        .ok_or("the Realm bootstrap queue is unavailable")?;
    let _serial = gate.lock().await;
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
        content_intent: None,
        history_stream_ref: None,
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
    let outcome: PeerRealmJoinBootstrapResponseBody =
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
    let genesis_original = verify_bootstrap_genesis(state, &outcome, located).await?;
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
            genesis_original: (genesis_original, outcome.producer_signer_fact.clone()),
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

async fn verify_bootstrap_genesis(
    state: &AppState,
    outcome: &PeerRealmJoinBootstrapResponseBody,
    located: &mut LocatedRealmAuthority,
) -> Result<arkret_wire::CommittedEventFullView, String> {
    let original = outcome.genesis_original().map_err(temporary)?;
    if located.bundle.genesis_event != original.event
        || located.bundle.genesis_commit != original.commit
    {
        return Err("bootstrap Genesis differs from its verified authority bundle".into());
    }
    ensure_historical_method_key(state, located, &original.commit.signature).await?;
    let producer = verify_committed_event_receipt_with_source(
        state.persistence(),
        &original.event,
        &original.commit,
        CommitContinuity::StreamStart,
        &located.authority,
        &located.keys,
        &state.service_core_id(),
        original.event.event_id.digest_suite_code().digest_suite(),
        outcome.producer_signer_fact.as_ref(),
    )
    .await
    .map_err(temporary)?;
    if producer == ReceivedProducer::OtherSigner {
        // A digestless native original still needs its exact retained
        // historical authority. A current DID document is not a fallback.
        verify_native_genesis_producer(state, &original).await?;
    }
    Ok(original)
}

/// Pull every Commit after the held head from the governing Station and
/// store it in order, until the peer scan reports no more.
async fn fill_to_head(
    state: &AppState,
    realm_id: &RealmId,
    governance: &DidCoreId,
    anchored: &CommitStreamHead,
    located: &mut LocatedRealmAuthority,
    target: Option<&CommitStreamHead>,
) -> Result<(), String> {
    let realm_stream = anchored.stream_ref.clone();
    loop {
        let mut held = state
            .authority_commits()
            .held_stream_head_commit(&realm_stream)
            .await
            .map_err(temporary)?
            .ok_or("the held Realm stream has no head")?;
        if let Some(target) = target {
            if target.stream_ref != realm_stream {
                return Err("the signed target belongs to another stream".into());
            }
            if held.stream_position >= target.stream_position {
                if held.stream_position == target.stream_position
                    && held.commit_id != target.commit_id
                {
                    return Err("the signed target conflicts with the held stream head".into());
                }
                return Ok(());
            }
        }
        let request = StreamScanRequestBody {
            realm_id: realm_id.clone(),
            stream_ref: realm_stream.clone(),
            direction: StreamScanDirection::After(Some(held.stream_position)),
            limit: SCAN_PAGE_LIMIT,
        };
        let body = post_peer(state, governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
        let page: arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody =
            serde_json::from_slice(&body).map_err(temporary)?;
        page.validate_for_request(&request).map_err(temporary)?;
        if page.committed_events.is_empty() {
            if target.is_some() {
                return Err("the peer scan ended before the signed Snapshot head".into());
            }
            return Ok(());
        }
        verify_scanned_page(state, realm_id, located, &held, &page).await?;
        require_scanned_snapshot_target(&page, target)?;
        let mut index = 0;
        while index < page.committed_events.len() {
            let item = &page.committed_events[index];
            if is_pair_business(item)? {
                let boundary;
                let pair_page = if index + 1 == page.committed_events.len() {
                    // Never persist the first half at a page boundary. The
                    // next authorized scan starts at the same held prefix.
                    let request = StreamScanRequestBody {
                        realm_id: realm_id.clone(),
                        stream_ref: realm_stream.clone(),
                        direction: StreamScanDirection::After(Some(held.stream_position)),
                        limit: 2,
                    };
                    let body =
                        post_peer(state, governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
                    boundary = serde_json::from_slice::<
                        arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody,
                    >(&body)
                    .map_err(temporary)?;
                    boundary.validate_for_request(&request).map_err(temporary)?;
                    verify_scanned_page(state, realm_id, located, &held, &boundary).await?;
                    require_scanned_snapshot_target(&boundary, target)?;
                    if boundary.committed_events.first() != Some(item) {
                        return Err("revision_unavailable: paired scan boundary changed".into());
                    }
                    (&boundary, 0)
                } else {
                    (&page, index)
                };
                held = store_scanned_pair(
                    state,
                    realm_id,
                    anchored,
                    located,
                    &held,
                    pair_page.0,
                    pair_page.1,
                )
                .await?;
                index += 2;
            } else {
                let fact = scan_fact(&page, item.commit());
                store_scanned(
                    state,
                    realm_id,
                    anchored,
                    located,
                    &held,
                    item,
                    ScannedItemEvidence {
                        producer_signer_fact: fact,
                    },
                )
                .await?;
                held = item.commit().clone();
                index += 1;
            }
        }
        // Fold the complete authenticated page, including any observed
        // revocation after the target, before rechecking Account disclosure.
        if target.is_some_and(|target| held.stream_position >= target.stream_position) {
            return Ok(());
        }
        if !page.truncated {
            if target.is_some() {
                return Err("the peer scan omitted the signed Snapshot head".into());
            }
            return Ok(());
        }
    }
}

fn require_scanned_snapshot_target(
    page: &arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody,
    target: Option<&CommitStreamHead>,
) -> Result<(), String> {
    let Some(target) = target else {
        return Ok(());
    };
    for item in &page.committed_events {
        let commit = item.commit();
        if commit.stream_position == target.stream_position {
            if commit.commit_id != target.commit_id {
                return Err("the peer scan conflicts with the signed Snapshot head".into());
            }
            if is_pair_business(item)? {
                return Err("the signed Snapshot head bisects a registered atomic pair".into());
            }
        }
    }
    Ok(())
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
        let request = StreamScanRequestBody {
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
        let page: arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody =
            serde_json::from_slice(&body).map_err(temporary)?;
        page.validate_for_request(&request).map_err(temporary)?;
        verify_scanned_page(state, &event.realm_id, located, &held, &page).await?;
        for item in &page.committed_events {
            validate_forward_scan_target(item, event, expected)?;
        }
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
                // Ordinary Event identity is complete by itself. A scan cannot
                // reconstruct the original complete MLS retry status or key.
                if event.kind != arkret_wire::EventKind::MlsCommit {
                    commits
                        .retain_forwarded_outcome(
                            event,
                            &arkret_wire::AuthoritySubmitResponseBody::Accepted {
                                status: arkret_wire::AuthorityCommitStatus::Duplicate,
                                commit: commit.clone(),
                            },
                            crate::wire::now(),
                        )
                        .await
                        .map_err(temporary)?;
                }
            }
            require_forward_source(state, session, event, located).await?;
            store_scanned(
                state,
                &event.realm_id,
                anchored,
                located,
                &held,
                item,
                ScannedItemEvidence {
                    producer_signer_fact: fact,
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
    // is reused here. The accepted Realm join is checked by the
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
            let request = StreamScanRequestBody {
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
            let page: arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody =
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
                historical_commit: (full.commit.governance_generation
                    < located.authority.current_generation())
                .then(|| {
                    located
                        .authority
                        .verify_historical_commit(&full.commit, &located.keys)
                })
                .transpose()
                .map_err(temporary)?,
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
        // The caller already supplied this complete signed message. The two
        // callers verified and materialized its governing receipt. Returning
        // that exact receipt discloses no stored message or other history.
        if event.kind == arkret_wire::EventKind::MessageCreate
            && event.executed_by.is_none()
            && event.applet_id.is_none()
            && commit.event_ref == event.event_id
            && session.agent_session().is_some_and(|agent| {
                event.actor_id.as_account_id() == Some(&agent.metadata.account_id)
                    && agent.metadata.account_id.station_id == state.service_core_id()
            })
        {
            return Ok(());
        }
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
    let request = StreamScanRequestBody {
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

fn scan_fact<'a>(
    page: &'a arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody,
    commit: &RealmCommit,
) -> Option<&'a arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact> {
    page.producer_signer_facts
        .iter()
        .find(|entry| entry.target.commit_id == commit.commit_id)
        .map(|entry| &entry.producer_signer_fact)
}

fn is_pair_business(item: &CommittedEventView) -> Result<bool, String> {
    match item {
        CommittedEventView::Full(full)
            if full.event.kind != arkret_wire::EventKind::AuditAccessed =>
        {
            arkret_models_collaboration::authority_commit::is_audit_paired_event_slot(&full.event)
                .map_err(temporary)
        }
        _ => Ok(false),
    }
}

async fn store_scanned_pair(
    state: &AppState,
    realm_id: &RealmId,
    anchored: &CommitStreamHead,
    located: &mut LocatedRealmAuthority,
    held: &RealmCommit,
    page: &arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody,
    index: usize,
) -> Result<RealmCommit, String> {
    use arkret_models_collaboration::authority_commit::{
        AuditPairedEventFederationSubmission, AuditPairedEventUnitKind, CommittedEventSubmission,
    };
    let items = page
        .committed_events
        .get(index..index + 2)
        .ok_or("revision_unavailable: paired scan has no complete successor")?;
    if let [
        CommittedEventView::Full(business),
        CommittedEventView::Full(audit),
    ] = items
    {
        let source = AuditPairedEventFederationSubmission {
            unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
            committed_events: [business, audit].map(|full| CommittedEventSubmission {
                event_submission: arkret_wire::EventAdmissionSubmission::new(full.event.clone()),
                source_commit: full.commit.clone(),
                genesis_event_ref: None,
                welcomes: None,
                producer_signer_fact: scan_fact(page, &full.commit).cloned(),
            }),
        };
        source.validate().map_err(temporary)?;
        let mut previous = held;
        let mut replicas = Vec::with_capacity(2);
        for slot in &source.committed_events {
            ensure_historical_method_key(state, located, &slot.source_commit.signature).await?;
            verify_committed_event_receipt_with_source(
                state.persistence(),
                &slot.event_submission.event,
                &slot.source_commit,
                CommitContinuity::After(previous),
                &located.authority,
                &located.keys,
                &state.service_core_id(),
                state.projections().realm_digest_suite(realm_id.as_str()),
                slot.producer_signer_fact.as_ref(),
            )
            .await
            .map_err(temporary)?;
            replicas.push(CommittedReplica {
                local_service_id: state.service_core_id(),
                authority: located.current_authority(),
                historical_commit: (slot.source_commit.governance_generation
                    < located.authority.current_generation())
                .then(|| {
                    located
                        .authority
                        .verify_historical_commit(&slot.source_commit, &located.keys)
                })
                .transpose()
                .map_err(temporary)?,
                event: slot.event_submission.event.clone(),
                commit: slot.source_commit.clone(),
                producer_signer_fact: slot.producer_signer_fact.clone(),
                genesis_event_ref: None,
                role: CommittedReplicaRole::HeldStream,
                received_at: crate::wire::now(),
                welcomes: Vec::new(),
            });
            previous = &slot.source_commit;
        }
        let replicas: [CommittedReplica; 2] = replicas
            .try_into()
            .map_err(|_| "paired scan omitted a replica")?;
        let status = state
            .authority_commits()
            .install_committed_audit_pair(&source, &replicas)
            .await
            .map_err(temporary)?;
        if status
            == arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed
        {
            for slot in &source.committed_events {
                if slot.source_commit.stream_position > anchored.stream_position {
                    crate::routing::events::notify::dispatch_committed_event_notifications(
                        state,
                        &slot.event_submission.event,
                    )
                    .await;
                }
            }
        }
    } else {
        let mut previous = held.clone();
        for item in items {
            store_scanned(
                state,
                realm_id,
                anchored,
                located,
                &previous,
                item,
                ScannedItemEvidence {
                    producer_signer_fact: scan_fact(page, item.commit()),
                },
            )
            .await?;
            previous = item.commit().clone();
        }
    }
    Ok(items[1].commit().clone())
}

struct ScannedItemEvidence<'a> {
    producer_signer_fact:
        Option<&'a arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
}

/// Authenticate the complete physical page before retaining its first row.
/// Later source, ownership and locked installer checks still fence each write.
#[inline(never)]
fn verify_scanned_page<'a>(
    state: &'a AppState,
    realm_id: &'a RealmId,
    located: &'a mut LocatedRealmAuthority,
    held: &'a RealmCommit,
    page: &'a arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody,
) -> std::pin::Pin<Box<impl std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let mut previous = held;
        for item in &page.committed_events {
            let commit = item.commit();
            ensure_historical_method_key(state, located, &commit.signature).await?;
            match item {
                CommittedEventView::Full(full) => {
                    verify_committed_event_receipt_with_source(
                        state.persistence(),
                        &full.event,
                        commit,
                        CommitContinuity::After(previous),
                        &located.authority,
                        &located.keys,
                        &state.service_core_id(),
                        state.projections().realm_digest_suite(realm_id.as_str()),
                        scan_fact(page, commit),
                    )
                    .await
                    .map_err(temporary)?;
                }
                CommittedEventView::Withheld(_) => {
                    located
                        .authority
                        .verify_commit(commit, &located.keys)
                        .map_err(temporary)?;
                    commit.validate_successor_of(previous).map_err(temporary)?;
                }
            }
            previous = commit;
        }
        Ok(())
    })
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
    if let CommittedEventView::Full(view) = item
        && view.event.kind == arkret_wire::EventKind::CallState
    {
        let payload: arkret_models_collaboration::events_payloads::call::CallStatePayload =
            serde_json::from_value(serde_json::to_value(&view.event.payload).map_err(temporary)?)
                .map_err(temporary)?;
        if let Some(arkret_models_collaboration::events_payloads::call::CallRosterDelta::Join {
            participant,
        }) = payload.roster_delta
            && let Some(binding) = participant.participant_binding
        {
            ensure_call_issuer_history(state, &binding.issuer_kid).await?;
        }
    }
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
            if arkret_models_collaboration::authority_commit::is_audit_paired_event_slot(
                &view.event,
            )
            .map_err(temporary)?
            {
                // A Full fragment still proves only continuity until the
                // complete authorized pair is available. No business current
                // or canonical Event is installed from this fragment.
                commits
                    .install_committed_chain_node(&CommittedChainNode {
                        local_service_id: state.service_core_id(),
                        authority: located.current_authority(),
                        historical_commit: (commit.governance_generation
                            < located.authority.current_generation())
                        .then(|| {
                            located
                                .authority
                                .verify_historical_commit(commit, &located.keys)
                        })
                        .transpose()
                        .map_err(temporary)?,
                        commit: commit.clone(),
                    })
                    .await
                    .map_err(temporary)?;
                return Ok(());
            }
            let outcome = commits
                .install_committed_replica(&CommittedReplica {
                    local_service_id: state.service_core_id(),
                    authority: located.current_authority(),
                    historical_commit: (commit.governance_generation
                        < located.authority.current_generation())
                    .then(|| {
                        located
                            .authority
                            .verify_historical_commit(commit, &located.keys)
                    })
                    .transpose()
                    .map_err(temporary)?,
                    event: view.event.clone(),
                    commit: commit.clone(),
                    producer_signer_fact: fact.cloned(),
                    genesis_event_ref: None,
                    role: CommittedReplicaRole::HeldStream,
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
                    historical_commit: (commit.governance_generation
                        < located.authority.current_generation())
                    .then(|| {
                        located
                            .authority
                            .verify_historical_commit(commit, &located.keys)
                    })
                    .transpose()
                    .map_err(temporary)?,
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
