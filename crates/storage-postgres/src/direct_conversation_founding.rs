//! The self Direct Conversation founding unit.
//!
//! `contact-and-direct-conversation.md` sections 5.4 to 6.2: the founder's
//! current Station admits the caller-authored four-Event unit in one
//! transaction. Inside it the Station
//!
//! 1. answers an exact retry (same founder, idempotency key and unit digest) with the stored four
//!    Commits before anything else is judged, and refuses the same key with another unit as
//!    `duplicate_conflict`;
//! 2. claims the founder's unique `(founder_id, trust_domain_id, pair_key)` slot, refusing a second
//!    unit as `direct_conversation_slot_already_committed`;
//! 3. reads the founding authority from its own current state: the pair's accepted Contact round
//!    and both directional heads, from which the root round's founder is derived and must be the
//!    unit's author;
//! 4. installs the genesis authority and commits the four Events on four consecutive Realm-stream
//!    Commits with their typed current results.
//!
//! Any refusal rolls the whole unit back. No founding receipt exists; the
//! Commits and the slot are the only durable acceptance.

use std::collections::BTreeSet;

#[cfg(feature = "test-support")]
mod profile_admission_spy {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    use arkret_wire::RealmId;
    use coland_storage::{PersistenceError, PersistenceResult};

    static WATCHED_REALMS: LazyLock<Mutex<HashMap<String, u64>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Test-only tripwire keyed by a unique Realm, so parallel PG tests cannot
    /// affect one another. A call to the founder's profile admission fails.
    pub struct FoundingProfileAdmissionSpy {
        realm_id: String,
    }

    impl FoundingProfileAdmissionSpy {
        pub fn watch(realm_id: &RealmId) -> Self {
            let realm_id = realm_id.as_str().to_owned();
            WATCHED_REALMS
                .lock()
                .expect("profile spy lock")
                .insert(realm_id.clone(), 0);
            Self { realm_id }
        }

        pub fn hits(&self) -> u64 {
            *WATCHED_REALMS
                .lock()
                .expect("profile spy lock")
                .get(&self.realm_id)
                .expect("profile spy remains registered")
        }
    }

    impl Drop for FoundingProfileAdmissionSpy {
        fn drop(&mut self) {
            WATCHED_REALMS
                .lock()
                .expect("profile spy lock")
                .remove(&self.realm_id);
        }
    }

    pub(super) fn trip_if_watched(realm_id: &RealmId) -> PersistenceResult<()> {
        let mut watched = WATCHED_REALMS.lock().expect("profile spy lock");
        if let Some(hits) = watched.get_mut(realm_id.as_str()) {
            *hits += 1;
            return Err(PersistenceError::Internal(
                "test-only founder profile admission spy tripped".to_owned(),
            ));
        }
        Ok(())
    }
}

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, CommittedEventSubmission,
    DirectConversationFoundingFederationSubmission, PeerAuthoritySubmitRequest,
    PeerRegisteredAtomicUnit, PeerRegisteredAtomicUnitRequest, RegisteredAtomicUnitBranch,
};
use arkret_models_collaboration::contact_operations::{ContactRound, GlareConcurrencyAttestation};
use arkret_models_collaboration::objects::direct_conversation::{
    DirectConversationAuthorizationBasis, DirectConversationFoundingAuthorityEvidence,
};
use arkret_wire::{ActorId, EventId};
use coland_storage::{
    AuthorityCommitWriteOutcome, ConflictCode, ContactRecord,
    DirectConversationFoundingAuthorityRef, DirectConversationFoundingCommitOutcome,
    DirectConversationFoundingCommitUnit, DirectConversationFoundingFacts, FederationOutboxRecord,
    SelfProducerCommitGuard,
};
#[cfg(feature = "test-support")]
pub use profile_admission_spy::FoundingProfileAdmissionSpy;

use super::{
    AsyncConnection, BigInt, Binary, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, sql_query,
};
use crate::authority_commit::{
    check_self_producer_guard_in_connection, commit_transaction_in_connection,
    queue_event_in_connection,
};
use crate::{PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct StoredUnitRow {
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Jsonb)]
    commits_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct AgentProvisionCurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct AcceptedEventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

fn conflict(code: ConflictCode, detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", code.as_str()))
}

fn verify_agent_founding_join_binding(
    unit: &DirectConversationFoundingCommitUnit,
    facts: &DirectConversationFoundingFacts,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::membership_invite::MembershipPayload;

    let invalid =
        |detail: &str| conflict(ConflictCode::DirectConversationFoundingUnitInvalid, detail);
    let controller = facts
        .founder_id
        .as_account_id()
        .ok_or_else(|| invalid("the Agent controller must be an account"))?;
    let payload: MembershipPayload = serde_json::from_value(
        serde_json::to_value(&unit.transactions[2].event.payload)
            .map_err(PersistenceError::database)?,
    )
    .map_err(|error| {
        invalid(&format!(
            "the owned Agent founding join payload is invalid: {error}"
        ))
    })?;
    let binding = payload.agent_controller_binding.as_ref().ok_or_else(|| {
        invalid("the owned Agent founding join must carry its controller binding")
    })?;
    if binding.controller_account_id != *controller
        || binding.controller_membership_generation_ref != unit.transactions[1].event.event_id
        || binding.controller_terminal_event_ref.is_some()
    {
        return Err(invalid(
            "the owned Agent founding join does not bind the staged controller generation",
        ));
    }
    Ok(())
}

/// Section 5.4 controller/owned-Agent authority at the founding slot cut.
///
/// The provision Event is accepted in the controller PCR and remains the
/// exact `agent_provisioning` current row.  The Agent PCR is active and has
/// exactly one non-expired current runtime-key authorization.  The returned
/// basis names those two accepted Events; the portable evidence commits to
/// the complete provision payload through the shared SDK derivation.
async fn verify_agent_founding_authority(
    conn: &mut diesel_async::AsyncPgConnection,
    founder_id: &arkret_wire::ActorId,
    peer_id: &arkret_wire::ActorId,
    provision_ref: &EventId,
    at: chrono::DateTime<chrono::Utc>,
    missing_code: ConflictCode,
    lock_current: bool,
) -> PersistenceResult<(
    DirectConversationAuthorizationBasis,
    DirectConversationFoundingAuthorityEvidence,
)> {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyAuthorizePayload, AgentProvisionPayload, AgentProvisioningValue,
    };

    let stale = |detail: &str| conflict(ConflictCode::FailedPrecondition, detail);
    let founder = founder_id
        .as_account_id()
        .ok_or_else(|| stale("the Agent controller must be an account"))?;
    let agent = peer_id
        .as_account_id()
        .ok_or_else(|| stale("the owned Agent must use an account ActorId"))?;
    if founder.station_id != agent.station_id {
        return Err(stale(
            "the controller and owned Agent must use the same Station",
        ));
    }

    let token = crate::ids::parse_event_id(provision_ref.as_str())
        .ok_or_else(|| stale("the Agent provision Event id is invalid"))?;
    let accepted = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<AcceptedEventRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict(missing_code, "the Agent provision Event is not accepted"))?;
    let provision_event: arkret_wire::Event =
        serde_json::from_value(accepted.envelope).map_err(|error| {
            PersistenceError::Database(format!("stored Agent provision Event is invalid: {error}"))
        })?;
    let provision_commit: arkret_wire::RealmCommit = serde_json::from_value(accepted.commit_json)
        .map_err(|error| {
        PersistenceError::Database(format!("stored Agent provision Commit is invalid: {error}"))
    })?;
    if provision_event.kind != arkret_wire::EventKind::AgentProvision
        || provision_event.event_id != *provision_ref
        || provision_commit.event_ref != *provision_ref
        || provision_commit.realm_id != provision_event.realm_id
    {
        return Err(stale(
            "the accepted Agent provision Event/Commit binding is invalid",
        ));
    }
    let payload = AgentProvisionPayload::try_from(&provision_event).map_err(|error| {
        stale(&format!(
            "the accepted Agent provision payload is invalid: {error}"
        ))
    })?;
    payload
        .validate_envelope(&provision_event)
        .map_err(|error| {
            stale(&format!(
                "the accepted Agent provision envelope is invalid: {error}"
            ))
        })?;
    if payload.controller_principal_id != founder.principal_id
        || payload.agent_id != agent.principal_id
        || &provision_event.actor_id != founder_id
    {
        return Err(stale(
            "the accepted provision does not bind the founding controller/Agent pair",
        ));
    }

    let lock_clause = if lock_current { " FOR SHARE" } else { "" };
    let current = sql_query(format!(
        "SELECT current_commit_id,current_stream_position,value \
         FROM agent_provisioning_current_results \
         WHERE realm_id=$1 AND agent_id=$2{lock_clause}",
    ))
    .bind::<Text, _>(provision_event.realm_id.as_str())
    .bind::<Text, _>(agent.principal_id.as_str())
    .get_result::<AgentProvisionCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        conflict(
            missing_code,
            "the Agent provision current result is unavailable",
        )
    })?;
    let current_value: AgentProvisioningValue =
        serde_json::from_value(current.value).map_err(|error| {
            PersistenceError::Database(format!(
                "stored Agent provision current is invalid: {error}"
            ))
        })?;
    if current.current_commit_id != provision_commit.commit_id.as_str()
        || u64::try_from(current.current_stream_position).ok()
            != Some(provision_commit.stream_position)
        || current_value != payload.provisioning_value()
    {
        return Err(stale(
            "the accepted provision is not the Agent's current controller binding",
        ));
    }

    let status = sql_query(format!(
        "SELECT value FROM agent_status_current_results \
         WHERE realm_id=$1 AND agent_id=$2{lock_clause}",
    ))
    .bind::<Text, _>(payload.principal_control_realm_id.as_str())
    .bind::<Text, _>(agent.principal_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if status.as_ref().and_then(|row| row.value.as_str()) != Some("active") {
        return Err(stale("the owned Agent lifecycle is not active"));
    }

    let key_rows = sql_query(format!(
        "SELECT value FROM agent_key_current_results \
         WHERE realm_id=$1 AND agent_id=$2{lock_clause}",
    ))
    .bind::<Text, _>(payload.principal_control_realm_id.as_str())
    .bind::<Text, _>(agent.principal_id.as_str())
    .load::<CurrentValueRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut current_authorizations = Vec::new();
    for row in key_rows {
        let entries = row
            .value
            .get("authorizations")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                PersistenceError::Database(
                    "stored Agent key current has no authorizations".to_owned(),
                )
            })?;
        for entry in entries {
            let authorization: AgentKeyAuthorizePayload = serde_json::from_value(
                entry
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .map_err(|error| {
                PersistenceError::Database(format!(
                    "stored Agent key authorization is invalid: {error}"
                ))
            })?;
            if authorization.agent_id != agent.principal_id
                || authorization.accountable_principal_id != founder.principal_id
                || authorization
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= at)
            {
                continue;
            }
            let tag = entry
                .get("tag_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    PersistenceError::Database(
                        "stored Agent key authorization has no tag id".to_owned(),
                    )
                })?;
            let event_id = tag
                .strip_suffix(":1")
                .and_then(|value| EventId::new(value.to_owned()).ok())
                .ok_or_else(|| {
                    PersistenceError::Database(
                        "stored Agent key authorization tag is invalid".to_owned(),
                    )
                })?;
            current_authorizations.push((event_id, authorization));
        }
    }
    let [(key_event_ref, key_payload)] = current_authorizations.as_slice() else {
        return Err(stale(
            "the owned Agent must have exactly one current active key authorization",
        ));
    };
    let key_token = crate::ids::parse_event_id(key_event_ref.as_str())
        .ok_or_else(|| stale("the Agent key authorization Event id is invalid"))?;
    let key_event = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(key_token.to_vec())
    .get_result::<AcceptedEventRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| stale("the current Agent key authorization Event is not accepted"))?;
    let key_event: arkret_wire::Event =
        serde_json::from_value(key_event.envelope).map_err(|error| {
            PersistenceError::Database(format!("stored Agent key Event is invalid: {error}"))
        })?;
    if key_event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || key_event.event_id != *key_event_ref
        || key_event.realm_id != payload.principal_control_realm_id
        || serde_json::to_value(&key_event.payload).map_err(PersistenceError::database)?
            != serde_json::to_value(key_payload).map_err(PersistenceError::database)?
    {
        return Err(stale(
            "the current Agent key authorization differs from its accepted Event",
        ));
    }

    let evidence = DirectConversationFoundingAuthorityEvidence::from_agent_provision(
        provision_ref.clone(),
        &payload,
    )
    .map_err(|error| stale(&format!("the Agent founding evidence is invalid: {error}")))?;
    let mut refs = vec![provision_ref.clone(), key_event_ref.clone()];
    refs.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let basis = DirectConversationAuthorizationBasis::agent_controller(refs);
    basis
        .validate_shape()
        .map_err(|error| stale(&format!("the Agent controller basis is invalid: {error}")))?;
    Ok((basis, evidence))
}

/// Current authority for the immutable controller/Agent pair. A runtime-key
/// replacement does not rewrite the founding basis or binding digest.
pub(crate) async fn agent_controller_pair_current(
    conn: &mut diesel_async::AsyncPgConnection,
    founder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    basis: &DirectConversationAuthorizationBasis,
) -> PersistenceResult<bool> {
    agent_controller_pair_current_with_lock(conn, founder, peer, basis, true).await
}

pub(crate) async fn agent_controller_pair_current_snapshot(
    conn: &mut diesel_async::AsyncPgConnection,
    founder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    basis: &DirectConversationAuthorizationBasis,
) -> PersistenceResult<bool> {
    agent_controller_pair_current_with_lock(conn, founder, peer, basis, false).await
}

async fn agent_controller_pair_current_with_lock(
    conn: &mut diesel_async::AsyncPgConnection,
    founder: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
    basis: &DirectConversationAuthorizationBasis,
    lock_current: bool,
) -> PersistenceResult<bool> {
    basis
        .validate_shape()
        .map_err(|error| PersistenceError::Database(error.to_string()))?;
    let mut provision_refs = Vec::new();
    for reference in &basis.event_refs {
        let Some(token) = crate::ids::parse_event_id(reference.as_str()) else {
            return Ok(false);
        };
        let accepted = sql_query(
            "SELECT e.envelope,c.commit_json FROM canonical_events e \
             JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.id=$1 AND e.state='committed'",
        )
        .bind::<Binary, _>(token.to_vec())
        .get_result::<AcceptedEventRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(accepted) = accepted else {
            return Ok(false);
        };
        let event: arkret_wire::Event =
            serde_json::from_value(accepted.envelope).map_err(PersistenceError::database)?;
        if event.kind == arkret_wire::EventKind::AgentProvision {
            provision_refs.push(reference);
        }
    }
    let [provision_ref] = provision_refs.as_slice() else {
        return Ok(false);
    };
    match verify_agent_founding_authority(
        conn,
        founder,
        peer,
        provision_ref,
        chrono::Utc::now(),
        ConflictCode::FailedPrecondition,
        lock_current,
    )
    .await
    {
        Ok(_) => Ok(true),
        Err(PersistenceError::Conflict(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The scope both directions of the pair must grant.
const DIRECT_MESSAGE_SCOPE: &str = "direct_message";

/// The current accepted Contact of the pair: the most recent row, with a
/// non-accepted row winning a tie so stale acceptance never masks a change.
pub(crate) fn current_contact(records: Vec<ContactRecord>) -> Option<ContactRecord> {
    records.into_iter().max_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            .then_with(|| (left.status != "accepted").cmp(&(right.status != "accepted")))
    })
}

/// Section 5.4 at the slot-commit linearization point: the pair's current
/// accepted Contact round is the one the genesis names, both directional
/// current heads reference it, grant `direct_message` and are fresh, and the
/// founder derived from its root round is the unit's author.
///
/// Returns the canonical `accepted_contact` authorization basis every binding
/// endorsement must name (section 8.3): the round's accepted request and
/// accept Event refs, its two directional current heads.
async fn verify_contact_round_founding_authority(
    conn: &mut diesel_async::AsyncPgConnection,
    facts: &DirectConversationFoundingFacts,
    contact_round_id: &arkret_wire::Hash,
    local_station: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
    missing_code: ConflictCode,
) -> PersistenceResult<(
    DirectConversationAuthorizationBasis,
    DirectConversationFoundingAuthorityEvidence,
)> {
    let stale = |detail: &str| conflict(ConflictCode::FailedPrecondition, detail);
    let contact = current_contact(
        crate::contacts::pair_contacts_in_connection(conn, &facts.founder_id, &facts.peer_id)
            .await?,
    )
    .ok_or_else(|| conflict(missing_code, "the pair has no local Contact round"))?;
    let grants_direct_message = |scopes: &[String]| {
        scopes
            .iter()
            .any(|scope| scope.as_str() == DIRECT_MESSAGE_SCOPE)
    };
    if contact.status != "accepted"
        || contact.tombstone_event_ref.is_some()
        || !grants_direct_message(&contact.granted_to_target_scopes)
        || !grants_direct_message(&contact.granted_to_requester_scopes)
    {
        return Err(stale(
            "the pair's current Contact does not grant direct_message both ways",
        ));
    }
    let evidence = contact
        .contact_round_evidence
        .clone()
        .ok_or_else(|| stale("the pair's current Contact round has no evidence"))?;
    if contact.contact_round_id.as_ref() != Some(&evidence.contact_round_id)
        || &evidence.contact_round_id != contact_round_id
    {
        return Err(stale(
            "the genesis names a Contact round that is not the pair's current round",
        ));
    }
    if evidence.current_proofs.len() != 2 {
        return Err(stale("both directional current heads are required"));
    }
    let glare_requests = match &evidence.contact_round {
        ContactRound::Glare { requests, .. } => {
            if !requests.iter().any(|request| {
                contact.request_event_ref.as_ref() == Some(&request.request_event_ref)
            }) {
                return Err(stale(
                    "the local Contact request is outside the glare round",
                ));
            }
            Some(requests)
        }
        ContactRound::Normal { .. } => None,
    };
    for proof in &evidence.current_proofs {
        let peer = proof.peer.contact_actor_id();
        let head = if let Some(requests) = glare_requests {
            let matching = evidence
                .request_receipts
                .iter()
                .filter(|receipt| {
                    receipt.core.peer.contact_actor_id() == peer
                        && requests.iter().any(|request| {
                            request.request_event_ref == receipt.core.request_event_ref
                        })
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(stale("a glare direction has no unique accepted request"));
            }
            Some(&matching[0].core.request_event_ref)
        } else if peer == contact.target_id {
            contact.request_event_ref.as_ref()
        } else if peer == contact.requester_id {
            contact.response_event_ref.as_ref()
        } else {
            None
        };
        if proof.terminal
            || proof.contact_round_id != evidence.contact_round_id
            || head != Some(&proof.head_event_ref)
            || (&proof.issuer_id != local_station && proof.fresh_until <= at)
        {
            return Err(stale(
                "a directional current head is terminal, stale or not the accepted head",
            ));
        }
    }
    let founding = DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence: evidence,
        contact_round_continuity_chains: contact.contact_round_evidence_history.clone(),
    };
    let (participants, founder) = founding.participants_and_founder().map_err(|error| {
        stale(&format!(
            "the Contact round evidence does not derive a founder: {error}"
        ))
    })?;
    let DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence,
        contact_round_continuity_chains,
    } = &founding
    else {
        unreachable!("constructed as the human branch above")
    };
    let root = contact_round_evidence
        .continuity_checkpoint
        .is_none()
        .then(|| {
            contact_round_continuity_chains
                .last()
                .unwrap_or(contact_round_evidence)
        });
    if let Some(root) = root
        && let ContactRound::Glare { requests, .. } = &root.contact_round
    {
        let attestations = root
            .glare_concurrency_attestations
            .as_ref()
            .ok_or_else(|| stale("a glare root round needs both concurrency attestations"))?;
        if root.request_receipts.len() != 2
            || attestations.iter().any(|attestation| {
                attestation.complete_through == 0
                    || requests.iter().any(|request| {
                        !attestation
                            .observed_commit_event_ids
                            .contains(&request.request_event_ref)
                    })
            })
        {
            return Err(stale(
                "the glare root round attestations do not cover both requests",
            ));
        }
    }
    if participants.iter().collect::<BTreeSet<_>>()
        != [&facts.founder_id, &facts.peer_id]
            .into_iter()
            .collect::<BTreeSet<_>>()
    {
        return Err(stale(
            "the Contact round pair is not the founding unit's pair",
        ));
    }
    if founder != facts.founder_id {
        return Err(conflict(
            ConflictCode::CapabilityDenied,
            "only the founder derived from the pair's root Contact round may found it",
        ));
    }
    let mut heads = contact_round_evidence
        .current_proofs
        .iter()
        .map(|proof| proof.head_event_ref.clone())
        .collect::<Vec<_>>();
    heads.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    let basis = DirectConversationAuthorizationBasis::accepted_contact(heads);
    basis
        .validate_shape()
        .map_err(|error| stale(&format!("the Contact round heads are not a basis: {error}")))?;
    Ok((basis, founding))
}

fn account_station(actor: &ActorId) -> Option<&arkret_wire::DidCoreId> {
    actor.as_account_id().map(|account| &account.station_id)
}

pub(crate) async fn admit_self_direct_conversation_founding_unit(
    pool: &PgPool,
    unit: &DirectConversationFoundingCommitUnit,
    producer_guards: &[SelfProducerCommitGuard; 4],
    queued_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<DirectConversationFoundingCommitOutcome> {
    let facts = unit
        .facts()
        .map_err(|error| conflict(ConflictCode::DirectConversationFoundingUnitInvalid, error))?;
    #[cfg(feature = "test-support")]
    profile_admission_spy::trip_if_watched(&facts.realm_id)?;
    unit.validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let authority = unit.transactions[0].expected_authority.clone();
    if facts.governance_station_id != authority.service_id {
        return Err(conflict(
            ConflictCode::DirectConversationFoundingUnitInvalid,
            "the genesis governance Station is not the admitting Station",
        ));
    }
    if account_station(&facts.founder_id) != Some(&authority.service_id) {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "the founder's current Station admits the founding unit",
        ));
    }
    let peer_station = account_station(&facts.peer_id).cloned().ok_or_else(|| {
        conflict(
            ConflictCode::DirectConversationFoundingUnitInvalid,
            "the peer must have a routable Account Station",
        )
    })?;
    let founder_id = facts.founder_id.to_string();
    let peer_id = facts.peer_id.to_string();
    let trust_domain_id = facts.trust_domain_id.as_str().to_owned();
    let pair_key = facts.pair_key.as_str().to_owned();
    let digest = facts.founding_unit_digest.as_str().to_owned();
    let idempotency_key = unit.submission.idempotency_key.as_uuid().to_string();
    let commits = unit.commits();
    let committed_at = commits[3].committed_at;
    let event_ids = unit
        .transactions
        .iter()
        .map(|transaction| transaction.event.event_id.to_string())
        .collect::<Vec<_>>();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        crate::unit_of_work::advisory_lock(
            conn,
            format!("direct-conversation-founding:{founder_id}:{trust_domain_id}:{pair_key}"),
        )
        .await?;
        crate::unit_of_work::advisory_lock(
            conn,
            format!("direct-conversation-founding-key:{founder_id}:{idempotency_key}"),
        )
        .await?;
        let replay = sql_query(
            "SELECT founding_unit_digest,commits_json FROM direct_conversation_founding_slots \
             WHERE founder_id=$1 AND idempotency_key=$2",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&idempotency_key)
        .get_result::<StoredUnitRow>(&mut *conn)
        .await
        .optional()?;
        if let Some(stored) = replay {
            if stored.founding_unit_digest != digest {
                return Err(conflict(
                    ConflictCode::DuplicateConflict,
                    "the idempotency key already founded another unit",
                )
                .into());
            }
            let stored: [arkret_wire::RealmCommit; 4] =
                serde_json::from_value(stored.commits_json).map_err(|error| {
                    PersistenceError::Database(format!(
                        "stored Direct Conversation founding Commits are invalid: {error}"
                    ))
                })?;
            return Ok(DirectConversationFoundingCommitOutcome::Duplicate(stored));
        }
        let occupied = sql_query(
            "SELECT founding_unit_digest,commits_json FROM direct_conversation_founding_slots \
             WHERE founder_id=$1 AND trust_domain_id=$2 AND pair_key=$3",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .get_result::<StoredUnitRow>(&mut *conn)
        .await
        .optional()?;
        if occupied.is_some() {
            return Err(conflict(
                ConflictCode::DirectConversationSlotAlreadyCommitted,
                "the founder's slot for this pair is closed",
            )
            .into());
        }
        let (authorization_basis, founding_evidence) = match &facts.authority_ref {
            DirectConversationFoundingAuthorityRef::ContactRound(contact_round_id) => {
                verify_contact_round_founding_authority(
                    conn,
                    &facts,
                    contact_round_id,
                    &authority.service_id,
                    committed_at,
                    ConflictCode::FailedPrecondition,
                )
                .await?
            }
            DirectConversationFoundingAuthorityRef::AgentProvision(provision_ref) => {
                verify_agent_founding_join_binding(unit, &facts)?;
                verify_agent_founding_authority(
                    conn,
                    &facts.founder_id,
                    &facts.peer_id,
                    provision_ref,
                    committed_at,
                    ConflictCode::FailedPrecondition,
                    true,
                )
                .await?
            }
        };
        let authority_inserted = sql_query(
            "INSERT INTO realm_authorities \
             (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
             VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
        )
        .bind::<Text, _>(authority.realm_id.as_str())
        .bind::<Text, _>(authority.service_id.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?,
        )
        .execute(&mut *conn)
        .await?;
        if authority_inserted != 1 {
            return Err(conflict(
                ConflictCode::RealmAlreadyExists,
                "the founding genesis names an existing Realm",
            )
            .into());
        }
        for (transaction, guard) in unit.transactions.iter().zip(producer_guards) {
            check_self_producer_guard_in_connection(
                conn,
                &transaction.event,
                guard,
                transaction.commit.committed_at,
            )
            .await?;
            let prepared_human = crate::agent_producer_signer_keys::validate_prepared_local_human_in_connection(conn, transaction).await?;
            queue_event_in_connection(conn, &transaction.event, queued_at).await?;
            match commit_transaction_in_connection(conn, transaction).await? {
                AuthorityCommitWriteOutcome::Committed => {}
                AuthorityCommitWriteOutcome::Duplicate => {
                    return Err(conflict(
                        ConflictCode::DuplicateConflict,
                        "a founding Event is already committed",
                    )
                    .into());
                }
                AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                    return Err(PersistenceError::Conflict(
                        "stale_realm_authority: the founding genesis authority moved".to_owned(),
                    )
                    .into());
                }
            }
            if let Some(fact) = prepared_human.as_ref() {
                crate::agent_producer_signer_keys::retain_prepared_human_in_connection(conn, &transaction.event, &transaction.commit, fact).await?;
            } else {
                crate::agent_producer_signer_keys::retain_in_connection(conn, &transaction.event, &transaction.commit, Some(guard)).await?;
            }
            let event = &transaction.event;
            let commit = &transaction.commit;
            crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
            crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
            crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit)
                .await?;
            if event.kind == arkret_wire::EventKind::StrandCreate {
                crate::strand_current_results::commit_direct_conversation_founding_strand_in_connection(
                    conn, event, commit,
                 None)
                .await?;
            }
        }
        crate::account_summary::publish_realm_account_summary_in_connection(
            conn,
            &authority.realm_id,
        )
        .await?;
        sql_query(
            "INSERT INTO direct_conversation_founding_slots \
             (founder_id,trust_domain_id,pair_key,peer_id,founding_unit_digest,realm_id,\
              main_strand_id,authorization_basis,event_ids,commits_json,idempotency_key,accepted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .bind::<Text, _>(&peer_id)
        .bind::<Text, _>(&digest)
        .bind::<Text, _>(facts.realm_id.as_str())
        .bind::<Text, _>(facts.main_strand_id.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&authorization_basis).map_err(PersistenceError::database)?,
        )
        .bind::<Jsonb, _>(serde_json::to_value(&event_ids).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(serde_json::to_value(&commits).map_err(PersistenceError::database)?)
        .bind::<Text, _>(&idempotency_key)
        .bind::<Timestamptz, _>(committed_at)
        .execute(&mut *conn)
        .await?;
        if peer_station != authority.service_id {
            let request = PeerAuthoritySubmitRequest::RegisteredAtomicUnit(
                PeerRegisteredAtomicUnitRequest {
                    branch: RegisteredAtomicUnitBranch::RegisteredAtomicUnit,
                    unit: PeerRegisteredAtomicUnit::DirectConversationFounding(
                        DirectConversationFoundingFederationSubmission {
                            unit_kind: unit.submission.unit_kind,
                            committed_events: std::array::from_fn(|index| {
                                CommittedEventSubmission {
                                    event_submission: unit.submission.events[index].clone(),
                                    source_commit: commits[index].clone(),
                                    producer_signer_fact: unit.transactions[index].producer_signer_fact.clone(),
                                    genesis_event_ref: None,
                                    welcomes: None,
                                }
                            }),
                            founding_authority_evidence: founding_evidence,
                        },
                    ),
                },
            );
            request
                .validate()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let payload_json = String::from_utf8(
                arkret_canonical::canonical_json_bytes(&request)
                    .map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
            let delivery_key = format!("direct-conversation-founding:{digest}");
            let delivery = FederationOutboxRecord::pending_without_locator(
                delivery_key.clone(),
                peer_station,
                crate::realm_fanout::PEER_EVENTS_ENDPOINT.to_owned(),
                delivery_key,
                payload_json,
                queued_at.timestamp(),
            );
            crate::federation::enqueue_federation_outbox_in_connection(conn, &delivery).await?;
        }
        Ok(DirectConversationFoundingCommitOutcome::Committed(
            commits.clone(),
        ))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

fn sort_distinct_glare_attestations(attestations: &mut [GlareConcurrencyAttestation; 2]) -> bool {
    if attestations[0].issuer_id == attestations[1].issuer_id {
        return false;
    }
    attestations.sort_by(|left, right| left.issuer_id.as_str().cmp(right.issuer_id.as_str()));
    true
}

fn same_distinct_glare_attestations(
    local: &mut [GlareConcurrencyAttestation; 2],
    source: &mut [GlareConcurrencyAttestation; 2],
) -> bool {
    sort_distinct_glare_attestations(local)
        && sort_distinct_glare_attestations(source)
        && local == source
}

/// The two Stations can store their own attestation first. The Contact round's
/// request array has a mandatory wire order; the two independently signed
/// attestations have no prescribed order. Keep every signed byte and all
/// other founding material exact while comparing this pair by unique issuer.
fn same_peer_founding_evidence(
    local: &DirectConversationFoundingAuthorityEvidence,
    source: &DirectConversationFoundingAuthorityEvidence,
) -> bool {
    let mut local = local.clone();
    let mut source = source.clone();
    if let (
        DirectConversationFoundingAuthorityEvidence::Human {
            contact_round_evidence: local_round,
            ..
        },
        DirectConversationFoundingAuthorityEvidence::Human {
            contact_round_evidence: source_round,
            ..
        },
    ) = (&mut local, &mut source)
        && matches!(local_round.contact_round, ContactRound::Glare { .. })
        && matches!(source_round.contact_round, ContactRound::Glare { .. })
    {
        let (Some(local_attestations), Some(source_attestations)) = (
            &mut local_round.glare_concurrency_attestations,
            &mut source_round.glare_concurrency_attestations,
        ) else {
            return false;
        };
        if !same_distinct_glare_attestations(local_attestations, source_attestations) {
            return false;
        }
    }
    local == source
}

/// The peer materialization cut. The source has already signed all four
/// Commits; the peer locks its local Contact evidence and installs exactly
/// those rows with a complete anchored replica stream in one transaction.
pub(crate) async fn materialize_peer_direct_conversation_founding_unit(
    pool: &PgPool,
    unit: &DirectConversationFoundingCommitUnit,
    evidence: &DirectConversationFoundingAuthorityEvidence,
    local_station: &arkret_wire::DidCoreId,
    received_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AggregateAcceptanceStatus> {
    let facts = unit
        .facts()
        .map_err(|error| conflict(ConflictCode::DirectConversationFoundingUnitInvalid, error))?;
    unit.validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if &facts.governance_station_id == local_station
        || facts.peer_id.route_service_id() != local_station
    {
        return Err(conflict(
            ConflictCode::DirectConversationFoundingUnitInvalid,
            "the peer Station is not the recipient of the founding unit",
        ));
    }
    let founder_id = facts.founder_id.to_string();
    let peer_id = facts.peer_id.to_string();
    let trust_domain_id = facts.trust_domain_id.as_str().to_owned();
    let pair_key = facts.pair_key.as_str().to_owned();
    let digest = facts.founding_unit_digest.as_str().to_owned();
    let commits = unit.commits();
    let event_ids = unit
        .transactions
        .iter()
        .map(|transaction| transaction.event.event_id.to_string())
        .collect::<Vec<_>>();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        crate::unit_of_work::advisory_lock(
            conn,
            format!("direct-conversation-founding:{founder_id}:{trust_domain_id}:{pair_key}"),
        )
        .await?;
        let occupied = sql_query(
            "SELECT founding_unit_digest,commits_json FROM direct_conversation_founding_slots \
             WHERE founder_id=$1 AND trust_domain_id=$2 AND pair_key=$3",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .get_result::<StoredUnitRow>(&mut *conn)
        .await
        .optional()?;
        if let Some(occupied) = occupied {
            let stored: [arkret_wire::RealmCommit; 4] =
                serde_json::from_value(occupied.commits_json).map_err(PersistenceError::database)?;
            if occupied.founding_unit_digest == digest && stored == commits {
                for transaction in &unit.transactions {
                    let original = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(conn, &transaction.event, &transaction.commit).await?;
                    if original != transaction.producer_signer_fact {
                        return Err(PersistenceError::Conflict("Direct founding source differs from original".into()).into());
                    }
                }
                return Ok(AggregateAcceptanceStatus::Duplicate);
            }
            return Err(conflict(
                ConflictCode::DirectConversationSlotAlreadyCommitted,
                "the peer already holds another founding unit for this pair",
            )
            .into());
        }
        let (basis, local_evidence) = match &facts.authority_ref {
            DirectConversationFoundingAuthorityRef::ContactRound(round_id) => {
                verify_contact_round_founding_authority(
                    conn,
                    &facts,
                    round_id,
                    local_station,
                    commits[3].committed_at,
                    ConflictCode::DependencyMissing,
                )
                .await?
            }
            DirectConversationFoundingAuthorityRef::AgentProvision(provision_ref) => {
                verify_agent_founding_join_binding(unit, &facts)?;
                verify_agent_founding_authority(
                    conn,
                    &facts.founder_id,
                    &facts.peer_id,
                    provision_ref,
                    commits[3].committed_at,
                    ConflictCode::DependencyMissing,
                    true,
                )
                .await?
            }
        };
        if !same_peer_founding_evidence(&local_evidence, evidence) {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "the source founding evidence does not match the peer's current Contact round",
            )
            .into());
        }
        // The replayed founding Events are evaluated by the Direct
        // Conversation admission table, which reads the pair from this slot;
        // the slot and the four Commits land in the same transaction.
        sql_query(
            "INSERT INTO direct_conversation_founding_slots \
             (founder_id,trust_domain_id,pair_key,peer_id,founding_unit_digest,realm_id,\
              main_strand_id,authorization_basis,event_ids,commits_json,idempotency_key,accepted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind::<Text, _>(&founder_id)
        .bind::<Text, _>(&trust_domain_id)
        .bind::<Text, _>(&pair_key)
        .bind::<Text, _>(&peer_id)
        .bind::<Text, _>(&digest)
        .bind::<Text, _>(facts.realm_id.as_str())
        .bind::<Text, _>(facts.main_strand_id.as_str())
        .bind::<Jsonb, _>(serde_json::to_value(&basis).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(serde_json::to_value(&event_ids).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(serde_json::to_value(&commits).map_err(PersistenceError::database)?)
        .bind::<Text, _>(format!("peer:{digest}"))
        .bind::<Timestamptz, _>(commits[3].committed_at)
        .execute(&mut *conn)
        .await?;
        crate::authority_commit::replica::materialize_founding_in_connection(
            conn,
            unit,
            local_station,
            received_at,
        )
        .await?;
        Ok(AggregateAcceptanceStatus::Committed)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::contact_operations::GlareConcurrencyAttestation;
    use arkret_wire::{AccountId, ActorId, DidCoreId, DidUrl, EventId, Hash, ProtocolSignature};

    use super::same_distinct_glare_attestations;

    fn attestation(
        issuer: DidCoreId,
        subject: ActorId,
        peer: ActorId,
    ) -> GlareConcurrencyAttestation {
        let observed_at = chrono::Utc::now();
        let hash = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        GlareConcurrencyAttestation {
            subject_id: subject,
            issuer_id: issuer,
            peer_id: peer,
            request_receipt_digests: [hash.clone(), hash.clone()],
            observed_commit_event_ids: vec![EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [3; 32],
            )],
            complete_through: 1,
            unconsumed_slot_checkpoint: hash,
            observed_at,
            signature: ProtocolSignature {
                verification_method: DidUrl::new("did:web:station.example#key".to_owned()).unwrap(),
                created_at: observed_at,
                jws: "signed-exact-attestation".to_owned(),
            },
        }
    }

    #[test]
    fn glare_attestations_match_by_unique_issuer_without_ignoring_signed_bytes() {
        let first_station: DidCoreId = "ak:did_core:web:first.example".parse().unwrap();
        let second_station: DidCoreId = "ak:did_core:web:second.example".parse().unwrap();
        let first = ActorId::account(AccountId::new(
            "ak:did_core:web:first-account.example".parse().unwrap(),
            first_station.clone(),
        ));
        let second = ActorId::account(AccountId::new(
            "ak:did_core:web:second-account.example".parse().unwrap(),
            second_station.clone(),
        ));
        let first_attestation = attestation(first_station, first.clone(), second.clone());
        let second_attestation = attestation(second_station, second, first);

        let mut local = [first_attestation.clone(), second_attestation.clone()];
        let mut source = [second_attestation.clone(), first_attestation.clone()];
        assert!(same_distinct_glare_attestations(&mut local, &mut source));

        let mut altered = [second_attestation.clone(), first_attestation.clone()];
        altered[0].signature.jws.push('x');
        assert!(!same_distinct_glare_attestations(
            &mut [first_attestation.clone(), second_attestation.clone()],
            &mut altered,
        ));

        let mut duplicate_issuer = [first_attestation.clone(), second_attestation];
        duplicate_issuer[1].issuer_id = duplicate_issuer[0].issuer_id.clone();
        assert!(!same_distinct_glare_attestations(
            &mut [first_attestation.clone(), first_attestation],
            &mut duplicate_issuer,
        ));
    }
}
