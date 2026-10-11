//! The Direct Conversation admission table at the governing Station's cut.
//!
//! `contact-and-direct-conversation.md` section 8.4 and the registry's
//! `direct_conversation_admission_mappings` fix seven producer paths for every
//! write that targets a Direct Conversation Realm. They are evaluated here,
//! inside the accepting transaction and before any action authority, kind
//! writer or RealmCommit, in the registered precedence order:
//!
//! 1. `binding_integrity` for `ak.direct_conversation.bound`;
//! 2. `terminal_guard` for `ak.realm.destroy` and `ak.realm.tombstone`;
//! 3. `exact_two_projection` for every write;
//! 4. `third_party_member_guard` for invite and membership candidates;
//! 5. `invite_guard` for invite flows;
//! 6. `root_phase_mask` for actions the technical authority root would carry;
//! 7. the closed participant evaluator: `ak.authority.direct_conversation_participant.v1` once a
//!    binding is accepted, and the two verifier-derived phases of
//!    `ak.authority.direct_conversation_bootstrap_participant.v1` before it (section 7.2).
//!
//! A Direct Conversation Realm is identified by its create-locked genesis
//! `purpose`; its immutable pair, main Strand, founding digest and
//! authorization basis come from the founder's local founding slot written by
//! the founding unit. The binding, the unique group's exact-pair state,
//! membership and the pair's Contact are read at the same cut, under the Realm
//! authority row lock every writer of them holds. The in-process reducer
//! projection is never an input. Every refusal is a [`ConflictCode`] the
//! caller turns into the closed `{status="rejected",reason_code}` outcome with
//! zero writes.

use std::collections::BTreeSet;

use arkret_models_collaboration::events_payloads::direct_conversation::{
    DirectConversationBindingCurrentValue, DirectConversationBoundPayload,
};
use arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis;
use arkret_wire::{ActorId, AuthoritySourceId, EventId, EventKind, RealmId, ScopeRef};
use coland_storage::ConflictCode;

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};

/// The role of the critical ref a participant Event names its binding by.
const BINDING_REF_ROLE: &str = "direct_conversation_binding";
/// The role of the critical ref a bootstrap Event names its founding unit by.
const FOUNDING_UNIT_REF_ROLE: &str = "direct_conversation_founding_unit";
/// The scope both directions of the pair must grant for a send-like action.
const DIRECT_MESSAGE_SCOPE: &str = "direct_message";

#[derive(QueryableByName)]
struct GenesisPurposeRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    purpose: Option<String>,
}

#[derive(QueryableByName)]
struct FoundingSlotRow {
    #[diesel(sql_type = Text)]
    founder_id: String,
    #[diesel(sql_type = Text)]
    peer_id: String,
    #[diesel(sql_type = Text)]
    pair_key: String,
    #[diesel(sql_type = Text)]
    main_strand_id: String,
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
    #[diesel(sql_type = Jsonb)]
    authorization_basis: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    event_ids: serde_json::Value,
}

#[derive(QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership: String,
}

#[derive(QueryableByName)]
struct RootControllerRow {
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: serde_json::Value,
}

#[derive(QueryableByName)]
struct GroupStateRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    current_exact_pair: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    initial_exact_pair_group_state_ref: Option<String>,
}

#[derive(QueryableByName)]
struct BindingRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// Immutable founding facts of a Direct Conversation Realm.
pub(crate) struct DirectConversationRealm {
    /// The exact pair and its founding coordinates, when this Station holds
    /// the founder's slot. A Direct Conversation Realm governed without it
    /// cannot resolve its immutable pair.
    founding: Option<FoundingFacts>,
}

impl DirectConversationRealm {
    /// The immutable pair, when this Station holds the founding slot.
    pub(crate) fn pair(&self) -> Option<BTreeSet<&ActorId>> {
        self.founding.as_ref().map(FoundingFacts::pair)
    }

    /// Signal reads use the same branch-specific pair gate in their read-only
    /// snapshot, without acquiring the row locks used by durable admission.
    pub(crate) async fn pair_grants_direct_message_snapshot(
        &self,
        conn: &mut AsyncPgConnection,
    ) -> PersistenceResult<bool> {
        let Some(founding) = &self.founding else {
            return Ok(false);
        };
        use arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind;
        if founding.authorization_basis.kind == DirectConversationAuthorizationKind::AgentController
        {
            return crate::direct_conversation_founding::agent_controller_pair_current_snapshot(
                conn,
                &founding.founder,
                &founding.peer,
                &founding.authorization_basis,
            )
            .await;
        }
        let contact = crate::direct_conversation_founding::current_contact(
            crate::contacts::pair_contacts_snapshot_in_connection(
                conn,
                &founding.founder,
                &founding.peer,
            )
            .await?,
        );
        Ok(contact_grants_direct_message(contact.as_ref()))
    }
}

struct FoundingFacts {
    founder: ActorId,
    peer: ActorId,
    pair_key: String,
    main_strand_id: String,
    founding_unit_digest: String,
    authorization_basis: DirectConversationAuthorizationBasis,
    /// The founding unit's accepted `ak.realm.create`.
    create_event_id: EventId,
}

impl FoundingFacts {
    fn pair(&self) -> BTreeSet<&ActorId> {
        [&self.founder, &self.peer].into_iter().collect()
    }
}

/// The unique scope-derived group of the Realm against the pair, when its
/// Genesis is accepted.
struct GroupState {
    current_exact_pair: bool,
    initial_exact_pair_group_state_ref: Option<EventId>,
}

/// How the profile decided an Event's authority at this cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileAuthority {
    /// The participant evaluator, a bootstrap phase or the technical root's
    /// current phase mask authorizes the Event. No ordinary grant or owner
    /// aggregation is consulted after it.
    Profile,
    /// No profile stage decides the Event; ordinary Realm authority does.
    General,
}

fn decode_actor(value: &str, what: &str) -> PersistenceResult<ActorId> {
    serde_json::from_str(value)
        .map_err(|error| PersistenceError::Database(format!("stored {what} is invalid: {error}")))
}

fn stored<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    what: &str,
) -> PersistenceResult<T> {
    serde_json::from_value(value)
        .map_err(|error| PersistenceError::Database(format!("stored {what} is invalid: {error}")))
}

/// The Realm's create-locked role. `None` for every Realm that is not a Direct
/// Conversation, including one this Station holds no genesis for.
pub(crate) async fn direct_conversation_realm_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<DirectConversationRealm>> {
    let purpose = sql_query(
        "SELECT value->>'purpose' AS purpose FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_genesis'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<GenesisPurposeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .and_then(|row| row.purpose);
    if purpose.as_deref() != Some("direct_conversation") {
        return Ok(None);
    }
    let founding = sql_query(
        "SELECT founder_id,peer_id,pair_key,main_strand_id,founding_unit_digest,\
                authorization_basis,event_ids \
         FROM direct_conversation_founding_slots WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<FoundingSlotRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| {
        let event_ids: Vec<EventId> = stored(row.event_ids, "founding slot Event ids")?;
        Ok::<_, PersistenceError>(FoundingFacts {
            founder: decode_actor(&row.founder_id, "founding slot founder")?,
            peer: decode_actor(&row.peer_id, "founding slot peer")?,
            pair_key: row.pair_key,
            main_strand_id: row.main_strand_id,
            founding_unit_digest: row.founding_unit_digest,
            authorization_basis: stored(
                row.authorization_basis,
                "founding slot authorization basis",
            )?,
            create_event_id: event_ids.into_iter().next().ok_or_else(|| {
                PersistenceError::Database("stored founding slot has no create Event".to_owned())
            })?,
        })
    })
    .transpose()?;
    Ok(Some(DirectConversationRealm { founding }))
}

/// Whether the Event maps to an action of the closed participant allowlist
/// (`ak.authority.direct_conversation_participant.v1` `event_action_allowlist`).
fn participant_action(event: &arkret_wire::Event) -> bool {
    if arkret_models_collaboration::direct_conversation::direct_conversation_structure_action(
        &event.kind,
    ) {
        return true;
    }
    match event.kind {
        EventKind::MessageCreate
        | EventKind::MessageRedact
        | EventKind::MessageRevise
        | EventKind::MlsCommit
        | EventKind::ReactionAdd
        | EventKind::ReactionRemove
        | EventKind::ReadCursorAdvance
        | EventKind::StrandWatchSet
        | EventKind::StrandCreate => true,
        EventKind::MemberState => {
            membership_of(event).as_deref() == Some("leave")
                && membership_target(event).as_ref() == Some(&event.actor_id)
        }
        _ => false,
    }
}

/// The repair source is deliberately disjoint from the ordinary participant
/// source: it carries only an existing participant's `leave -> join` edge.
fn repair_action(event: &arkret_wire::Event) -> bool {
    event.kind == EventKind::MemberState
        && membership_of(event).as_deref() == Some("join")
        && membership_target(event).as_ref() == Some(&event.actor_id)
}

/// Whether the Event maps to an action of the bootstrap source's allowlist
/// (`ak.authority.direct_conversation_bootstrap_participant.v1`).
fn bootstrap_action(event: &arkret_wire::Event) -> bool {
    matches!(
        event.kind,
        EventKind::DirectConversationBound | EventKind::MessageCreate | EventKind::MlsCommit
    )
}

/// The send-like actions the directional Contact heads gate: new content or
/// key material delivered to the peer (sections 8.2 and 8.3).
fn send_like(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::MessageCreate
            | EventKind::MessageRevise
            | EventKind::ReactionAdd
            | EventKind::MlsCommit
    )
}

fn membership_of(event: &arkret_wire::Event) -> Option<String> {
    event
        .payload
        .get("membership")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn membership_target(event: &arkret_wire::Event) -> Option<ActorId> {
    event
        .payload
        .get("member_id")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

/// The invite or join candidate the third-party stage compares with the pair.
fn member_candidate(event: &arkret_wire::Event) -> Option<ActorId> {
    match event.kind {
        EventKind::MemberState => membership_target(event),
        EventKind::InviteCreate => event
            .payload
            .get("invitee_account_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok())
            .map(ActorId::account),
        _ => None,
    }
}

fn is_space_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::SpaceCreate
            | EventKind::SpaceUpdate
            | EventKind::SpaceParent
            | EventKind::SpaceArchive
            | EventKind::SpaceRestore
            | EventKind::SpaceTombstone
    )
}

/// Whether the Event's authority could only come from the technical
/// authority root's owner aggregate: a capability-gated kind, or a membership
/// edge on another member. Self membership edges are decided by the join rule,
/// never by the root.
fn root_reliant(event: &arkret_wire::Event) -> bool {
    if event.kind == EventKind::MemberState {
        return membership_target(event).as_ref() != Some(&event.actor_id);
    }
    arkret_schema::capability_actions_for_event_kind(event.kind.as_str())
        .next()
        .is_some()
}

/// The root phase mask's closed `masked_actions` of the phase after the
/// founding unit: until the first binding endorsement is accepted the Realm is
/// materializing and the root may carry the scope's unique `ak.mls.genesis`
/// and the `ak.mls.commit` adding the other participant; once `found`, the
/// mask is empty. The founding phase's four-Event unit never reaches here.
fn root_masked(kind: &EventKind, bound: bool) -> bool {
    !bound && matches!(kind, EventKind::MlsGenesis | EventKind::MlsCommit)
}

/// The membership rows of `exact_two_projection`: every member row of the
/// Realm, joined or left, so a participant who left still counts and can
/// rejoin (`contact-and-direct-conversation.md` §8.4).
async fn participant_members(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Vec<(ActorId, String)>> {
    sql_query(
        "SELECT member_id,membership FROM member_state_current_results \
         WHERE realm_id=$1 AND membership IN ('join','leave') ORDER BY member_id FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<MemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .into_iter()
    .map(|row| {
        Ok((
            decode_actor(&row.member_id, "member_state member")?,
            row.membership,
        ))
    })
    .collect()
}

async fn root_controller(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<ActorId>> {
    sql_query(
        "SELECT controller_actor_id FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootControllerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| stored(row.controller_actor_id, "authority-root controller"))
    .transpose()
}

/// The scope-derived group's state against the pair, `None` before its
/// Genesis is accepted.
async fn group_state(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<GroupState>> {
    sql_query(
        "SELECT current_exact_pair,initial_exact_pair_group_state_ref \
         FROM direct_conversation_group_states WHERE realm_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<GroupStateRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| {
        Ok(GroupState {
            current_exact_pair: row.current_exact_pair,
            initial_exact_pair_group_state_ref: row
                .initial_exact_pair_group_state_ref
                .map(EventId::new)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Database(format!("stored group state ref: {error}"))
                })?,
        })
    })
    .transpose()
}

/// The accepted `direct_conversation_binding` of the Realm, if any.
pub(crate) async fn binding_current_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<DirectConversationBindingCurrentValue>> {
    read_binding_current_in_connection(conn, realm_id, true).await
}

/// Read facts from an enclosing repeatable-read snapshot. This never locks an
/// admission row: its caller either selects a read-only cut or already holds
/// the Realm authority write lock before revalidating a public-cache install.
pub(crate) async fn binding_current_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<DirectConversationBindingCurrentValue>> {
    read_binding_current_in_connection(conn, realm_id, false).await
}

async fn read_binding_current_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    lock: bool,
) -> PersistenceResult<Option<DirectConversationBindingCurrentValue>> {
    let query = if lock {
        "SELECT value FROM direct_conversation_binding_current_results WHERE realm_id=$1 FOR SHARE"
    } else {
        "SELECT value FROM direct_conversation_binding_current_results WHERE realm_id=$1"
    };
    sql_query(query)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<BindingRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| stored(row.value, "direct_conversation_binding value"))
        .transpose()
}

/// The pair's current branch-specific authority: Contact consent or the
/// exact current controller/provision and accepted Agent runtime binding.
async fn pair_grants_direct_message(
    conn: &mut AsyncPgConnection,
    founding: &FoundingFacts,
) -> PersistenceResult<bool> {
    use arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind;
    if founding.authorization_basis.kind == DirectConversationAuthorizationKind::AgentController {
        return crate::direct_conversation_founding::agent_controller_pair_current(
            conn,
            &founding.founder,
            &founding.peer,
            &founding.authorization_basis,
        )
        .await;
    }
    let contact = crate::direct_conversation_founding::current_contact(
        crate::contacts::pair_contacts_in_connection(conn, &founding.founder, &founding.peer)
            .await?,
    );
    Ok(contact_grants_direct_message(contact.as_ref()))
}

fn contact_grants_direct_message(contact: Option<&coland_storage::ContactRecord>) -> bool {
    let grants = |scopes: &[String]| scopes.iter().any(|scope| scope == DIRECT_MESSAGE_SCOPE);
    contact.is_some_and(|contact| {
        contact.status == "accepted"
            && contact.tombstone_event_ref.is_none()
            && grants(&contact.granted_to_target_scopes)
            && grants(&contact.granted_to_requester_scopes)
    })
}

/// Read the current peer leaf's creation provenance, never an obsolete Add.
/// Update preserves a leaf's Add; Remove permanently retires that occurrence.
pub(crate) async fn peer_mls_admission_snapshot(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<
    arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission,
> {
    use arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission;
    #[derive(QueryableByName)]
    struct AdmissionRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        has_peer: bool,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        durable: bool,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        pending: bool,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        unknown: bool,
    }
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&scope).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    // Every accepted Add freezes the producer-signed Welcome at the same cut.
    // Recipient roster attestations arrive later and are not claim provenance.
    let row = sql_query(
        "WITH active AS ( \
         SELECT p.* FROM mls_consumed_proposal_provenance p \
         JOIN direct_conversation_founding_slots f ON f.realm_id=p.realm_id \
         WHERE p.scope_key=$1 AND p.proposal_type=1 \
           AND p.target_after_actor_id=f.peer_id::jsonb \
           AND NOT EXISTS(SELECT 1 FROM mls_consumed_proposal_provenance removed \
             WHERE removed.scope_key=p.scope_key AND removed.proposal_type=3 \
               AND removed.target_before_leaf_index=p.target_after_leaf_index \
               AND removed.commit_stream_position>p.commit_stream_position)), \
         claims AS (SELECT a.*,att.welcome_id,att.claim_id,c.state,c.claim_expires_at_unix_ms, \
           (c.state='consumed' AND (b.claim_id IS NOT NULL OR EXISTS( \
             SELECT 1 FROM federation_outbox fan \
             WHERE fan.endpoint='/_arkret/peer/events' AND fan.state='delivered' \
               AND fan.payload_json::jsonb #>> '{replications,0,source_commit,event_ref}'=a.commit_event_ref \
               AND fan.payload_json::jsonb #>> '{replications,0,welcomes,0,welcome_id}'=att.welcome_id \
               AND fan.peer_id=c.outcome #>> '{claim_receipt,destination_id}' \
               AND c.consume_receipt #>> '{recipient_durable_receipt,welcome_ref}'=att.welcome_id \
           ))) AS durable \
         FROM active a \
         LEFT JOIN mls_welcome_provenance att ON att.scope_key=a.scope_key \
           AND att.commit_event_ref=a.commit_event_ref \
           AND convert_from(att.delivery_canonical_json,'UTF8')::jsonb->'recipient_actor_id' \
               =a.target_after_actor_id \
         LEFT JOIN keypackage_claim_welcome_bindings b ON b.claim_id=att.claim_id \
           AND b.welcome_id=att.welcome_id AND b.commit_event_ref=a.commit_event_ref \
         LEFT JOIN peer_keypackage_claims c ON \
           (b.claim_id IS NOT NULL AND c.source_id=b.source_id AND c.claim_request_id=b.claim_request_id) \
           OR (b.claim_id IS NULL AND c.outcome #>> '{claims,0,claim_id}'=att.claim_id)) \
         SELECT EXISTS(SELECT 1 FROM active) AS has_peer, \
           EXISTS(SELECT 1 FROM claims WHERE durable) AS durable, \
           EXISTS(SELECT 1 FROM claims WHERE state IN ('claimed','last_resort_claimed') \
             AND claim_expires_at_unix_ms>$2) AS pending, \
           (EXISTS(SELECT 1 FROM claims WHERE claim_id IS NULL OR state IS NULL \
             OR (state='consumed' AND NOT durable)) \
            OR (NOT EXISTS(SELECT 1 FROM active) AND EXISTS( \
              SELECT 1 FROM direct_conversation_group_states WHERE realm_id=$3 AND current_exact_pair))) AS unknown",
    ).bind::<Text, _>(&key)
     .bind::<diesel::sql_types::BigInt, _>(chrono::Utc::now().timestamp_millis())
    .bind::<Text, _>(realm_id.as_str())
     .get_result::<AdmissionRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if row.unknown {
        return Err(PersistenceError::Internal(
            "current Direct peer admission evidence unavailable".into(),
        ));
    }
    Ok(if !row.has_peer {
        DirectConversationPeerMlsAdmission::Missing
    } else if row.durable {
        DirectConversationPeerMlsAdmission::Durable
    } else if row.pending {
        DirectConversationPeerMlsAdmission::Pending
    } else {
        DirectConversationPeerMlsAdmission::RepairRequired
    })
}

/// The one critical semantic ref of `role` an authority source requires.
fn critical_ref<'a>(event: &'a arkret_wire::Event, role: &str) -> Option<&'a str> {
    let mut refs = event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == role);
    match (refs.next(), refs.next()) {
        (Some(reference), None) if reference.critical => Some(reference.id.as_str()),
        _ => None,
    }
}

fn bound_payload(event: &arkret_wire::Event) -> Option<DirectConversationBoundPayload> {
    serde_json::to_value(&event.payload)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok())
        .filter(|payload: &DirectConversationBoundPayload| payload.validate_shape().is_ok())
}

/// Binding integrity (`ak.direct_conversation.admission.binding_integrity.v1`):
/// every immutable field of the endorsement equals the accepted founding facts,
/// the canonical authorization basis and the first exact-pair winning state of
/// the unique scope-derived group, and an already accepted binding carries the
/// same semantic digest.
fn binding_is_exact(
    event: &arkret_wire::Event,
    founding: Option<&FoundingFacts>,
    group: Option<&GroupState>,
    binding: Option<&DirectConversationBindingCurrentValue>,
) -> bool {
    let (Some(founding), Some(payload)) = (founding, bound_payload(event)) else {
        return false;
    };
    let normalized_refs = |basis: &DirectConversationAuthorizationBasis| {
        basis.event_refs.iter().cloned().collect::<BTreeSet<_>>()
    };
    let fields_match = payload.pair_key.as_str() == founding.pair_key
        && payload.realm_id == event.realm_id
        && payload.main_strand_id.as_str() == founding.main_strand_id
        && payload.founding_unit_digest.as_str() == founding.founding_unit_digest
        && payload.authorization_basis.kind == founding.authorization_basis.kind
        && normalized_refs(&payload.authorization_basis)
            == normalized_refs(&founding.authorization_basis)
        && payload
            .unordered_participant_ids
            .iter()
            .collect::<BTreeSet<_>>()
            == founding.pair();
    let group_state_is_initial = group
        .and_then(|group| group.initial_exact_pair_group_state_ref.as_ref())
        == Some(&payload.initial_exact_pair_group_state_ref);
    let same_binding = binding
        .is_none_or(|binding| binding.binding_digest().ok() == payload.binding_digest().ok());
    fields_match && group_state_is_initial && same_binding
}

/// The cut inputs stage 7 reads besides the Event.
struct EvaluatorInputs<'a> {
    founding: &'a FoundingFacts,
    members: &'a [(ActorId, String)],
    group: Option<&'a GroupState>,
    binding: Option<&'a DirectConversationBindingCurrentValue>,
}

/// Stage 7 at the cut: whether the Event's registered authority source admits
/// it. Every failed input collapses into one `false`.
async fn participant_authority_admits(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    inputs: EvaluatorInputs<'_>,
) -> PersistenceResult<bool> {
    let EvaluatorInputs {
        founding,
        members,
        group,
        binding,
    } = inputs;
    let actor_membership = members.iter().find_map(|(member, membership)| {
        (member == &event.actor_id).then_some(membership.as_str())
    });
    let realm_scope =
        matches!(&event.scope_ref, ScopeRef::Realm { realm_id } if realm_id == &event.realm_id);
    let valid_executor = event.executed_by.as_ref().is_none_or(|executor|
        founding.authorization_basis.kind == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController
        && event.actor_id == founding.peer && &founding.founder == executor);
    if !valid_executor || !realm_scope || !founding.pair().contains(&event.actor_id) {
        return Ok(false);
    }
    let source = event
        .authorization_ref
        .as_ref()
        .and_then(|reference| AuthoritySourceId::from_wire(reference.as_str()));
    let admitted = match source {
        Some(AuthoritySourceId::DirectConversationParticipantV1) => {
            let (Some(binding), Some(group)) = (binding, group) else {
                return Ok(false);
            };
            let covered = critical_ref(event, BINDING_REF_ROLE)
                .and_then(|reference| EventId::new(reference).ok())
                .is_some_and(|reference| binding.endorsed_by(&reference));
            participant_action(event)
                && actor_membership == Some("join")
                && covered
                && group.current_exact_pair
                && (event.kind != EventKind::StrandWatchSet
                    || watch_admits_in_connection(conn, event, founding).await?)
                && (!arkret_models_collaboration::direct_conversation::direct_conversation_structure_action(&event.kind)
                    || structure_admits_in_connection(conn, event, founding).await?)
        }
        Some(AuthoritySourceId::DirectConversationRepairV1) => {
            let Some(binding) = binding else {
                return Ok(false);
            };
            let covered = critical_ref(event, BINDING_REF_ROLE)
                .and_then(|reference| EventId::new(reference).ok())
                .is_some_and(|reference| binding.endorsed_by(&reference));
            repair_action(event) && actor_membership == Some("leave") && covered
        }
        Some(AuthoritySourceId::DirectConversationBootstrapParticipantV1) => {
            let names_founding = critical_ref(event, FOUNDING_UNIT_REF_ROLE)
                == Some(founding.create_event_id.as_str());
            let Some(group) = group else {
                return Ok(false);
            };
            if !bootstrap_action(event) || !names_founding {
                return Ok(false);
            }
            match (binding, &group.initial_exact_pair_group_state_ref) {
                // Section 7.2: after the first endorsement both phases have
                // exited; only a compatible endorsement of the settled digest
                // (checked by binding integrity) still accumulates.
                (Some(_), _) => event.kind == EventKind::DirectConversationBound,
                // `exact_pair_founding_completion`.
                (None, Some(_)) if peer_mls_admission_snapshot(conn, &event.realm_id).await?
                    == arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission::Durable => {
                    event.kind == EventKind::DirectConversationBound && group.current_exact_pair
                }
                // `provisional_history_send`: the founder alone manages its
                // own leaf, sends and Adds the peer.
                (None, _) => {
                    event.actor_id == founding.founder
                        && event.kind != EventKind::DirectConversationBound
                }
            }
        }
        _ => false,
    };
    if !admitted {
        return Ok(false);
    }
    if (send_like(&event.kind)
        || repair_action(event)
        || event.kind == EventKind::StrandWatchSet
        || arkret_models_collaboration::direct_conversation::direct_conversation_structure_action(
            &event.kind,
        ))
        && !pair_grants_direct_message(conn, founding).await?
    {
        return Ok(false);
    }
    Ok(true)
}

/// Read only the exact current object cuts, never the in-memory projection.
async fn structure_admits_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    founding: &FoundingFacts,
) -> PersistenceResult<bool> {
    use std::collections::BTreeMap;

    use arkret_models_collaboration::objects::space::Space;
    use arkret_models_collaboration::objects::strand::Strand;
    #[derive(QueryableByName)]
    struct ObjectRow {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let main_id =
        arkret_wire::StrandId::new(&founding.main_strand_id).map_err(PersistenceError::database)?;
    let target = event
        .payload
        .get("strand_id")
        .or_else(|| event.payload.get("target_ref"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&founding.main_strand_id);
    let rows = sql_query("SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.strand_id IN ($2,$3) AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id FOR SHARE OF s")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&founding.main_strand_id).bind::<Text,_>(target)
        .load::<ObjectRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut strands = BTreeMap::new();
    for row in rows {
        let strand: Strand = stored(row.value, "DM structure Strand")?;
        if let Some(id) = strand.id.clone() {
            strands.insert(id, strand);
        }
    }
    let rows = sql_query("SELECT s.value || p.value || CASE WHEN q.value='null'::jsonb THEN '{}'::jsonb ELSE jsonb_build_object('child_scope_policy',q.value) END AS value FROM space_current_results s JOIN space_parent_current_results p ON p.space_id=s.space_id AND p.realm_id=s.realm_id JOIN space_child_scope_policy_current_results q ON q.space_id=s.space_id AND q.realm_id=s.realm_id JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position JOIN realm_commits pc ON pc.commit_id=p.current_commit_id AND pc.realm_id=p.realm_id AND pc.stream_position=p.current_stream_position JOIN realm_commits qc ON qc.commit_id=q.current_commit_id AND qc.realm_id=q.realm_id AND qc.stream_position=q.current_stream_position WHERE s.realm_id=$1 AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id AND pc.stream_ref=c.stream_ref AND qc.stream_ref=c.stream_ref FOR SHARE OF s,p,q")
        .bind::<Text,_>(event.realm_id.as_str()).load::<ObjectRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut spaces = BTreeMap::new();
    for row in rows {
        let mut value = row.value;
        if value
            .get("parent_space_id")
            .is_some_and(serde_json::Value::is_null)
        {
            value.as_object_mut().unwrap().remove("parent_space_id");
        }
        let space: Space = stored(value, "DM structure Space")?;
        if let Some(id) = space.id.clone() {
            spaces.insert(id, space);
        }
    }
    Ok(
        arkret_models_collaboration::direct_conversation::direct_conversation_structure_admits(
            event, &main_id, &strands, &spaces,
        ),
    )
}

async fn watch_admits_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    founding: &FoundingFacts,
) -> PersistenceResult<bool> {
    let Ok(payload) = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload,
    >(serde_json::json!(&event.payload)) else {
        return Ok(false);
    };
    if payload.watcher_actor_id != event.actor_id {
        return Ok(false);
    }
    let main = arkret_wire::StrandId::new(founding.main_strand_id.clone())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let rows = sql_query("SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.strand_id IN ($2,$3) AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id FOR SHARE OF s")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(main.as_str()).bind::<Text,_>(payload.strand_id.as_str())
        .load::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut strands = std::collections::BTreeMap::new();
    for row in rows {
        let strand: arkret_models_collaboration::objects::strand::Strand =
            serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        if let Some(id) = strand.id.clone() {
            strands.insert(id, strand);
        }
    }
    Ok(
        arkret_models_collaboration::direct_conversation::direct_conversation_watch_admits(
            event, &main, &strands,
        ),
    )
}

/// The table's verdict for `event` at the caller's cut: the first refusing
/// stage, or whether the profile itself authorized the Event.
async fn evaluate_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &DirectConversationRealm,
    event: &arkret_wire::Event,
) -> PersistenceResult<Result<ProfileAuthority, ConflictCode>> {
    let founding = realm.founding.as_ref();
    let group = group_state(conn, &event.realm_id).await?;
    let binding = binding_current_in_connection(conn, &event.realm_id).await?;
    if event.kind == EventKind::DirectConversationBound
        && !binding_is_exact(event, founding, group.as_ref(), binding.as_ref())
    {
        return Ok(Err(ConflictCode::DirectConversationBindingInvalid));
    }
    if matches!(
        event.kind,
        EventKind::RealmDestroy | EventKind::RealmTombstone
    ) {
        return Ok(Err(ConflictCode::DirectConversationTerminalForbidden));
    }
    let Some(founding) = founding else {
        return Ok(Err(ConflictCode::DirectConversationMemberCountInvalid));
    };
    let pair = founding.pair();
    let members = participant_members(conn, &event.realm_id).await?;
    let distinct = members
        .iter()
        .map(|(member, _)| member)
        .collect::<BTreeSet<_>>();
    if pair.len() != 2 || distinct.len() != members.len() || distinct != pair {
        return Ok(Err(ConflictCode::DirectConversationMemberCountInvalid));
    }
    if event.kind == EventKind::InviteThirdParty
        || (matches!(event.kind, EventKind::InviteCreate | EventKind::MemberState)
            && member_candidate(event).is_none_or(|candidate| !pair.contains(&candidate)))
    {
        return Ok(Err(
            ConflictCode::DirectConversationThirdPartyMemberForbidden,
        ));
    }
    if matches!(
        event.kind,
        EventKind::InviteCreate | EventKind::InviteThirdParty
    ) {
        return Ok(Err(ConflictCode::DirectConversationInviteForbidden));
    }
    let evaluated = participant_action(event) || repair_action(event) || bootstrap_action(event);
    if !evaluated
        && root_reliant(event)
        && root_controller(conn, &event.realm_id).await?.as_ref() == Some(&event.actor_id)
    {
        if root_masked(&event.kind, binding.is_some()) {
            return Ok(Ok(ProfileAuthority::Profile));
        }
        return Ok(Err(ConflictCode::DirectConversationRootMaskViolation));
    }
    if evaluated {
        if event.kind == EventKind::SpaceCreate
            && event
                .payload
                .get("object")
                .and_then(|object| object.get("kind"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind != "topic")
        {
            return Ok(Err(ConflictCode::DirectConversationSpaceForbidden));
        }
        let admitted = participant_authority_admits(
            conn,
            event,
            EvaluatorInputs {
                founding,
                members: &members,
                group: group.as_ref(),
                binding: binding.as_ref(),
            },
        )
        .await?;
        return Ok(if admitted {
            Ok(ProfileAuthority::Profile)
        } else {
            Err(ConflictCode::DirectConversationParticipantAuthorityDenied)
        });
    }
    if is_space_kind(&event.kind) {
        return Ok(Err(ConflictCode::DirectConversationSpaceForbidden));
    }
    Ok(Ok(ProfileAuthority::General))
}

/// Evaluate the admission table for `event` at the caller's cut.
///
/// The caller either holds the Realm authority row lock inside the accepting
/// transaction or reads inside one snapshot.
pub(crate) async fn admission_refusal_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<ConflictCode>> {
    let Some(realm) = direct_conversation_realm_in_connection(conn, &event.realm_id).await? else {
        return Ok(None);
    };
    Ok(evaluate_in_connection(conn, &realm, event).await?.err())
}

fn refusal(code: ConflictCode, event: &arkret_wire::Event) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: the Direct Conversation admission table refused {}",
        code.as_str(),
        event.kind.as_str()
    ))
}

/// Refuse `event` inside its accepting transaction when a stage matches. The
/// Realm authority row lock is taken first so the verdict and the Commit it
/// gates share one cut.
pub(crate) async fn admit_direct_conversation_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    profile_authority_in_connection(conn, event)
        .await
        .map(|_| ())
}

/// The profile's authority verdict for `event` inside its accepting
/// transaction, under the Realm authority row lock: `None` for a Realm that is
/// not a Direct Conversation, a refusal as its registered conflict, and
/// otherwise whether the profile authorized the Event or leaves it to
/// ordinary Realm authority. Kind writers that decide capability-gated
/// authority call this instead of counting grants or the owner aggregate for
/// a Direct Conversation (section 8.3: they never substitute the evaluator).
pub(crate) async fn profile_authority_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<ProfileAuthority>> {
    let Some(realm) = direct_conversation_realm_in_connection(conn, &event.realm_id).await? else {
        return Ok(None);
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    match evaluate_in_connection(conn, &realm, event).await? {
        Ok(authority) => Ok(Some(authority)),
        Err(code) => Err(refusal(code, event)),
    }
}

/// The Realm's scope-derived group state against its pair after an accepted
/// `ak.mls.genesis` or `ak.mls.commit`, written with the group current in
/// the same transaction. The first Commit whose roster principals are exactly
/// the pair becomes the Realm's `initial_exact_pair_group_state_ref`.
pub(crate) async fn record_group_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    member_principals: &BTreeSet<ActorId>,
) -> PersistenceResult<()> {
    let Some(realm) = direct_conversation_realm_in_connection(conn, &event.realm_id).await? else {
        return Ok(());
    };
    let exact_pair = realm
        .pair()
        .is_some_and(|pair| member_principals.iter().collect::<BTreeSet<_>>() == pair);
    sql_query(
        "INSERT INTO direct_conversation_group_states \
         (realm_id,current_group_state_ref,current_exact_pair,initial_exact_pair_group_state_ref) \
         VALUES ($1,$2,$3,CASE WHEN $3 THEN $2 END) \
         ON CONFLICT (realm_id) DO UPDATE SET \
           current_group_state_ref=EXCLUDED.current_group_state_ref, \
           current_exact_pair=EXCLUDED.current_exact_pair, \
           initial_exact_pair_group_state_ref=COALESCE(\
             direct_conversation_group_states.initial_exact_pair_group_state_ref,\
             EXCLUDED.initial_exact_pair_group_state_ref)",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<diesel::sql_types::Bool, _>(exact_pair)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// `ak.direct_conversation.bound` `result_writes`: add the accepted
/// endorsement under its `<event_id>:0` dot to the Realm's binding set. The
/// table already refused an endorsement of another digest before this write.
pub(crate) async fn commit_binding_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingEndorsementEntry;
    if event.kind != EventKind::DirectConversationBound {
        return Ok(());
    }
    let payload = bound_payload(event).ok_or_else(|| {
        PersistenceError::SchemaViolation("ak.direct_conversation.bound payload is invalid".into())
    })?;
    if payload.realm_id != event.realm_id
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(PersistenceError::SchemaViolation(
            "binding projection differs from its accepted Event/Realm stream".into(),
        ));
    }
    let entry = DirectConversationBindingEndorsementEntry {
        tag_id: arkret_models_collaboration::exact_current_results::CanonicalEventDot::new(
            event.event_id.clone(),
            0,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
        value: payload.clone(),
    };
    let value = match binding_current_in_connection(conn, &event.realm_id).await? {
        Some(current) if current.endorsements.contains(&entry) => Ok(current),
        Some(current) => current.with_endorsement(entry),
        None => Ok(DirectConversationBindingCurrentValue {
            endorsements: vec![entry],
        }),
    }
    .map_err(|error| {
        PersistenceError::Conflict(format!(
            "{}: {error}",
            ConflictCode::DirectConversationBindingInvalid.as_str()
        ))
    })?;
    let digest = value
        .binding_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("binding stream position exceeds BIGINT".to_owned())
    })?;
    let changed = sql_query(
        "INSERT INTO direct_conversation_binding_current_results \
         (realm_id,pair_key,binding_digest,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (realm_id) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value, updated_at=EXCLUDED.updated_at \
         WHERE direct_conversation_binding_current_results.binding_digest=EXCLUDED.binding_digest \
           AND direct_conversation_binding_current_results.pair_key=EXCLUDED.pair_key \
           AND (direct_conversation_binding_current_results.current_stream_position<EXCLUDED.current_stream_position \
             OR (direct_conversation_binding_current_results.current_stream_position=EXCLUDED.current_stream_position \
               AND direct_conversation_binding_current_results.current_commit_id=EXCLUDED.current_commit_id \
               AND direct_conversation_binding_current_results.value=EXCLUDED.value))",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.pair_key.as_str())
    .bind::<Text, _>(digest.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<diesel::sql_types::BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(&value).map_err(PersistenceError::database)?)
    .bind::<diesel::sql_types::Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PersistenceError::Conflict(
            "failed_precondition: binding projection changes its pair, digest or accepted revision"
                .into(),
        ))
    }
}

/// Validate an authenticated replica value without re-running governing admission.
pub(crate) async fn guard_binding_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    entry: &arkret_wire::TypedCurrentRow,
) -> PersistenceResult<()> {
    let arkret_wire::TypedCurrentRow::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } = entry;
    let arkret_wire::CurrentSelector::DirectConversationBinding { pair_key } = selector else {
        return Err(PersistenceError::SchemaViolation(
            "binding selector is invalid".into(),
        ));
    };
    if *source_stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
    {
        return Err(PersistenceError::SchemaViolation(
            "binding requires its exact Realm stream".into(),
        ));
    }
    let incoming: DirectConversationBindingCurrentValue =
        serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
    let digest = incoming
        .binding_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if incoming.endorsements.iter().any(|endorsement| {
        endorsement.value.realm_id != *realm_id || endorsement.value.pair_key != *pair_key
    }) || incoming
        .endorsements
        .windows(2)
        .any(|entries| entries[0].tag_id >= entries[1].tag_id)
    {
        return Err(PersistenceError::SchemaViolation(
            "binding Realm, pair or canonical dots differ".into(),
        ));
    }
    #[derive(diesel::QueryableByName)]
    struct Retained {
        #[diesel(sql_type = Text)]
        pair_key: String,
        #[diesel(sql_type = Text)]
        binding_digest: String,
        #[diesel(sql_type = Text)]
        current_commit_id: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        current_stream_position: i64,
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let retained = sql_query("SELECT pair_key,binding_digest,current_commit_id,current_stream_position,value FROM direct_conversation_binding_current_results WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text,_>(realm_id.as_str()).get_result::<Retained>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(retained) = retained {
        let old: DirectConversationBindingCurrentValue =
            serde_json::from_value(retained.value.clone()).map_err(PersistenceError::database)?;
        let position = i64::try_from(revision.stream_position).map_err(|_| {
            PersistenceError::SchemaViolation("binding revision exceeds BIGINT".into())
        })?;
        if retained.pair_key != pair_key.as_str()
            || retained.binding_digest != digest.as_str()
            || retained.current_stream_position > position
            || old
                .endorsements
                .iter()
                .any(|item| !incoming.endorsements.contains(item))
            || (retained.current_stream_position == position
                && (retained.current_commit_id != revision.commit_id.as_str()
                    || retained.value != *value))
        {
            return Err(PersistenceError::Conflict("failed_precondition: binding snapshot changes its pair, digest, revision or retained endorsements".into()));
        }
    }
    Ok(())
}

pub(crate) async fn install_binding_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    entry: &arkret_wire::TypedCurrentRow,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    guard_binding_snapshot_in_connection(conn, realm_id, entry).await?;
    let arkret_wire::TypedCurrentRow::Value {
        selector,
        revision,
        value,
        ..
    } = entry;
    let arkret_wire::CurrentSelector::DirectConversationBinding { pair_key } = selector else {
        unreachable!()
    };
    let binding: DirectConversationBindingCurrentValue =
        serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
    let digest = binding
        .binding_digest()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let position = i64::try_from(revision.stream_position)
        .map_err(|_| PersistenceError::SchemaViolation("binding revision exceeds BIGINT".into()))?;
    let changed = sql_query("INSERT INTO direct_conversation_binding_current_results (realm_id,pair_key,binding_digest,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE direct_conversation_binding_current_results.pair_key=EXCLUDED.pair_key AND direct_conversation_binding_current_results.binding_digest=EXCLUDED.binding_digest AND (direct_conversation_binding_current_results.current_stream_position<EXCLUDED.current_stream_position OR (direct_conversation_binding_current_results.current_stream_position=EXCLUDED.current_stream_position AND direct_conversation_binding_current_results.current_commit_id=EXCLUDED.current_commit_id AND direct_conversation_binding_current_results.value=EXCLUDED.value))")
        .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(pair_key.as_str()).bind::<Text,_>(digest.as_str()).bind::<Text,_>(revision.commit_id.as_str()).bind::<diesel::sql_types::BigInt,_>(position).bind::<Jsonb,_>(value).bind::<diesel::sql_types::Timestamptz,_>(installed_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PersistenceError::Conflict(
            "failed_precondition: binding snapshot revision differs".into(),
        ))
    }
}
