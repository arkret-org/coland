//! Caller-aware snapshots from one REPEATABLE READ authority cut.
//!
//! Realm, Circle membership and exact Sidecar authority determine visible streams;
//! hidden scope objects, member rows, heads and floors are omitted together.
//! Current rows retain their source stream and revision, including state
//! below that stream's history floor. Message content is constrained by its
//! original accepted scope, covering position, retention and redaction overlay.
//! Reports and franking proofs additionally require exact target-scope
//! moderator authority; a Realm-stream proof never broadens a Circle target.
//!
//! Every installed current family and the installed handoff tenure are audited.
//! Unsupported families remain unproved. Bootstrap changes only its own
//! join stream's history floor (`federation.md` section 4.1.1).

use arkret_wire::{
    AccountId, ActorId, CircleId, CommitStreamRef, CurrentSelector, EventKind, ReadableFloor,
    RealmId, StreamHistoryFloor, TypedCurrentRow,
};
use diesel::sql_types::Text as SqlText;

use super::{
    AsyncConnection, AsyncPgConnection, Bool, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[cfg(test)]
/// Event kinds whose admission writes only disclosed current families. Any
/// other accepted kind refuses the cut rather than risk an omitted result.
pub(crate) const DISCLOSED_EVENT_KINDS: &[EventKind] = &[
    EventKind::RealmCreate,
    EventKind::ProfileCreate,
    EventKind::ProfileUpdate,
    EventKind::RealmProfile,
    EventKind::RealmPolicyBundle,
    EventKind::PolicySet,
    EventKind::RealmJoinRule,
    EventKind::RealmHistoryAccess,
    EventKind::ScopeReadReceiptPolicy,
    EventKind::RealmPreviewPolicy,
    EventKind::RealmDiscovery,
    EventKind::RealmAlias,
    EventKind::RealmPlaintextVisibleServices,
    EventKind::MemberState,
    EventKind::MemberIdentityUpdate,
    EventKind::DirectConversationBound,
    EventKind::AppletRegistration,
    EventKind::InviteCreate,
    EventKind::InviteRevoke,
    EventKind::InviteCancel,
    EventKind::InviteAccept,
    EventKind::CapabilityGrant,
    EventKind::CapabilityRevoke,
    EventKind::CapabilityRelinquish,
    EventKind::StrandCreate,
    EventKind::StrandUpdate,
    EventKind::StrandTracksUpdate,
    EventKind::RsvpSet,
    EventKind::StrandArchive,
    EventKind::StrandRestore,
    EventKind::StrandStageSet,
    EventKind::StrandMove,
    EventKind::StrandReorder,
    EventKind::SpaceCreate,
    EventKind::SpaceUpdate,
    EventKind::SchemaDefine,
    EventKind::SpaceArchive,
    EventKind::SpaceRestore,
    EventKind::RealmSetDefaultStrand,
    EventKind::MessageCreate,
    EventKind::MessageRevise,
    EventKind::MessageRedact,
    EventKind::ReactionAdd,
    EventKind::ReactionRemove,
    EventKind::PinAdd,
    EventKind::PinRemove,
    EventKind::PinReorder,
    EventKind::MlsGenesis,
    EventKind::MlsCommit,
    EventKind::CircleCreate,
    EventKind::CircleMemberState,
    EventKind::ModerationDecision,
    EventKind::ModerationDecisionLift,
    EventKind::SelfModerationReport,
    EventKind::ModerationFrankingProof,
    EventKind::RealmOrganization,
    EventKind::CallCreate,
];

/// Registered shared durable kinds are admitted by their canonical contract,
/// rather than by the subset of writers installed on this Station. Private
/// source material keeps its kind-specific read boundary.
pub(crate) fn member_shared_event_kind(kind: &EventKind) -> bool {
    kind.descriptor().is_some_and(|descriptor| {
        descriptor.wire_scope == arkret_wire::EventWireScope::DurableEvent
    }) && !matches!(
        kind.as_str(),
        arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
            | arkret_wire::event_kind_str::AGENT_PROVISION
            | arkret_wire::CapabilityActionId::AGENT_KEY_AUTHORIZE
            | arkret_wire::CapabilityActionId::AGENT_KEY_REVOKE
            | arkret_wire::event_kind_str::SIDECAR_CREATE
    ) && !kind.as_str().starts_with("ak.realm.actor.")
        && !kind.as_str().starts_with("ak.device.")
        && !kind.as_str().starts_with("ak.self.agent.")
        && !kind.as_str().starts_with("ak.consent.")
}

/// Every typed-current table this Station installs. A new family could be
/// written by an admitted Event, so it must be classified here before any
/// Snapshot is signed again.
const AUDITED_FAMILIES: &[&str] = &[
    // Private control currents are excluded from ordinary snapshot SQL.
    "realm_actor_current_results",
    "relation_current_results",
    // A reaction set is state disclosed with its target Message's exact scope.
    "message_reactions_current_results",
    "pin_current_results",
    "realm_authority_root_current_results",
    "capability_grant_current_results",
    "realm_policy_bundle_current_results",
    "schema_definition_current_results",
    // Exact Realm-bound Access, Moderation and Agent policies are shared state.
    "policy_current_results",
    "policy_action_current_results",
    // Controller-PCR confirmation state has no ordinary Realm disclosure carrier.
    "agent_action_approval_current_results",
    "mimi_room_binding_current_results",
    "realm_link_current_results",
    "member_state_current_results",
    "member_identity_updates_current_results",
    "applet_registration_current_results",
    // Circle membership and Sidecar authority classify their private rows.
    "circle_current_results",
    "circle_member_state_current_results",
    "call_state_current_results",
    "call_component_current_results",
    "realm_media_service_current_results",
    "sidecar_current_results",
    "sidecar_context_current_results",
    "sidecar_exchange_controls_current_results",
    "strand_current_results",
    "strand_watch_current_results",
    "strand_position_current_results",
    "rsvp_current_results",
    "space_current_results",
    "space_parent_current_results",
    "space_child_scope_policy_current_results",
    "realm_set_default_strand_current_results",
    "message_revision_current_results",
    "mls_group_current_results",
    "object_redaction_current_results",
    "invite_lifecycle_current_results",
    "invite_live_target_current_results",
    "invite_directed_invitee_current_results",
    // Reports and proofs have a separate exact-scope moderator disclosure gate.
    "moderation_report_current_results",
    "moderation_franking_proof_current_results",
    "moderation_state_current_results",
    "realm_organization_current_results",
    "realm_bootstrap_current_results",
    "scope_read_receipt_policy_current_results",
    "agent_status_current_results",
    "agent_interaction_current_results",
    "agent_key_current_results",
    "key_backup_active_series_current_results",
    "pcr_device_generation_current_results",
    "pcr_device_authorization_current_results",
    // Ordinary scope Profiles are shared; PCR identity remains private.
    "actor_profile_current_results",
    "identity_accountability_current_results",
    // Controller-PCR Agent provisioning state: likewise never in an ordinary
    // collaboration Realm.
    "agent_provisioning_current_results",
    "agent_pcr_genesis_declaration_current_results",
    "agent_selector_claim_current_results",
    // Direct Conversation binding is visible only to its exact participants.
    "direct_conversation_binding_current_results",
    // Holder-private PCR Consent is outside ordinary Realm disclosure.
    "consent_current_results",
];

/// A committed kind of the Realm outside [`DISCLOSED_EVENT_KINDS`].
pub(crate) fn undisclosed_kind_sql() -> String {
    let disclosed_kinds = EventKind::ALL
        .iter()
        .filter(|kind| {
            kind.descriptor().is_some_and(|descriptor| {
                descriptor.wire_scope == arkret_wire::EventWireScope::DurableEvent
            })
        })
        .map(|kind| format!("'{}'", kind.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "SELECT kind FROM realm_commit_event_kinds \
         WHERE realm_id=$1 AND kind NOT IN ({disclosed_kinds},'ak.strand.watch.set') LIMIT 1"
    )
}

/// Whether a RealmCommit of the Realm names an Event that is not committed.
pub(crate) const UNSETTLED_COMMIT_SQL: &str = "SELECT EXISTS(SELECT 1 FROM canonical_events \
     event_row JOIN realm_commits commit_row ON commit_row.event_pk = event_row.pk \
     WHERE event_row.realm_id=$1 AND event_row.state <> 'committed') AS present";

#[derive(QueryableByName)]
struct TableNameRow {
    #[diesel(sql_type = SqlText)]
    tablename: String,
}

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = SqlText)]
    service_id: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct KindRow {
    #[diesel(sql_type = SqlText)]
    kind: String,
}

/// What one cut says about the Realm and the caller beyond its candidate
/// material.
pub(crate) struct DisclosureFacts {
    /// Content carriers withheld by retention or redaction at this same cut.
    pub(crate) withheld_content_commits: std::collections::BTreeSet<String>,
    /// Original accepted Message creation scopes, including revised carriers.
    pub(crate) message_streams: std::collections::BTreeMap<arkret_wire::MessageId, CommitStreamRef>,
    pub(crate) call_creations: std::collections::BTreeMap<arkret_wire::CallId, CallCreationFact>,
    /// Exact current Circle memberships and readable floors at this same cut.
    pub(crate) circle_floors: std::collections::BTreeMap<CircleId, ReadableFloor>,
    pub(crate) sidecar_floors: std::collections::BTreeMap<arkret_wire::SidecarId, ReadableFloor>,
    /// Pending desired recipients may learn public MLS current, never content.
    pub(crate) sidecar_public_floors:
        std::collections::BTreeMap<arkret_wire::SidecarId, ReadableFloor>,
    pub(crate) owned_sidecars: std::collections::BTreeSet<arkret_wire::SidecarId>,
    /// Report subjects whose exact scope's moderator grant is proved at this cut.
    pub(crate) report_subjects: std::collections::BTreeSet<arkret_wire::EventId>,
    /// Encrypted target subjects authorized through their actual signed scopes.
    pub(crate) franking_subjects: std::collections::BTreeSet<arkret_wire::EventId>,
    pub(crate) relation_subjects: std::collections::BTreeSet<arkret_wire::RelationId>,
    /// The caller's readable floor on the Realm stream, `None` when the caller
    /// is not a currently joined member or the floor is not provable.
    pub(crate) caller_floor: Option<ReadableFloor>,
    /// An accepted Event whose kind is outside [`DISCLOSED_EVENT_KINDS`].
    pub(crate) undisclosed_kind: Option<String>,
    /// A family without a disclosure rule holds a row of this Realm.
    pub(crate) undisclosed_family_row: bool,
}

pub(crate) struct CallCreationFact {
    stream: CommitStreamRef,
    initial_state: arkret_models_collaboration::events_payloads::call::CallLifecycleState,
}

/// Read the candidate material and the disclosure facts from one MVCC cut.
pub async fn account_snapshot_material(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        account_snapshot_material_in_connection(conn, realm_id, account)
            .await
            .map_err(Into::into)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// A continuation cannot mint a replacement window below its validated cut.
/// This check issues nothing and never classifies missing evidence as stale.
pub(crate) async fn account_continuation_heads_covered(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    minimum_heads: &[arkret_wire::CommitStreamHead],
) -> PersistenceResult<bool> {
    if minimum_heads.is_empty() {
        return Ok(true);
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let material = match account_snapshot_material_in_connection(conn, realm_id, account).await
        {
            Ok(Some(material)) => material,
            Ok(None) => return Ok(false),
            Err(error) => {
                // A proved membership loss must reach the ordinary unavailable
                // response, not be mistaken for an unproved storage failure.
                let Some(material) =
                    crate::authority_commit::realm_state_snapshot_material_in_connection(
                        conn, realm_id,
                    )
                    .await?
                else {
                    return Ok(false);
                };
                let caller = ActorId::account(account.clone());
                let membership = material
                    .current_state_entries
                    .iter()
                    .find_map(|entry| match entry {
                        TypedCurrentRow::Value {
                            selector: CurrentSelector::MemberState { actor_id },
                            value,
                            ..
                        } if actor_id == &caller => Some(value),
                        _ => None,
                    })
                    .map(|value| {
                        serde_json::from_value::<arkret_wire::MemberStateCurrent>(value.clone())
                    })
                    .transpose()
                    .map_err(PersistenceError::database)?;
                if membership
                    .is_some_and(|current| current.membership != arkret_wire::MembershipState::Join)
                    && continuation_heads_covered_in_material(
                        conn,
                        realm_id,
                        &material,
                        minimum_heads,
                    )
                    .await?
                {
                    return Ok(true);
                }
                return Err(error.into());
            }
        };
        continuation_heads_covered_in_material(conn, realm_id, &material, minimum_heads)
            .await
            .map_err(Into::into)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn continuation_heads_covered_in_material(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    material: &coland_storage::RealmStateSnapshotMaterial,
    minimum_heads: &[arkret_wire::CommitStreamHead],
) -> PersistenceResult<bool> {
    for required in minimum_heads {
        if required.stream_ref.realm_id() != realm_id {
            return Ok(false);
        }
        let Some(current) = material
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == required.stream_ref)
        else {
            // A formerly visible private stream may no longer be owed.
            continue;
        };
        if current.stream_position < required.stream_position
            || (current.stream_position == required.stream_position
                && current.commit_id != required.commit_id)
        {
            return Ok(false);
        }
        if material
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| {
                floor.stream_ref == required.stream_ref
                    && required.stream_position < floor.oldest_position
            })
        {
            // Preserve the existing retained-floor/resync contract.
            continue;
        }
        let position = i64::try_from(required.stream_position)
            .map_err(|_| rejected("continuation head exceeds the stored position range"))?;
        let present = sql_query(
            "SELECT (EXISTS(SELECT 1 FROM realm_commits c \
                 LEFT JOIN canonical_events e ON e.pk=c.event_pk \
                 WHERE c.stream_key=$1 AND c.stream_position=$2 AND c.commit_id=$3 \
                   AND c.stream_ref=$4 \
                   AND c.commit_json->>'commit_id'=c.commit_id \
                   AND c.commit_json->>'stream_position'=c.stream_position::text \
                   AND c.commit_json->'stream_ref'=c.stream_ref \
                   AND (c.event_pk IS NULL OR (e.state='committed' \
                     AND c.commit_json->>'event_ref'=e.envelope->>'event_id'))) \
                 OR EXISTS(SELECT 1 FROM replica_stream_anchors a \
                 WHERE a.stream_key=$1 AND a.anchor_stream_position=$2 \
                   AND a.anchor_commit_id=$3)) AS present",
        )
        .bind::<Text, _>(crate::authority_commit::stream_key(&required.stream_ref)?)
        .bind::<diesel::sql_types::BigInt, _>(position)
        .bind::<Text, _>(required.commit_id.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&required.stream_ref).map_err(PersistenceError::database)?,
        )
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present;
        if !present {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Issue the complete signed Snapshot to `account` at one durable cut. The
/// governing row is share-locked first, so no handoff can commit between the
/// tenure check, the disclosure proof, the signature, and the issuance write.
/// An unchanged cut returns the object already issued to the Account for it.
pub async fn issue_account_snapshot(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    issuer: &arkret_wire::DidCoreId,
    sign: coland_storage::RealmStateSnapshotSigner<'_>,
) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
    issue_snapshot(
        pool,
        realm_id,
        &ActorId::account(account.clone()),
        issuer,
        sign,
        None,
    )
    .await
}

/// Native scope selection is part of the material signed at this cut, never
/// a rewritten foreign Snapshot or a client-supplied authorization assertion.
pub(crate) async fn issue_native_snapshot(
    pool: &PgPool,
    endpoint: &coland_storage::AppletManagedDeviceScopeGuard,
    issuer: &arkret_wire::DidCoreId,
    expiry: chrono::DateTime<chrono::Utc>,
    sign: coland_storage::RealmStateSnapshotSigner<'_>,
) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
    let result = issue_snapshot(
        pool,
        endpoint.effective_scope.realm_id(),
        &endpoint.authority.actor_id,
        issuer,
        sign,
        Some((endpoint, expiry)),
    )
    .await;
    tracing::debug!(target: "coland_storage_postgres::applet_content_delivery",
        available = result.as_ref().is_ok_and(|value| value.is_some()),
        reason = ?result.as_ref().err().map(ToString::to_string),
        "native snapshot issuance finished");
    result
}

async fn issue_snapshot(
    pool: &PgPool,
    realm_id: &RealmId,
    actor: &ActorId,
    issuer: &arkret_wire::DidCoreId,
    sign: coland_storage::RealmStateSnapshotSigner<'_>,
    native: Option<(
        &coland_storage::AppletManagedDeviceScopeGuard,
        chrono::DateTime<chrono::Utc>,
    )>,
) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
    let mut conn =
        crate::issued_realm_snapshots::SnapshotIssuanceConnection::acquire(pool, realm_id).await?;
    let result = conn
        .transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *conn)
                .await?;
            if let Some((endpoint, _)) = native {
                crate::boxed_future(|| {
                    crate::applet_content_delivery::lock_snapshot_device_authorities(
                        conn, issuer, endpoint,
                    )
                })
                .await?;
            }
            // Issuance and issued-snapshot GC exclude each other (0441).
            crate::sync_cursor::retention::lock(conn, false).await?;
            let Some(tenure) = sql_query(
                "SELECT service_id, generation FROM realm_authorities \
             WHERE realm_id=$1 FOR SHARE",
            )
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
            else {
                return Ok(None);
            };
            crate::pcr_private_authority::validate_installed_governance(conn, realm_id).await?;
            let Some(material) =
                actor_snapshot_material_in_connection(conn, realm_id, actor).await?
            else {
                return Ok(None);
            };
            let (material, native_proofs) = if let Some((endpoint, expiry)) = native {
                let (material, proofs) = crate::boxed_future(|| {
                    crate::applet_content_delivery::snapshot_material_for_device(
                        conn, issuer, endpoint, expiry, material,
                    )
                })
                .await?;
                (material, Some(proofs))
            } else {
                (material, None)
            };
            if i64::try_from(material.governance_generation).ok() != Some(tenure.generation) {
                return Err(rejected("material generation differs from the locked tenure").into());
            }
            crate::issued_realm_snapshots::require_actor_snapshot_serving_cut(
                conn,
                actor,
                issuer,
                &tenure.service_id,
                &material,
            )
            .await?;
            if tenure.service_id != issuer.as_str() {
                return crate::issued_realm_snapshots::served_current_snapshot(
                    conn,
                    actor.as_account_id().ok_or_else(|| {
                        rejected("Realm actor reads require the governing Station")
                    })?,
                    issuer,
                    &material,
                )
                .await?
                .map(Some)
                .ok_or_else(|| {
                    rejected("the current governing Snapshot has not been installed").into()
                });
            }
            if material.governance_generation > 0 {
                let full = crate::authority_commit::realm_state_snapshot_material_in_connection(
                    conn, realm_id,
                )
                .await?
                .ok_or_else(|| rejected("the governing handoff material is unavailable"))?;
                prove_handoff_tenure_in_connection(conn, &full).await?;
            }
            let snapshot = sign(&material)?;
            if !coland_storage::signed_snapshot_matches_material(&snapshot, &material) {
                return Err(PersistenceError::Internal(
                    "snapshot signer changed the proved disclosure material".to_owned(),
                )
                .into());
            }
            coland_storage::enforce_inline_realm_state_snapshot_capacity(&snapshot)?;
            let issued = crate::issued_realm_snapshots::issue_actor_head_in_connection(
                conn, actor, &material, snapshot,
            )
            .await?;
            if native_proofs.as_ref().is_some_and(|proofs| {
                proofs
                    .iter()
                    .any(|proof| !proof.permits_at(chrono::Utc::now()))
            }) {
                return Err(rejected(
                    "native snapshot permission expired before issuance committed",
                )
                .into());
            }
            Ok(Some(issued))
        })
        .await
        .map_err(crate::issued_realm_snapshots::snapshot_transaction_error);
    conn.finish(result).await
}

#[derive(QueryableByName)]
struct JoinPositionRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    stream_ref: serde_json::Value,
}

/// Material for `ak.peer.realm_join.read.bootstrap.v1` (`federation.md`
/// §4.1.1, member Station bootstrap): the member Account's complete
/// disclosure at one cut, with an ordinary join-position prefix or the exact
/// registered founding-unit position-zero prefix. `None` unless `membership_commit_id` is still the
/// member's current joined membership.
async fn current_bootstrap_join_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    account: &AccountId,
    membership_commit_id: &arkret_wire::RealmCommitId,
) -> PersistenceResult<Option<JoinPositionRow>> {
    sql_query(
            "SELECT membership.current_stream_position,covering.stream_ref FROM ( \
             SELECT current_stream_position,current_commit_id FROM member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2 AND membership='join' AND current_commit_id=$3 \
             UNION ALL SELECT current_stream_position,current_commit_id FROM circle_member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2 AND membership='join' AND current_commit_id=$3 \
             AND circle_member_parent_join_current(realm_id,member_id,value) \
             ) membership JOIN realm_commits covering ON covering.realm_id=$1 \
             AND covering.commit_id=membership.current_commit_id \
             AND covering.stream_position=membership.current_stream_position",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(ActorId::account(account.clone()).to_string())
        .bind::<Text, _>(membership_commit_id.as_str())
        .get_result::<JoinPositionRow>(&mut *conn)
        .await
        .optional()
    .map_err(PersistenceError::database)
}

pub(crate) async fn member_station_bootstrap_floor(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    membership_commit_id: &arkret_wire::RealmCommitId,
) -> PersistenceResult<Option<u64>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let current =
            current_bootstrap_join_in_connection(conn, realm_id, account, membership_commit_id)
                .await?;
        let join = if current.is_some() {
            current
        } else {
            pending_circle_bootstrap_join(conn, realm_id, account, membership_commit_id).await?
        };
        let Some(join) = join else {
            return Ok(None);
        };
        let stream: CommitStreamRef =
            serde_json::from_value(join.stream_ref).map_err(PersistenceError::database)?;
        Ok(Some(
            crate::account_stream_scan::bootstrap_floor_in_connection(
                conn,
                realm_id,
                &stream,
                membership_commit_id.as_str(),
                join.current_stream_position,
            )
            .await?,
        ))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// A pending Circle anchor holds the accepted join before the private Circle
/// object and its current rows arrive in the bootstrap Snapshot. It proves only
/// the requested join's floor; it never authorizes issuing Snapshot material.
async fn pending_circle_bootstrap_join(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    account: &AccountId,
    membership_commit_id: &arkret_wire::RealmCommitId,
) -> PersistenceResult<Option<JoinPositionRow>> {
    #[derive(QueryableByName)]
    struct PendingJoin {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        current_stream_position: i64,
        #[diesel(sql_type = Jsonb)]
        stream_ref: serde_json::Value,
        #[diesel(sql_type = Jsonb)]
        envelope: serde_json::Value,
    }
    let pending = sql_query(
        "SELECT c.stream_position AS current_stream_position,c.stream_ref,e.envelope \
         FROM replica_stream_anchors a JOIN realm_commits c \
         ON c.realm_id=a.realm_id AND c.commit_id=a.join_commit_id AND c.stream_key=a.stream_key \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE a.realm_id=$1 AND a.member_account_id=$2 AND a.join_commit_id=$3 \
         AND a.anchor_commit_id IS NULL AND a.anchor_stream_position IS NULL \
         AND c.stream_ref->>'kind'='circle' AND e.state='committed'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(account).map_err(PersistenceError::database)?)
    .bind::<Text, _>(membership_commit_id.as_str())
    .get_result::<PendingJoin>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(pending) = pending else {
        return Ok(None);
    };
    let event: arkret_wire::Event =
        serde_json::from_value(pending.envelope).map_err(PersistenceError::database)?;
    let stream: CommitStreamRef =
        serde_json::from_value(pending.stream_ref.clone()).map_err(PersistenceError::database)?;
    if event.kind != EventKind::CircleMemberState || event.realm_id != *realm_id {
        return Ok(None);
    }
    let payload: arkret_models_collaboration::events_payloads::circle::CircleMemberStatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    let member = ActorId::account(account.clone());
    if payload.member_id != member
        || payload.membership
            != arkret_models_collaboration::governance::circle::CircleMembership::Join
        || stream
            != (CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: payload.circle_id,
            })
    {
        return Ok(None);
    }
    let Some(parent) = payload.parent_membership_revision else {
        return Ok(None);
    };
    if !crate::authority_commit::parent_join_at_revision_in_connection(
        conn, realm_id, &member, &parent,
    )
    .await?
    {
        return Ok(None);
    }
    Ok(Some(JoinPositionRow {
        current_stream_position: pending.current_stream_position,
        stream_ref: pending.stream_ref,
    }))
}

pub async fn member_station_bootstrap_material(
    pool: &PgPool,
    realm_id: &RealmId,
    account: &AccountId,
    membership_commit_id: &arkret_wire::RealmCommitId,
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(join) =
            current_bootstrap_join_in_connection(conn, realm_id, account, membership_commit_id)
                .await?
        else {
            return Ok(None);
        };
        let Some(mut material) =
            account_snapshot_material_in_connection(conn, realm_id, account).await?
        else {
            return Ok(None);
        };
        let join_position = u64::try_from(join.current_stream_position).map_err(|_| {
            PersistenceError::Internal("stored join position is negative".to_owned())
        })?;
        let stream: CommitStreamRef =
            serde_json::from_value(join.stream_ref).map_err(PersistenceError::database)?;
        let floor = crate::account_stream_scan::bootstrap_floor_in_connection(
            conn,
            realm_id,
            &stream,
            membership_commit_id.as_str(),
            join.current_stream_position,
        )
        .await?;
        anchor_bootstrap_join(
            &mut material,
            &stream,
            membership_commit_id,
            join_position,
            floor,
        )?;
        Ok(Some(material))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// A bootstrap prefix anchors only its exact stream; other readable streams
/// retain their independent positions and history floors.
fn anchor_bootstrap_join(
    material: &mut coland_storage::RealmStateSnapshotMaterial,
    stream: &CommitStreamRef,
    commit_id: &arkret_wire::RealmCommitId,
    position: u64,
    floor_position: u64,
) -> PersistenceResult<()> {
    if stream.realm_id() != &material.realm_id {
        return Err(rejected("bootstrap join is outside its Realm"));
    }
    let head = material
        .visible_stream_heads
        .iter()
        .find(|head| &head.stream_ref == stream)
        .ok_or_else(|| rejected("bootstrap join stream is not visible"))?;
    if position > head.stream_position
        || (position == head.stream_position && commit_id != &head.commit_id)
    {
        return Err(rejected(
            "bootstrap join is outside the visible stream prefix",
        ));
    }
    let floor = material
        .retention_and_history_floor
        .stream_floors
        .iter_mut()
        .find(|floor| &floor.stream_ref == stream)
        .ok_or_else(|| rejected("bootstrap join stream has no authorized floor"))?;
    if floor_position > position || (floor_position != 0 && floor_position != position) {
        return Err(rejected(
            "bootstrap floor does not bind the registered opening unit",
        ));
    }
    floor.oldest_position = floor_position;
    material.current_state_entries.retain(|row| !matches!(row,
        TypedCurrentRow::Value { selector: CurrentSelector::MessageRevision { .. }, source_stream_ref, revision, .. }
        if source_stream_ref == stream && revision.stream_position < floor_position
    ));
    Ok(())
}

/// The Account's disclosed material on the caller's cut.
async fn prove_handoff_tenure_in_connection(
    conn: &mut AsyncPgConnection,
    material: &coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<()> {
    let governance =
        crate::pcr_private_authority::validate_installed_governance(conn, &material.realm_id)
            .await?;
    if material.governance_generation != 0 {
        governance
            .require_transferable()
            .map_err(crate::pcr_private_authority::refused)?;
    }
    if material.governance_generation == 0 {
        return Ok(());
    }
    #[derive(QueryableByName)]
    struct InstalledHandoff {
        #[diesel(sql_type = Jsonb)]
        handoff_json: serde_json::Value,
        #[diesel(sql_type = Jsonb)]
        snapshot_json: serde_json::Value,
    }
    let row = sql_query(
        "SELECT h.handoff_json,s.snapshot_json FROM realm_authorities a \
         JOIN realm_authority_handoffs h ON h.handoff_id=a.last_handoff_ref \
           AND h.realm_id=a.realm_id AND h.to_generation=a.generation AND h.to_service_id=a.service_id \
         JOIN realm_state_snapshots s ON s.snapshot_id=h.handoff_json->>'snapshot_ref' \
         WHERE a.realm_id=$1 AND a.generation=$2",
    )
    .bind::<Text, _>(material.realm_id.as_str())
    .bind::<super::BigInt, _>(i64::try_from(material.governance_generation).map_err(PersistenceError::database)?)
    .get_result::<InstalledHandoff>(&mut *conn).await.optional().map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("the nonzero tenure has no complete installed handoff cut"))?;
    let handoff: arkret_wire::RealmAuthorityHandoff =
        serde_json::from_value(row.handoff_json).map_err(rejected)?;
    let snapshot: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(row.snapshot_json).map_err(rejected)?;
    handoff.validate_shape().map_err(rejected)?;
    if handoff.historical_signer_facts_digest.is_none()
        || snapshot.snapshot_id != handoff.snapshot_ref
        || snapshot.realm_id != material.realm_id
        || snapshot.governance_generation != handoff.from_generation
        || arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&snapshot.visible_stream_heads).map_err(rejected)?,
        )
        .map_err(rejected)?
            != handoff.final_stream_heads_digest
        || !snapshot.visible_stream_heads.iter().all(|old| {
            material.visible_stream_heads.iter().any(|head| {
                head.stream_ref == old.stream_ref
                    && (head.stream_position > old.stream_position || head == old)
            })
        })
    {
        return Err(rejected(
            "the nonzero tenure does not extend the complete installed handoff cut",
        ));
    }
    Ok(())
}

/// The Account's disclosed material on the caller's cut.
pub(crate) async fn account_snapshot_material_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    account: &AccountId,
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    actor_snapshot_material_in_connection(conn, realm_id, &ActorId::account(account.clone())).await
}

pub(crate) async fn actor_snapshot_material_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    actor_snapshot_candidate_in_connection(conn, realm_id, actor, None).await
}

pub(crate) async fn actor_snapshot_candidate_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    candidate: Option<coland_storage::RealmStateSnapshotMaterial>,
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    let materials = crate::boxed_future(|| {
        actor_snapshot_candidates_in_connection(conn, realm_id, actor, vec![candidate])
    })
    .await?;
    match materials {
        None => Ok(None),
        Some(mut materials) if materials.len() == 1 => Ok(materials.pop()),
        Some(_) => Err(rejected(
            "the disclosure cut returned an unexpected candidate count",
        )),
    }
}

pub(crate) async fn actor_snapshot_candidates_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    candidates: Vec<Option<coland_storage::RealmStateSnapshotMaterial>>,
) -> PersistenceResult<Option<Vec<coland_storage::RealmStateSnapshotMaterial>>> {
    if candidates.is_empty() {
        return Err(rejected("a disclosure cut requires at least one candidate"));
    }
    crate::agent_management_admission::read_controller_in_connection(
        conn,
        realm_id,
        None,
        &actor.clone(),
    )
    .await?;
    let Some(authority_material) =
        crate::authority_commit::realm_state_snapshot_material_in_connection(conn, realm_id)
            .await?
    else {
        return Ok(None);
    };
    crate::pcr_private_authority::validate_installed_governance(conn, realm_id).await?;
    let families = sql_query(
        "SELECT tablename FROM pg_catalog.pg_tables \
         WHERE schemaname=current_schema() AND tablename LIKE '%_current_results'",
    )
    .load::<TableNameRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if families
        .iter()
        .any(|family| !AUDITED_FAMILIES.contains(&family.tablename.as_str()))
    {
        return Err(rejected("an unaudited typed-current family is installed"));
    }
    let caller = actor.clone();
    let controller = if actor.as_account_id().is_some()
        && crate::committed_disclosure::ordinary_agent_read_ceiling(
            crate::account_stream_scan::realm_purpose(conn, realm_id).await?,
        ) {
        crate::realm_authorization_cut::owned_controller_snapshot_in_connection(
            conn,
            realm_id,
            &caller,
            chrono::Utc::now(),
        )
        .await?
        .map(|controller| {
            controller
                .as_account_id()
                .cloned()
                .ok_or_else(|| rejected("the Agent controller is not an Account"))
        })
        .transpose()?
    } else {
        None
    };
    let mut materials = Vec::with_capacity(candidates.len());
    let mut sources = Vec::new();
    let mut source_ids = std::collections::BTreeSet::new();
    let mut cached_disclosure: Option<(Vec<TypedCurrentRow>, SnapshotCandidateDisclosureFacts)> =
        None;
    for mut candidate in candidates {
        if let Some(candidate) = &mut candidate {
            if candidate.realm_id != *realm_id {
                return Err(rejected("candidate rows belong to another Realm"));
            }
            candidate.visible_stream_heads = authority_material.visible_stream_heads.clone();
        }
        // Exact row equality includes selector, source stream, revision and
        // complete value. Facts proved for these rows at this same cut cover
        // their subset; changed or newly requested rows require fresh facts.
        let reusable = cached_disclosure.as_ref().filter(|(rows, _)| {
            candidate.as_ref().is_some_and(|candidate| {
                candidate
                    .current_state_entries
                    .iter()
                    .all(|row| rows.contains(row))
            })
        });
        let (material, fresh_facts) = if let Some((_, facts)) = reusable {
            (
                disclose_snapshot_candidate_at_facts(actor, &authority_material, candidate, facts)?,
                None,
            )
        } else {
            let facts = crate::boxed_future(|| {
                snapshot_candidate_disclosure_facts_in_connection(
                    conn,
                    realm_id,
                    actor,
                    &authority_material,
                    candidate.as_ref().unwrap_or(&authority_material),
                    controller.as_ref(),
                )
            })
            .await?;
            let material = disclose_snapshot_candidate_at_facts(
                actor,
                &authority_material,
                candidate,
                &facts,
            )?;
            (material, Some(facts))
        };
        if cached_disclosure.is_none() {
            cached_disclosure = Some((
                material.current_state_entries.clone(),
                fresh_facts.expect("first candidate reads its disclosure facts"),
            ));
        }
        if controller.is_some() {
            for row in &material.current_state_entries {
                let TypedCurrentRow::Value {
                    source_stream_ref,
                    revision,
                    ..
                } = row;
                let event = crate::account_content_delivery::current_source_in_connection(
                    conn,
                    realm_id,
                    source_stream_ref,
                    revision,
                )
                .await?;
                if source_ids.insert(event.event_id.clone()) {
                    sources.push(event);
                }
            }
        }
        materials.push(material);
    }
    if let Some(controller) = controller.as_ref() {
        crate::account_content_delivery::require_owned_content_sources_in_connection(
            conn,
            &sources,
            controller,
            actor
                .as_account_id()
                .ok_or_else(|| rejected("owned Agent reader must be an Account"))?,
            chrono::Utc::now(),
            arkret_wire::CapabilityActionId::ObjectRead,
        )
        .await?;
    }
    Ok(Some(materials))
}

struct SnapshotCandidateDisclosureFacts {
    caller: DisclosureFacts,
    owner: Option<(AccountId, DisclosureFacts)>,
}

async fn snapshot_candidate_disclosure_facts_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    authority_material: &coland_storage::RealmStateSnapshotMaterial,
    material: &coland_storage::RealmStateSnapshotMaterial,
    controller_account: Option<&AccountId>,
) -> PersistenceResult<SnapshotCandidateDisclosureFacts> {
    let mut facts =
        disclosure_facts_in_connection(conn, realm_id, actor, authority_material, material).await?;
    let owner = if let Some(controller_account) = controller_account {
        let owner_facts = disclosure_facts_in_connection(
            conn,
            realm_id,
            &ActorId::account(controller_account.clone()),
            authority_material,
            material,
        )
        .await?;
        let Some(owner_floor) = owner_facts.caller_floor.as_ref() else {
            return Err(rejected(
                "the Agent controller has no current readable floor",
            ));
        };
        if facts
            .caller_floor
            .as_ref()
            .is_none_or(|floor| floor.oldest_position < owner_floor.oldest_position)
        {
            facts.caller_floor = Some(owner_floor.clone());
        }
        {
            let (agent_floors, owner_floors) =
                (&mut facts.circle_floors, &owner_facts.circle_floors);
            agent_floors.retain(|id, floor| {
                let Some(owner_floor) = owner_floors.get(id) else {
                    return false;
                };
                if floor.oldest_position < owner_floor.oldest_position {
                    *floor = owner_floor.clone();
                }
                true
            });
        }
        for agent_floors in [&mut facts.sidecar_floors, &mut facts.sidecar_public_floors] {
            agent_floors.retain(|id, floor| {
                let owner_floor = owner_facts
                    .sidecar_floors
                    .get(id)
                    .or_else(|| owner_facts.sidecar_public_floors.get(id));
                let Some(owner_floor) = owner_floor else {
                    return false;
                };
                if floor.oldest_position < owner_floor.oldest_position {
                    *floor = owner_floor.clone();
                }
                true
            });
        }
        Some((controller_account.clone(), owner_facts))
    } else {
        None
    };
    Ok(SnapshotCandidateDisclosureFacts {
        caller: facts,
        owner,
    })
}

fn disclose_snapshot_candidate_at_facts(
    actor: &ActorId,
    authority_material: &coland_storage::RealmStateSnapshotMaterial,
    candidate: Option<coland_storage::RealmStateSnapshotMaterial>,
    facts: &SnapshotCandidateDisclosureFacts,
) -> PersistenceResult<coland_storage::RealmStateSnapshotMaterial> {
    let original_rows = candidate
        .as_ref()
        .map(|material| material.current_state_entries.clone());
    let mut material = candidate.unwrap_or_else(|| authority_material.clone());
    if original_rows.is_some() {
        // A historical exact slice may contain only Circle rows. Its current
        // authorization basis is read from the real authority cut, never
        // inferred from missing rows in the archived object. These internal
        // Realm rows are removed before returning the original row slice.
        for row in &authority_material.current_state_entries {
            let TypedCurrentRow::Value { selector, .. } = row;
            let required = matches!(
                selector,
                CurrentSelector::RealmGenesis
                    | CurrentSelector::RealmAuthorityRoot
                    | CurrentSelector::RealmHistoryAccess
            ) || matches!(selector, CurrentSelector::MemberState { actor_id }
                    if actor_id == actor
                        || facts.owner.as_ref().is_some_and(|(owner, _)| actor_id.as_account_id() == Some(owner)));
            if required
                && !material.current_state_entries.iter().any(|present| {
                    let TypedCurrentRow::Value {
                        selector: actual, ..
                    } = present;
                    actual == selector
                })
            {
                material.current_state_entries.push(row.clone());
            }
        }
    }
    let mut disclosed = if let Some((controller_account, owner_facts)) = &facts.owner {
        let owner_material =
            disclose_to_account(material.clone(), controller_account, owner_facts)?;
        let mut agent_material = disclose_to_actor(material, actor, &facts.caller)?;
        agent_material
            .visible_stream_heads
            .retain(|head| owner_material.visible_stream_heads.contains(head));
        agent_material
            .current_state_entries
            .retain(|row| owner_material.current_state_entries.contains(row));
        // Even an exact row subset must independently retain its required
        // genesis, membership, subjects and complete current-family closure.
        disclose_to_actor(agent_material, actor, &facts.caller)?
    } else {
        disclose_to_actor(material, actor, &facts.caller)?
    };
    if let Some(original_rows) = original_rows {
        disclosed
            .current_state_entries
            .retain(|row| original_rows.contains(row));
    }
    Ok(disclosed)
}

async fn disclosure_facts_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    authority_material: &coland_storage::RealmStateSnapshotMaterial,
    material: &coland_storage::RealmStateSnapshotMaterial,
) -> PersistenceResult<DisclosureFacts> {
    let undisclosed_family_row = sql_query(
        "SELECT (EXISTS(SELECT 1 FROM realm_link_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM mimi_room_binding_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM policy_current_results WHERE realm_id=$1 \
                AND (value->>'schema' IS DISTINCT FROM 'ak.schema.policy.v1' \
                    OR COALESCE(value->>'policy_kind','') NOT IN ('access','moderation','agent','applet') \
                    OR value->>'realm_id' IS DISTINCT FROM realm_id)) \
            OR EXISTS(SELECT 1 FROM agent_status_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_key_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM key_backup_active_series_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_generation_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM actor_profile_current_results p WHERE p.realm_id=$1 AND NOT EXISTS(SELECT 1 FROM realm_bootstrap_current_results g WHERE g.realm_id=$1 AND g.result_family='realm_genesis' AND g.value->>'purpose'='collaboration')) \
            OR EXISTS(SELECT 1 FROM agent_pcr_genesis_declaration_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM agent_selector_claim_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_authorization_current_results WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM pcr_device_revocation_proposals WHERE realm_id=$1) \
            OR EXISTS(SELECT 1 FROM consent_current_results WHERE realm_id=$1)) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    // Both reads are bounded by the Realm's distinct kinds and its unsettled
    // Events, never by its committed history (0436).
    let undisclosed_kind = sql_query(undisclosed_kind_sql())
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<KindRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| row.kind);
    let unsettled_commit = sql_query(UNSETTLED_COMMIT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present;
    if unsettled_commit {
        return Err(PersistenceError::SchemaViolation(
            "snapshot cut includes an uncommitted Event".to_owned(),
        ));
    }
    let caller_floor = crate::account_stream_scan::snapshot_realm_floor_in_connection(
        conn,
        realm_id,
        &actor.clone(),
    )
    .await?;
    let mut message_streams = std::collections::BTreeMap::new();
    for entry in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector: CurrentSelector::MessageRevision { message_id },
            ..
        } = entry
        else {
            continue;
        };
        message_streams.insert(
            message_id.clone(),
            message_creation_stream(conn, realm_id, message_id).await?,
        );
    }
    // A reaction set shares its target Message's exact scope
    // (`models/strand-and-message.md` section 9.8.2), so its disclosure
    // follows that Message's accepted creation stream.
    for entry in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector: CurrentSelector::MessageReactions { target_ref },
            ..
        } = entry
        else {
            continue;
        };
        let message_id = arkret_wire::MessageId::new(target_ref.as_str())
            .map_err(|_| rejected("a non-Message reaction target has no disclosure rule"))?;
        if let std::collections::btree_map::Entry::Vacant(entry) = message_streams.entry(message_id)
        {
            let stream = message_creation_stream(conn, realm_id, entry.key()).await?;
            entry.insert(stream);
        }
    }
    let mut call_creations = std::collections::BTreeMap::new();
    for entry in &material.current_state_entries {
        if let TypedCurrentRow::Value {
            selector:
                CurrentSelector::CallState { call_id }
                | CurrentSelector::CallFocus { call_id }
                | CurrentSelector::CallRoster { call_id }
                | CurrentSelector::CallModeration { call_id },
            ..
        } = entry
        {
            call_creations.insert(
                call_id.clone(),
                call_creation_fact(conn, realm_id, call_id).await?,
            );
        }
    }
    let caller = actor.clone();
    // circle.md section 9.1: effective Circle membership compares the two
    // typed currents of this one cut -- the caller's parent Realm
    // member_state and each Circle join's bound parent revision.
    let parent = authority_material
        .current_state_entries
        .iter()
        .find_map(|entry| match entry {
            TypedCurrentRow::Value {
                selector: CurrentSelector::MemberState { actor_id },
                source_stream_ref,
                revision,
                value,
            } if actor_id == &caller => Some((source_stream_ref, revision, value)),
            _ => None,
        })
        .map(|(source, revision, value)| {
            serde_json::from_value::<arkret_wire::MemberStateCurrent>(value.clone())
                .map(|current| (source, revision, current.membership))
        })
        .transpose()
        .map_err(PersistenceError::database)?;
    let mut circle_floors = std::collections::BTreeMap::new();
    for entry in &authority_material.current_state_entries {
        let TypedCurrentRow::Value {
            selector:
                CurrentSelector::CircleMemberState {
                    circle_id,
                    member_actor_id,
                },
            source_stream_ref,
            revision,
            value,
        } = entry
        else {
            continue;
        };
        if member_actor_id != &caller {
            continue;
        }
        let membership: arkret_wire::CircleMemberStateCurrent =
            serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
        if !parent.is_some_and(|(parent_source, parent_revision, parent_membership)| {
            membership.is_effective_under_parent(
                realm_id,
                parent_source,
                parent_revision,
                parent_membership,
            )
        }) {
            continue;
        }
        let stream = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        if source_stream_ref != &stream {
            return Err(rejected(
                "Circle member current has a different source stream",
            ));
        }
        let object = authority_material
            .current_state_entries
            .iter()
            .find_map(|entry| match entry {
                TypedCurrentRow::Value {
                    selector: CurrentSelector::Circle { circle_id: subject },
                    value,
                    ..
                } if subject == circle_id => Some(value),
                _ => None,
            })
            .ok_or_else(|| rejected("Circle membership has no Circle object current"))?;
        let circle: arkret_models_collaboration::governance::circle::Circle =
            serde_json::from_value(object.clone()).map_err(PersistenceError::database)?;
        if circle.id.as_ref() != Some(circle_id) || &circle.realm_id != realm_id {
            return Err(rejected("Circle object differs from its typed subject"));
        }
        let mut floor = if circle.history_access == arkret_wire::HistoryAccess::SinceJoin {
            // The verified effective join is this caller's exact lower bound.
            // A member replica must not need the private pre-join position zero
            // merely to disclose its already proved current cut.
            ReadableFloor {
                oldest_position: revision.stream_position,
                floor_commit_id: revision.commit_id.clone(),
                floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
            }
        } else {
            let page = crate::authority_commit::stream_page_in_connection(
                conn,
                &arkret_wire::StreamScanRequest {
                    realm_id: realm_id.clone(),
                    stream_ref: stream.clone(),
                    direction: arkret_wire::StreamScanDirection::After(None),
                    limit: 1,
                },
            )
            .await?;
            page.readable_floor
                .ok_or_else(|| rejected("joined Circle stream has no provable floor"))?
        };
        let Some(current_floor) = crate::account_stream_scan::caller_circle_floor_in_connection(
            conn, realm_id, circle_id, &caller,
        )
        .await?
        else {
            continue;
        };
        if current_floor.oldest_position > floor.oldest_position {
            floor = current_floor;
        }
        circle_floors.insert(circle_id.clone(), floor);
    }
    let mut report_subjects = std::collections::BTreeSet::new();
    let at = chrono::Utc::now();
    for entry in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector: CurrentSelector::ModerationReport { event_id },
            source_stream_ref,
            ..
        } = entry
        else {
            continue;
        };
        let scope = match source_stream_ref {
            CommitStreamRef::Realm { realm_id: realm } if realm == realm_id => {
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                }
            }
            CommitStreamRef::Circle {
                realm_id: realm,
                circle_id,
            } if realm == realm_id && circle_floors.contains_key(circle_id) => {
                arkret_wire::ScopeRef::Circle {
                    realm_id: realm.clone(),
                    circle_id: circle_id.clone(),
                }
            }
            _ => continue,
        };
        if crate::moderation_report_current_results::scope_moderator(
            conn,
            realm_id,
            &scope,
            &caller,
            &[
                arkret_wire::CapabilityActionId::POLICY_MANAGE,
                arkret_wire::CapabilityActionId::MODERATION_DECISION,
            ],
            at,
        )
        .await?
        {
            report_subjects.insert(event_id.clone());
        }
    }
    let mut franking_subjects = std::collections::BTreeSet::new();
    for entry in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector: CurrentSelector::ModerationFrankingProof { event_id },
            ..
        } = entry
        else {
            continue;
        };
        let scope =
            crate::moderation_franking_proof_current_results::franking_target_scope_in_connection(
                conn, realm_id, event_id,
            )
            .await?;
        if crate::moderation_report_current_results::scope_moderator(
            conn,
            realm_id,
            &scope,
            &caller,
            &[
                arkret_wire::CapabilityActionId::POLICY_MANAGE,
                arkret_wire::CapabilityActionId::MODERATION_DECISION,
            ],
            at,
        )
        .await?
        {
            franking_subjects.insert(event_id.clone());
        }
    }
    let mut sidecar_floors = std::collections::BTreeMap::new();
    let mut sidecar_public_floors = std::collections::BTreeMap::new();
    let mut owned_sidecars = std::collections::BTreeSet::new();
    if caller_floor.is_some() {
        for row in &authority_material.current_state_entries {
            if let TypedCurrentRow::Value {
                selector: CurrentSelector::Sidecar { sidecar_id },
                value,
                ..
            } = row
            {
                let floor = crate::sidecar_authority_cut::caller_floor_in_connection(
                    conn, realm_id, sidecar_id, &caller,
                )
                .await?;
                if floor.is_none()
                    && let Some(public_floor) =
                        crate::sidecar_authority_cut::handshake_floor_in_connection(
                            conn, realm_id, sidecar_id, &caller,
                        )
                        .await?
                {
                    sidecar_public_floors.insert(sidecar_id.clone(), public_floor);
                }
                if floor.is_some()
                    || serde_json::from_value::<AccountId>(value["controller_account_id"].clone())
                        .ok()
                        .as_ref()
                        == actor.as_account_id()
                {
                    owned_sidecars.insert(sidecar_id.clone());
                    if let Some(floor) = floor {
                        sidecar_floors.insert(sidecar_id.clone(), floor);
                    }
                }
            }
        }
    }
    let mut relation_subjects = std::collections::BTreeSet::new();
    for entry in &material.current_state_entries {
        if let TypedCurrentRow::Value {
            selector:
                CurrentSelector::Relation {
                    primary_conflict_domain,
                },
            value,
            ..
        } = entry
        {
            let relation: arkret_wire::relation::Relation =
                serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            relation
                .validate_current_for_domain(realm_id, primary_conflict_domain)
                .map_err(PersistenceError::database)?;
            if crate::relation_disclosure::relation_visible_in_connection(conn, &relation, &caller)
                .await?
            {
                relation_subjects.insert(relation.id.expect("validated current has a Relation id"));
            }
        }
    }
    let content_commits = material
        .current_state_entries
        .iter()
        .filter_map(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::MessageRevision { .. },
                revision,
                ..
            } => Some(revision.commit_id.as_str().to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let withheld_content_commits =
        crate::committed_disclosure::withheld_commit_ids_in_connection(conn, &content_commits)
            .await?;
    Ok(DisclosureFacts {
        withheld_content_commits,
        message_streams,
        call_creations,
        circle_floors,
        sidecar_floors,
        sidecar_public_floors,
        owned_sidecars,
        report_subjects,
        franking_subjects,
        relation_subjects,
        caller_floor,
        undisclosed_kind,
        undisclosed_family_row,
    })
}

#[derive(QueryableByName)]
struct MessageCreationScopeRow {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    stream_ref: serde_json::Value,
}

async fn message_creation_stream(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    message_id: &arkret_wire::MessageId,
) -> PersistenceResult<CommitStreamRef> {
    let event_id = message_id.event_id();
    let token = crate::ids::parse_event_id(event_id.as_str())
        .ok_or_else(|| rejected("Message creation identity is invalid"))?;
    let row = sql_query(
        "SELECT e.envelope,c.stream_ref FROM canonical_events e \
        JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.realm_id=$2 \
        AND c.realm_id=$2 AND e.kind='ak.message.create' AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<MessageCreationScopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("Message current has no accepted creation"))?;
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let stream: CommitStreamRef =
        serde_json::from_value(row.stream_ref).map_err(PersistenceError::database)?;
    if event.event_id != event_id
        || event.realm_id != *realm_id
        || CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != stream
    {
        return Err(rejected("Message creation is bound to a different stream"));
    }
    Ok(stream)
}

fn rejected(reason: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("snapshot disclosure is unproved: {reason}"))
}

async fn call_creation_fact(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    call_id: &arkret_wire::CallId,
) -> PersistenceResult<CallCreationFact> {
    let event_id = arkret_wire::EventId::from_token_bytes(call_id.token_bytes())
        .map_err(PersistenceError::database)?;
    let token = crate::ids::parse_event_id(event_id.as_str())
        .ok_or_else(|| rejected("Call creation identity is invalid"))?;
    let row = sql_query(
        "SELECT e.envelope,c.stream_ref FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.realm_id=$2 \
         AND c.realm_id=$2 AND e.kind='ak.call.create' AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<MessageCreationScopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("Call current has no accepted creation"))?;
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let stream: CommitStreamRef =
        serde_json::from_value(row.stream_ref).map_err(PersistenceError::database)?;
    if event.event_id != event_id
        || event.realm_id != *realm_id
        || CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != stream
    {
        return Err(rejected("Call creation is bound to a different stream"));
    }
    let payload: arkret_models_collaboration::events_payloads::call::CallCreatePayload =
        serde_json::from_value(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    payload.validate().map_err(rejected)?;
    Ok(CallCreationFact {
        stream,
        initial_state: payload.initial_state,
    })
}

/// Decide the Account's complete disclosure of one candidate cut, or refuse
/// it whole. Invisible families are omitted, and content rows respect the
/// Account's independent readable floor on each disclosed stream.
pub(crate) fn disclose_to_account(
    material: coland_storage::RealmStateSnapshotMaterial,
    account: &AccountId,
    facts: &DisclosureFacts,
) -> PersistenceResult<coland_storage::RealmStateSnapshotMaterial> {
    disclose_to_actor(material, &ActorId::account(account.clone()), facts)
}

pub(crate) fn disclose_to_actor(
    mut material: coland_storage::RealmStateSnapshotMaterial,
    actor: &ActorId,
    facts: &DisclosureFacts,
) -> PersistenceResult<coland_storage::RealmStateSnapshotMaterial> {
    if facts.undisclosed_family_row {
        return Err(rejected(
            "a current family outside the disclosure subset has a row",
        ));
    }
    if let Some(kind) = &facts.undisclosed_kind {
        return Err(rejected(format!(
            "accepted Event kind {kind} is outside the disclosure subset"
        )));
    }
    let caller = actor.clone();
    let Some(floor) = &facts.caller_floor else {
        return Err(rejected(
            "the Account is not a joined member with a provable readable floor",
        ));
    };
    let realm_stream = CommitStreamRef::Realm {
        realm_id: material.realm_id.clone(),
    };
    material
        .visible_stream_heads
        .retain(|head| match &head.stream_ref {
            CommitStreamRef::Realm { realm_id } => realm_id == &material.realm_id,
            CommitStreamRef::Circle {
                realm_id,
                circle_id,
            } => realm_id == &material.realm_id && facts.circle_floors.contains_key(circle_id),
            CommitStreamRef::Sidecar {
                realm_id,
                sidecar_id,
            } => {
                realm_id == &material.realm_id
                    && (facts.sidecar_floors.contains_key(sidecar_id)
                        || facts.sidecar_public_floors.contains_key(sidecar_id))
            }
            _ => false,
        });
    if !material
        .visible_stream_heads
        .iter()
        .any(|head| head.stream_ref == realm_stream)
    {
        return Err(rejected("the disclosed cut has no Realm stream head"));
    }
    for (circle_id, floor) in &facts.circle_floors {
        if !material.visible_stream_heads.iter().any(|head| {
            head.stream_ref
                == (CommitStreamRef::Circle {
                    realm_id: material.realm_id.clone(),
                    circle_id: circle_id.clone(),
                })
        }) {
            return Err(rejected("a joined Circle has no visible stream head"));
        }
        let head = material
            .visible_stream_heads
            .iter()
            .find(|head| {
                head.stream_ref
                    == (CommitStreamRef::Circle {
                        realm_id: material.realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
            })
            .unwrap();
        if floor.oldest_position > head.stream_position
            || (floor.oldest_position == head.stream_position
                && floor.floor_commit_id != head.commit_id)
        {
            return Err(rejected(
                "a Circle readable floor is outside its visible stream prefix",
            ));
        }
    }
    let strands = material
        .current_state_entries
        .iter()
        .filter_map(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::Strand { strand_id },
                value,
                ..
            } => Some((strand_id.clone(), value.clone())),
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut private_applet_policies = std::collections::BTreeSet::new();
    for row in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            value,
            ..
        } = row;
        let scope_stream = |circle: Option<CircleId>| match circle {
            Some(circle_id) => CommitStreamRef::Circle {
                realm_id: material.realm_id.clone(),
                circle_id,
            },
            None => realm_stream.clone(),
        };
        let object_scope = |value: &serde_json::Value| -> PersistenceResult<CommitStreamRef> {
            let circle = value
                .get("scope_circle_id")
                .filter(|value| !value.is_null())
                .map(|value| {
                    serde_json::from_value::<CircleId>(value.clone())
                        .map_err(PersistenceError::database)
                })
                .transpose()?;
            Ok(scope_stream(circle))
        };
        let expected = match selector {
            CurrentSelector::Pin { pin_scope } => Some(match pin_scope {
                arkret_wire::PinScope::Realm { id } if id == &material.realm_id => {
                    realm_stream.clone()
                }
                arkret_wire::PinScope::Circle { id } => scope_stream(Some(id.clone())),
                arkret_wire::PinScope::Strand { id } => object_scope(
                    strands
                        .get(id)
                        .ok_or_else(|| rejected("Pin home has no Strand current"))?,
                )?,
                arkret_wire::PinScope::Space { id } => {
                    let space = material
                        .current_state_entries
                        .iter()
                        .find_map(|row| match row {
                            TypedCurrentRow::Value {
                                selector: CurrentSelector::Space { space_id },
                                value,
                                ..
                            } if space_id == id => Some(value),
                            _ => None,
                        })
                        .ok_or_else(|| rejected("Pin home has no Space current"))?;
                    object_scope(space)?
                }
                _ => return Err(rejected("Pin home differs from its Realm")),
            }),
            CurrentSelector::SidecarContext { sidecar_id, .. }
            | CurrentSelector::AgentSidecarExchangeControls { sidecar_id, .. } => {
                Some(CommitStreamRef::Sidecar {
                    realm_id: material.realm_id.clone(),
                    sidecar_id: sidecar_id.clone(),
                })
            }
            CurrentSelector::CircleMemberState { circle_id, .. } => {
                Some(scope_stream(Some(circle_id.clone())))
            }
            CurrentSelector::Strand { .. }
            | CurrentSelector::Space { .. }
            | CurrentSelector::Relation { .. } => Some(object_scope(value)?),
            CurrentSelector::StrandWatch { strand_id, .. } => {
                Some(object_scope(strands.get(strand_id).ok_or_else(|| {
                    rejected("Watch target has no Strand current")
                })?)?)
            }
            CurrentSelector::Rsvp { event_ref, .. }
            | CurrentSelector::CalendarScheduleSource {
                strand_id: event_ref,
            } => {
                let strand = strands
                    .get(event_ref)
                    .ok_or_else(|| rejected("RSVP target has no disclosed Strand current"))?;
                Some(object_scope(strand)?)
            }
            CurrentSelector::MlsGroup { scope_ref }
            | CurrentSelector::ScopeReadReceiptPolicy { scope_ref } => Some(
                CommitStreamRef::from_scope(scope_ref, None).map_err(PersistenceError::database)?,
            ),
            CurrentSelector::ActorProfile { actor_profile_id } => {
                crate::applet_scope_profiles::validate_disclosed(
                    actor_profile_id,
                    source_stream_ref,
                    value,
                )?;
                Some(source_stream_ref.clone())
            }
            CurrentSelector::Policy { policy_id } => {
                crate::policy_current_results::management_policy_scope_target(
                    &material.realm_id,
                    source_stream_ref,
                )
                .map_err(rejected)?;
                if value.get("policy_kind").and_then(serde_json::Value::as_str) == Some("applet") {
                    use arkret_models_collaboration::governance::operation_wire::PolicySetValue;
                    let document: PolicySetValue =
                        serde_json::from_value(value.clone()).map_err(|_| {
                            rejected("private Applet Policy has an invalid closed value")
                        })?;
                    document.validate().map_err(rejected)?;
                    if !matches!(document, PolicySetValue::Governance(ref policy)
                        if policy.id == *policy_id
                            && policy.realm_id.as_ref() == Some(&material.realm_id)
                            && policy.policy_kind == arkret_wire::PolicyKind::Applet)
                    {
                        return Err(rejected(
                            "private Applet Policy has a different subject or scope",
                        ));
                    }
                    private_applet_policies.insert(policy_id.clone());
                }
                Some(source_stream_ref.clone())
            }
            CurrentSelector::MessageRevision { message_id } => Some(
                facts
                    .message_streams
                    .get(message_id)
                    .ok_or_else(|| rejected("Message current has no accepted creation scope"))?
                    .clone(),
            ),
            CurrentSelector::MessageReactions { target_ref } => Some(
                arkret_wire::MessageId::new(target_ref.as_str())
                    .ok()
                    .and_then(|message_id| facts.message_streams.get(&message_id))
                    .ok_or_else(|| rejected("reaction target has no accepted creation scope"))?
                    .clone(),
            ),
            CurrentSelector::CallState { call_id }
            | CurrentSelector::CallFocus { call_id }
            | CurrentSelector::CallRoster { call_id }
            | CurrentSelector::CallModeration { call_id } => Some(
                facts
                    .call_creations
                    .get(call_id)
                    .ok_or_else(|| rejected("Call current has no accepted creation scope"))?
                    .stream
                    .clone(),
            ),
            CurrentSelector::AppletRegistration { .. }
            | CurrentSelector::ModerationReport { .. }
            | CurrentSelector::ModerationState { .. }
            | CurrentSelector::CapabilityGrant { .. }
            | CurrentSelector::ObjectRedaction { .. } => None,
            _ => Some(realm_stream.clone()),
        };
        if source_stream_ref.realm_id() != &material.realm_id
            || expected
                .as_ref()
                .is_some_and(|expected| expected != source_stream_ref)
        {
            return Err(rejected(
                "a current family is bound to a different security scope",
            ));
        }
    }
    material.current_state_entries.retain(|row| match row {
        TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            value,
            ..
        } => {
            let visible_stream = match source_stream_ref {
                CommitStreamRef::Realm { realm_id } => realm_id == &material.realm_id,
                CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                } => realm_id == &material.realm_id && facts.circle_floors.contains_key(circle_id),
                CommitStreamRef::Sidecar {
                    realm_id,
                    sidecar_id,
                } => {
                    realm_id == &material.realm_id
                        && (facts.sidecar_floors.contains_key(sidecar_id)
                            || matches!(selector, CurrentSelector::MlsGroup {
                                scope_ref: arkret_wire::ScopeRef::Sidecar {
                                    realm_id: scope_realm, sidecar_id: scope_sidecar,
                                }
                            } if scope_realm == realm_id && scope_sidecar == sidecar_id
                                && facts.sidecar_public_floors.contains_key(sidecar_id)))
                }
                _ => false,
            };
            visible_stream
                && match selector {
                    // constraint-schema §9.2.6 makes the confirmation nonce
                    // private. Snapshot §3 and current-results §3 include only
                    // rows disclosed to the requester, never a redacted value.
                    CurrentSelector::AgentActionApproval { .. } => false,
                    // managed-governance section 1 restricts Applet Policy
                    // reads to authorized writers. Ordinary member snapshots
                    // must not enumerate these validated private rows.
                    CurrentSelector::Policy { policy_id }
                        if private_applet_policies.contains(policy_id) =>
                    {
                        false
                    }
                    CurrentSelector::PolicyAction {
                        subject: arkret_wire::PolicyActionSelector::PolicyRef { .. },
                    } => false,
                    CurrentSelector::Sidecar { sidecar_id }
                    | CurrentSelector::SidecarContext { sidecar_id, .. } => {
                        facts.owned_sidecars.contains(sidecar_id)
                    }
                    CurrentSelector::AgentSidecarExchangeControls { sidecar_id, .. } => {
                        facts.sidecar_floors.contains_key(sidecar_id)
                    }
                    CurrentSelector::Circle { circle_id }
                    | CurrentSelector::CircleMemberState { circle_id, .. } => {
                        facts.circle_floors.contains_key(circle_id)
                    }
                    CurrentSelector::ModerationReport { event_id } => {
                        facts.report_subjects.contains(event_id)
                    }
                    CurrentSelector::ModerationFrankingProof { event_id } => {
                        facts.franking_subjects.contains(event_id)
                    }
                    CurrentSelector::Relation { .. } => {
                        serde_json::from_value::<arkret_wire::RelationId>(value["id"].clone())
                            .is_ok_and(|id| facts.relation_subjects.contains(&id))
                    }
                    _ => true,
                }
        }
    });
    arkret_models_collaboration::exact_current_results::validate_calendar_current_pairs(
        &material.realm_id,
        &material.current_state_entries,
    )
    .map_err(PersistenceError::database)?;
    let mut genesis = false;
    let mut root = false;
    let mut history_access = None;
    let mut own_join = false;
    let mut redacted = std::collections::BTreeSet::new();
    let mut below_floor = std::collections::BTreeSet::new();
    let mut space_families = std::collections::BTreeMap::new();
    let mut position_subjects = Vec::new();
    for row in &material.current_state_entries {
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row;
        let source_head = material
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == source_stream_ref)
            .ok_or_else(|| rejected("a current row has no visible source head"))?;
        if revision.stream_position > source_head.stream_position
            || (revision.stream_position == source_head.stream_position
                && revision.commit_id != source_head.commit_id)
        {
            return Err(rejected(
                "a current row is not sourced from its disclosed stream prefix",
            ));
        }
        match selector {
            CurrentSelector::AgentInteraction { .. } => {
                let _: arkret_models_collaboration::agent_interaction::AgentInteractionCurrentValue = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if source_stream_ref != &realm_stream {
                    return Err(rejected("Agent interaction current is not Realm scoped"));
                }
            }
            CurrentSelector::Sidecar { sidecar_id } => {
                let sidecar: arkret_models_collaboration::agent_sidecar::AgentSidecar =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if sidecar.id != *sidecar_id
                    || sidecar.realm_id != material.realm_id
                    || !facts.owned_sidecars.contains(sidecar_id)
                    || source_stream_ref != &realm_stream
                {
                    return Err(rejected(
                        "Sidecar metadata differs from its accepted controller and Realm source",
                    ));
                }
            }
            CurrentSelector::SidecarContext {
                sidecar_id,
                source_context_ref,
            } => {
                let context: arkret_models_collaboration::events_payloads::sidecar::SidecarContextAttachPayload = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                context
                    .validate()
                    .map_err(|error| rejected(error.to_string()))?;
                if context.sidecar_id != *sidecar_id
                    || context.source_context_ref != *source_context_ref
                {
                    return Err(rejected("Sidecar context differs from its exact selector"));
                }
            }
            CurrentSelector::AgentSidecarExchangeControls {
                sidecar_id,
                source_context_ref,
            } => {
                let controls: arkret_models_collaboration::agent_sidecar::AgentSidecarExchangeControlsCurrentValue =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                controls
                    .validate_for_context(sidecar_id, source_context_ref)
                    .map_err(|error| rejected(error.to_string()))?;
                if controls.assertions().is_empty() {
                    return Err(rejected(
                        "Sidecar control current has no accepted assertion",
                    ));
                }
            }
            CurrentSelector::CallState { call_id } => {
                let current: arkret_models_collaboration::events_payloads::call::CallStateCurrentValue =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                current.validate().map_err(rejected)?;
                let creation = facts
                    .call_creations
                    .get(call_id)
                    .ok_or_else(|| rejected("Call current has no accepted creation"))?;
                if current.from.is_none() && current.to != creation.initial_state {
                    return Err(rejected("Call current differs from its accepted creation"));
                }
            }
            CurrentSelector::CallFocus { .. } => {
                let _: arkret_models_collaboration::events_payloads::call::CallFocus =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            }
            CurrentSelector::CallRoster { .. } => {
                let roster: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                roster
                    .validate_sources(source_stream_ref, revision)
                    .map_err(PersistenceError::database)?;
            }
            CurrentSelector::CallModeration { .. } => {
                let moderation: arkret_models_collaboration::events_payloads::call::CallModerationCurrentValue =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                moderation
                    .validate_sources(source_stream_ref, revision)
                    .map_err(PersistenceError::database)?;
            }
            CurrentSelector::RealmMediaService => {
                let descriptor: arkret_models_collaboration::events_payloads::RealmMediaServiceValue =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                descriptor.validate().map_err(PersistenceError::database)?;
            }
            CurrentSelector::DirectConversationBinding { pair_key } => {
                let binding: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue =
                    serde_json::from_value(value.clone()).map_err(|_| {
                        rejected("Direct Conversation binding current value is not closed")
                    })?;
                if binding.binding.validate_shape().is_err()
                    || binding.binding.pair_key != *pair_key
                    || binding.binding.realm_id != material.realm_id
                    || !binding.binding.unordered_participant_ids.contains(&caller)
                {
                    return Err(rejected(
                        "Direct Conversation binding is not disclosed to this exact participant",
                    ));
                }
            }
            CurrentSelector::AppletRegistration {
                applet_id,
                service_id,
            } => {
                let registration: arkret_models_integration::AppletRegistrationPayload =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if registration.applet_id != *applet_id || registration.service_id != *service_id {
                    return Err(rejected(
                        "Applet registration differs from its current selector",
                    ));
                }
            }
            CurrentSelector::MemberIdentityUpdates { member_id, segment } => {
                let assertions = value
                    .get("assertions")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| rejected("member identity current is not an assertion set"))?;
                let mut dots = std::collections::BTreeSet::new();
                for assertion in assertions {
                    let tag = assertion
                        .get("tag_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| rejected("member identity assertion has no dot"))?;
                    let id = tag
                        .strip_suffix(":0")
                        .ok_or_else(|| rejected("member identity assertion has an invalid dot"))?;
                    arkret_wire::EventId::new(id).map_err(PersistenceError::database)?;
                    if !dots.insert(tag) {
                        return Err(rejected("member identity assertion repeats a dot"));
                    }
                    let payload: arkret_models_identity::MemberIdentityUpdatePayload =
                        serde_json::from_value(
                            assertion.get("value").cloned().ok_or_else(|| {
                                rejected("member identity assertion has no payload")
                            })?,
                        )
                        .map_err(PersistenceError::database)?;
                    if payload.realm_id != material.realm_id
                        || payload.member_id != *member_id
                        || payload.segment != *segment
                    {
                        return Err(rejected(
                            "member identity assertion differs from its current tuple",
                        ));
                    }
                }
            }
            CurrentSelector::Circle { circle_id } => {
                let circle: arkret_models_collaboration::governance::circle::Circle =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if circle.id.as_ref() != Some(circle_id)
                    || circle.realm_id != material.realm_id
                    || source_stream_ref != &realm_stream
                {
                    return Err(rejected(
                        "Circle metadata differs from its accepted Realm source",
                    ));
                }
            }
            CurrentSelector::CircleMemberState { circle_id, .. } => {
                serde_json::from_value::<arkret_wire::CircleMemberStateCurrent>(value.clone())
                    .map_err(PersistenceError::database)?;
                if source_stream_ref
                    != &(CommitStreamRef::Circle {
                        realm_id: material.realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
                {
                    return Err(rejected(
                        "Circle member current differs from its Circle source",
                    ));
                }
            }
            CurrentSelector::ModerationReport { .. } => {}
            CurrentSelector::ModerationFrankingProof { event_id } => {
                let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if proof.event_id != *event_id
                    || proof.realm_id != material.realm_id
                    || source_stream_ref != &realm_stream
                {
                    return Err(rejected(
                        "franking current differs from its target or accepted Realm source",
                    ));
                }
            }
            CurrentSelector::RealmOrganization {
                organization_id,
                relationship,
            } => {
                let statement: arkret_models_collaboration::events_payloads::realm::RealmOrganizationPayload =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if statement.organization_id != *organization_id
                    || statement.relationship != *relationship
                    || statement.realm_id != material.realm_id
                {
                    return Err(rejected(
                        "organization statement differs from its typed relationship cell",
                    ));
                }
            }
            CurrentSelector::ModerationState { .. } => {
                serde_json::from_value::<
                    arkret_models_collaboration::exact_current_results::ModerationStateCurrentValue,
                >(value.clone())
                .map_err(PersistenceError::database)?;
            }
            CurrentSelector::RealmGenesis => genesis = true,
            CurrentSelector::RealmTombstone
            | CurrentSelector::RealmArchive
            | CurrentSelector::RealmFreeze => {}
            CurrentSelector::RealmAuthorityRoot => root = true,
            CurrentSelector::RealmHistoryAccess => {
                history_access = Some(
                    serde_json::from_value::<arkret_wire::HistoryAccess>(value.clone())
                        .map_err(PersistenceError::database)?,
                );
            }
            CurrentSelector::ScopeReadReceiptPolicy { scope_ref } => {
                if &source_stream_ref.scope_ref() != scope_ref {
                    return Err(rejected("receipt policy current has another source scope"));
                }
                let policy: arkret_models_collaboration::events_payloads::ReadReceiptPolicyPayload =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                policy.validate().map_err(PersistenceError::database)?;
            }
            CurrentSelector::RealmPreviewPolicy => {
                let _: arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValue = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            }
            CurrentSelector::MemberState { actor_id } => {
                own_join |=
                    actor_id == &caller && value == &serde_json::json!({"membership":"join"});
            }
            CurrentSelector::StrandWatch { .. } => {
                let _: arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentValue = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            }
            CurrentSelector::Strand { .. } => {}
            CurrentSelector::CalendarScheduleSource { .. } => {}
            CurrentSelector::Relation {
                primary_conflict_domain,
            } => {
                let relation: arkret_wire::relation::Relation =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                relation
                    .validate_current_for_domain(&material.realm_id, primary_conflict_domain)
                    .map_err(PersistenceError::database)?;
                if !relation
                    .id
                    .as_ref()
                    .is_some_and(|id| facts.relation_subjects.contains(id))
                {
                    return Err(rejected("Relation references have no disclosure proof"));
                }
            }
            CurrentSelector::Rsvp {
                event_ref,
                occurrence,
                responder_actor_id: _,
            } => {
                let entry: arkret_models_collaboration::objects::productivity::RsvpEntry =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                entry
                    .validate()
                    .map_err(|error| rejected(error.to_string()))?;
                if let Some(occurrence) = occurrence {
                    arkret_models_collaboration::objects::productivity::validate_canonical_occurrence_key(occurrence)
                        .map_err(|error| rejected(error.to_string()))?;
                }
                let target = strands
                    .get(event_ref)
                    .ok_or_else(|| rejected("RSVP target has no disclosed Strand current"))?;
                if target
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .is_none()
                {
                    return Err(rejected("RSVP target Strand state is malformed"));
                }
            }
            CurrentSelector::StrandPosition {
                board_space_id,
                strand_id,
            } => {
                let position: Option<
                    arkret_models_collaboration::objects::strand::StrandPositionCurrent,
                > = serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                position_subjects.push((board_space_id, strand_id, position));
            }
            CurrentSelector::Pin { pin_scope } => {
                let set: arkret_models_collaboration::objects::productivity::PinCurrentValue =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                set.validate_for_scope(pin_scope)
                    .map_err(PersistenceError::database)?;
            }
            CurrentSelector::SchemaDefinition { schema_id } => {
                arkret_schema::validate_schema_definition_payload(
                    &serde_json::json!({"value":value}),
                )
                .map_err(PersistenceError::database)?;
                if value.get("$id").and_then(serde_json::Value::as_str) != Some(schema_id.as_str())
                    || source_stream_ref != &realm_stream
                {
                    return Err(rejected("Schema definition differs from its Realm subject"));
                }
            }
            CurrentSelector::Space { space_id } => {
                let space: arkret_models_collaboration::objects::space::Space =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if space.id.as_ref() != Some(space_id)
                    || space.realm_id != material.realm_id
                    || space.scope_circle_id.is_some()
                    || space.parent_space_id.is_some()
                    || space.child_scope_policy.is_some()
                {
                    return Err(rejected(
                        "Space metadata is not a Realm-scoped registered value",
                    ));
                }
                *space_families.entry(space_id.clone()).or_insert(0_u8) |= 1;
            }
            CurrentSelector::SpaceParent { space_id } => {
                let parent = value
                    .as_object()
                    .filter(|object| object.len() == 1 && object.contains_key("parent_space_id"))
                    .ok_or_else(|| rejected("Space parent value is not closed"))?;
                if !parent["parent_space_id"].is_null() {
                    serde_json::from_value::<arkret_wire::SpaceId>(
                        parent["parent_space_id"].clone(),
                    )
                    .map_err(PersistenceError::database)?;
                }
                *space_families.entry(space_id.clone()).or_insert(0_u8) |= 2;
            }
            CurrentSelector::SpaceChildScopePolicy { space_id } => {
                serde_json::from_value::<
                    Option<arkret_models_collaboration::objects::space::ChildScopePolicy>,
                >(value.clone())
                .map_err(PersistenceError::database)?;
                *space_families.entry(space_id.clone()).or_insert(0_u8) |= 4;
            }
            CurrentSelector::MessageRevision { message_id } => {
                let source_floor = match source_stream_ref {
                    CommitStreamRef::Realm { .. } => floor,
                    CommitStreamRef::Circle { circle_id, .. } => facts
                        .circle_floors
                        .get(circle_id)
                        .ok_or_else(|| rejected("a Circle Message has no readable floor"))?,
                    CommitStreamRef::Sidecar { sidecar_id, .. } => facts
                        .sidecar_floors
                        .get(sidecar_id)
                        .ok_or_else(|| rejected("a Sidecar Message has no readable floor"))?,
                    _ => return Err(rejected("Message source visibility is not proved")),
                };
                if revision.stream_position < source_floor.oldest_position {
                    below_floor.insert(message_id.clone());
                }
            }
            // State family: disclosed with its scope, never floored or
            // trimmed by a redaction (`realm-state-snapshot-schema.md` §3).
            CurrentSelector::MessageReactions { target_ref } => {
                let set: arkret_models_collaboration::events_payloads::reaction::MessageReactionsCurrentValue =
                    serde_json::from_value(value.clone())
                        .map_err(|_| rejected("reaction current value is not a closed dot set"))?;
                set.validate_for_target(target_ref)
                    .map_err(|_| rejected("reaction assertion differs from its target"))?;
                if set.assertions().is_empty() {
                    return Err(rejected("reaction current holds no assertion"));
                }
            }
            CurrentSelector::RealmProfile
            | CurrentSelector::RealmPolicyBundle
            | CurrentSelector::RealmJoinRule
            | CurrentSelector::RealmDiscovery
            | CurrentSelector::RealmAlias
            | CurrentSelector::RealmPlaintextVisibleServices
            | CurrentSelector::RealmSetDefaultStrand
            | CurrentSelector::InviteLifecycle { .. }
            | CurrentSelector::InviteLiveTarget { .. }
            | CurrentSelector::InviteDirectedInvitee { .. }
            | CurrentSelector::CapabilityGrant { .. } => {}
            CurrentSelector::ActorProfile { actor_profile_id } => {
                crate::applet_scope_profiles::validate_disclosed(
                    actor_profile_id,
                    source_stream_ref,
                    value,
                )?;
            }
            CurrentSelector::Policy { policy_id } => {
                crate::policy_current_results::validate_disclosed_shared_policy(
                    &material.realm_id,
                    policy_id,
                    source_stream_ref,
                    value,
                )?;
            }
            CurrentSelector::PolicyAction {
                subject: arkret_wire::PolicyActionSelector::RealmAction { .. },
            } => {
                let _: arkret_models_collaboration::events_payloads::PolicyActionDocument =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            }
            CurrentSelector::MlsGroup { scope_ref } => {
                if !matches!(scope_ref, arkret_wire::ScopeRef::Realm { realm_id }
                    if realm_id == &material.realm_id)
                    && !matches!(scope_ref, arkret_wire::ScopeRef::Circle { realm_id, circle_id }
                        if realm_id == &material.realm_id && facts.circle_floors.contains_key(circle_id))
                    && !matches!(scope_ref, arkret_wire::ScopeRef::Sidecar { realm_id, sidecar_id }
                        if realm_id == &material.realm_id
                            && (facts.sidecar_floors.contains_key(sidecar_id)
                                || facts.sidecar_public_floors.contains_key(sidecar_id)))
                {
                    return Err(rejected(
                        "the MLS group's exact scope visibility is not proved",
                    ));
                }
            }
            CurrentSelector::ObjectRedaction { target_ref } => {
                let value = serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::redaction::ObjectRedactionCurrentValue,
                >(value.clone())
                .map_err(PersistenceError::database)?;
                value
                    .validate_for_subject(target_ref)
                    .map_err(PersistenceError::database)?;
                if arkret_wire::MessageId::new(target_ref.as_str()).is_err() {
                    return Err(rejected(
                        "a non-Message redaction subject has no disclosure rule",
                    ));
                }
                redacted.insert(target_ref.clone());
            }
            _ => {
                return Err(rejected(
                    "a current row family has no disclosure rule for this Account",
                ));
            }
        }
    }
    if space_families.values().any(|families| *families != 7) {
        return Err(rejected(
            "a Space omits one of its registered sibling families",
        ));
    }
    for (board_id, strand_id, position) in position_subjects {
        let subject_value = |wanted: CurrentSelector| {
            material
                .current_state_entries
                .iter()
                .find_map(|row| match row {
                    TypedCurrentRow::Value {
                        selector, value, ..
                    } if selector == &wanted => Some(value.clone()),
                    _ => None,
                })
                .ok_or_else(|| rejected("a position subject has no disclosed metadata"))
        };
        let strand: arkret_models_collaboration::objects::strand::Strand =
            serde_json::from_value(subject_value(CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            })?)
            .map_err(PersistenceError::database)?;
        if strand.id.as_ref() != Some(strand_id)
            || strand.realm_id != material.realm_id
            || strand.scope_circle_id.is_some()
        {
            return Err(rejected("position Strand visibility is not proved"));
        }
        let board: arkret_models_collaboration::objects::space::Space =
            serde_json::from_value(subject_value(CurrentSelector::Space {
                space_id: board_id.clone(),
            })?)
            .map_err(PersistenceError::database)?;
        if board.kind != "board" {
            return Err(rejected("position Board subject is not a Board"));
        }
        if let Some(position) = position {
            let list: arkret_models_collaboration::objects::space::Space =
                serde_json::from_value(subject_value(CurrentSelector::Space {
                    space_id: position.list_space_id,
                })?)
                .map_err(PersistenceError::database)?;
            if list.kind != "list" {
                return Err(rejected("position List subject is not a List"));
            }
        }
    }
    let Some(history_access) = history_access else {
        return Err(rejected("the cut has no Realm history-access current"));
    };
    if !genesis || !root || !own_join {
        return Err(rejected(
            "the cut omits the genesis, authority root, or the Account's join",
        ));
    }
    let redacted_strands = strands
        .iter()
        .filter_map(|(strand_id, value)| {
            match value.get("state").and_then(serde_json::Value::as_str) {
                Some("redacted") => Some(strand_id.clone()),
                _ => None,
            }
        })
        .collect::<std::collections::BTreeSet<_>>();
    material.current_state_entries.retain(|row| {
        if let TypedCurrentRow::Value {
            selector:
                CurrentSelector::StrandWatch {
                    watcher_actor_id, ..
                },
            value,
            ..
        } = row
        {
            // This snapshot has no audit-read pairing. Only the exact watcher
            // or an explicit non-muted public opt-in may disclose the value.
            return watcher_actor_id == &caller
                || (value.get("level_public") == Some(&serde_json::json!(true))
                    && matches!(
                        value.get("level").and_then(serde_json::Value::as_str),
                        Some("all" | "participating")
                    ));
        }
        if matches!(row, TypedCurrentRow::Value {
            selector: CurrentSelector::Rsvp { event_ref, .. },
            ..
        } if redacted_strands.contains(event_ref))
        {
            return false;
        }
        !matches!(
            row,
            TypedCurrentRow::Value {
                selector: CurrentSelector::MessageRevision { message_id },
                revision,
                ..
            } if redacted.contains(message_id.as_str()) || below_floor.contains(message_id)
                || facts.withheld_content_commits.contains(revision.commit_id.as_str())
        )
    });
    let mut stream_floors = vec![StreamHistoryFloor {
        stream_ref: realm_stream,
        oldest_position: floor.oldest_position,
    }];
    stream_floors.extend(
        facts
            .circle_floors
            .iter()
            .map(|(circle_id, floor)| StreamHistoryFloor {
                stream_ref: CommitStreamRef::Circle {
                    realm_id: material.realm_id.clone(),
                    circle_id: circle_id.clone(),
                },
                oldest_position: floor.oldest_position,
            }),
    );
    stream_floors.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));
    stream_floors.extend(
        facts
            .sidecar_floors
            .iter()
            .chain(&facts.sidecar_public_floors)
            .map(|(sidecar_id, floor)| StreamHistoryFloor {
                stream_ref: CommitStreamRef::Sidecar {
                    realm_id: material.realm_id.clone(),
                    sidecar_id: sidecar_id.clone(),
                },
                oldest_position: floor.oldest_position,
            }),
    );
    material.retention_and_history_floor = arkret_wire::RetentionAndHistoryFloor {
        history_access,
        stream_floors,
    };
    Ok(material)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        CommitStreamHead, CurrentRevision, DidCoreId, HistoryAccess, MessageId,
        ReadableFloorReason, RealmCommitId, RetentionAndHistoryFloor, StrandId,
    };
    use serde_json::{Value, json};

    use super::*;

    fn account(name: &str) -> AccountId {
        AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn event_id(byte: u8) -> arkret_wire::EventId {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&event_id(0x11))
    }

    fn row(selector: CurrentSelector, position: u64, value: Value) -> TypedCurrentRow {
        TypedCurrentRow::Value {
            selector,
            source_stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            revision: CurrentRevision {
                commit_id: RealmCommitId::from_digest([position as u8 + 1; 32]),
                stream_position: position,
            },
            value,
        }
    }

    #[test]
    fn initial_schema_current_families_are_all_explicitly_classified() {
        let schema = include_str!("../migrations/00000000000000_initial/up.sql");
        for line in schema.lines() {
            let Some(table) = line.strip_prefix("CREATE TABLE ") else {
                continue;
            };
            let table = table
                .split_whitespace()
                .next()
                .unwrap()
                .trim_start_matches("public.");
            if table.ends_with("_current_results") {
                assert!(
                    AUDITED_FAMILIES.contains(&table),
                    "unclassified current family: {table}"
                );
            }
        }
    }

    #[test]
    fn watch_snapshot_filters_private_muted_and_cleared_values_by_complete_actor() {
        for (value, public) in [
            (json!({"level":"all"}), false),
            (json!({"level":"all","level_public":false}), false),
            (json!({"level":"all","level_public":true}), true),
            (json!({"level":"participating","level_public":true}), true),
            (json!({"level":"muted","level_public":true}), false),
            (json!({"level":"mentions_only","level_public":true}), false),
            (serde_json::Value::Null, false),
        ] {
            let (caller, mut material, facts) = fixture();
            let strand = material
                .current_state_entries
                .iter()
                .find_map(|entry| match entry {
                    TypedCurrentRow::Value {
                        selector: CurrentSelector::Strand { strand_id },
                        ..
                    } => Some(strand_id.clone()),
                    _ => None,
                })
                .unwrap();
            let other = ActorId::account(account("bob"));
            material.current_state_entries.push(row(
                CurrentSelector::StrandWatch {
                    strand_id: strand.clone(),
                    watcher_actor_id: other,
                },
                7,
                value.clone(),
            ));
            material.current_state_entries.push(row(
                CurrentSelector::StrandWatch {
                    strand_id: strand,
                    watcher_actor_id: ActorId::account(caller.clone()),
                },
                7,
                value,
            ));
            let disclosed = disclose_to_account(material, &caller, &facts).unwrap();
            let watches = disclosed
                .current_state_entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry,
                        TypedCurrentRow::Value {
                            selector: CurrentSelector::StrandWatch { .. },
                            ..
                        }
                    )
                })
                .count();
            assert_eq!(watches, if public { 2 } else { 1 });
        }
    }

    /// The founder's cut after bootstrap, a default Strand and one message.
    fn fixture() -> (
        AccountId,
        coland_storage::RealmStateSnapshotMaterial,
        DisclosureFacts,
    ) {
        let founder = account("alice");
        let actor = ActorId::account(founder.clone());
        let strand = StrandId::from_event_id(&event_id(0x22));
        let rows = vec![
            row(
                CurrentSelector::RealmGenesis,
                0,
                json!({"purpose":"collaboration"}),
            ),
            row(
                CurrentSelector::RealmAuthorityRoot,
                0,
                json!({"controller_actor_id":actor,"controller_epoch":0,"authority_generation":0}),
            ),
            row(CurrentSelector::RealmProfile, 1, json!({"title":"Example"})),
            row(
                CurrentSelector::RealmPolicyBundle,
                2,
                json!({"policy_revision":1}),
            ),
            row(CurrentSelector::RealmJoinRule, 3, json!("invite")),
            row(CurrentSelector::RealmHistoryAccess, 4, json!("since_join")),
            row(CurrentSelector::RealmDiscovery, 5, json!({"listed":false})),
            row(
                CurrentSelector::MemberState {
                    actor_id: actor.clone(),
                },
                6,
                json!({"membership":"join"}),
            ),
            row(
                CurrentSelector::Strand {
                    strand_id: strand.clone(),
                },
                7,
                json!({ "id": strand }),
            ),
            row(
                CurrentSelector::RealmSetDefaultStrand,
                8,
                json!({ "default_strand_id": strand }),
            ),
            row(
                CurrentSelector::MessageRevision {
                    message_id: MessageId::from_event_id(&event_id(0x33)),
                },
                9,
                json!({ "strand_id": strand }),
            ),
        ];
        let realm_stream = CommitStreamRef::Realm {
            realm_id: realm_id(),
        };
        let material = coland_storage::RealmStateSnapshotMaterial {
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
            realm_id: realm_id(),
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: realm_stream.clone(),
                stream_position: 9,
                commit_id: RealmCommitId::from_digest([10; 32]),
            }],
            current_state_entries: rows,
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref: realm_stream,
                    oldest_position: 3,
                }],
            },
        };
        let facts = DisclosureFacts {
            withheld_content_commits: Default::default(),
            message_streams: [(
                MessageId::from_event_id(&event_id(0x33)),
                CommitStreamRef::Realm {
                    realm_id: realm_id(),
                },
            )]
            .into(),
            circle_floors: Default::default(),
            sidecar_floors: Default::default(),
            sidecar_public_floors: Default::default(),
            owned_sidecars: Default::default(),
            report_subjects: Default::default(),
            franking_subjects: Default::default(),
            relation_subjects: Default::default(),
            call_creations: Default::default(),
            caller_floor: Some(ReadableFloor {
                oldest_position: 0,
                floor_commit_id: RealmCommitId::from_digest([1; 32]),
                floor_reason: ReadableFloorReason::StreamStart,
            }),
            undisclosed_kind: None,
            undisclosed_family_row: false,
        };
        (founder, material, facts)
    }

    /// The fixture after Alice invites Bob (10), Bob accepts (11), Alice grants
    /// him `ak.message.create` (12) and Bob posts (13), with Bob's facts: his
    /// `since_join` floor is his accepting Commit.
    fn joined_fixture() -> (
        AccountId,
        coland_storage::RealmStateSnapshotMaterial,
        DisclosureFacts,
    ) {
        let (_, mut material, _) = fixture();
        let alice = ActorId::account(account("alice"));
        let bob_account = account("bob");
        let bob = ActorId::account(bob_account.clone());
        let invite_id = arkret_wire::InviteId::from_event_id(&event_id(0x44));
        let grant_id = arkret_wire::GrantId::from_event_id(&event_id(0x45));
        material.current_state_entries.extend([
            row(
                CurrentSelector::InviteDirectedInvitee {
                    invite_id: invite_id.clone(),
                },
                10,
                json!({ "invitee_account_id": bob_account }),
            ),
            row(
                CurrentSelector::InviteLifecycle {
                    invite_id: invite_id.clone(),
                },
                11,
                json!("accepted"),
            ),
            row(
                CurrentSelector::InviteLiveTarget {
                    invitee_account_id: bob_account.clone(),
                },
                11,
                Value::Null,
            ),
            row(
                CurrentSelector::MemberState { actor_id: bob },
                11,
                json!({"membership":"join"}),
            ),
            row(
                CurrentSelector::CapabilityGrant { grant_id },
                12,
                json!({ "issuer_id": alice }),
            ),
            row(
                CurrentSelector::MessageRevision {
                    message_id: MessageId::from_event_id(&event_id(0x46)),
                },
                13,
                json!({ "strand_id": StrandId::from_event_id(&event_id(0x22)) }),
            ),
        ]);
        material.visible_stream_heads[0].stream_position = 13;
        material.visible_stream_heads[0].commit_id = RealmCommitId::from_digest([14; 32]);
        let facts = DisclosureFacts {
            withheld_content_commits: Default::default(),
            message_streams: [
                (
                    MessageId::from_event_id(&event_id(0x33)),
                    CommitStreamRef::Realm {
                        realm_id: realm_id(),
                    },
                ),
                (
                    MessageId::from_event_id(&event_id(0x46)),
                    CommitStreamRef::Realm {
                        realm_id: realm_id(),
                    },
                ),
            ]
            .into(),
            circle_floors: Default::default(),
            sidecar_floors: Default::default(),
            sidecar_public_floors: Default::default(),
            owned_sidecars: Default::default(),
            report_subjects: Default::default(),
            franking_subjects: Default::default(),
            relation_subjects: Default::default(),
            call_creations: Default::default(),
            caller_floor: Some(ReadableFloor {
                oldest_position: 11,
                floor_commit_id: RealmCommitId::from_digest([12; 32]),
                floor_reason: ReadableFloorReason::MembershipJoin,
            }),
            undisclosed_kind: None,
            undisclosed_family_row: false,
        };
        (bob_account, material, facts)
    }

    #[test]
    fn joined_member_receives_state_rows_and_only_messages_from_its_floor() {
        let (bob, material, facts) = joined_fixture();
        let disclosed = disclose_to_account(material.clone(), &bob, &facts).unwrap();
        let mut expected = material.current_state_entries.clone();
        expected.remove(10);
        assert_eq!(disclosed.current_state_entries, expected);
        assert_eq!(
            disclosed.retention_and_history_floor.stream_floors,
            vec![StreamHistoryFloor {
                stream_ref: CommitStreamRef::Realm {
                    realm_id: realm_id()
                },
                oldest_position: 11,
            }]
        );
        // The founder's floor is the genesis Commit: every row, both Messages.
        let (founder, _, mut founder_facts) = fixture();
        founder_facts.message_streams.insert(
            MessageId::from_event_id(&event_id(0x46)),
            CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
        );
        let disclosed = disclose_to_account(material.clone(), &founder, &founder_facts).unwrap();
        assert_eq!(
            disclosed.current_state_entries,
            material.current_state_entries
        );
        // Bob's facts never serve an Account without its own join row.
        assert!(disclose_to_account(material, &account("carol"), &facts).is_err());
    }

    fn reaction_set(target: &MessageId, byte: u8) -> Value {
        json!({"assertions": [{
            "tag_id": format!("{}:0", event_id(byte).as_str()),
            "value": {"target_ref": target, "key": "+1"}
        }]})
    }

    #[test]
    fn reaction_sets_are_state_disclosed_with_their_target_scope() {
        let (bob, mut material, mut facts) = joined_fixture();
        let floored = MessageId::from_event_id(&event_id(0x33));
        let reactions = row(
            CurrentSelector::MessageReactions {
                target_ref: floored.to_string(),
            },
            12,
            reaction_set(&floored, 0x55),
        );
        // A Circle Message's reactions stay in that Circle's stream.
        let circle_id = CircleId::from_event_id(&event_id(0x56));
        let circle_stream = CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id,
        };
        let hidden = MessageId::from_event_id(&event_id(0x57));
        facts
            .message_streams
            .insert(hidden.clone(), circle_stream.clone());
        let TypedCurrentRow::Value {
            selector,
            revision,
            value,
            ..
        } = row(
            CurrentSelector::MessageReactions {
                target_ref: hidden.to_string(),
            },
            2,
            reaction_set(&hidden, 0x58),
        );
        material.current_state_entries.push(reactions.clone());
        material.current_state_entries.push(TypedCurrentRow::Value {
            selector,
            source_stream_ref: circle_stream,
            revision,
            value,
        });
        let disclosed = disclose_to_account(material.clone(), &bob, &facts).unwrap();
        // The target Message sits below Bob's floor, but the reaction set is
        // state: it is disclosed whole, while the hidden Circle's is omitted.
        let reaction_rows = disclosed
            .current_state_entries
            .iter()
            .filter(|row| {
                matches!(
                    row,
                    TypedCurrentRow::Value {
                        selector: CurrentSelector::MessageReactions { .. },
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(reaction_rows, vec![&reactions]);

        for drift in [
            reaction_set(&MessageId::from_event_id(&event_id(0x46)), 0x55),
            json!({"assertions": []}),
            json!({"reactions": [{"actor_id": ActorId::account(bob.clone()), "key": "+1"}]}),
        ] {
            let mut drifted = material.clone();
            let TypedCurrentRow::Value { value, .. } = drifted
                .current_state_entries
                .iter_mut()
                .find(|row| **row == reactions)
                .unwrap();
            *value = drift;
            assert!(disclose_to_account(drifted, &bob, &facts).is_err());
        }

        let mut foreign_scope = facts;
        foreign_scope.message_streams.insert(
            floored,
            CommitStreamRef::Circle {
                realm_id: realm_id(),
                circle_id: CircleId::from_event_id(&event_id(0x56)),
            },
        );
        assert!(disclose_to_account(material, &bob, &foreign_scope).is_err());
    }

    #[test]
    fn sole_founder_receives_every_row_with_the_genesis_floor() {
        let (founder, material, facts) = fixture();
        let disclosed = disclose_to_account(material.clone(), &founder, &facts).unwrap();
        assert_eq!(
            disclosed.current_state_entries,
            material.current_state_entries
        );
        assert_eq!(
            disclosed.retention_and_history_floor,
            RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref: CommitStreamRef::Realm {
                        realm_id: realm_id()
                    },
                    oldest_position: 0,
                }],
            }
        );
    }

    #[test]
    fn position_disclosure_requires_visible_board_strand_and_list_subjects() {
        use arkret_models_collaboration::objects::space::Space;
        use arkret_models_collaboration::objects::strand::Strand;
        let (founder, mut material, facts) = fixture();
        let actor = ActorId::account(founder.clone());
        let strand_id = StrandId::from_event_id(&event_id(0x22));
        material.current_state_entries[8] = row(
            CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            7,
            serde_json::to_value(Strand::new(
                strand_id.clone(),
                realm_id(),
                "Card",
                actor.clone(),
            ))
            .unwrap(),
        );
        let board_id = arkret_wire::SpaceId::from_event_id(&event_id(0x66));
        let list_id = arkret_wire::SpaceId::from_event_id(&event_id(0x67));
        for (id, kind) in [(&board_id, "board"), (&list_id, "list")] {
            material.current_state_entries.extend([
                row(
                    CurrentSelector::Space {
                        space_id: id.clone(),
                    },
                    7,
                    serde_json::to_value(Space::new(
                        id.clone(),
                        realm_id(),
                        kind,
                        kind,
                        actor.clone(),
                    ))
                    .unwrap(),
                ),
                row(
                    CurrentSelector::SpaceParent {
                        space_id: id.clone(),
                    },
                    7,
                    json!({"parent_space_id":null}),
                ),
                row(
                    CurrentSelector::SpaceChildScopePolicy {
                        space_id: id.clone(),
                    },
                    7,
                    Value::Null,
                ),
            ]);
        }
        material.current_state_entries.push(row(
            CurrentSelector::StrandPosition {
                board_space_id: board_id.clone(),
                strand_id: strand_id.clone(),
            },
            7,
            json!({"list_space_id":list_id,"rank":"a0"}),
        ));
        assert_eq!(
            disclose_to_account(material.clone(), &founder, &facts)
                .unwrap()
                .current_state_entries,
            material.current_state_entries
        );
        let mut null_position = material.clone();
        if let Some(TypedCurrentRow::Value { value, .. }) =
            null_position.current_state_entries.last_mut()
        {
            *value = Value::Null;
        }
        assert!(disclose_to_account(null_position, &founder, &facts).is_ok());
        for missing in [
            CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            CurrentSelector::Space { space_id: board_id },
            CurrentSelector::Space { space_id: list_id },
        ] {
            let mut incomplete = material.clone();
            incomplete.current_state_entries.retain(|entry| {
                !matches!(entry,
                TypedCurrentRow::Value { selector, .. } if selector == &missing)
            });
            assert!(disclose_to_account(incomplete, &founder, &facts).is_err());
        }
        let mut foreign = material;
        let TypedCurrentRow::Value { value, .. } = &mut foreign.current_state_entries[8];
        value["realm_id"] = json!(RealmId::from_event_id(&event_id(0x68)));
        assert!(disclose_to_account(foreign, &founder, &facts).is_err());
    }

    #[test]
    fn realm_space_disclosure_requires_complete_siblings_and_rejects_circle_metadata() {
        use arkret_models_collaboration::objects::space::Space;
        let (founder, mut material, facts) = fixture();
        let space_id = arkret_wire::SpaceId::from_event_id(&event_id(0x66));
        let mut space = Space::new(
            space_id.clone(),
            realm_id(),
            "board",
            "Board",
            ActorId::account(founder.clone()),
        );
        material.current_state_entries.extend([
            row(
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                7,
                serde_json::to_value(&space).unwrap(),
            ),
            row(
                CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                7,
                json!({"parent_space_id":null}),
            ),
            row(
                CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                7,
                Value::Null,
            ),
        ]);
        assert_eq!(
            disclose_to_account(material.clone(), &founder, &facts)
                .unwrap()
                .current_state_entries,
            material.current_state_entries,
        );
        let mut incomplete = material.clone();
        incomplete.current_state_entries.pop();
        assert!(disclose_to_account(incomplete, &founder, &facts).is_err());
        space.scope_circle_id = Some(arkret_wire::CircleId::from_event_id(&event_id(0x77)));
        let index = material.current_state_entries.len() - 3;
        material.current_state_entries[index] = row(
            CurrentSelector::Space { space_id },
            7,
            serde_json::to_value(space).unwrap(),
        );
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    fn redaction_row(target: &str, redacted: &MessageId, position: u64) -> TypedCurrentRow {
        row(
            CurrentSelector::ObjectRedaction {
                target_ref: target.to_owned(),
            },
            position,
            json!({"assertions": [{
                "tag_id": format!("{}:0", event_id(0x77)),
                "value": {"message_id": redacted, "reason": "retracted"}
            }]}),
        )
    }

    #[test]
    fn a_redacted_message_is_disclosed_as_its_redaction_only() {
        let (founder, mut material, facts) = fixture();
        let message = MessageId::from_event_id(&event_id(0x33));
        material.current_state_entries[10] = row(
            CurrentSelector::MessageRevision {
                message_id: message.clone(),
            },
            8,
            json!({"message_id": message, "content": {"kind": "ak.content.text", "body": "x", "format": "plain"}}),
        );
        let redaction = redaction_row(message.as_str(), &message, 9);
        material.current_state_entries.push(redaction.clone());
        let disclosed = disclose_to_account(material.clone(), &founder, &facts).unwrap();
        assert!(
            !disclosed.current_state_entries.iter().any(|entry| matches!(
                entry,
                TypedCurrentRow::Value {
                    selector: CurrentSelector::MessageRevision { .. },
                    ..
                }
            ))
        );
        assert_eq!(disclosed.current_state_entries.last(), Some(&redaction));
        assert_eq!(
            disclosed.current_state_entries.len(),
            material.current_state_entries.len() - 1
        );

        let other = MessageId::from_event_id(&event_id(0x34));
        let (founder, mut foreign, facts) = fixture();
        foreign
            .current_state_entries
            .push(redaction_row(message.as_str(), &other, 9));
        assert!(disclose_to_account(foreign, &founder, &facts).is_err());
        let (founder, mut event_subject, facts) = fixture();
        let event_target = event_id(0x33).to_string();
        event_subject.current_state_entries.push(row(
            CurrentSelector::ObjectRedaction {
                target_ref: event_target.clone(),
            },
            9,
            json!({"assertions": [{
                "tag_id": format!("{}:0", event_id(0x77)),
                "value": {"target_ref": event_target}
            }]}),
        ));
        assert!(disclose_to_account(event_subject, &founder, &facts).is_err());
    }

    #[test]
    fn accounts_without_a_join_or_a_provable_floor_are_refused() {
        let (_, material, facts) = fixture();
        assert!(disclose_to_account(material, &account("mallory"), &facts).is_err());
        let (founder, material, mut facts) = fixture();
        facts.caller_floor = None;
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        let TypedCurrentRow::Value { value, .. } = &mut material.current_state_entries[7];
        *value = json!({"membership":"leave"});
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    #[test]
    fn realm_agent_policy_current_is_disclosed_without_changing_signed_bytes() {
        let (caller, mut material, facts) = joined_fixture();
        let policy_id =
            arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000001").unwrap();
        let value = json!({"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm_id(),
            "policy_kind":"agent","rules":[{"rule_id":"ban","kind":"agent","effect":"deny",
                "agent_target":{"kind":"all"},"agent_operations":["authorize","execute"]}],
            "default_effect":"allow","created_by":ActorId::account(account("alice")),
            "created_at":"2026-10-05T12:00:00.000Z"});
        let policy = row(CurrentSelector::Policy { policy_id }, 1, value);
        material.current_state_entries.push(policy.clone());
        let disclosed = disclose_to_account(material, &caller, &facts).unwrap();
        assert!(disclosed.current_state_entries.contains(&policy));
        // Governance current remains available below the caller's content floor.
        let TypedCurrentRow::Value { revision, .. } = &policy;
        assert!(revision.stream_position < facts.caller_floor.as_ref().unwrap().oldest_position);
    }

    #[test]
    fn product_policy_disclosure_preserves_scope_and_signed_values_below_floor() {
        for kind in ["access", "moderation"] {
            for circle in [false, true] {
                let (caller, mut material, facts) = if circle {
                    circle_fixture()
                } else {
                    joined_fixture()
                };
                let policy_id =
                    arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000001")
                        .unwrap();
                let value = json!({"schema":"ak.schema.policy.v1","id":policy_id,
                    "realm_id":realm_id(),"policy_kind":kind,
                    "rules":[{"rule_id":"typing","kind":"action","effect":"deny",
                        "actions":["ak.typing.broadcast"]}],"default_effect":"allow",
                    "created_by":ActorId::account(caller.clone()),
                    "created_at":"2026-10-05T12:00:00.000Z"});
                let mut policy = row(CurrentSelector::Policy { policy_id }, 1, value);
                if circle {
                    let TypedCurrentRow::Value {
                        source_stream_ref, ..
                    } = &mut policy;
                    *source_stream_ref = CommitStreamRef::Circle {
                        realm_id: realm_id(),
                        circle_id: CircleId::from_event_id(&event_id(0x51)),
                    };
                }
                material.current_state_entries.push(policy.clone());
                let disclosed = disclose_to_account(material.clone(), &caller, &facts).unwrap();
                assert!(disclosed.current_state_entries.contains(&policy));
                if circle {
                    let mut outsider_facts = facts;
                    outsider_facts.circle_floors.clear();
                    let outsider = disclose_to_account(material, &caller, &outsider_facts).unwrap();
                    assert!(!outsider.current_state_entries.contains(&policy));
                }
            }
        }
    }

    #[test]
    fn circle_original_recheck_uses_current_realm_basis_without_disclosing_it() {
        let (account, authority, caller) = circle_fixture();
        let actor = ActorId::account(account);
        let mut original = authority.clone();
        original.current_state_entries.retain(|row| {
            matches!(
                row,
                TypedCurrentRow::Value {
                    source_stream_ref: CommitStreamRef::Circle { .. },
                    selector: CurrentSelector::Strand { .. }
                        | CurrentSelector::CircleMemberState { .. },
                    ..
                }
            )
        });
        assert!(!original.current_state_entries.is_empty());
        let frozen_rows = original.current_state_entries.clone();
        let facts = SnapshotCandidateDisclosureFacts {
            caller,
            owner: None,
        };
        let disclosed = disclose_snapshot_candidate_at_facts(
            &actor,
            &authority,
            Some(original.clone()),
            &facts,
        )
        .unwrap();
        assert_eq!(disclosed.current_state_entries, frozen_rows);
        assert_eq!(original.current_state_entries, frozen_rows);
        let mut missing = authority.clone();
        missing.current_state_entries.retain(|row| {
            !matches!(
                row,
                TypedCurrentRow::Value {
                    selector: CurrentSelector::RealmHistoryAccess,
                    ..
                }
            )
        });
        assert!(
            disclose_snapshot_candidate_at_facts(&actor, &missing, Some(original.clone()), &facts)
                .is_err(),
            "the historical slice cannot manufacture missing authority facts"
        );
        let (_, _, mut caller) = circle_fixture();
        caller.caller_floor = None;
        assert!(
            disclose_snapshot_candidate_at_facts(
                &actor,
                &authority,
                Some(original),
                &SnapshotCandidateDisclosureFacts {
                    caller,
                    owner: None
                }
            )
            .is_err(),
            "an archived slice never restores current membership"
        );
    }

    #[test]
    fn applet_policy_is_private_without_blocking_ordinary_member_snapshots() {
        for circle in [false, true] {
            let (caller, mut material, facts) = if circle {
                circle_fixture()
            } else {
                joined_fixture()
            };
            let policy_id =
                arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000001")
                    .unwrap();
            let scope = if circle {
                let circle_id = facts.circle_floors.keys().next().unwrap().clone();
                arkret_wire::ScopeRef::Circle {
                    realm_id: realm_id(),
                    circle_id,
                }
            } else {
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id(),
                }
            };
            let value = json!({"schema":"ak.schema.policy.v1","id":policy_id,
                "realm_id":realm_id(),"policy_kind":"applet",
                "rules":[{"rule_id":"execute","kind":"applet","effect":"deny",
                    "applet_target":{"kind":"all"},"applet_operations":["execute"]}],
                "default_effect":"allow","created_by":ActorId::account(caller.clone()),
                "created_at":"2026-10-19T10:00:00.000Z"});
            let mut policy = row(
                CurrentSelector::Policy {
                    policy_id: policy_id.clone(),
                },
                1,
                value,
            );
            let TypedCurrentRow::Value {
                source_stream_ref, ..
            } = &mut policy;
            *source_stream_ref = CommitStreamRef::from_scope(&scope, None).unwrap();
            material.current_state_entries.push(policy);
            let disclosed = disclose_to_account(material.clone(), &caller, &facts).unwrap();
            assert!(
                !disclosed
                    .current_state_entries
                    .iter()
                    .any(|row| matches!(row,
                TypedCurrentRow::Value { selector: CurrentSelector::Policy { policy_id: id }, .. }
                    if id == &policy_id))
            );
            let TypedCurrentRow::Value { value, .. } =
                material.current_state_entries.last_mut().unwrap();
            value["id"] = json!("ak:policy:0198ff00-0000-7000-8000-000000000002");
            assert!(
                disclose_to_account(material, &caller, &facts).is_err(),
                "private classification must not hide malformed authority state"
            );
        }
    }

    #[test]
    fn agent_policy_disclosure_refuses_unbound_private_and_mismatched_values() {
        let (caller, base, facts) = fixture();
        let id =
            arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000001").unwrap();
        let value = json!({"schema":"ak.schema.policy.v1","id":id,"realm_id":realm_id(),
            "policy_kind":"agent","rules":[{"rule_id":"allow","kind":"agent","effect":"allow",
                "agent_target":{"kind":"all"},"agent_operations":["join"]}],
            "default_effect":"allow","created_by":ActorId::account(caller.clone()),
            "created_at":"2026-10-05T12:00:00.000Z"});
        let mut invalid = vec![json!({"schema":"ak.schema.recovery_policy.v1"})];
        for field in ["id", "realm_id", "policy_kind", "rules"] {
            let mut changed = value.clone();
            changed[field] = match field {
                "id" => json!("ak:policy:0198ff00-0000-7000-8000-000000000002"),
                "realm_id" => json!(null),
                "policy_kind" => json!("access"),
                _ => json!([]),
            };
            invalid.push(changed);
        }
        for value in invalid {
            let mut material = base.clone();
            material.current_state_entries.push(row(
                CurrentSelector::Policy {
                    policy_id: id.clone(),
                },
                1,
                value,
            ));
            assert!(disclose_to_account(material, &caller, &facts).is_err());
        }
        let mut material = base;
        let mut policy = row(CurrentSelector::Policy { policy_id: id }, 1, value);
        let TypedCurrentRow::Value {
            source_stream_ref, ..
        } = &mut policy;
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: RealmId::from_event_id(&event_id(0x55)),
        };
        material.current_state_entries.push(policy);
        assert!(disclose_to_account(material, &caller, &facts).is_err());
    }

    #[test]
    fn undisclosed_kinds_and_families_refuse_the_whole_cut() {
        let (founder, material, mut facts) = fixture();
        facts.undisclosed_kind = Some("ak.moderation.decision".to_owned());
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, material, mut facts) = fixture();
        facts.undisclosed_family_row = true;
        let error = disclose_to_account(material, &founder, &facts).unwrap_err();
        assert!(error.to_string().contains("outside the disclosure subset"));
        let (founder, mut material, facts) = fixture();
        material.current_state_entries.push(row(
            CurrentSelector::ModerationReport {
                event_id: event_id(0x44),
            },
            9,
            json!({}),
        ));
        let disclosed = disclose_to_account(material, &founder, &facts).unwrap();
        assert!(!disclosed.current_state_entries.iter().any(|row| matches!(
            row,
            TypedCurrentRow::Value {
                selector: CurrentSelector::ModerationReport { .. },
                ..
            }
        )));
    }

    #[test]
    fn private_confirmation_rows_are_omitted_without_refusing_shared_snapshot() {
        let (founder, mut material, facts) = fixture();
        let shared_count = material.current_state_entries.len();
        material.current_state_entries.push(row(
            CurrentSelector::AgentActionApproval {
                approval_id: "private-controller-confirmation".into(),
            },
            9,
            json!({"approval_nonce":"private-controller-nonce"}),
        ));
        let disclosed = disclose_to_account(material, &founder, &facts).unwrap();
        assert_eq!(disclosed.current_state_entries.len(), shared_count);
        assert!(
            !disclosed.current_state_entries.iter().any(|entry| matches!(
                entry,
                TypedCurrentRow::Value {
                    selector: CurrentSelector::AgentActionApproval { .. },
                    ..
                }
            ))
        );
        assert!(
            !serde_json::to_string(&disclosed.current_state_entries)
                .unwrap()
                .contains("private-controller-nonce")
        );
        // Other unproved families still refuse the complete cut.
        let (founder, material, mut facts) = fixture();
        facts.undisclosed_family_row = true;
        assert!(disclose_to_account(material, &founder, &facts).is_err());
    }

    #[test]
    fn direct_conversation_binding_requires_exact_participant_and_selector() {
        use arkret_models_collaboration::events_payloads::direct_conversation::{
            DirectConversationBindingCurrentValue, DirectConversationBoundPayload,
        };

        let (alice, mut material, facts) = fixture();
        let pair_key = arkret_wire::Hash::new(format!("sha256:{}", "71".repeat(32))).unwrap();
        let bob = account("bob");
        let payload = DirectConversationBoundPayload {
            pair_key: pair_key.clone(),
            unordered_participant_ids: vec![
                ActorId::account(alice.clone()),
                ActorId::account(bob.clone()),
            ],
            realm_id: realm_id(),
            main_strand_id: StrandId::from_event_id(&event_id(0x72)),
            founding_unit_digest: arkret_wire::Hash::new(format!("sha256:{}", "73".repeat(32))).unwrap(),
            authorization_basis: arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis::accepted_contact(
                vec![event_id(0x74), event_id(0x75)],
            ),
            initial_exact_pair_group_state_ref: event_id(0x76),
            created_at: chrono::Utc::now(),
        };
        let value = serde_json::to_value(DirectConversationBindingCurrentValue {
            binding_event_ref: event_id(0x77),
            binding: payload,
        })
        .unwrap();
        material.current_state_entries.push(row(
            CurrentSelector::DirectConversationBinding {
                pair_key: pair_key.clone(),
            },
            9,
            value,
        ));
        assert!(disclose_to_account(material.clone(), &alice, &facts).is_ok());
        let carol = account("carol");
        let mut joined_outsider = material.clone();
        joined_outsider.current_state_entries.push(row(
            CurrentSelector::MemberState {
                actor_id: ActorId::account(carol.clone()),
            },
            9,
            json!({"membership":"join"}),
        ));
        let error = disclose_to_account(joined_outsider, &carol, &facts).unwrap_err();
        assert!(error.to_string().contains("exact participant"));
        let binding = material.current_state_entries.last_mut().unwrap();
        let TypedCurrentRow::Value { selector, .. } = binding;
        *selector = CurrentSelector::DirectConversationBinding {
            pair_key: arkret_wire::Hash::new(format!("sha256:{}", "78".repeat(32))).unwrap(),
        };
        assert!(disclose_to_account(material, &alice, &facts).is_err());
    }

    #[test]
    fn hidden_streams_are_omitted_and_foreign_sources_and_later_tenures_are_refused() {
        let circle = CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&event_id(0x55)),
        };
        let (founder, mut material, facts) = fixture();
        material.visible_stream_heads.push(CommitStreamHead {
            stream_ref: circle.clone(),
            stream_position: 0,
            commit_id: RealmCommitId::from_digest([0x66; 32]),
        });
        let disclosed = disclose_to_account(material, &founder, &facts).unwrap();
        assert_eq!(disclosed.visible_stream_heads.len(), 1);
        assert_eq!(disclosed.retention_and_history_floor.stream_floors.len(), 1);
        let (founder, mut material, facts) = fixture();
        let TypedCurrentRow::Value {
            source_stream_ref, ..
        } = &mut material.current_state_entries[10];
        *source_stream_ref = circle;
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        let TypedCurrentRow::Value { revision, .. } = &mut material.current_state_entries[10];
        revision.stream_position = 10;
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        let (founder, mut material, facts) = fixture();
        material.governance_generation = 1;
        assert!(disclose_to_account(material, &founder, &facts).is_ok());
    }

    #[test]
    fn circle_strands_and_missing_anchor_rows_are_refused() {
        let (founder, mut material, facts) = fixture();
        let TypedCurrentRow::Value { value, .. } = &mut material.current_state_entries[8];
        value["scope_circle_id"] = json!("ak:circle:x");
        assert!(disclose_to_account(material, &founder, &facts).is_err());
        for missing in [0, 1, 5, 7] {
            let (founder, mut material, facts) = fixture();
            material.current_state_entries.remove(missing);
            assert!(
                disclose_to_account(material, &founder, &facts).is_err(),
                "row {missing}"
            );
        }
    }

    fn circle_fixture() -> (
        AccountId,
        coland_storage::RealmStateSnapshotMaterial,
        DisclosureFacts,
    ) {
        let (caller, mut material, mut facts) = fixture();
        let circle_id = CircleId::from_event_id(&event_id(0x51));
        let stream = CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id: circle_id.clone(),
        };
        let strand_id = StrandId::from_event_id(&event_id(0x52));
        material.current_state_entries.push(row(CurrentSelector::Circle { circle_id: circle_id.clone() }, 7,
            json!({"id":circle_id,"schema":"ak.schema.circle.v1","realm_id":realm_id(),
                "title":"Private","display":{"short_name":"Private","color_token":"blue","symbol":{"glyph":"lock"}},
                "directory_visibility":"members","join_rule":"public","history_access":"since_join",
                "state":"active","created_by":ActorId::account(caller.clone()),"created_at":"2026-09-28T00:00:00.000Z"})));
        let mut circle_row = |selector, position, value| {
            let mut result = row(selector, position, value);
            let TypedCurrentRow::Value {
                source_stream_ref, ..
            } = &mut result;
            *source_stream_ref = stream.clone();
            material.current_state_entries.push(result);
        };
        circle_row(
            CurrentSelector::CircleMemberState {
                circle_id: circle_id.clone(),
                member_actor_id: ActorId::account(caller.clone()),
            },
            2,
            json!({"membership":"join",
                "parent_membership_revision":{"commit_id":RealmCommitId::from_digest([1; 32]),"stream_position":1},
                "effective_at":"2026-09-28T00:00:00.000Z"}),
        );
        circle_row(
            CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            0,
            json!({"id":strand_id,"scope_circle_id":circle_id}),
        );
        for (byte, position) in [(0x53, 1), (0x54, 3)] {
            let message_id = MessageId::from_event_id(&event_id(byte));
            circle_row(
                CurrentSelector::MessageRevision {
                    message_id: message_id.clone(),
                },
                position,
                json!({"message_id":message_id,"content":{"kind":"ak.content.text","format":"plain","body":"revised"}}),
            );
            facts.message_streams.insert(message_id, stream.clone());
        }
        material.visible_stream_heads.push(CommitStreamHead {
            stream_ref: stream,
            stream_position: 4,
            commit_id: RealmCommitId::from_digest([5; 32]),
        });
        facts.circle_floors.insert(
            circle_id,
            ReadableFloor {
                oldest_position: 2,
                floor_commit_id: RealmCommitId::from_digest([3; 32]),
                floor_reason: ReadableFloorReason::MembershipJoin,
            },
        );
        (caller, material, facts)
    }

    #[test]
    fn circle_metadata_and_content_use_exact_membership_and_independent_history_floor() {
        let (caller, material, facts) = circle_fixture();
        let disclosed = disclose_to_account(material.clone(), &caller, &facts).unwrap();
        assert_eq!(disclosed.visible_stream_heads.len(), 2);
        assert_eq!(disclosed.retention_and_history_floor.stream_floors.len(), 2);
        assert!(!disclosed.current_state_entries.iter().any(|row| matches!(row,
            TypedCurrentRow::Value { selector: CurrentSelector::MessageRevision { message_id }, .. }
                if message_id == &MessageId::from_event_id(&event_id(0x53))
        )));
        assert!(disclosed.current_state_entries.iter().any(|row| matches!(row,
            TypedCurrentRow::Value { selector: CurrentSelector::MessageRevision { message_id }, .. }
                if message_id == &MessageId::from_event_id(&event_id(0x33))
        )));
        assert!(disclosed.current_state_entries.iter().any(|row| matches!(row,
            TypedCurrentRow::Value { selector: CurrentSelector::MessageRevision { message_id }, .. }
                if message_id == &MessageId::from_event_id(&event_id(0x54))
        )));
        let mut outsider_facts = facts;
        outsider_facts.circle_floors.clear();
        let outsider = disclose_to_account(material, &caller, &outsider_facts).unwrap();
        assert_eq!(outsider.visible_stream_heads.len(), 1);
        assert_eq!(outsider.retention_and_history_floor.stream_floors.len(), 1);
        assert!(!outsider.current_state_entries.iter().any(|row| matches!(
            row,
            TypedCurrentRow::Value {
                selector: CurrentSelector::Circle { .. }
                    | CurrentSelector::CircleMemberState { .. },
                ..
            }
        )));
    }

    #[test]
    fn circle_agent_policy_preserves_exact_current_only_for_its_joined_members() {
        let (caller, mut material, facts) = circle_fixture();
        let circle_id = CircleId::from_event_id(&event_id(0x51));
        let policy_id =
            arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000001").unwrap();
        let value = json!({"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm_id(),
            "policy_kind":"agent","rules":[{"rule_id":"ban","kind":"agent","effect":"deny",
                "agent_target":{"kind":"all"},"agent_operations":["authorize"]}],
            "default_effect":"allow","created_by":ActorId::account(caller.clone()),
            "created_at":"2026-10-05T12:00:00.000Z"});
        let mut policy = row(CurrentSelector::Policy { policy_id }, 1, value);
        let TypedCurrentRow::Value {
            source_stream_ref, ..
        } = &mut policy;
        *source_stream_ref = CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id,
        };
        material.current_state_entries.push(policy.clone());
        let disclosed = disclose_to_account(material.clone(), &caller, &facts).unwrap();
        assert!(disclosed.current_state_entries.contains(&policy));
        let mut outsider_facts = facts;
        outsider_facts.circle_floors.clear();
        let outsider = disclose_to_account(material, &caller, &outsider_facts).unwrap();
        assert!(!outsider.current_state_entries.contains(&policy));
        assert!(!outsider.current_state_entries.iter().any(|row| matches!(
            row,
            TypedCurrentRow::Value {
                selector: CurrentSelector::Policy { .. },
                ..
            }
        )));
    }

    #[test]
    fn bootstrap_registered_zero_floor_preserves_complete_current_material() {
        let (caller, material, facts) = circle_fixture();
        let disclosed = disclose_to_account(material, &caller, &facts).unwrap();
        let stream = CommitStreamRef::Realm {
            realm_id: realm_id(),
        };
        let head = disclosed
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == stream)
            .unwrap()
            .clone();
        let mut retained = disclosed.clone();
        anchor_bootstrap_join(
            &mut retained,
            &stream,
            &head.commit_id,
            head.stream_position,
            0,
        )
        .unwrap();
        assert_eq!(retained, disclosed);
    }

    #[test]
    fn bootstrap_join_changes_only_its_own_stream_floor_and_content_interval() {
        let (caller, material, facts) = circle_fixture();
        let mut disclosed = disclose_to_account(material, &caller, &facts).unwrap();
        let stream = CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id: CircleId::from_event_id(&event_id(0x51)),
        };
        anchor_bootstrap_join(
            &mut disclosed,
            &stream,
            &RealmCommitId::from_digest([4; 32]),
            3,
            3,
        )
        .unwrap();
        assert_eq!(
            disclosed
                .retention_and_history_floor
                .stream_floors
                .iter()
                .find(|floor| floor.stream_ref == stream)
                .unwrap()
                .oldest_position,
            3
        );
        assert_eq!(
            disclosed
                .retention_and_history_floor
                .stream_floors
                .iter()
                .find(|floor| matches!(floor.stream_ref, CommitStreamRef::Realm { .. }))
                .unwrap()
                .oldest_position,
            0
        );
        assert!(
            anchor_bootstrap_join(
                &mut disclosed.clone(),
                &stream,
                &RealmCommitId::from_digest([4; 32]),
                3,
                2,
            )
            .is_err()
        );
        assert!(disclosed.current_state_entries.iter().any(|row| matches!(row,
            TypedCurrentRow::Value { selector: CurrentSelector::MessageRevision { message_id }, .. }
                if message_id==&MessageId::from_event_id(&event_id(0x33))
        )));
        assert!(
            anchor_bootstrap_join(
                &mut disclosed,
                &stream,
                &RealmCommitId::from_digest([9; 32]),
                4,
                4
            )
            .is_err()
        );
        assert!(
            anchor_bootstrap_join(
                &mut disclosed,
                &stream,
                &RealmCommitId::from_digest([9; 32]),
                5,
                5
            )
            .is_err()
        );
    }
}
