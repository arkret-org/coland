//! Current governing cut held through an Account content handoff.
use arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation;
use arkret_wire::{AccountId, ActorId, CapabilityActionId, CommittedEventView, DidCoreId};
use coland_storage::{AccountContentDeliveryGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::Text;
use diesel::{OptionalExtension as _, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

type Connection = diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>;

/// Export originals and local operation mapping facts on the same caller cut.
/// No reducer cache supplies content or authority, including an empty export.
pub(crate) async fn realm_export_for_actor(
    pool: &crate::PgPool,
    realm: &arkret_wire::RealmId,
    actor: &ActorId,
    station: &DidCoreId,
) -> PersistenceResult<
    Option<(
        arkret_models_collaboration::governance::realm_governance::RealmExport,
        Vec<CommittedEventView>,
    )>,
> {
    use diesel_async::AsyncConnection as _;
    let mut conn = crate::pg_conn(pool).await?;
    conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
        Ok(realm_export_in_connection(
            conn,
            realm,
            actor,
            station,
            arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        )
        .await?)
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
}

#[derive(QueryableByName)]
struct ExportSourceRow {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    has_event: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    envelope: Option<serde_json::Value>,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    stream_key: String,
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    mapping_operation_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    mapping_kind: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    mapping_operation_type: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    mapping_sender: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    mapping_realm: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    mapping_payload: Option<serde_json::Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    mapping_created_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub(crate) async fn realm_export_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    actor: &ActorId,
    station: &DidCoreId,
    generated_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<
    Option<(
        arkret_models_collaboration::governance::realm_governance::RealmExport,
        Vec<CommittedEventView>,
    )>,
> {
    use arkret_models_collaboration::governance::realm_governance::{
        RealmExport, RealmExportSchema,
    };
    use arkret_wire::{
        CommitStreamRef, CommittedEventFullView, CommittedEventWithheldView, EventDisclosure,
        EventDisclosureStatus,
    };
    if !crate::authority_commit::accepted_current_member_joined_in_connection(conn, realm, actor)
        .await?
    {
        return Ok(None);
    }
    let governor = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Governor>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("Realm export has no accepted authority"))?;
    let governs = governor.service_id == station.as_str();
    let controller = if crate::committed_disclosure::ordinary_agent_read_ceiling(
        crate::account_stream_scan::realm_purpose(conn, realm).await?,
    ) {
        crate::realm_authorization_cut::owned_controller_snapshot_in_connection(
            conn,
            realm,
            actor,
            chrono::Utc::now(),
        )
        .await?
    } else {
        None
    };
    let rows = sql_query("SELECT c.commit_json,c.stream_position,c.stream_key,c.commit_id,c.event_pk IS NOT NULL AS has_event,e.envelope,\
        p.operation_id::text AS mapping_operation_id,p.event_kind AS mapping_kind,\
        p.operation_kind AS mapping_operation_type,p.sender_id AS mapping_sender,\
        p.realm_id AS mapping_realm,p.payload AS mapping_payload,p.created_at AS mapping_created_at \
        FROM realm_commits c LEFT JOIN committed_events e ON e.pk=c.event_pk \
        LEFT JOIN projection_events p ON p.event_pk=e.pk \
        WHERE c.realm_id=$1 ORDER BY c.stream_key COLLATE \"C\",c.stream_position,c.commit_id COLLATE \"C\"")
        .bind::<Text,_>(realm.as_str()).load::<ExportSourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut operations = Vec::new();
    let mut events = Vec::new();
    let mut sources = Vec::new();
    let mut prior = std::collections::BTreeMap::<CommitStreamRef, arkret_wire::RealmCommit>::new();
    let mut floors = std::collections::BTreeMap::<CommitStreamRef, Option<u64>>::new();
    for row in rows {
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
        if &commit.realm_id != realm
            || commit.stream_ref.realm_id() != realm
            || commit.commit_id.as_str() != row.commit_id
            || i64::try_from(commit.stream_position).map_err(PersistenceError::database)?
                != row.stream_position
            || crate::authority_commit::stream_key(&commit.stream_ref)? != row.stream_key
        {
            return Err(unavailable(
                "Realm export Commit coordinates differ from their original row",
            ));
        }
        let floor = if let Some(floor) = floors.get(&commit.stream_ref) {
            *floor
        } else {
            let caller_floor =
                export_floor_in_connection(conn, &commit.stream_ref, actor, governs).await?;
            let floor = if let Some(controller) = &controller {
                match (
                    caller_floor,
                    export_floor_in_connection(conn, &commit.stream_ref, controller, governs)
                        .await?,
                ) {
                    (Some(caller), Some(owner)) => Some(caller.max(owner)),
                    _ => None,
                }
            } else {
                caller_floor
            };
            floors.insert(commit.stream_ref.clone(), floor);
            floor
        };
        let Some(floor) = floor else {
            continue;
        };
        // Export obeys the ordinary stream interval, including its opening.
        // Bootstrap genesis and MLS handshake exceptions belong to their
        // registered surfaces, not to an export of ordinary history.
        if commit.stream_position < floor {
            continue;
        }
        if row.has_event != row.envelope.is_some() {
            return Err(unavailable(
                "Realm export original is not in committed state",
            ));
        }
        let event = row
            .envelope
            .map(serde_json::from_value::<arkret_wire::Event>)
            .transpose()
            .map_err(PersistenceError::database)?;
        commit
            .verify_commit_id_matches_content()
            .map_err(PersistenceError::database)?;
        if let Some(previous) = prior.get(&commit.stream_ref) {
            if previous.stream_position.checked_add(1) != Some(commit.stream_position)
                || commit.previous_commit_ref.as_ref() != Some(&previous.commit_id)
            {
                return Err(unavailable(
                    "Realm export has an unexplained readable Commit gap",
                ));
            }
        } else if commit.stream_position != floor {
            return Err(unavailable(
                "Realm export is missing its readable opening Commit",
            ));
        }
        prior.insert(commit.stream_ref.clone(), commit.clone());
        let view = if let Some(event) = event {
            let suite = arkret_canonical::canonical::digest_suite(
                event.event_id.digest_suite_code().as_str(),
            )
            .map_err(PersistenceError::database)?;
            event
                .verify_event_id_matches_content_with_digest_suite(suite)
                .map_err(PersistenceError::database)?;
            if event.event_id != commit.event_ref
                || &event.realm_id != realm
                || arkret_wire::CommitStreamRef::from_scope(
                    &event.scope_ref,
                    Some(event.realm_id.clone()),
                )
                .map_err(PersistenceError::database)?
                    != commit.stream_ref
            {
                return Err(unavailable(
                    "Realm export Event differs from its accepted Commit",
                ));
            }
            let original = crate::committed_disclosure::accepted_full_event_in_connection(
                conn,
                &event.event_id,
            )
            .await?
            .ok_or_else(|| unavailable("Realm export original accepted Event is missing"))?;
            if original.event != event || original.commit != commit {
                return Err(unavailable(
                    "Realm export source differs from its exact accepted original",
                ));
            }
            let mut disclosed = crate::committed_disclosure::disclose_in_connection(
                conn,
                vec![CommittedEventFullView { event, commit }],
            )
            .await?;
            let view = disclosed
                .pop()
                .ok_or_else(|| unavailable("Realm export disclosure is missing"))?;
            match view {
                CommittedEventView::Full(full)
                    if crate::committed_disclosure::full_event_for_member_in_connection(
                        conn,
                        &full,
                        actor,
                        chrono::Utc::now(),
                    )
                    .await? =>
                {
                    CommittedEventView::Full(full)
                }
                CommittedEventView::Full(full) => {
                    CommittedEventView::Withheld(CommittedEventWithheldView {
                        commit: full.commit,
                        event_disclosure: EventDisclosure {
                            status: EventDisclosureStatus::Withheld,
                        },
                    })
                }
                withheld => withheld,
            }
        } else {
            CommittedEventView::Withheld(CommittedEventWithheldView {
                commit,
                event_disclosure: EventDisclosure {
                    status: EventDisclosureStatus::Withheld,
                },
            })
        };
        let value = serde_json::to_value(&view).map_err(PersistenceError::database)?;
        let mut exported = value
            .as_object()
            .ok_or_else(|| unavailable("Realm export source is not an object"))?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        if let CommittedEventView::Full(full) = &view {
            let event = &full.event;
            exported.extend([
                ("event_id".to_owned(), serde_json::json!(event.event_id)),
                ("realm_id".to_owned(), serde_json::json!(event.realm_id)),
                ("event_kind".to_owned(), serde_json::json!(event.kind)),
                (
                    "sender".to_owned(),
                    serde_json::json!(event.actor_id.to_string()),
                ),
                (
                    "payload".to_owned(),
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                ),
                (
                    "created_at".to_owned(),
                    serde_json::json!(arkret_canonical::format_timestamp_canonical(
                        event.created_at
                    )),
                ),
            ]);
            if row.mapping_kind.is_some() {
                if row.mapping_kind.as_deref() != Some(event.kind.as_str())
                    || row.mapping_realm.as_deref() != Some(realm.as_str())
                    || row.mapping_sender.as_deref() != Some(event.actor_id.to_string().as_str())
                    || row.mapping_created_at != Some(event.created_at)
                    || row.mapping_payload
                        != Some(
                            serde_json::to_value(&event.payload)
                                .map_err(PersistenceError::database)?,
                        )
                {
                    return Err(unavailable(
                        "Realm export operation mapping differs from its accepted Event",
                    ));
                }
                let operation_type = row
                    .mapping_operation_type
                    .ok_or_else(|| unavailable("Realm export operation mapping type is missing"))?;
                if operation_type.is_empty() {
                    return Err(unavailable("Realm export operation mapping type is empty"));
                }
                exported.insert(
                    "operation_type".to_owned(),
                    serde_json::json!(operation_type),
                );
                if let Some(operation_id) = row.mapping_operation_id {
                    let id = arkret_wire::OperationId::new(crate::ids::format_typed_uuid(
                        "operation",
                        &uuid::Uuid::parse_str(&operation_id)
                            .map_err(PersistenceError::database)?,
                    ))
                    .map_err(PersistenceError::database)?;
                    exported.insert("operation_id".to_owned(), serde_json::json!(id));
                    operations.push(std::collections::BTreeMap::from([
                        ("operation_id".to_owned(), serde_json::json!(id)),
                        ("realm_id".to_owned(), serde_json::json!(realm)),
                        ("object_kind".to_owned(), serde_json::json!(event.kind)),
                        (
                            "operation_type".to_owned(),
                            serde_json::json!(operation_type),
                        ),
                        (
                            "payload".to_owned(),
                            serde_json::to_value(&event.payload)
                                .map_err(PersistenceError::database)?,
                        ),
                        (
                            "created_at".to_owned(),
                            serde_json::json!(arkret_canonical::format_timestamp_canonical(
                                event.created_at
                            )),
                        ),
                    ]));
                }
            }
        }
        events.push(exported);
        sources.push(view);
    }
    Ok(Some((
        RealmExport {
            schema: RealmExportSchema::V1,
            realm_id: realm.clone(),
            generated_at,
            operations,
            events,
        },
        sources,
    )))
}

async fn export_floor_in_connection(
    conn: &mut AsyncPgConnection,
    stream: &arkret_wire::CommitStreamRef,
    actor: &ActorId,
    governs: bool,
) -> PersistenceResult<Option<u64>> {
    use arkret_wire::CommitStreamRef;
    let realm = stream.realm_id();
    let floor = match stream {
        CommitStreamRef::Realm { .. } if governs => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm, actor).await?
        }
        CommitStreamRef::Realm { .. } => {
            crate::account_stream_scan::replica_realm_floor_in_connection(conn, realm, actor)
                .await?
                .ok()
        }
        CommitStreamRef::Circle { circle_id, .. } if governs => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn, realm, circle_id, actor,
            )
            .await?
        }
        CommitStreamRef::Circle { circle_id, .. } => {
            crate::account_stream_scan::replica_circle_floor_in_connection(
                conn, realm, circle_id, actor,
            )
            .await?
            .ok()
        }
        CommitStreamRef::Sidecar { sidecar_id, .. } if governs => {
            crate::sidecar_authority_cut::caller_floor_in_connection(conn, realm, sidecar_id, actor)
                .await?
        }
        CommitStreamRef::Sidecar { sidecar_id, .. } => {
            crate::sidecar_replica_authority::floor_in_connection(conn, realm, sidecar_id, actor)
                .await?
                .ok()
                .flatten()
        }
        _ => {
            return Err(unavailable(
                "Realm export stream has no registered visibility proof",
            ));
        }
    };
    Ok(floor.map(|floor| floor.oldest_position))
}

struct DeliveryGuard {
    connection: Option<Connection>,
    runtime: tokio::runtime::Handle,
    clock: Option<DeliveryClockProof>,
}

struct DeliveryClockProof {
    checked_at: chrono::DateTime<chrono::Utc>,
    key_expiry: Option<chrono::DateTime<chrono::Utc>>,
    credential_expiry: Option<chrono::DateTime<chrono::Utc>>,
    key_scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    provision_scope: arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    session_scope: Option<(Vec<String>, serde_json::Map<String, serde_json::Value>)>,
    scope_operations: Vec<(
        ActorId,
        arkret_wire::WireResourceSelector,
        coland_storage::OperationFacts,
        CapabilityActionId,
    )>,
    accountability:
        Vec<Vec<arkret_models_collaboration::governance::accountability::AccountabilityProjection>>,
    policies: Vec<arkret_models_collaboration::governance::operation_wire::Policy>,
    positive_actions: Vec<(
        crate::realm_authorization_cut::RealmAuthorizationCut,
        arkret_wire::WireResourceSelector,
        Vec<&'static str>,
    )>,
    native_projection_reads: Vec<crate::morph_projection_reads::NativeTimeProof>,
    native_reply: Option<NativeReplyTimeProof>,
    reads: Vec<ContentReadTimeProof>,
}

type ContentReadTimeProof = (
    crate::realm_authorization_cut::RealmAuthorizationCut,
    Option<arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef>,
    Vec<arkret_wire::Event>,
    Vec<(arkret_wire::Event, CapabilityActionId)>,
);

struct NativeReplyTimeProof {
    checked_at: chrono::DateTime<chrono::Utc>,
    agent: AccountId,
    controller: AccountId,
    agent_cut: crate::realm_authorization_cut::RealmAuthorizationCut,
    controller_cut: crate::realm_authorization_cut::RealmAuthorizationCut,
    source: arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef,
    target: arkret_wire::WireResourceSelector,
    facts: coland_storage::OperationFacts,
    policies: Vec<arkret_models_collaboration::governance::operation_wire::Policy>,
    input_resources: Vec<(
        Vec<arkret_models_collaboration::governance::operation_wire::PolicyResourceSelector>,
        CapabilityActionId,
    )>,
    body_events: Vec<arkret_wire::Event>,
}
impl NativeReplyTimeProof {
    fn permits_at(&self, at: chrono::DateTime<chrono::Utc>) -> bool {
        if at < self.checked_at
            || !self.agent_cut.time_sources_unchanged(self.checked_at, at)
            || !self
                .controller_cut
                .time_sources_unchanged(self.checked_at, at)
            || self
                .agent_cut
                .require_unreserved_native_message_reply(
                    &self.controller_cut,
                    &self.target,
                    &self.facts,
                    &self.source,
                    at,
                )
                .is_err()
            || crate::agent_management_admission::require_native_message_reply_policy(
                &self.policies,
                self.target.realm_id.as_ref().expect("confirmed Realm"),
                &self.controller,
                &self.agent,
                &self.target,
                at,
            )
            .is_err()
        {
            return false;
        }
        // Reevaluate Read and Deliver policy recurrence at physical provider
        // handoff too; a unchanged policy row is not a timeless permission.
        if self.body_events.iter().any(|event| {
            self.agent_cut
                .require_unreserved_native_message_body(
                    &self.controller_cut,
                    event,
                    &self.source,
                    at,
                )
                .is_err()
        }) {
            return false;
        }
        for (resources, action) in &self.input_resources {
            for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
                if arkret_policy::agent_management::evaluate_agent_management(
                    Some(&self.policies),
                    &arkret_policy::agent_management::AgentManagementContext {
                        realm_id: self.target.realm_id.as_ref().expect("confirmed Realm"),
                        ownership: Some((&self.controller, &self.agent)),
                        operation,
                        content_action: Some(*action),
                        resources: Some(resources),
                        at,
                    },
                )
                .ok()
                    != Some(arkret_wire::PolicyEffect::Allow)
                {
                    return false;
                }
            }
        }
        true
    }
}

struct NativeReplyContext<'a> {
    controller: &'a AccountId,
    caller: &'a AccountId,
    source: &'a arkret_wire::CommittedEventFullView,
    strand: &'a arkret_wire::StrandId,
    deployment: arkret_models_collaboration::governance::agent_participation::ParticipationBits,
}

impl DeliveryClockProof {
    fn permits_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self
            .native_reply
            .as_ref()
            .is_some_and(|proof| !proof.permits_at(now))
            || now < self.checked_at
            || self.key_expiry.is_some_and(|expiry| now >= expiry)
            || self.credential_expiry.is_some_and(|expiry| now >= expiry)
        {
            tracing::warn!(
                diagnostic = "native_reply_or_expiry",
                "owned content handoff clock refused"
            );
            return false;
        }
        if self
            .accountability
            .iter()
            .any(|values| !values.iter().any(|value| value.verifies_at(now)))
        {
            tracing::warn!(
                diagnostic = "accountability",
                "owned content handoff clock refused"
            );
            return false;
        }
        if !self
            .scope_operations
            .iter()
            .all(|(actor, target, facts, action)| {
                let operation = coland_storage::AuthorizationOperation {
                    actor,
                    target,
                    facts,
                    at: now,
                    actions: &[action.as_str()],
                };
                [&self.provision_scope, &self.key_scope]
                    .iter()
                    .enumerate()
                    .all(|(ceiling, scope)| {
                        let allowed = crate::agent_management_admission::require_key_scope_content_ceiling(
                            scope, &operation,
                        )
                        .is_ok();
                        if !allowed {
                            tracing::warn!(ceiling, action = action.as_str(), target_kind = ?target.kind,
                                "owned content handoff ceiling is unavailable");
                        }
                        allowed
                    })
                    && self
                        .session_scope
                        .as_ref()
                        .is_none_or(|(actions, details)| {
                            let allowed = crate::agent_management_admission::require_session_content_ceiling(
                                actions, details, &operation,
                            )
                            .is_ok();
                            if !allowed {
                                tracing::warn!(diagnostic = "session_scope", action = action.as_str(), target_kind = ?target.kind,
                                    "owned content handoff clock refused");
                            }
                            allowed
                        })
            })
        {
            return false;
        }
        let active = |policy: &arkret_models_collaboration::governance::operation_wire::Policy,
                      at| {
            policy.not_before.is_none_or(|start| at >= start)
                && policy.expires_at.is_none_or(|end| at < end)
        };
        let policies = self
            .policies
            .iter()
            .all(|policy| active(policy, self.checked_at) == active(policy, now));
        if !policies {
            tracing::warn!(
                diagnostic = "policy_time",
                "owned content handoff clock refused"
            );
            return false;
        }
        if !self.positive_actions.iter().all(|(cut, target, actions)| {
            cut.permits_unreserved_current_actions(actions, target, now)
        }) {
            tracing::warn!(
                diagnostic = "positive_actions",
                "owned content handoff clock refused"
            );
            return false;
        }
        if !self
            .native_projection_reads
            .iter()
            .all(|(cut, source, fact)| {
                cut.time_sources_unchanged(self.checked_at, now)
                    && cut
                        .require_native_projection_read(
                            &fact.target,
                            &fact.facts,
                            fact.action,
                            source.clone(),
                            now,
                        )
                        .is_ok()
            })
        {
            tracing::warn!(
                diagnostic = "native_projection_read",
                "owned content handoff clock refused"
            );
            return false;
        }
        self.reads.iter().all(|(cut, source, events, objects)| {
            if !cut.time_sources_unchanged(self.checked_at, now) {
                tracing::warn!(
                    diagnostic = "read_time_sources",
                    "owned content handoff clock refused"
                );
                return false;
            }
            if !events.iter().all(|event| {
                cut.require_membership_read_constraints(event, now, source.clone())
                    .is_ok()
            }) {
                tracing::warn!(
                    diagnostic = "membership_read",
                    "owned content handoff clock refused"
                );
                return false;
            }
            let allowed = objects.iter().all(|(event, action)| {
                cut.require_content_read_constraints(event, now, source.clone(), *action)
                    .is_ok()
            });
            if !allowed {
                tracing::warn!(
                    diagnostic = "object_read",
                    "owned content handoff clock refused"
                );
            }
            allowed
        })
    }
}
impl DeliveryGuard {
    fn connection(&mut self) -> &mut AsyncPgConnection {
        self.connection.as_mut().expect("content cut is held")
    }
}
#[async_trait::async_trait]
impl AccountContentDeliveryGuard for DeliveryGuard {
    fn permits_handoff(&self) -> bool {
        self.clock
            .as_ref()
            .is_some_and(|proof| proof.permits_at(chrono::Utc::now()))
    }
    async fn finish(mut self: Box<Self>) -> PersistenceResult<()> {
        sql_query("ROLLBACK")
            .execute(self.connection())
            .await
            .map_err(PersistenceError::database)?;
        drop(self.connection.take());
        Ok(())
    }
}
impl Drop for DeliveryGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            let connection = Connection::take(connection);
            let cancel = connection.cancel_token();
            drop(connection);
            self.runtime.spawn(async move {
                let _ = cancel.cancel_query(tokio_postgres::NoTls).await;
            });
        }
    }
}
fn unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("revision_unavailable: {detail}"))
}
#[derive(QueryableByName)]
struct Governor {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct SourceEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
}

pub(crate) async fn provision_scope_in_connection(
    conn: &mut AsyncPgConnection,
    endpoint: &coland_storage::AgentEndpointGuard,
    evidence: &coland_storage::VerifiedAgentScopeEvidence,
    station: &DidCoreId,
) -> PersistenceResult<arkret_models_collaboration::events_payloads::agent::AgentKeyScope> {
    let (realm, payload, reference) =
        crate::agent_provisioning::declared_agent_provision_in_connection(
            conn,
            &endpoint.pcr_realm_id,
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?
        .ok_or_else(|| unavailable("delivery provision source is unavailable"))?;
    if payload.agent_id != endpoint.agent_id {
        return Err(unavailable("delivery provision belongs to another Agent"));
    }
    let full =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &reference.event_id)
            .await?
            .ok_or_else(|| unavailable("delivery provision has no accepted canonical source"))?;
    payload
        .validate_envelope(&full.event)
        .map_err(PersistenceError::database)?;
    let value = sql_query("SELECT value FROM agent_provisioning_current_results WHERE realm_id=$1 AND agent_id=$2 AND current_commit_id=$3 AND current_stream_position=$4 FOR SHARE")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(endpoint.agent_id.as_str())
        .bind::<Text,_>(reference.commit_id.as_str())
        .bind::<diesel::sql_types::BigInt,_>(i64::try_from(reference.stream_position).map_err(PersistenceError::database)?)
        .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("delivery provision is not the current accepted revision"))?;
    if serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentProvisioningValue,
    >(value.value)
    .map_err(PersistenceError::database)?
        != payload.provisioning_value()
    {
        return Err(unavailable(
            "delivery provision current differs from its accepted source",
        ));
    }
    let binding = evidence.accepted_binding();
    let command = evidence.command();
    let disclosure = &command.requested_scope_disclosure;
    if reference != binding.provision_ref
        || !matches_source(&full, &binding.provision_ref)
        || full.event.actual_signer().as_account_id() != Some(&binding.controller_account)
        || binding.controller_account.principal_id != payload.controller_principal_id
        || disclosure.agent_id != endpoint.agent_id
        || disclosure.controller_principal_id != payload.controller_principal_id
        || disclosure.verifier_id != *station
        || disclosure.audience.as_str()
            != arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1
        || binding.requested_scope_digest != payload.requested_scope_digest
        || binding.verified_at < disclosure.issued_at
        || binding.verified_at > disclosure.expires_at
        || binding.initial_resolution.did != binding.binding_resolution.did
        || arkret_wire::project_did_to_core_id(&binding.initial_resolution.did)
            .map_err(PersistenceError::database)?
            != endpoint.agent_id
    {
        return Err(unavailable(
            "delivery private scope qualification differs from its accepted binding",
        ));
    }
    // The presentation window was checked by its fact owner when received.
    // Loading integrity-protected custody is not a new presentation and does
    // not expire a non-expiring key when that original window has elapsed.
    let genesis = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &binding.pcr_genesis_ref.event_id,
    )
    .await?
    .ok_or_else(|| unavailable("qualified Agent genesis source is unavailable"))?;
    let genesis_payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&genesis.event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    if !matches_source(&genesis, &binding.pcr_genesis_ref)
        || genesis.event.realm_id != endpoint.pcr_realm_id
        || arkret_wire::RealmId::from_event_id(&genesis.event.event_id) != endpoint.pcr_realm_id
        || genesis
            .event
            .actor_id
            .as_account_id()
            .is_none_or(|account| account.principal_id != endpoint.agent_id)
        || genesis
            .event
            .executed_by
            .as_ref()
            .and_then(ActorId::as_account_id)
            != Some(&binding.controller_account)
        || genesis
            .event
            .authorization_ref
            .as_ref()
            .map(|reference| reference.as_str())
            != Some(payload.controller_authorization_ref.as_str())
        || genesis_payload.object.initial_resolution.as_ref() != Some(&binding.initial_resolution)
        || genesis.commit.committed_at > binding.verified_at
    {
        return Err(unavailable(
            "qualified Agent genesis differs from its exact accepted source",
        ));
    }
    let accepted_authorization = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &evidence.accepted_authorization_ref().event_id,
    )
    .await?
    .ok_or_else(|| unavailable("qualified pairing authorization is unavailable"))?;
    if !matches_source(
        &accepted_authorization,
        evidence.accepted_authorization_ref(),
    ) || accepted_authorization.event != command.authorize_event.event
        || accepted_authorization.event.realm_id != endpoint.pcr_realm_id
        || accepted_authorization
            .event
            .executed_by
            .as_ref()
            .and_then(ActorId::as_account_id)
            != Some(&binding.controller_account)
    {
        return Err(unavailable(
            "private scope custody belongs to a different accepted command",
        ));
    }
    let receipt = crate::agents::pairing_scope_receipt_in_connection(
        conn,
        evidence.accepted_authorization_ref().event_id.as_str(),
    )
    .await?
    .ok_or_else(|| unavailable("qualified pairing receipt is unavailable"))?;
    if receipt.outcome.activation_state
        != arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active
        || receipt.agent_id != endpoint.agent_id.as_str()
        || receipt.controller_principal_id != payload.controller_principal_id.as_str()
        || receipt.authorize_event_ref != evidence.accepted_authorization_ref().event_id.as_str()
        || receipt.request_digest != evidence.request_digest()
        || receipt.scope_custody_ref.as_ref() != Some(evidence.custody_ref())
        || receipt.pairing_request_id != command.pairing_request_id
        || receipt.approval_request_id != command.approval_request_id
        || receipt.runtime_key_binding_digest != evidence.runtime_key_binding_digest()
    {
        return Err(unavailable(
            "private scope custody differs from its durable active receipt",
        ));
    }
    let paired_key =
        arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload::try_from(
            &accepted_authorization.event,
        )
        .map_err(PersistenceError::database)?;
    let runtime_binding =
        arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
            &paired_key.agent_id,
            &command.pairing_request_id,
            &paired_key.verification_method,
            &paired_key.public_key,
            paired_key.runtime_attestation.as_ref(),
        )
        .map_err(PersistenceError::database)?;
    if paired_key.agent_id != endpoint.agent_id
        || paired_key.accountable_principal_id != payload.controller_principal_id
        || runtime_binding.as_str() != evidence.runtime_key_binding_digest()
        || disclosure.challenge.as_str() != command.pairing_request_id.as_str()
        || command
            .pairing_request_id
            .as_str()
            .strip_prefix("agent_pairing_request:")
            .is_none_or(|id| disclosure.request_id.as_str() != format!("ak:request:{id}"))
    {
        return Err(unavailable(
            "qualified scope command or runtime binding differs",
        ));
    }
    let scope = disclosure.requested_scope.clone();
    if arkret_models_collaboration::agent_scope::agent_requested_scope_digest(
        &endpoint.agent_id,
        &payload.controller_principal_id,
        &scope,
    )
    .map_err(PersistenceError::database)?
        != payload.requested_scope_digest
    {
        return Err(unavailable(
            "private disclosed scope differs from the immutable DID commitment",
        ));
    }
    Ok(scope)
}

fn matches_source(
    full: &arkret_wire::CommittedEventFullView,
    reference: &arkret_wire::CommittedEventRef,
) -> bool {
    full.event.event_id == reference.event_id
        && full.commit.event_ref == reference.event_id
        && full.commit.commit_id == reference.commit_id
        && full.commit.stream_ref == reference.stream_ref
        && full.commit.stream_position == reference.stream_position
}

pub(crate) async fn current_source_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    stream: &arkret_wire::CommitStreamRef,
    revision: &arkret_wire::CurrentRevision,
) -> PersistenceResult<arkret_wire::Event> {
    if stream.realm_id() != realm {
        return Err(unavailable(
            "current source stream belongs to another Realm",
        ));
    }
    let row = sql_query("SELECT commit_json->>'event_ref' AS event_id FROM realm_commits WHERE realm_id=$1 AND commit_id=$2 AND stream_position=$3 AND stream_ref=$4")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(revision.commit_id.as_str())
        .bind::<diesel::sql_types::BigInt,_>(i64::try_from(revision.stream_position).map_err(PersistenceError::database)?)
        .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(stream).map_err(PersistenceError::database)?)
        .get_result::<SourceEventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("current has no exact accepted covering Commit"))?;
    let id = arkret_wire::EventId::new(row.event_id).map_err(PersistenceError::database)?;
    let full = crate::committed_disclosure::accepted_full_event_in_connection(conn, &id)
        .await?
        .ok_or_else(|| unavailable("current has no accepted canonical source"))?;
    if full.commit.commit_id != revision.commit_id
        || full.commit.stream_position != revision.stream_position
        || full.commit.stream_ref != *stream
    {
        return Err(unavailable(
            "current source differs from its covering Commit",
        ));
    }
    Ok(full.event)
}

pub(crate) async fn require_owned_current_source_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    owner: &AccountId,
    account: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    require_owned_content_source_in_connection(
        conn,
        event,
        owner,
        account,
        at,
        CapabilityActionId::ObjectRead,
    )
    .await
}

async fn require_owned_content_source_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    owner: &AccountId,
    account: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    action: CapabilityActionId,
) -> PersistenceResult<()> {
    let resources = crate::agent_management_admission::event_content_resources(event)?;
    let circle = match &event.scope_ref {
        arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    };
    for recipient in [account, owner] {
        let actor = ActorId::account(recipient.clone());
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &event.realm_id,
            &actor,
        )
        .await?;
        let source = crate::realm_authorization_cut::owned_source_in_connection(
            conn,
            &event.realm_id,
            &actor,
            at,
            false,
        )
        .await?;
        cut.require_content_read_constraints(event, at, source, action)?;
    }
    for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
        crate::agent_management_admission::require_content_snapshot_in_connection(
            conn,
            &event.realm_id,
            circle,
            owner,
            account,
            operation,
            action,
            &resources,
            at,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn acquire(
    pool: &crate::PgPool,
    account: &AccountId,
    station: &DidCoreId,
    input: &coland_storage::AccountContentDeliveryInput,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    // Bound the nested admission future without changing the caller stack budget.
    Box::pin(acquire_with_native_reply(
        pool, account, station, input, None,
    ))
    .await
}

pub(crate) async fn acquire_native_message_reply_preparation(
    pool: &crate::PgPool,
    request: coland_storage::NativeMessageReplyPreparation<'_>,
) -> PersistenceResult<Box<dyn AccountContentDeliveryGuard>> {
    let coland_storage::NativeMessageReplyPreparation {
        agent,
        controller,
        caller,
        station,
        source,
        strand,
        input,
        deployment,
    } = request;
    source
        .validate_shape()
        .map_err(PersistenceError::database)?;
    let payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
        serde_json::from_value(serde_json::json!(source.event.payload))
            .map_err(PersistenceError::database)?;
    if source.event.kind != arkret_wire::EventKind::MessageCreate
        || source.event.actor_id.as_account_id() != Some(caller)
        || caller == agent
        || caller == controller
        || payload.strand_id != *strand
        || payload.track_name != "discussion"
        || source.event.realm_id != source.commit.realm_id
        || !matches!(
            source.event.scope_ref,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        )
        || input.credential_expires_at.is_none()
        || input.agent_session_scope.is_none()
        || input.agent_endpoint.is_none()
        || input.qualified_agent_scope_evidence.is_none()
        || !input.current_views.is_empty()
        || !input.projection_lists.is_empty()
        || !input.morph_lists.is_empty()
        || !input.morph_documents.is_empty()
        || !input.morph_absences.is_empty()
        || !input.realm_exports.is_empty()
        || !input.snapshots.is_empty()
        || !input.future_materials.is_empty()
        || !input.notifications.is_empty()
        || !input.exact_reads.is_empty()
        || !input.watch_reads.is_empty()
        || !input.blobs.is_empty()
        || !input.unresolved_content_realms.is_empty()
        || !input
            .committed_events
            .iter()
            .any(|row| row == &CommittedEventView::Full(source.clone()))
        || input
            .realms
            .iter()
            .any(|realm| realm != &source.event.realm_id)
        || input.committed_events.iter().any(|row| match row {
            CommittedEventView::Full(full) => {
                let payload = serde_json::from_value::<
                    arkret_models_collaboration::events_payloads::message::MessageCreatePayload,
                >(serde_json::json!(full.event.payload));
                full.event.kind != arkret_wire::EventKind::MessageCreate
                    || full.event.realm_id != source.event.realm_id
                    || full.event.scope_ref != source.event.scope_ref
                    || payload.as_ref().map_or(true, |payload| {
                        payload.strand_id != *strand || payload.track_name != "discussion"
                    })
            }
            CommittedEventView::Withheld(_) => true,
        })
    {
        return Err(unavailable(
            "native reply has no exact accepted third-party source or trusted credential",
        ));
    }
    Box::pin(acquire_with_native_reply(
        pool,
        agent,
        station,
        input,
        Some(NativeReplyContext {
            controller,
            caller,
            source,
            strand,
            deployment,
        }),
    ))
    .await?
    .ok_or_else(|| unavailable("native reply has no current owned governing cut"))
}

// Revalidate original queued Events on the same locked transaction cut.
async fn revalidate_committed_events_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    actor: ActorId,
    realms: &std::collections::BTreeSet<arkret_wire::RealmId>,
    input: &coland_storage::AccountContentDeliveryInput,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    for row in &input.committed_events {
        let realm = row.commit().stream_ref.realm_id();
        if !realms.contains(realm) {
            continue;
        }
        let controller = Box::pin(
            crate::realm_authorization_cut::owned_controller_in_connection(
                &mut *conn, realm, &actor, at,
            ),
        )
        .await?
        .ok_or_else(|| unavailable("current controller is unavailable"))?;
        let controller_account = controller
            .as_account_id()
            .ok_or_else(|| unavailable("controller is not an Account"))?;
        let accepted = Box::pin(
            crate::committed_disclosure::accepted_full_event_in_connection(
                &mut *conn,
                &row.commit().event_ref,
            ),
        )
        .await?
        .ok_or_else(|| unavailable("delivery has no accepted canonical pair"))?;
        if accepted.commit != *row.commit() {
            return Err(unavailable("queued Commit differs from accepted content"));
        }
        for recipient in [&actor, &controller] {
            let floor = match &row.commit().stream_ref {
                arkret_wire::CommitStreamRef::Realm { .. } => {
                    Box::pin(
                        crate::account_stream_scan::caller_realm_floor_in_connection(
                            &mut *conn, realm, recipient,
                        ),
                    )
                    .await?
                }
                arkret_wire::CommitStreamRef::Circle { circle_id, .. } => {
                    Box::pin(
                        crate::account_stream_scan::caller_circle_floor_in_connection(
                            &mut *conn, realm, circle_id, recipient,
                        ),
                    )
                    .await?
                }
                arkret_wire::CommitStreamRef::Sidecar { sidecar_id, .. } => {
                    if !Box::pin(crate::sidecar_access::participant_in_connection(
                        &mut *conn, realm, sidecar_id, recipient,
                    ))
                    .await?
                    {
                        return Err(unavailable("current Sidecar delivery recipient changed"));
                    }
                    // The complete current snapshot also proves the private
                    // Sidecar's exact readable floor on this governing cut.
                    let recipient = recipient
                        .as_account_id()
                        .ok_or_else(|| unavailable("delivery recipient is not an Account"))?;
                    let material = Box::pin(
                        crate::snapshot_disclosure_gate::account_snapshot_material_in_connection(
                            &mut *conn, realm, recipient,
                        ),
                    )
                    .await?
                    .ok_or_else(|| unavailable("Sidecar delivery floor is unavailable"))?;
                    let floor = material
                        .retention_and_history_floor
                        .stream_floors
                        .into_iter()
                        .find(|floor| floor.stream_ref == row.commit().stream_ref)
                        .ok_or_else(|| unavailable("Sidecar delivery floor is unavailable"))?;
                    if row.commit().stream_position < floor.oldest_position {
                        return Err(unavailable("Sidecar queued position is no longer readable"));
                    }
                    None
                }
                _ => {
                    return Err(unavailable(
                        "delivery stream has no registered current proof",
                    ));
                }
            };
            if !matches!(
                row.commit().stream_ref,
                arkret_wire::CommitStreamRef::Sidecar { .. }
            ) && floor
                .as_ref()
                .is_none_or(|floor| row.commit().stream_position < floor.oldest_position)
            {
                return Err(unavailable(
                    "queued position is no longer readable by the recipient",
                ));
            }
        }
        match row {
            CommittedEventView::Full(full) => {
                if full != &accepted
                    || !Box::pin(
                        crate::committed_disclosure::withheld_commit_ids_in_connection(
                            &mut *conn,
                            &[full.commit.commit_id.to_string()],
                        ),
                    )
                    .await?
                    .is_empty()
                {
                    return Err(unavailable(
                        "queued full content is no longer the accepted disclosure",
                    ));
                }
                if !Box::pin(
                    crate::committed_disclosure::full_event_for_member_in_connection(
                        &mut *conn, full, &actor, at,
                    ),
                )
                .await?
                {
                    return Err(PersistenceError::Conflict(
                        "capability_denied: current content is withheld".into(),
                    ));
                }
                let resources =
                    crate::agent_management_admission::event_content_resources(&full.event)?;
                let circle = match &full.event.scope_ref {
                    arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
                    _ => None,
                };
                Box::pin(
                    crate::agent_management_admission::require_content_snapshot_in_connection(
                        &mut *conn,
                        realm,
                        circle,
                        controller_account,
                        account,
                        AgentPolicyOperation::Deliver,
                        CapabilityActionId::EventRead,
                        &resources,
                        at,
                    ),
                )
                .await?;
            }
            CommittedEventView::Withheld(_) => {
                let resources =
                    crate::agent_management_admission::event_content_resources(&accepted.event)?;
                let circle = match &accepted.event.scope_ref {
                    arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
                    _ => None,
                };
                for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
                    Box::pin(
                        crate::agent_management_admission::require_content_snapshot_in_connection(
                            &mut *conn,
                            realm,
                            circle,
                            controller_account,
                            account,
                            operation,
                            CapabilityActionId::EventRead,
                            &resources,
                            at,
                        ),
                    )
                    .await?;
                }
            }
        }
    }
    Ok(())
}

// Build the physical native reply time proof under the original held cut.
async fn native_reply_time_proof_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    station: &DidCoreId,
    input: &coland_storage::AccountContentDeliveryInput,
    actor: ActorId,
    realms: &std::collections::BTreeSet<arkret_wire::RealmId>,
    native_human_pcrs: &std::collections::BTreeMap<AccountId, arkret_wire::RealmId>,
    reply: NativeReplyContext<'_>,
) -> PersistenceResult<NativeReplyTimeProof> {
    let realm = &reply.source.event.realm_id;
    if realms.len() != 1
        || !realms.contains(realm)
        || input
            .qualified_agent_scope_evidence
            .as_ref()
            .map(|e| &e.accepted_binding().controller_account)
            != Some(reply.controller)
    {
        return Err(unavailable(
            "native reply controller or governing Realm differs",
        ));
    }
    // Authentication refresh happens before acquire. These original native
    // observations bind exact AA heads under the held current cut, never a
    // fabricated active default or a product account projection.
    for (human, pcr) in native_human_pcrs {
        let observation = input
            .account_status_observations
            .iter()
            .find(|observation| observation.record().account_id == *human);
        Box::pin(
            crate::morph_projection_reads::require_accepted_human_identity(
                &mut *conn,
                human,
                pcr,
                station,
                observation,
            ),
        )
        .await?;
    }
    let source = Box::pin(crate::realm_authorization_cut::owned_source_in_connection(
        &mut *conn,
        realm,
        &actor,
        chrono::Utc::now(),
        true,
    ))
    .await?
    .ok_or_else(|| unavailable("native reply has no accepted owned source"))?;
    let owner_actor = ActorId::account(reply.controller.clone());
    let agent_cut = Box::pin(crate::realm_authorization_cut::RealmAuthorizationCut::read(
        &mut *conn, realm, &actor,
    ))
    .await?;
    let controller_cut = Box::pin(crate::realm_authorization_cut::RealmAuthorizationCut::read(
        &mut *conn,
        realm,
        &owner_actor,
    ))
    .await?;
    let (target, facts) = Box::pin(agent_cut.native_message_reply_target_in_connection(
        &mut *conn,
        &reply.source.event.scope_ref,
        reply.strand,
        &controller_cut,
        &ActorId::account(reply.caller.clone()),
    ))
    .await?;
    Box::pin(
        crate::agent_interaction_current_results::require_current_public_in_connection(
            &mut *conn,
            realm,
            reply.controller,
            account,
        ),
    )
    .await?;
    Box::pin(
        crate::agent_participation_admission::require_native_reply_current(
            &mut *conn,
            account,
            &reply.source.event.scope_ref,
            reply.strand,
            station,
            reply.deployment,
        ),
    )
    .await?;
    let policies = Box::pin(
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            &mut *conn,
            realm,
            target
                .circle_id
                .as_ref()
                .or(match &reply.source.event.scope_ref {
                    arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
                    _ => None,
                }),
        ),
    )
    .await?;
    let mut input_resources = Vec::new();
    let mut body_events = Vec::new();
    for row in &input.committed_events {
        let CommittedEventView::Full(full) = row else {
            return Err(unavailable(
                "native reply model input cannot use withheld bytes",
            ));
        };
        agent_cut.require_unreserved_native_message_body(
            &controller_cut,
            &full.event,
            &source,
            chrono::Utc::now(),
        )?;
        let resources = crate::agent_management_admission::event_content_resources(&full.event)?;
        for action in [
            CapabilityActionId::EventRead,
            CapabilityActionId::ObjectReadContent,
        ] {
            input_resources.push((resources.clone(), action));
        }
        body_events.push(full.event.clone());
    }
    let proof = NativeReplyTimeProof {
        checked_at: chrono::Utc::now(),
        agent: account.clone(),
        controller: reply.controller.clone(),
        agent_cut,
        controller_cut,
        source,
        target: target.clone(),
        facts: facts.clone(),
        policies,
        input_resources,
        body_events,
    };
    Ok(proof)
}

#[derive(Default)]
struct QueuedContentFacts {
    object_sources: std::collections::BTreeMap<
        arkret_wire::RealmId,
        Vec<(arkret_wire::Event, CapabilityActionId)>,
    >,
    native_projection_reads: Vec<crate::morph_projection_reads::NativeTimeProof>,
    positive_actions: Vec<(
        crate::realm_authorization_cut::RealmAuthorizationCut,
        arkret_wire::WireResourceSelector,
        Vec<&'static str>,
    )>,
    blob_scope_operations: Vec<(
        ActorId,
        arkret_wire::WireResourceSelector,
        coland_storage::OperationFacts,
        CapabilityActionId,
    )>,
    blob_source_actions: std::collections::BTreeSet<(arkret_wire::EventId, &'static str)>,
}

// Preserve queued material checks on the caller's existing transaction cut.
async fn revalidate_projection_inputs_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    station: &DidCoreId,
    actor: ActorId,
    realms: &std::collections::BTreeSet<arkret_wire::RealmId>,
    input: &mut coland_storage::AccountContentDeliveryInput,
    facts: &mut QueuedContentFacts,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let QueuedContentFacts {
        object_sources,
        native_projection_reads,
        positive_actions,
        blob_scope_operations: _,
        blob_source_actions: _,
    } = facts;
    for export in input.realm_exports.clone() {
        if !realms.contains(&export.realm_id) {
            continue;
        }
        let (fresh, sources) = Box::pin(realm_export_in_connection(
            &mut *conn,
            &export.realm_id,
            &actor,
            station,
            export.generated_at,
        ))
        .await?
        .ok_or_else(|| unavailable("queued Realm export has no current caller cut"))?;
        if arkret_canonical::canonical_json_bytes(&export).map_err(PersistenceError::database)?
            != arkret_canonical::canonical_json_bytes(&fresh).map_err(PersistenceError::database)?
        {
            return Err(unavailable(
                "queued Realm export differs from the complete accepted cut",
            ));
        }
        // Reconstructed originals, including withheld slots, enter the same
        // per-source Read/Deliver and transport ceilings as ordinary content.
        for source in sources {
            if !input.committed_events.contains(&source) {
                input.committed_events.push(source);
            }
        }
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn,
            &export.realm_id,
            &actor,
            at,
        )
        .await?
        .ok_or_else(|| unavailable("export controller is unavailable"))?;
        let owner = controller
            .as_account_id()
            .ok_or_else(|| unavailable("export controller is not an Account"))?;
        let resources = [arkret_models_collaboration::governance::operation_wire::PolicyResourceSelector {
            kind: arkret_models_collaboration::governance::operation_wire::PolicyResourceKind::Realm,
            realm_id: Some(export.realm_id.clone()), resource_ref: Some(export.realm_id.to_string()),
        }];
        for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
            Box::pin(
                crate::agent_management_admission::require_content_snapshot_in_connection(
                    &mut *conn,
                    &export.realm_id,
                    None,
                    owner,
                    account,
                    operation,
                    CapabilityActionId::EventRead,
                    &resources,
                    at,
                ),
            )
            .await?;
        }
    }
    for (realm, include_terminal, spaces, strands) in &input.projection_lists {
        if !realms.contains(realm) {
            continue;
        }
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn, realm, &actor, at,
        )
        .await?
        .ok_or_else(|| unavailable("projection controller is unavailable"))?;
        let owner = controller
            .as_account_id()
            .ok_or_else(|| unavailable("projection controller is not an Account"))?;
        if !crate::object_projection_reads::projection_lists_match_in_connection(
            &mut *conn,
            realm,
            &actor,
            *include_terminal,
            spaces,
            strands,
            owner,
        )
        .await?
        {
            return Err(unavailable(
                "queued projection list differs from the current complete cut",
            ));
        }
    }
    for (realm, include_terminal, output) in &input.morph_lists {
        if !realms.contains(realm) {
            continue;
        }
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn, realm, &actor, at,
        )
        .await?
        .ok_or_else(|| unavailable("Morph controller is unavailable"))?;
        let owner = controller
            .as_account_id()
            .ok_or_else(|| unavailable("Morph controller is not an Account"))?;
        let (fresh, facts) = Box::pin(crate::morph_projection_reads::list_in_connection(
            &mut *conn,
            realm,
            &actor,
            station,
            *include_terminal,
            at,
        ))
        .await?
        .ok_or_else(|| unavailable("Morph list has no current actor cut"))?;
        if arkret_canonical::canonical_json_bytes(&fresh).map_err(PersistenceError::database)?
            != arkret_canonical::canonical_json_bytes(output).map_err(PersistenceError::database)?
        {
            return Err(unavailable(
                "Morph list changed before publication, including empty output",
            ));
        }
        let (owner_output, _) = Box::pin(crate::morph_projection_reads::list_in_connection(
            &mut *conn,
            realm,
            &controller,
            station,
            *include_terminal,
            at,
        ))
        .await?
        .ok_or_else(|| unavailable("Morph list has no current controller cut"))?;
        for row in &output.morphs {
            let Some(owner_row) = owner_output
                .morphs
                .iter()
                .find(|candidate| candidate.morph_id == row.morph_id)
            else {
                return Err(unavailable("controller cannot see a returned Morph row"));
            };
            if arkret_canonical::canonical_json_bytes(row).map_err(PersistenceError::database)?
                != arkret_canonical::canonical_json_bytes(owner_row)
                    .map_err(PersistenceError::database)?
            {
                return Err(unavailable(
                    "controller's Morph row differs from the exact returned content",
                ));
            }
        }
        native_projection_reads.extend(
            Box::pin(crate::morph_projection_reads::qualify_delivery_facts(
                &mut *conn, account, owner, facts, at,
            ))
            .await?,
        );
    }
    for (realm, morph, output) in &input.morph_documents {
        if !realms.contains(realm) {
            continue;
        }
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn, realm, &actor, at,
        )
        .await?
        .ok_or_else(|| unavailable("document controller is unavailable"))?;
        let owner = controller
            .as_account_id()
            .ok_or_else(|| unavailable("document controller is not an Account"))?;
        let (fresh, facts) = Box::pin(crate::morph_projection_reads::document_in_connection(
            &mut *conn, realm, morph, &actor, station, at,
        ))
        .await?
        .ok_or_else(|| unavailable("document has no current actor cut"))?;
        if arkret_canonical::canonical_json_bytes(&fresh).map_err(PersistenceError::database)?
            != arkret_canonical::canonical_json_bytes(output).map_err(PersistenceError::database)?
        {
            return Err(unavailable(
                "complete document output changed before publication",
            ));
        }
        let (owner_output, _) = Box::pin(crate::morph_projection_reads::document_in_connection(
            &mut *conn,
            realm,
            morph,
            &controller,
            station,
            at,
        ))
        .await?
        .ok_or_else(|| unavailable("document has no current controller cut"))?;
        if !crate::morph_projection_reads::owner_covers_document(output, &owner_output)? {
            return Err(unavailable(
                "controller cannot see every returned document component",
            ));
        }
        native_projection_reads.extend(
            Box::pin(crate::morph_projection_reads::qualify_delivery_facts(
                &mut *conn, account, owner, facts, at,
            ))
            .await?,
        );
    }
    for (realm, morph) in &input.morph_absences {
        if !realms.contains(realm) {
            continue;
        }
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn, realm, &actor, at,
        )
        .await?
        .ok_or_else(|| unavailable("document absence controller is unavailable"))?;
        let owner = controller
            .as_account_id()
            .ok_or_else(|| unavailable("document absence controller is not an Account"))?;
        let facts = Box::pin(
            crate::morph_projection_reads::document_absence_in_connection(
                &mut *conn, realm, morph, &actor, station, at,
            ),
        )
        .await?;
        Box::pin(
            crate::morph_projection_reads::document_absence_in_connection(
                &mut *conn,
                realm,
                morph,
                &controller,
                station,
                at,
            ),
        )
        .await?;
        native_projection_reads.extend(
            Box::pin(crate::morph_projection_reads::qualify_delivery_facts(
                &mut *conn, account, owner, facts, at,
            ))
            .await?,
        );
    }
    for (request, outcome) in &input.exact_reads {
        if !realms.contains(&request.realm_id) {
            continue;
        }
        let owner = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn,
            &request.realm_id,
            &actor,
            at,
        )
        .await?
        .ok_or_else(|| unavailable("exact current controller is unavailable"))?;
        let owner = owner
            .as_account_id()
            .ok_or_else(|| unavailable("current controller is not an Account"))?;
        for recipient in [account, owner] {
            let fresh = Box::pin(
                crate::self_current_reads::exact_current_result_in_connection(
                    &mut *conn, request, recipient, station,
                ),
            )
            .await
            .map_err(crate::PgTransactionError::into_persistence)?;
            let coland_storage::SelfExactCurrentRead::Answer(fresh) = fresh else {
                return Err(unavailable(
                    "exact current is not currently disclosed to both recipients",
                ));
            };
            if arkret_canonical::canonical_json_bytes(&fresh).map_err(PersistenceError::database)?
                != arkret_canonical::canonical_json_bytes(outcome)
                    .map_err(PersistenceError::database)?
            {
                return Err(unavailable(
                    "queued exact current differs from the held cut",
                ));
            }
        }
        use arkret_models_collaboration::exact_current_results::{
            ExactCurrentResultEntry as Entry, ExactCurrentResultsReadOutcome as Outcome,
        };
        let Outcome::Present { entry, .. } = outcome else {
            return Err(unavailable(
                "owned absence disclosure has no complete target proof",
            ));
        };
        let (stream, revision) = match entry {
            Entry::Relation(row) => (&row.source_stream_ref, &row.revision),
            Entry::ModerationState(row) => (&row.source_stream_ref, &row.revision),
            Entry::AgentInteraction(row) => (&row.source_stream_ref, &row.revision),
            Entry::CapabilityGrant(row) => (&row.source_stream_ref, &row.revision),
            Entry::Policy(row) => (&row.source_stream_ref, &row.revision),
            Entry::CalendarScheduleSource(row) => (&row.source_stream_ref, &row.revision),
        };
        if matches!(entry, Entry::Policy(_)) {
            let target = crate::policy_current_results::management_policy_scope_target(
                &request.realm_id,
                stream,
            )?;
            let actions = arkret_schema::capability_actions_for_event_kind(
                arkret_wire::EventKind::PolicySet.as_str(),
            )
            .filter(|action| action.required_evaluator_checks.is_empty())
            .map(|action| action.action.as_str())
            .collect::<Vec<_>>();
            for recipient in [account, owner] {
                let cut = Box::pin(crate::realm_authorization_cut::RealmAuthorizationCut::read(
                    &mut *conn,
                    &request.realm_id,
                    &ActorId::account(recipient.clone()),
                ))
                .await?;
                if !cut.permits_unreserved_current_actions(&actions, &target, at) {
                    return Err(unavailable("Policy current action coverage changed"));
                }
                positive_actions.push((cut, target.clone(), actions.clone()));
            }
        }
        let event =
            current_source_in_connection(&mut *conn, &request.realm_id, stream, revision).await?;
        Box::pin(require_owned_current_source_in_connection(
            &mut *conn, &event, owner, account, at,
        ))
        .await?;
        object_sources
            .entry(request.realm_id.clone())
            .or_default()
            .push((event, CapabilityActionId::ObjectRead));
    }
    for (request, outcome) in &input.watch_reads {
        if !realms.contains(&request.realm_id) {
            continue;
        }
        let fresh = Box::pin(
            crate::self_current_reads::strand_watch_current_in_connection(
                &mut *conn, request, account, station,
            ),
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)?;
        let coland_storage::SelfExactCurrentRead::Answer(fresh) = fresh else {
            return Err(unavailable("watch current is unavailable at the held cut"));
        };
        if arkret_canonical::canonical_json_bytes(&fresh).map_err(PersistenceError::database)?
            != arkret_canonical::canonical_json_bytes(outcome)
                .map_err(PersistenceError::database)?
        {
            return Err(unavailable(
                "queued watch current differs from the held cut",
            ));
        }
        let owner = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn,
            &request.realm_id,
            &actor,
            at,
        )
        .await?
        .ok_or_else(|| unavailable("watch current controller is unavailable"))?;
        let owner = owner
            .as_account_id()
            .ok_or_else(|| unavailable("current controller is not an Account"))?;
        // The self-only watch cell is confirmed above, including native
        // never-written proof. Its content boundary is the actual Strand;
        // another recipient's watch cell is never a substitute read source.
        let material = Box::pin(
            crate::authority_commit::realm_state_snapshot_material_in_connection(
                &mut *conn,
                &request.realm_id,
            ),
        )
        .await?
        .ok_or_else(|| unavailable("watch target current material is unavailable"))?;
        let (generation, head) = match outcome {
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome::Current {
                governance_generation, stream_head, ..
            }
            | arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome::NeverWritten {
                governance_generation, stream_head, ..
            } => (*governance_generation, stream_head),
        };
        if material.governance_generation != generation
            || !material.visible_stream_heads.contains(head)
        {
            return Err(unavailable(
                "watch target differs from its confirmed current cut",
            ));
        }
        let row = material
            .current_state_entries
            .iter()
            .find(|row| {
                let arkret_wire::TypedCurrentRow::Value { selector, .. } = row;
                matches!(selector, arkret_wire::CurrentSelector::Strand { strand_id }
                if strand_id == &request.strand_id)
            })
            .ok_or_else(|| unavailable("watch target Strand current is unavailable"))?;
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref,
            revision,
            ..
        } = row;
        if source_stream_ref != &head.stream_ref
            || revision.stream_position > head.stream_position
            || (revision.stream_position == head.stream_position
                && revision.commit_id != head.commit_id)
        {
            return Err(unavailable(
                "watch target Strand is outside its confirmed prefix",
            ));
        }
        let event = current_source_in_connection(
            &mut *conn,
            &request.realm_id,
            source_stream_ref,
            revision,
        )
        .await?;
        Box::pin(require_owned_content_source_in_connection(
            &mut *conn,
            &event,
            owner,
            account,
            at,
            CapabilityActionId::StrandRead,
        ))
        .await?;
        object_sources
            .entry(request.realm_id.clone())
            .or_default()
            .push((event, CapabilityActionId::StrandRead));
    }
    Ok(())
}

// Preserve queued material checks on the caller's existing transaction cut.
async fn revalidate_content_inputs_in_connection(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    actor: ActorId,
    realms: &std::collections::BTreeSet<arkret_wire::RealmId>,
    input: &mut coland_storage::AccountContentDeliveryInput,
    facts: &mut QueuedContentFacts,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let QueuedContentFacts {
        object_sources,
        native_projection_reads: _,
        positive_actions: _,
        blob_scope_operations,
        blob_source_actions,
    } = facts;
    for realm in realms {
        Box::pin(crate::realm_authorization_cut::owned_source_in_connection(
            &mut *conn, realm, &actor, at, true,
        ))
        .await?
        .ok_or_else(|| unavailable("current owned Agent source is unavailable"))?;
    }
    for delta in &input.notifications {
        let Some(content) = delta.ordinary_projection() else {
            continue;
        };
        if !realms.contains(&content.realm_id) {
            continue;
        }
        let arkret_models_collaboration::objects::read_receipts::NotificationIdentity::Projection(
            id,
        ) = &delta.id
        else {
            return Err(unavailable("ordinary notification identity differs"));
        };
        content
            .verify_id(account, id)
            .map_err(|_| unavailable("ordinary notification recipient differs"))?;
        let stored = sql_query("SELECT projection_data AS value FROM notifications WHERE projection_id=$1 AND recipient_actor_id=$2 AND realm_id=$3 AND source_event_id=$4 AND projection_action='upsert' FOR SHARE")
            .bind::<Text,_>(id.as_str())
            .bind::<Text,_>(actor.to_string())
            .bind::<Text,_>(content.realm_id.as_str())
            .bind::<Text,_>(content.source_event_id.as_str())
            .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| unavailable("ordinary notification current source changed"))?;
        let mut original: arkret_models_collaboration::objects::read_receipts::OrdinaryProjectionContent = serde_json::from_value(stored.value).map_err(PersistenceError::database)?;
        original
            .verify_id(account, id)
            .map_err(|_| unavailable("stored notification recipient differs"))?;
        // The original channel budget may omit a preview, never replace it.
        if content.preview.is_none() {
            original.preview = None;
        }
        if &original != content {
            return Err(unavailable(
                "queued notification differs from its current source",
            ));
        }
        let full = crate::committed_disclosure::accepted_full_event_in_connection(
            &mut *conn,
            &content.source_event_id,
        )
        .await?
        .ok_or_else(|| unavailable("ordinary notification has no accepted source"))?;
        if full.event.realm_id != content.realm_id {
            return Err(unavailable("ordinary notification source Realm differs"));
        }
        let view = CommittedEventView::Full(full);
        if !input.committed_events.contains(&view) {
            input.committed_events.push(view);
        }
    }
    for (blob_ref, original, action) in &input.blobs {
        if !matches!(
            action,
            CapabilityActionId::ObjectReadContent | CapabilityActionId::ObjectReadMetadata
        ) {
            return Err(unavailable(
                "attachment has no registered content surface action",
            ));
        }
        let realm = original
            .realm_id
            .as_deref()
            .map(arkret_wire::RealmId::new)
            .transpose()
            .map_err(PersistenceError::database)?;
        let Some(realm) = realm.filter(|realm| realms.contains(realm)) else {
            continue;
        };
        let held = crate::blobs::blob_for_delivery_in_connection(&mut *conn, blob_ref)
            .await?
            .ok_or_else(|| unavailable("attachment current metadata is unavailable"))?;
        if &held != original || held.redacted || held.legal_hold {
            return Err(unavailable("attachment current source changed"));
        }
        let sources = sql_query("SELECT e.envelope->>'event_id' AS event_id FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND e.state='committed' AND e.kind='ak.message.create' AND e.envelope->'payload'->'blob_refs' ? $2 ORDER BY e.envelope->>'event_id'")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(blob_ref.as_str()).load::<SourceEventRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let owner = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn, &realm, &actor, at,
        )
        .await?
        .ok_or_else(|| unavailable("attachment controller is unavailable"))?;
        let owner = owner
            .as_account_id()
            .ok_or_else(|| unavailable("attachment controller is not an Account"))?;
        let mut selected = None;
        for source in sources {
            let id =
                arkret_wire::EventId::new(source.event_id).map_err(PersistenceError::database)?;
            let full =
                crate::committed_disclosure::accepted_full_event_in_connection(&mut *conn, &id)
                    .await?
                    .ok_or_else(|| unavailable("attachment has no accepted producer"))?;
            let body: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
                serde_json::from_value(
                    serde_json::to_value(&full.event.payload)
                        .map_err(PersistenceError::database)?,
                )
                .map_err(PersistenceError::database)?;
            if !body
                .blob_refs
                .iter()
                .any(|value| value == blob_ref.as_str())
                || full.event.realm_id != realm
            {
                return Err(unavailable("attachment original signed binding differs"));
            }
            if !crate::committed_disclosure::withheld_commit_ids_in_connection(
                &mut *conn,
                &[full.commit.commit_id.to_string()],
            )
            .await?
            .is_empty()
                || !crate::committed_disclosure::full_event_for_member_in_connection(
                    &mut *conn, &full, &actor, at,
                )
                .await?
            {
                continue;
            }
            let authorized: PersistenceResult<()> = async {
        let mut resources =
            crate::agent_management_admission::event_content_resources(&full.event)?;
        let resource = arkret_models_collaboration::governance::operation_wire::PolicyResourceSelector {
            kind: arkret_models_collaboration::governance::operation_wire::PolicyResourceKind::Object,
            realm_id: Some(realm.clone()),
            resource_ref: Some(blob_ref.as_str().to_owned()),
        };
        if !resources.contains(&resource) {
            resources.push(resource);
        }
        let circle = match &full.event.scope_ref {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
            _ => None,
        };
        for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
            Box::pin(crate::agent_management_admission::require_content_snapshot_in_connection(
                &mut *conn,
                &realm,
                circle,
                owner,
                account,
                operation,
                *action,
                &resources,
                at,
            ))
            .await?;
        }
                for recipient in [account, owner] {
                    let recipient_actor = ActorId::account(recipient.clone());
                    let cut = Box::pin(crate::realm_authorization_cut::RealmAuthorizationCut::read(
                        &mut *conn, &realm, &recipient_actor,
                    )).await?;
                    let source = Box::pin(crate::realm_authorization_cut::owned_source_in_connection(
                        &mut *conn, &realm, &recipient_actor, at, false,
                    )).await?;
                    cut.require_content_read_constraints(
                        &full.event, at, source, *action,
                    )?;
                }
                Ok(())
            }.await;
            match authorized {
                Ok(()) => {
                    selected = Some(full);
                    break;
                }
                Err(error)
                    if error.conflict_code()
                        == Some(coland_storage::ConflictCode::CapabilityDenied) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        let full = selected
            .ok_or_else(|| unavailable("attachment has no currently readable signed source"))?;
        let cut = Box::pin(crate::realm_authorization_cut::RealmAuthorizationCut::read(
            &mut *conn, &realm, &actor,
        ))
        .await?;
        let (_, facts) = cut.content_scope_facts(&full.event, *action)?;
        let mut target = arkret_wire::WireResourceSelector::realm(realm.clone());
        target.kind = arkret_wire::ResourceSelectorKind::Blob;
        target.blob_ref = Some(blob_ref.clone());
        blob_scope_operations.push((actor.clone(), target, facts, *action));
        blob_source_actions.insert((full.event.event_id.clone(), action.as_str()));
        object_sources
            .entry(realm)
            .or_default()
            .push((full.event.clone(), *action));
    }
    for realm in realms {
        if input.unresolved_content_realms.contains(realm) {
            return Err(unavailable(
                "the content carrier has no current target proof",
            ));
        }
        let views = input
            .current_views
            .iter()
            .filter(|view| &view.realm_id == realm);
        let snapshots = input
            .snapshots
            .iter()
            .filter(|snapshot| &snapshot.realm_id == realm);
        if input
            .current_views
            .iter()
            .any(|view| &view.realm_id == realm)
            || input
                .snapshots
                .iter()
                .any(|snapshot| &snapshot.realm_id == realm)
        {
            let current = Box::pin(
                crate::snapshot_disclosure_gate::account_snapshot_material_in_connection(
                    &mut *conn, realm, account,
                ),
            )
            .await?
            .ok_or_else(|| unavailable("current disclosure material is unavailable"))?;
            for row in input
                .current_views
                .iter()
                .filter(|view| &view.realm_id == realm)
                .flat_map(|view| &view.entries)
                .chain(
                    input
                        .snapshots
                        .iter()
                        .filter(|snapshot| &snapshot.realm_id == realm)
                        .flat_map(|snapshot| &snapshot.current_state_entries),
                )
            {
                let arkret_wire::TypedCurrentRow::Value {
                    source_stream_ref,
                    revision,
                    ..
                } = row;
                object_sources.entry(realm.clone()).or_default().push((
                    current_source_in_connection(&mut *conn, realm, source_stream_ref, revision)
                        .await?,
                    CapabilityActionId::ObjectRead,
                ));
            }
            for view in views {
                view.validate()
                    .map_err(|error| unavailable(&error.to_string()))?;
                if view.governance_generation != current.governance_generation
                    || view
                        .entries
                        .iter()
                        .any(|row| !current.current_state_entries.contains(row))
                    || view
                        .stream_heads
                        .iter()
                        .any(|head| !current.visible_stream_heads.contains(head))
                {
                    return Err(unavailable(
                        "queued current bytes no longer match the current disclosure cut",
                    ));
                }
            }
            for snapshot in snapshots {
                if snapshot.governance_generation != current.governance_generation
                    || snapshot
                        .current_state_entries
                        .iter()
                        .any(|row| !current.current_state_entries.contains(row))
                    || snapshot
                        .visible_stream_heads
                        .iter()
                        .any(|head| !current.visible_stream_heads.contains(head))
                    || snapshot.retention_and_history_floor != current.retention_and_history_floor
                {
                    return Err(unavailable(
                        "issued snapshot has no current complete disclosure proof",
                    ));
                }
            }
        }
    }
    for welcome in &input.future_materials {
        if !realms.contains(&welcome.realm_id) {
            continue;
        }
        welcome
            .validate_shape()
            .map_err(|error| unavailable(&error.to_string()))?;
        if welcome.recipient_actor_id != actor {
            return Err(unavailable("future material recipient differs"));
        }
        let full = crate::committed_disclosure::accepted_full_event_in_connection(
            &mut *conn,
            &welcome.commit_event_ref,
        )
        .await?
        .ok_or_else(|| unavailable("future material has no accepted producer"))?;
        if full.event.realm_id != welcome.realm_id
            || full.event.scope_ref != welcome.effective_scope
            || !crate::committed_disclosure::full_event_for_member_in_connection(
                &mut *conn, &full, &actor, at,
            )
            .await
            .inspect_err(|_| {
                tracing::warn!(
                    stage = "future_material_disclosure_error",
                    "owned future material delivery is unavailable"
                );
            })?
        {
            tracing::warn!(
                stage = "future_material_disclosure",
                "owned future material delivery is unavailable"
            );
            return Err(unavailable(
                "future material has no current disclosure proof",
            ));
        }
        let queued = sql_query("SELECT EXISTS(SELECT 1 FROM mls_welcome_deliveries WHERE welcome_id=$1 AND state='queued' AND delivery_json=$2) AS present")
            .bind::<Text,_>(welcome.welcome_id.as_str())
            .bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(welcome).map_err(PersistenceError::database)?)
            .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
        if !queued {
            return Err(unavailable("future material queue source changed"));
        }
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            &mut *conn,
            &welcome.realm_id,
            &actor,
            at,
        )
        .await?
        .ok_or_else(|| unavailable("future material controller is unavailable"))?;
        let owner = controller
            .as_account_id()
            .ok_or_else(|| unavailable("controller is not an Account"))?;
        let resources = crate::agent_management_admission::event_content_resources(&full.event)?;
        let circle = match &welcome.effective_scope {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
            _ => None,
        };
        Box::pin(
            crate::agent_management_admission::require_content_snapshot_in_connection(
                &mut *conn,
                &welcome.realm_id,
                circle,
                owner,
                account,
                AgentPolicyOperation::Deliver,
                CapabilityActionId::EventRead,
                &resources,
                at,
            ),
        )
        .await?;
    }
    Box::pin(revalidate_committed_events_in_connection(
        &mut *conn,
        account,
        actor.clone(),
        &realms,
        &input,
        at,
    ))
    .await?;
    Ok(())
}

async fn acquire_with_native_reply(
    pool: &crate::PgPool,
    account: &AccountId,
    station: &DidCoreId,
    input: &coland_storage::AccountContentDeliveryInput,
    reply: Option<NativeReplyContext<'_>>,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    let input = input.clone();
    let mut guard = Box::new(DeliveryGuard {
        connection: Some(crate::pg_conn(pool).await?),
        runtime: tokio::runtime::Handle::current(),
        clock: None,
    });
    sql_query("BEGIN")
        .execute(guard.connection())
        .await
        .map_err(PersistenceError::database)?;
    let mut realms = std::collections::BTreeSet::new();
    let candidates = input
        .realms
        .iter()
        .chain(
            input
                .committed_events
                .iter()
                .map(|row| &row.commit().realm_id),
        )
        .chain(input.realm_exports.iter().map(|export| &export.realm_id))
        .chain(input.current_views.iter().map(|view| &view.realm_id))
        .chain(input.snapshots.iter().map(|snapshot| &snapshot.realm_id))
        .chain(
            input
                .future_materials
                .iter()
                .map(|welcome| &welcome.realm_id),
        )
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for realm in &candidates {
        if crate::committed_disclosure::ordinary_agent_read_ceiling(
            crate::account_stream_scan::realm_purpose(guard.connection(), realm).await?,
        ) && crate::realm_authorization_cut::is_owned_agent_in_connection(
            guard.connection(),
            realm,
            account,
        )
        .await?
        {
            realms.insert(realm.clone());
        }
    }
    if realms.is_empty() && reply.is_some() {
        return Err(unavailable(
            "native reply is not at its current governing owned cut",
        ));
    }
    if realms.is_empty() {
        guard.finish().await?;
        return Box::pin(crate::morph_projection_reads::ordinary_delivery_guard(
            pool, account, station, &input,
        ))
        .await;
    }
    // Keep the ordinary branch out of the owned-content state machine. Both
    // branches preserve the same transaction and handoff ownership rules.
    Box::pin(acquire_owned_delivery_guard(
        guard, account, station, input, realms, reply,
    ))
    .await
}

async fn acquire_owned_delivery_guard(
    mut guard: Box<DeliveryGuard>,
    account: &AccountId,
    station: &DidCoreId,
    mut input: coland_storage::AccountContentDeliveryInput,
    realms: std::collections::BTreeSet<arkret_wire::RealmId>,
    reply: Option<NativeReplyContext<'_>>,
) -> PersistenceResult<Option<Box<dyn AccountContentDeliveryGuard>>> {
    // Discover immutable PCR bindings without taking subordinate row locks.
    // Keep the original business-then-Agent-then-Human hierarchy. Original
    // ordinary Morph also sorts its business/PCR cuts together, so added PCR
    // acquisitions must never wait while this business cut is already held.
    let mut native_human_pcrs = std::collections::BTreeMap::new();
    if let Some(reply) = reply.as_ref() {
        let humans = [reply.controller.clone(), reply.caller.clone()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        for human in humans {
            let pcr = crate::morph_projection_reads::human_realm_in_connection(
                guard.connection(),
                &human,
            )
            .await?;
            native_human_pcrs.insert(human, pcr);
        }
    }
    for realm in &realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(guard.connection(), realm)
            .await?;
        let governor = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(realm.as_str())
            .get_result::<Governor>(guard.connection())
            .await
            .map_err(PersistenceError::database)?;
        if governor.service_id != station.as_str() {
            return Err(unavailable(
                "no authenticated current governing delivery barrier",
            ));
        }
    }
    let actor = ActorId::account(account.clone());
    let endpoint = input
        .agent_endpoint
        .as_ref()
        .ok_or_else(|| unavailable("Agent delivery has no current endpoint binding"))?
        .clone();
    if endpoint.agent_id != account.principal_id {
        return Err(unavailable(
            "Agent delivery endpoint differs from recipient",
        ));
    }
    if reply.is_some() {
        // Agent-control writers lock Agent PCR before controller PCR. Preserve
        // that hierarchy; sort all additional Human PCRs within their class.
        // NOWAIT prevents a cycle with the original ordinary Morph cut order.
        // A refusal drops this guard and its entire transaction, never granting
        // authority without the complete cut or retrying a provider request.
        let mut pcrs = vec![endpoint.pcr_realm_id.clone()];
        pcrs.extend(
            native_human_pcrs
                .values()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
        );
        for pcr in pcrs {
            sql_query(
                "SELECT service_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE NOWAIT",
            )
            .bind::<Text, _>(pcr.as_str())
            .get_result::<Governor>(guard.connection())
            .await
            .map_err(|_| unavailable("native reply PCR cut is changing or unavailable"))?;
        }
    }
    // Take the producer lock before reading the clock. The same lock is held
    // by native status/key writers; a waiter cannot reuse pre-wait liveness.
    Box::pin(crate::agent_current_results::lock_agent_producer_current(
        guard.connection(),
        &endpoint.pcr_realm_id,
        &endpoint.agent_id,
    ))
    .await?;
    // Acquire every membership, provisioning, accountability and lifecycle
    // dependency before fixing the content evaluation time.
    for realm in &realms {
        Box::pin(crate::realm_authorization_cut::owned_source_in_connection(
            guard.connection(),
            realm,
            &actor,
            chrono::Utc::now(),
            true,
        ))
        .await
        .inspect_err(|_| {
            if !input.future_materials.is_empty() {
                tracing::warn!(
                    stage = "future_material_owned_source",
                    "owned future material delivery is unavailable"
                );
            }
        })?
        .ok_or_else(|| {
            if !input.future_materials.is_empty() {
                tracing::warn!(
                    stage = "future_material_owned_source_absent",
                    "owned future material delivery is unavailable"
                );
            }
            unavailable("current owned Agent source is unavailable")
        })?;
    }
    let at = chrono::Utc::now();
    Box::pin(
        crate::authority_commit::check_agent_endpoint_current_in_connection(
            guard.connection(),
            &endpoint.pcr_realm_id,
            &endpoint.agent_id,
            &endpoint.authorization_ref,
            &endpoint.verification_method,
            at,
        ),
    )
    .await?;
    let mut queued = QueuedContentFacts::default();
    Box::pin(revalidate_projection_inputs_in_connection(
        guard.connection(),
        account,
        station,
        actor.clone(),
        &realms,
        &mut input,
        &mut queued,
        at,
    ))
    .await?;
    Box::pin(revalidate_content_inputs_in_connection(
        guard.connection(),
        account,
        actor.clone(),
        &realms,
        &mut input,
        &mut queued,
        at,
    ))
    .await
    .inspect_err(|_| {
        if !input.future_materials.is_empty() {
            tracing::warn!(
                stage = "future_material_content_inputs",
                "owned future material delivery is unavailable"
            );
        }
    })?;
    let QueuedContentFacts {
        mut object_sources,
        native_projection_reads,
        positive_actions,
        blob_scope_operations,
        blob_source_actions,
    } = queued;
    if reply.is_some() {
        for row in &input.committed_events {
            let CommittedEventView::Full(full) = row else {
                return Err(unavailable("native reply body source is withheld"));
            };
            let message_id = arkret_wire::MessageId::from_event_id(&full.event.event_id);
            let current = crate::message_revision_current_results::locked_message_target(
                guard.connection(),
                &full.event.realm_id,
                &message_id,
            )
            .await
            .map_err(|error| match error {
                PersistenceError::NotFound(_) => {
                    unavailable("native reply Message current is unavailable")
                }
                error => error,
            })?;
            if current.current_commit_id != full.commit.commit_id.to_string()
                || current.author != full.event.actor_id
                || current.created_at != full.event.created_at
                || current.scope_ref != full.event.scope_ref
                || current.strand_id != reply.as_ref().expect("native context").strand.clone()
                || crate::message_revision_current_results::message_is_redacted(
                    guard.connection(),
                    &full.event.realm_id,
                    &message_id,
                )
                .await?
            {
                return Err(unavailable(
                    "native reply body is not its exact current Message revision",
                ));
            }
            Box::pin(require_owned_content_source_in_connection(
                guard.connection(),
                &full.event,
                reply.as_ref().expect("native context").controller,
                account,
                at,
                CapabilityActionId::ObjectReadContent,
            ))
            .await?;
            object_sources
                .entry(full.event.realm_id.clone())
                .or_default()
                .push((full.event.clone(), CapabilityActionId::ObjectReadContent));
        }
    }
    let key_source = crate::committed_disclosure::accepted_full_event_in_connection(
        guard.connection(),
        &endpoint.authorization_ref.event_id,
    )
    .await?
    .ok_or_else(|| unavailable("delivery key source is unavailable"))?;
    let key: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
        serde_json::from_value(
            serde_json::to_value(&key_source.event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
    if input.credential_expires_at.is_some() && input.agent_session_scope.is_none() {
        return Err(unavailable(
            "Agent credential delivery has no issuer-ledger scope",
        ));
    }
    let evidence = input
        .qualified_agent_scope_evidence
        .as_ref()
        .ok_or_else(|| unavailable("Agent delivery has no qualified private scope custody"))?;
    let provision_scope = Box::pin(provision_scope_in_connection(
        guard.connection(),
        &endpoint,
        evidence,
        station,
    ))
    .await?;
    let mut clock = DeliveryClockProof {
        checked_at: at,
        key_expiry: key.expires_at,
        credential_expiry: input.credential_expires_at,
        key_scope: key.agent_key_scope,
        provision_scope,
        session_scope: input.agent_session_scope.clone(),
        scope_operations: blob_scope_operations,
        accountability: Vec::new(),
        policies: Vec::new(),
        positive_actions,
        native_projection_reads,
        native_reply: None,
        reads: Vec::new(),
    };
    for (_, _, fact) in &clock.native_projection_reads {
        clock.scope_operations.push((
            actor.clone(),
            fact.target.clone(),
            fact.facts.clone(),
            fact.action,
        ));
    }
    for realm in &realms {
        let source = Box::pin(crate::realm_authorization_cut::owned_source_in_connection(
            guard.connection(),
            realm,
            &actor,
            chrono::Utc::now(),
            true,
        ))
        .await?
        .ok_or_else(|| unavailable("current owned Agent source is unavailable"))?;
        let arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::OwnedAgent { controller_account_id, .. } = &source else {
            return Err(unavailable("delivery source is not owned Agent authority"));
        };
        let controller_account_id = controller_account_id.clone();
        if controller_account_id != evidence.accepted_binding().controller_account {
            return Err(unavailable(
                "current owned controller differs from private scope custody",
            ));
        }
        if let Some((_, details)) = &clock.session_scope {
            if details.get("controller_principal_id")
                != Some(&serde_json::json!(controller_account_id.principal_id))
                || details.get("agent_key_authorization_ref")
                    != Some(&serde_json::json!(endpoint.authorization_ref.event_id))
            {
                return Err(unavailable(
                    "session scope differs from the current controller or key",
                ));
            }
        }
        let accountability = sql_query("SELECT value FROM identity_accountability_current_results WHERE subject_id=$1 AND issuer_id=$2 ORDER BY realm_id,scope_set_digest FOR SHARE")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(controller_account_id.principal_id.as_str())
            .load::<ValueRow>(guard.connection()).await.map_err(PersistenceError::database)?;
        let values = accountability.into_iter().map(|row| serde_json::from_value::<arkret_models_collaboration::governance::accountability::AccountabilityProjection>(row.value)
            .map_err(PersistenceError::database)).collect::<PersistenceResult<Vec<_>>>()?
            .into_iter().filter(|value| value.accountability_scope.scopes().contains(&arkret_wire::AccountabilityScopeKind::AgentOperator)).collect::<Vec<_>>();
        clock.accountability.push(values);
        let policies = sql_query("SELECT value FROM policy_current_results WHERE value->>'policy_kind'='agent' AND value->>'realm_id'=$1 ORDER BY policy_id")
            .bind::<Text,_>(realm.as_str()).load::<ValueRow>(guard.connection()).await.map_err(PersistenceError::database)?;
        for row in policies {
            let policy: arkret_models_collaboration::governance::operation_wire::Policy =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            policy.validate().map_err(PersistenceError::database)?;
            clock.policies.push(policy);
        }
        let mut events = Vec::new();
        for event_id in input
            .committed_events
            .iter()
            .filter(|row| &row.commit().realm_id == realm)
            .map(|row| &row.commit().event_ref)
            .chain(
                input
                    .future_materials
                    .iter()
                    .filter(|welcome| &welcome.realm_id == realm)
                    .map(|welcome| &welcome.commit_event_ref),
            )
        {
            let accepted = crate::committed_disclosure::accepted_full_event_in_connection(
                guard.connection(),
                event_id,
            )
            .await?
            .ok_or_else(|| unavailable("delivery time proof has no accepted producer"))?;
            events.push(accepted.event);
        }
        for (recipient, source) in [
            (actor.clone(), Some(source)),
            (ActorId::account(controller_account_id.clone()), None),
        ] {
            let cut = Box::pin(crate::realm_authorization_cut::RealmAuthorizationCut::read(
                guard.connection(),
                realm,
                &recipient,
            ))
            .await?;
            if recipient == actor {
                if input
                    .realm_exports
                    .iter()
                    .any(|export| &export.realm_id == realm)
                {
                    clock.scope_operations.push((
                        actor.clone(),
                        arkret_wire::WireResourceSelector::realm(realm.clone()),
                        coland_storage::OperationFacts::default(),
                        CapabilityActionId::EventRead,
                    ));
                }
                if input.projection_lists.iter().any(|(id, ..)| id == realm)
                    || input
                        .current_views
                        .iter()
                        .any(|view| &view.realm_id == realm && view.entries.is_empty())
                    || input.snapshots.iter().any(|snapshot| {
                        &snapshot.realm_id == realm && snapshot.current_state_entries.is_empty()
                    })
                {
                    clock.scope_operations.push((
                        actor.clone(),
                        arkret_wire::WireResourceSelector::realm(realm.clone()),
                        coland_storage::OperationFacts::default(),
                        CapabilityActionId::ObjectRead,
                    ));
                }
                for (event, action) in events
                    .iter()
                    .map(|event| (event, CapabilityActionId::EventRead))
                    .chain(
                        object_sources
                            .get(realm)
                            .into_iter()
                            .flatten()
                            .filter(|(event, action)| {
                                !blob_source_actions
                                    .contains(&(event.event_id.clone(), action.as_str()))
                            })
                            .map(|(event, action)| (event, *action)),
                    )
                {
                    let (target, facts) = cut.content_scope_facts(event, action)?;
                    clock
                        .scope_operations
                        .push((actor.clone(), target, facts, action));
                }
            }
            clock.reads.push((
                cut,
                source,
                events.clone(),
                object_sources.get(realm).cloned().unwrap_or_default(),
            ));
        }
    }
    if let Some(reply) = reply {
        let proof = Box::pin(native_reply_time_proof_in_connection(
            guard.connection(),
            account,
            station,
            &input,
            actor.clone(),
            &realms,
            &native_human_pcrs,
            reply,
        ))
        .await?;
        // MessageCreate remains additional to every model input Read/Deliver ceiling.
        clock.scope_operations.push((
            actor.clone(),
            proof.target.clone(),
            proof.facts.clone(),
            CapabilityActionId::MessageCreate,
        ));
        clock.native_reply = Some(proof);
    }
    guard.clock = Some(clock);
    if !guard.permits_handoff() {
        return Err(unavailable(
            "delivery time authority changed before handoff",
        ));
    }
    Ok(Some(guard))
}
