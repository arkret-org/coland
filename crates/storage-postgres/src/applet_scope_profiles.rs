//! One private Profile per Realm actor, signed by its accepted control method.
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, ActorProfileUpdatePayload,
};
use arkret_models_identity::{ActorProfile, AppletInteractionIntent, AppletInteractionMode};
use arkret_wire::{CurrentRevision, Event, EventKind, RealmCommit, ScopeRef};
use coland_storage::{AppletManagedDeviceScopeGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::{Array, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};
use serde_json::{Value, json};

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}
pub(crate) struct Admission {
    original_digest: String,
    pub(crate) profile: ActorProfile,
    previous: Option<Value>,
    pub(crate) publish_scope: Option<ScopeRef>,
    pub(crate) fact: arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
}
impl Admission {
    pub(crate) fn applies_to(&self, event: &Event) -> bool {
        arkret_canonical::canonical_sha256(event).ok().as_ref() == Some(&self.original_digest)
    }
    pub(crate) fn is_public(&self) -> bool {
        self.publish_scope.is_some()
    }
    pub(crate) fn pins(&self) -> Value {
        json!({"previous":self.previous,"postimage":self.profile,"publish_scope":self.publish_scope})
    }
    pub(crate) async fn write(
        &self,
        conn: &mut AsyncPgConnection,
        event: &Event,
        commit: &RealmCommit,
    ) -> Result<(), crate::PgTransactionError> {
        if !self.applies_to(event) {
            return Err(denied("Profile admission names another original").into());
        }
        crate::realm_actor_control::write_current(
            conn,
            &event.actor_id,
            json!({"kind":"realm_actor_profile","actor_id":event.actor_id}),
            json!({"profile_id":self.profile.id,"profile":self.profile}),
            commit,
        )
        .await?;
        Ok(())
    }
}
pub(crate) fn is_profile(event: &Event) -> bool {
    event.actor_id.as_realm_actor_id().is_some()
        && matches!(
            event.kind,
            EventKind::ProfileCreate | EventKind::ProfileUpdate
        )
}
fn intent(profile: &ActorProfile) -> PersistenceResult<Option<AppletInteractionIntent>> {
    profile
        .profile_fields
        .get("applet_interaction")
        .map(|value| serde_json::from_value(value.clone()).map_err(denied))
        .transpose()
}
fn publish_transition(
    previous: Option<&ActorProfile>,
    profile: &ActorProfile,
) -> PersistenceResult<Option<ScopeRef>> {
    let next = intent(profile)?;
    let old = previous.map(intent).transpose()?.flatten();
    Ok(next
        .filter(|next| {
            next.mode == AppletInteractionMode::Public
                && old.as_ref().is_none_or(|old| {
                    old.mode != AppletInteractionMode::Public
                        || old.effective_scope != next.effective_scope
                })
        })
        .map(|next| next.effective_scope))
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}

pub(crate) async fn publish_basis(
    conn: &mut AsyncPgConnection,
    event: &Event,
    admission: &Admission,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(
    Value,
    arkret_policy::applet_management::AppletManagementDecision,
)> {
    use arkret_models_collaboration::governance::operation_wire::{
        AppletPolicyOperation, PolicyResourceKind, PolicyResourceSelector,
    };
    let scope = admission
        .publish_scope
        .as_ref()
        .ok_or_else(|| denied("Profile does not open public intent"))?;
    let applet = event
        .applet_id
        .as_ref()
        .ok_or_else(|| denied("Profile has no Applet"))?;
    let registration = crate::managed_message_actor::registration(conn, event).await?;
    let document = sql_query(
        "SELECT did_document AS value FROM webvh_documents WHERE id=$1 AND expires_at>$2 FOR SHARE",
    )
    .bind::<Text, _>(
        registration
            .manifest
            .registration_epoch_evidence
            .did
            .as_str(),
    )
    .bind::<Timestamptz, _>(at)
    .get_result::<JsonRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let document: arkret_identity::DidDocument =
        serde_json::from_value(document.value).map_err(denied)?;
    let (_, installation) = crate::applet_device_admission::installation_identity(
        conn,
        &event.actor_id,
        applet,
        &registration.service_id,
        scope,
        &document,
        at,
        true,
    )
    .await?;
    let policies =
        crate::policy_current_results::read_scoped_applet_management_policies_in_connection(
            conn,
            &event.realm_id,
            scope.circle_id(),
        )
        .await?;
    let mut resources = vec![PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(event.realm_id.clone()),
        resource_ref: Some(event.realm_id.to_string()),
    }];
    if let Some(circle) = scope.circle_id() {
        resources.push(PolicyResourceSelector {
            kind: PolicyResourceKind::Object,
            realm_id: Some(event.realm_id.clone()),
            resource_ref: Some(circle.to_string()),
        });
    }
    let service = arkret_wire::ActorId::service(registration.service_id.clone());
    let decision = arkret_policy::applet_management::select_applet_management(
        Some(&policies),
        &arkret_policy::applet_management::AppletManagementContext {
            device_control: None,
            realm_id: &event.realm_id,
            requester_actor_id: &service,
            applet_id: applet,
            service_id: &registration.service_id,
            effective_scope: scope,
            managed_actor_id: Some(&event.actor_id),
            operation: AppletPolicyOperation::Publish,
            content_action: None,
            resources: Some(&resources),
            at,
        },
    )
    .map_err(denied)?;
    if matches!(
        decision.effect,
        arkret_wire::PolicyEffect::Deny | arkret_wire::PolicyEffect::Quarantine
    ) {
        return Err(denied("current management Policy refuses public intent"));
    }
    let ids = policies
        .iter()
        .map(|policy| policy.id.to_string())
        .collect::<Vec<_>>();
    let revisions = sql_query("SELECT to_jsonb(p) AS value FROM policy_current_results p WHERE policy_id=ANY($1) ORDER BY policy_id FOR SHARE")
        .bind::<Array<Text>,_>(ids).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let actor_currents = sql_query("SELECT to_jsonb(r) AS value FROM realm_actor_current_results r WHERE realm_id=$1 AND selector->'actor_id'=$2 AND selector->>'kind' IN ('realm_actor_control','realm_actor_manager','realm_actor_status','realm_actor_profile','realm_actor_recovery') ORDER BY selector::text FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(event.actor_id)).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let root = sql_query("SELECT to_jsonb(r) AS value FROM realm_authority_root_current_results r WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let bundle = sql_query("SELECT to_jsonb(p) AS value FROM realm_policy_bundle_current_results p WHERE realm_id=$1 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mut fact = json!(admission.fact);
    fact.as_object_mut()
        .ok_or_else(|| denied("invalid control fact"))?
        .remove("accepted_at");
    Ok((
        json!({"producer":fact,"profile":admission.pins(),"requester":service,
        "registration":registration,"installation_status":installation["status"],"installation_registration":installation["registration_event"],"package":installation["package"],
        "actor_currents":actor_currents.into_iter().map(|row| row.value).collect::<Vec<_>>(),
        "authority_root":root.value,"policy_bundle":bundle.map(|row| row.value),
        "policy_revisions":revisions.into_iter().map(|row| row.value).collect::<Vec<_>>() }),
        decision,
    ))
}
pub(crate) async fn prepare_control(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Admission> {
    event.validate_for_submit_structural().map_err(denied)?;
    if !is_profile(event)
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
    {
        return Err(denied(
            "Realm Profile requires its own private control branch",
        ));
    }
    let creation = crate::realm_actor_control::creation_source(conn, &event.actor_id).await?;
    if event.applet_id.as_ref() != Some(&creation.applet_id) {
        return Err(denied("Profile Applet differs from identity"));
    }
    for gate in ["owner", "governance"] {
        let (status, _) = crate::realm_actor_control::current_source(
            conn,
            &event.actor_id,
            json!({"kind":"realm_actor_status","actor_id":event.actor_id,"gate":gate}),
        )
        .await?;
        if status == "retired" {
            return Err(denied("retired Realm actor cannot maintain Profile"));
        }
    }
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_open_lifecycle(event)?;
    let fact = crate::realm_actor_control_source::signer_fact(conn, event, at).await?;
    let previous = crate::realm_actor_control::optional_current_source(
        conn,
        &event.actor_id,
        json!({"kind":"realm_actor_profile","actor_id":event.actor_id}),
    )
    .await?;
    let previous_profile: Option<ActorProfile> = previous
        .as_ref()
        .map(|(value, _)| serde_json::from_value(value["profile"].clone()).map_err(denied))
        .transpose()?;
    let profile = match event.kind {
        EventKind::ProfileCreate => {
            if previous.is_some() {
                return Err(denied("Realm actor Profile is create-once"));
            }
            let payload: ActorProfileCreatePayload =
                serde_json::from_value(json!(event.payload)).map_err(denied)?;
            payload.materialize(event).map_err(denied)?
        }
        EventKind::ProfileUpdate => {
            let payload: ActorProfileUpdatePayload =
                serde_json::from_value(json!(event.payload)).map_err(denied)?;
            let (value, source) = previous
                .as_ref()
                .ok_or_else(|| denied("Profile has never been created"))?;
            if payload.expected_revision.as_ref()
                != Some(&CurrentRevision {
                    commit_id: source.commit_id.clone(),
                    stream_position: source.stream_position,
                })
                || value["profile_id"] != json!(payload.target_ref)
            {
                return Err(denied("Profile CAS or target differs"));
            }
            payload
                .apply(
                    event,
                    previous_profile
                        .as_ref()
                        .ok_or_else(|| denied("Profile original missing"))?,
                )
                .map_err(denied)?
        }
        _ => return Err(denied("unsupported Profile writer")),
    };
    profile.validate_display_members().map_err(denied)?;
    let kind = match creation.actor_role {
        arkret_models_integration::RealmActorCreatePayloadActorRole::Bot => {
            arkret_wire::ActorKind::Bot
        }
        arkret_models_integration::RealmActorCreatePayloadActorRole::Ghost => {
            arkret_wire::ActorKind::Integration
        }
    };
    if profile.actor_id.as_ref() != Some(&event.actor_id)
        || profile.principal_id.is_some()
        || profile.actor_kind != kind
        || profile.realm_id.as_ref() != Some(&event.realm_id)
        || profile.accountable_principal_ids.is_some()
        || profile.resolution.is_some()
        || profile.handle.is_some()
        || profile.agent_slug.is_some()
    {
        return Err(denied(
            "Realm Profile changes identity or includes Account-only fields",
        ));
    }
    if let Some(intent) = intent(&profile)?
        && (intent.effective_scope.realm_id() != &event.realm_id
            || !matches!(
                intent.effective_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
            ))
    {
        return Err(denied(
            "Profile intent must select a business scope of its own Realm",
        ));
    }
    let publish_scope = publish_transition(previous_profile.as_ref(), &profile)?;
    Ok(Admission {
        original_digest: arkret_canonical::canonical_sha256(event).map_err(denied)?,
        profile,
        previous: previous.map(|(value, source)| json!({"value":value,"source":source})),
        publish_scope,
        fact,
    })
}

pub(crate) async fn admit_control(
    conn: &mut AsyncPgConnection,
    transaction: &coland_storage::AuthorityCommitTransaction,
    carrier: &coland_storage::AppletControlCarrier,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> Result<arkret_wire::AuthoritySubmitOutcome, crate::PgTransactionError> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    if !is_profile(event)
        || event.actor_id != carrier.actor_id
        || carrier.governance_service_id != transaction.expected_authority.service_id
        || carrier.governance_generation != transaction.expected_authority.generation
    {
        return Err(denied("Profile transport or governance identity differs").into());
    }
    crate::agent_management_review::lock_candidate_current_realms_in_connection(
        conn,
        event,
        prepared,
        None,
        &[],
    )
    .await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let actual = crate::realm_actor_control_transport::current_carrier(
        conn,
        &carrier.actor_id,
        &carrier.governance_service_id,
        commit.committed_at,
    )
    .await?;
    if &actual != carrier {
        return Err(denied("Profile control method changed before acceptance").into());
    }
    if let Some(original) =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
            .await?
    {
        if original.event != *event {
            return Err(denied("duplicate_conflict: Profile original differs").into());
        }
        return Ok(arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate,
            commit: original.commit,
        });
    }
    let admission = prepare_control(conn, event, commit.committed_at).await?;
    crate::agent_producer_signer_keys::validate_producer_fact_binding(
        event,
        commit,
        Some(&admission.fact),
    )?;
    let mut management = Vec::new();
    let mut governance = Vec::new();
    let has_management = prepared.is_some_and(|prepared| {
        prepared.methods.iter().any(|method| {
            matches!(
                method.signature.input.approval_context,
                arkret_wire::ApprovalContext::Management { .. }
            )
        })
    });
    if let Some(scope) = &admission.publish_scope {
        let (_, decision) = publish_basis(conn, event, &admission, commit.committed_at).await?;
        if !decision.review_requirements.is_empty() || has_management {
            management = crate::agent_management_review::require_approved_in_connection(
                conn,
                event,
                prepared,
                commit.committed_at,
            )
            .await?;
        }
        let target = match scope {
            ScopeRef::Realm { realm_id } => {
                arkret_wire::WireResourceSelector::realm(realm_id.clone())
            }
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
            _ => return Err(denied("invalid public Profile scope").into()),
        };
        let registration = crate::managed_message_actor::registration(conn, event).await?;
        let facts = coland_storage::OperationFacts {
            applet_id: event.applet_id.as_ref().map(ToString::to_string),
            registration_epoch: Some(registration.registration_epoch.to_string()),
            executed_by: Some(event.actor_id.clone()),
            circle_id: scope.circle_id().map(ToString::to_string),
            ..Default::default()
        };
        governance = crate::approval_admission::require_governance(
            conn,
            event,
            commit,
            prepared,
            arkret_wire::CapabilityActionId::AppletPublish,
            &target,
            &facts,
            &[],
        )
        .await?;
    } else if has_management {
        return Err(denied("unchanged or private intent cannot consume a publish decision").into());
    }
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    let result = crate::authority_commit::commit_managed_scope_profile_in_connection(
        conn,
        transaction,
        prepared,
        &admission,
    )
    .await?;
    if !matches!(
        result,
        coland_storage::AuthorityCommitWriteOutcome::Committed
    ) {
        return Err(denied("Profile control head or governance changed").into());
    }
    crate::agent_producer_signer_keys::retain_prepared_applet_in_connection(
        conn,
        event,
        commit,
        &admission.fact,
    )
    .await?;
    crate::agent_management_review::consume_in_connection(conn, event, commit, &management).await?;
    crate::approval_admission::consume_and_audit(
        conn,
        event,
        commit,
        &governance,
        &json!({"realm_profile_publish":admission.publish_scope}),
    )
    .await?;
    Ok(arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    })
}
/// Device-authenticated business admission cannot impersonate a control method.
pub(crate) async fn prepare(
    _conn: &mut AsyncPgConnection,
    _event: &Event,
    _guard: &AppletManagedDeviceScopeGuard,
    _at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Admission> {
    Err(denied(
        "Realm Profile requires authenticated subject control, not Device admission",
    ))
}
pub(crate) async fn prepare_source(
    _conn: &mut AsyncPgConnection,
    _event: &Event,
    _source: crate::managed_forward_admission::Source<'_>,
    _at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Admission> {
    Err(denied(
        "Realm Profile is not a managed business Device Event",
    ))
}
/// Realm control Profiles never enter ordinary member snapshots or replica reducers.
pub(crate) fn validate_disclosed(
    _id: &arkret_wire::ActorProfileId,
    _stream: &arkret_wire::CommitStreamRef,
    _value: &Value,
) -> PersistenceResult<ActorProfile> {
    Err(denied(
        "private Realm Profile cannot be disclosed as shared state",
    ))
}
pub(crate) async fn project_replica(
    _conn: &mut AsyncPgConnection,
    _event: &Event,
    _commit: &RealmCommit,
) -> PersistenceResult<()> {
    Err(denied(
        "private Realm Profile cannot be installed from member replication",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_gate_tracks_public_transitions_not_display_maintenance() {
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [131; 32],
        ));
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let mut private: ActorProfile = serde_json::from_value(json!({
            "schema":ActorProfile::SCHEMA,"realm_id":realm,"actor_kind":"bot","display_name":"Bridge",
            "created_at":"2026-10-20T00:00:00.000Z","profile_fields":{}
        })).unwrap();
        assert!(publish_transition(None, &private).unwrap().is_none());
        private.profile_fields.insert(
            "applet_interaction".into(),
            json!({"effective_scope":scope,"mode":"private"}),
        );
        let mut public = private.clone();
        public.profile_fields.insert(
            "applet_interaction".into(),
            json!({"effective_scope":scope,"mode":"public"}),
        );
        assert_eq!(
            publish_transition(None, &public).unwrap(),
            Some(scope.clone())
        );
        assert_eq!(
            publish_transition(Some(&private), &public).unwrap(),
            Some(scope.clone())
        );
        assert!(
            publish_transition(Some(&public), &private)
                .unwrap()
                .is_none()
        );
        let mut renamed = public.clone();
        renamed.display_name = "New name".into();
        assert!(
            publish_transition(Some(&public), &renamed)
                .unwrap()
                .is_none()
        );
        let other = ScopeRef::Circle {
            realm_id: realm,
            circle_id: arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [132; 32],
            )),
        };
        renamed.profile_fields.insert(
            "applet_interaction".into(),
            json!({"effective_scope":other,"mode":"public"}),
        );
        assert_eq!(
            publish_transition(Some(&public), &renamed).unwrap(),
            Some(other)
        );
        renamed.profile_fields.clear();
        assert!(
            publish_transition(Some(&public), &renamed)
                .unwrap()
                .is_none()
        );
        renamed.profile_fields.insert(
            "applet_interaction".into(),
            json!({"effective_scope":scope,"mode":"public","extra":true}),
        );
        assert!(publish_transition(Some(&public), &renamed).is_err());
    }
}
