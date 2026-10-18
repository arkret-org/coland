//! Subject-original Applet interaction profiles, distinct from private PCR identity.
use arkret_models_identity::{ActorProfile, AppletInteractionIntent, AppletInteractionMode};
use arkret_wire::{ActorId, Event, EventKind, RealmCommit, ScopeRef};
use coland_storage::{AppletManagedDeviceScopeGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

/// Constructed only after real current state is read under the owning UoW's
/// ordered PCR and business Realm locks. It cannot authorize another original.
pub(crate) struct Admission {
    original_digest: String,
    profile: ActorProfile,
    previous: Option<Value>,
    public: bool,
}
impl Admission {
    pub(crate) fn applies_to(&self, event: &Event) -> bool {
        arkret_canonical::canonical_sha256(event).ok().as_ref() == Some(&self.original_digest)
    }
    pub(crate) fn is_public(&self) -> bool {
        self.public
    }
    pub(crate) fn pins(&self) -> Value {
        json!({"previous":self.previous,"postimage":self.profile})
    }
    pub(crate) async fn write(
        &self,
        conn: &mut AsyncPgConnection,
        event: &Event,
        commit: &RealmCommit,
    ) -> Result<(), crate::PgTransactionError> {
        if !self.applies_to(event) {
            return Err(denied("scope Profile admission belongs to another original").into());
        }
        crate::actor_profiles::write_profile_current_in_connection(
            conn,
            event,
            commit,
            &self.profile,
        )
        .await
    }
}

pub(crate) fn is_profile(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::ProfileCreate | EventKind::ProfileUpdate
    )
}

pub(crate) async fn prepare(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletManagedDeviceScopeGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Admission> {
    prepare_source(
        conn,
        event,
        crate::managed_forward_admission::Source::Local(guard),
        at,
    )
    .await
}

pub(crate) async fn prepare_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    source: crate::managed_forward_admission::Source<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Admission> {
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
    source.ensure_event(event, at)?;
    let pcr = match source {
        crate::managed_forward_admission::Source::Local(guard) => &guard.authority.pcr_realm_id,
        crate::managed_forward_admission::Source::Forwarded(source) => {
            &source
                .verified()
                .original()
                .creation
                .pcr_genesis
                .event
                .realm_id
        }
    };
    if !is_profile(event)
        || event.actor_id != ActorId::account(source.account().clone())
        || event.executed_by.is_some()
        || event.applet_id.as_ref() != Some(source.applet())
        || event.scope_ref.realm_id() != &event.realm_id
        || &event.realm_id == pcr
        || !matches!(
            crate::account_stream_scan::realm_purpose(conn, &event.realm_id).await?,
            Some(RealmPurpose::Collaboration)
        )
    {
        return Err(denied(
            "scope Profile requires its real native subject and collaboration scope",
        ));
    }
    let cut = crate::boxed_future(|| {
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event)
    })
    .await?;
    let cut = cut.with_forwarded_managed(source.forwarded());
    cut.require_open_lifecycle(event)?;
    cut.require_governed_member(&event.kind)?;
    match &event.scope_ref {
        ScopeRef::Realm { realm_id } if realm_id == &event.realm_id => {}
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == &event.realm_id => {
            let active=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM circle_current_results c JOIN realm_commits k ON k.commit_id=c.current_commit_id WHERE c.realm_id=$1 AND c.circle_id=$2 AND c.value->>'state'='active' AND k.realm_id=c.realm_id AND k.stream_ref=c.source_stream_ref AND k.stream_position=c.current_stream_position)) AS value")
                .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(circle_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if active.value.as_bool() != Some(true)
                || !crate::circle_current_results::effective_member_in_connection(
                    conn,
                    realm_id,
                    circle_id,
                    &event.actor_id,
                )
                .await?
            {
                return Err(denied(
                    "scope Profile requires an active Circle and effective member",
                ));
            }
        }
        _ => {
            return Err(denied(
                "Applet Profile scope is not an ordinary Realm or Circle",
            ));
        }
    }
    let identity = if let Some(source) = source.forwarded() {
        source
            .verified()
            .original()
            .current
            .profile
            .result
            .value
            .clone()
    } else {
        let identity=sql_query("SELECT value FROM actor_profile_current_results WHERE realm_id=$1 AND actor_id=$2 AND scope_ref=$3 FOR SHARE")
        .bind::<Text,_>(pcr.as_str()).bind::<Jsonb,_>(json!(event.actor_id))
        .bind::<Jsonb,_>(json!(ScopeRef::Realm{realm_id:pcr.clone()}))
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("native PCR identity Profile is unavailable"))?;
        let identity: ActorProfile = serde_json::from_value(identity.value).map_err(invalid)?;
        identity
    };
    let previous=sql_query("SELECT to_jsonb(p) AS value FROM actor_profile_current_results p WHERE realm_id=$1 AND actor_id=$2 AND scope_ref=$3 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(event.actor_id)).bind::<Jsonb,_>(json!(event.scope_ref))
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.map(|r|r.value);
    let profile = crate::boxed_future(|| {
        crate::actor_profiles::materialize_profile_at_with_source(
            conn,
            event,
            at,
            source.account(),
            source.forwarded(),
        )
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)?;
    if profile.principal_id != identity.principal_id
        || profile.actor_kind != identity.actor_kind
        || profile.accountable_principal_ids != identity.accountable_principal_ids
        || profile.realm_id.as_ref() != Some(&event.realm_id)
        || profile.resolution.is_some()
        || profile.agent_slug.is_some()
        || profile.profile_fields.get("managed_by_applet")
            != identity.profile_fields.get("managed_by_applet")
        || profile.profile_fields.get("external_ref") != identity.profile_fields.get("external_ref")
    {
        return Err(denied(
            "scope Profile changes accepted managed identity or private resolution",
        ));
    }
    let public = match profile.profile_fields.get("applet_interaction") {
        None => false,
        Some(value) => {
            let intent: AppletInteractionIntent =
                serde_json::from_value(value.clone()).map_err(invalid)?;
            if intent.effective_scope != event.scope_ref {
                return Err(denied(
                    "Applet interaction intent differs from the Profile's exact scope",
                ));
            }
            intent.mode == AppletInteractionMode::Public
        }
    };
    Ok(Admission {
        original_digest: arkret_canonical::canonical_sha256(event).map_err(invalid)?,
        profile,
        previous,
        public,
    })
}

/// Shared snapshot evidence is never installed as private PCR identity current.
pub(crate) fn validate_disclosed(
    profile_id: &arkret_wire::ActorProfileId,
    stream: &arkret_wire::CommitStreamRef,
    value: &Value,
) -> PersistenceResult<ActorProfile> {
    let profile: ActorProfile = serde_json::from_value(value.clone()).map_err(invalid)?;
    profile.validate_display_members().map_err(invalid)?;
    if profile.id.as_ref() != Some(profile_id)
        || profile.realm_id.as_ref() != Some(stream.realm_id())
        || profile.resolution.is_some()
        || !matches!(
            profile.actor_kind,
            arkret_wire::ActorKind::Bot | arkret_wire::ActorKind::Integration
        )
        || !matches!(
            stream,
            arkret_wire::CommitStreamRef::Realm { .. }
                | arkret_wire::CommitStreamRef::Circle { .. }
        )
    {
        return Err(invalid(
            "shared Applet Profile differs from its source or contains private identity",
        ));
    }
    if let Some(intent) = profile.profile_fields.get("applet_interaction") {
        let intent: AppletInteractionIntent =
            serde_json::from_value(intent.clone()).map_err(invalid)?;
        if arkret_wire::CommitStreamRef::from_scope(&intent.effective_scope, None)
            .map_err(invalid)?
            != *stream
        {
            return Err(invalid(
                "shared Applet Profile intent differs from its source",
            ));
        }
    }
    Ok(profile)
}

/// Pure projection of an already recipient-verified ordinary Event. No local
/// installation, authority, private identity or capability is manufactured.
pub(crate) async fn project_replica(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::{
        ActorProfileCreatePayload, ActorProfileUpdatePayload,
    };
    use arkret_wire::{ActorProfileId, CurrentRevision, CurrentSelector, TypedCurrentRow};
    if event.applet_id.is_none()
        || event.executed_by.is_some()
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None).map_err(invalid)?
    {
        return Err(denied(
            "shared Profile requires its original native subject and exact source",
        ));
    }
    let profile = match event.kind {
        EventKind::ProfileCreate => {
            let body: ActorProfileCreatePayload =
                serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            body.materialize(event).map_err(invalid)?
        }
        EventKind::ProfileUpdate => {
            let body: ActorProfileUpdatePayload =
                serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            let selector = json!(CurrentSelector::ActorProfile {
                actor_profile_id: body.target_ref.clone()
            });
            let previous=sql_query("SELECT value FROM replica_authorization_rows WHERE realm_id=$1 AND selector=$2 AND source_stream_ref=$3 FOR UPDATE")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(selector).bind::<Jsonb,_>(json!(commit.stream_ref)).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
                .ok_or_else(||PersistenceError::Conflict("revision_unavailable: shared Profile postimage needs its verified current".into()))?;
            let current =
                validate_disclosed(&body.target_ref, &commit.stream_ref, &previous.value)?;
            body.apply(event, &current).map_err(invalid)?
        }
        _ => return Err(invalid("not a shared Profile Event")),
    };
    if event.actor_id.as_account_id().map(|a| &a.principal_id) != Some(&profile.principal_id) {
        return Err(denied("shared Profile differs from its original subject"));
    }
    let id = profile
        .id
        .clone()
        .ok_or_else(|| invalid("shared Profile has no id"))?;
    if event.kind == EventKind::ProfileCreate
        && id != ActorProfileId::from_event_id(&event.event_id)
    {
        return Err(invalid("shared Profile create id differs"));
    }
    let value = json!(profile);
    validate_disclosed(&id, &commit.stream_ref, &value)?;
    crate::replica_authorization::save_row(
        conn,
        &event.realm_id,
        &TypedCurrentRow::Value {
            selector: CurrentSelector::ActorProfile {
                actor_profile_id: id,
            },
            source_stream_ref: commit.stream_ref.clone(),
            revision: CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            value,
        },
        commit.committed_at,
    )
    .await
}

#[cfg(test)]
mod replica_tests {
    use arkret_wire::*;

    use super::*;

    /// Projection component fixture: caller verification is outside this unit.
    /// This test creates no managed provision, accepted identity or private PCR row.
    #[tokio::test]
    async fn scoped_profile_snapshot_and_tail_keep_public_evidence_without_private_identity() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x72; 32],
        ));
        let actor = ActorId::account(AccountId::new(
            "ak:did_core:web:managed-profile.example".parse().unwrap(),
            "ak:did_core:web:profile-origin.example".parse().unwrap(),
        ));
        let id = ActorProfileId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x73; 32],
        ));
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let value = json!({"id":id,"schema":ActorProfile::SCHEMA,"realm_id":realm,"principal_id":actor.signing_principal_id(),"actor_kind":"bot","display_name":"Scoped Bot","accountable_principal_ids":["ak:did_core:web:profile-service.example"],"profile_fields":{"managed_by_applet":"ak:applet:0198ff00-0000-7000-8000-000000000075","applet_interaction":{"effective_scope":scope,"mode":"public"}},"created_at":at});
        let head = CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: RealmCommitId::from_digest([7; 32]),
        };
        let entry = TypedCurrentRow::Value {
            selector: CurrentSelector::ActorProfile {
                actor_profile_id: id.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: value.clone(),
        };
        crate::replica_current::install_snapshot_in_connection(
            &mut conn,
            &realm,
            &head,
            &[entry.clone()],
            at,
        )
        .await
        .unwrap();
        let read = "SELECT jsonb_build_object('rows',(SELECT jsonb_agg(to_jsonb(r)) FROM replica_authorization_rows r WHERE realm_id=$1),'private_profiles',(SELECT count(*) FROM actor_profile_current_results WHERE realm_id=$1)) AS value";
        let before = sql_query(read)
            .bind::<Text, _>(realm.as_str())
            .get_result::<JsonRow>(&mut conn)
            .await
            .unwrap()
            .value;
        assert_eq!(before["private_profiles"], 0);
        assert_eq!(before["rows"][0]["value"], value);
        for private in [json!("resolution"), json!("scope")] {
            let mut malformed = entry.clone();
            let TypedCurrentRow::Value { value, .. } = &mut malformed;
            if private == "resolution" {
                value["resolution"] = json!({});
            } else {
                value["profile_fields"]["applet_interaction"]["effective_scope"] = json!({"kind":"circle","realm_id":realm,"circle_id":CircleId::from_event_id(&EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[0x74;32]))});
            }
            sql_query("BEGIN").execute(&mut conn).await.unwrap();
            assert!(
                crate::replica_current::install_snapshot_in_connection(
                    &mut conn,
                    &realm,
                    &head,
                    &[malformed],
                    at
                )
                .await
                .is_err()
            );
            sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
            assert_eq!(
                before,
                sql_query(read)
                    .bind::<Text, _>(realm.as_str())
                    .get_result::<JsonRow>(&mut conn)
                    .await
                    .unwrap()
                    .value
            );
        }
        let mut event=arkret_wire::test_support::raw_event_for_actor_at(EventKind::ProfileUpdate.as_str(),scope,actor,json!({"target_ref":id,"patch":{"profile_fields.applet_interaction.mode":"private","display_name":"Updated scoped Bot"}}),at).unwrap();
        event.applet_id = Some(
            "ak:applet:0198ff00-0000-7000-8000-000000000075"
                .parse()
                .unwrap(),
        );
        let commit = RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: RealmCommitId::from_digest([8; 32]),
            realm_id: realm.clone(),
            stream_ref: stream,
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id.clone()),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
            committed_at: at,
            signature: DetachedObjectSignature {
                context: DetachedSignatureContext::RealmCommit,
                signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
                verification_method: DidUrl::new("did:web:profile-origin.example#authority")
                    .unwrap(),
                signed_digest: Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
                created_at: at,
                sig: Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        };
        crate::replica_current::advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap();
        let after = sql_query(read)
            .bind::<Text, _>(realm.as_str())
            .get_result::<JsonRow>(&mut conn)
            .await
            .unwrap()
            .value;
        assert_eq!(after["private_profiles"], 0);
        assert_eq!(
            after["rows"][0]["value"]["display_name"],
            "Updated scoped Bot"
        );
        assert_eq!(
            after["rows"][0]["value"]["profile_fields"]["applet_interaction"]["mode"],
            "private"
        );
        assert_eq!(
            after["rows"][0]["current_commit_id"],
            json!(commit.commit_id)
        );
    }
}
