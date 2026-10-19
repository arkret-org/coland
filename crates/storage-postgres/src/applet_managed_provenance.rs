//! Private original Service history and the managed first-forward source.

use arkret_models_collaboration::authority_commit::{
    ForwardManagedActorProvenance, ManagedAccountabilityCurrent, ManagedAccountabilitySelector,
    ManagedCreationAcceptedEvent, ManagedCreationOriginals, ManagedIdentityCurrent,
    ManagedIdentityResult, ManagedProfileCurrent, ManagedProfileSelector,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityProjection,
};
use arkret_models_identity::{ActorProfile, AuthenticatedServiceResolution};
use arkret_models_integration::{
    AppletManagedActorProvisionPayload, AppletManagedActorRole, GhostActorProfileFields,
};
use arkret_wire::{ActorId, ActorKind, CurrentRevision, Event, EventId, RealmCommit, ScopeRef};
use coland_storage::{AppletAuthoringUnitWrite, PersistenceError, PersistenceResult};
use diesel::sql_types::{Binary, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

/// A mutable current DID projection is never an archival substitute. Every
/// original is independently verified under its actual historical assertion
/// method before any accepted creation source can be retained.
pub(crate) async fn validate_creation_service_history(
    input: &AppletAuthoringUnitWrite,
    originals: &[Event],
) -> PersistenceResult<()> {
    let input = input.clone();
    let originals = originals.to_vec();
    tokio::task::spawn_blocking(move || validate_creation_history(&input, &originals))
        .await
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "creation history verification task failed: {error}"
            ))
        })?
}

fn validate_creation_history(
    input: &AppletAuthoringUnitWrite,
    originals: &[Event],
) -> PersistenceResult<()> {
    if originals.is_empty() {
        if input.creation_service_resolution.is_some() {
            return Err(denied(
                "installation or reuse cannot replace creation history",
            ));
        }
        return Ok(());
    }
    if originals.len() != 4 {
        return Err(denied("managed creation has no closed four-Event source"));
    }
    let source = input
        .creation_service_resolution
        .as_ref()
        .ok_or_else(|| denied("managed creation requires original Service method history"))?;
    arkret_identity::verify_authenticated_service_resolution_history(
        source,
        &input.package.service_id,
        input.accepted_at,
    )
    .map_err(denied)?;
    if arkret_models_identity::normalized_did_document_digest(&source.normalized_did_document)
        .map_err(denied)?
        != arkret_models_identity::normalized_did_document_digest(&input.service_did_document)
            .map_err(denied)?
    {
        return Err(denied(
            "creation history differs from the admitted Service document",
        ));
    }
    let service = ActorId::service(input.package.service_id.clone());
    for event in originals {
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| denied("managed creation original has no Service proof"))?;
        let document = arkret_identity::authenticated_service_document_at(
            source,
            &input.package.service_id,
            event.created_at,
        )
        .map_err(denied)?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &proof.verification_method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(denied)?;
        let key = arkret_identity::public_key_material_from_document(
            &document,
            &proof.verification_method,
        )
        .map_err(denied)?;
        let suite = arkret_canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(denied)?;
        arkret_identity::VerifiedProducerEvent::verify(
            event.clone(),
            &arkret_identity::ProducerVerificationContext {
                actor: service.clone(),
                verification_method: proof.verification_method.clone(),
                public_key: key,
                digest_suite: suite,
            },
        )
        .map_err(denied)?;
    }
    Ok(())
}

#[derive(QueryableByName)]
struct StoredServiceSource {
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Jsonb)]
    service_resolution: Value,
}

#[derive(QueryableByName)]
struct ExactCurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct OriginalRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

async fn accepted_original(
    conn: &mut AsyncPgConnection,
    id: &EventId,
) -> PersistenceResult<ManagedCreationAcceptedEvent> {
    let row = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(id.token_bytes().to_vec())
    .get_result::<OriginalRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| denied("original managed creation Event/Commit is unavailable"))?;
    Ok(ManagedCreationAcceptedEvent {
        event: serde_json::from_value(row.envelope).map_err(PersistenceError::database)?,
        commit: serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?,
    })
}

/// The caller already verified this exact native Event and holds its confirmed
/// PCR writer lock. Both current rows remain share-locked through attestation
/// preparation or its final immutable retention check.
pub(crate) async fn prepare_managed_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    fact: &arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact,
    attested_at: chrono::DateTime<chrono::Utc>,
    device_deadline: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ForwardManagedActorProvenance> {
    let actor = ActorId::account(authority.account_id.clone());
    if event.actor_id != actor || event.applet_id.as_ref() != Some(&authority.applet_id) {
        return Err(denied(
            "managed source differs from the actual native producer",
        ));
    }
    let row = sql_query(
        "SELECT p.value,c.commit_json FROM actor_profile_current_results p \
         JOIN realm_commits c ON c.commit_id=p.current_commit_id \
           AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position \
         JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE p.realm_id=$1 AND p.actor_id=$2 AND p.scope_ref=$3 FOR SHARE OF p",
    )
    .bind::<Text, _>(authority.pcr_realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&actor).map_err(PersistenceError::database)?)
    .bind::<Jsonb, _>(
        serde_json::to_value(ScopeRef::Realm {
            realm_id: authority.pcr_realm_id.clone(),
        })
        .map_err(PersistenceError::database)?,
    )
    .get_result::<ExactCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| denied("managed Profile current is unavailable at its exact PCR"))?;
    let profile: ActorProfile =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    let profile_commit: RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    let profile_id = profile
        .id
        .clone()
        .ok_or_else(|| denied("managed Profile has no original identity"))?;
    let original_profile = accepted_original(
        conn,
        &EventId::from_token_bytes(profile_id.token_bytes()).map_err(denied)?,
    )
    .await?;
    let original_accountability = accepted_original(
        conn,
        &crate::managed_message_actor::exact_ref(&original_profile.event, "accountability")?,
    )
    .await?;
    let original_provision = accepted_original(
        conn,
        &crate::managed_message_actor::exact_ref(
            &original_accountability.event,
            "applet_managed_actor_provision",
        )?,
    )
    .await?;
    let genesis = accepted_original(
        conn,
        &EventId::from_token_bytes(authority.pcr_realm_id.token_bytes()).map_err(denied)?,
    )
    .await?;
    let provision: AppletManagedActorProvisionPayload = serde_json::from_value(
        serde_json::to_value(&original_provision.event.payload)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let role = match provision.actor_role {
        AppletManagedActorRole::Bot => ActorKind::Bot,
        AppletManagedActorRole::Ghost => ActorKind::Integration,
    };
    if provision.actor_id != actor
        || provision.applet_id != authority.applet_id
        || provision.service_id != authority.source_service_id
        || profile.principal_id != authority.account_id.principal_id
        || profile.actor_kind != role
        || profile.accountable_principal_ids.as_slice() != [authority.source_service_id.clone()]
        || profile.profile_fields.get("managed_by_applet")
            != Some(
                &serde_json::to_value(&authority.applet_id).map_err(PersistenceError::database)?,
            )
        || profile_commit.stream_position > fact.key.revision.stream_position
        || profile_commit.governance_generation > fact.key.governance_generation
        || (profile_commit.stream_position == fact.key.revision.stream_position
            && profile_commit.commit_id != fact.key.revision.commit_id)
    {
        return Err(denied(
            "managed current Profile differs from its native creation or PCR cut",
        ));
    }
    if provision.actor_role == AppletManagedActorRole::Ghost {
        let ghost = GhostActorProfileFields::from_profile_fields(&profile.profile_fields)
            .map_err(denied)?;
        if provision.external_ref.as_ref() != Some(&ghost.external_ref) {
            return Err(denied(
                "current Ghost tuple differs from its original creation",
            ));
        }
    } else if profile.profile_fields.get("external_ref").is_some() {
        return Err(denied("Bot Profile cannot acquire a Ghost tuple"));
    }
    let accountability =
        exact_accountability_current(conn, &original_accountability.event, attested_at).await?;
    if profile_commit.committed_at > attested_at || accountability.commit.committed_at > attested_at
    {
        return Err(PersistenceError::Conflict(
            "temporarily_unavailable: identity source advanced after its frozen Device cut".into(),
        ));
    }
    let expires_at = accountability
        .result
        .value
        .expires_at
        .map_or(device_deadline, |end| device_deadline.min(end));
    if expires_at <= chrono::Utc::now() {
        return Err(denied("managed source expired during preparation"));
    }
    let resolution =
        read_creation_service_history(conn, &original_provision.event.event_id).await?;
    if resolution.service_id != authority.source_service_id {
        return Err(denied(
            "creation Service history belongs to a different original issuer",
        ));
    }
    Ok(ForwardManagedActorProvenance {
        creation: ManagedCreationOriginals {
            provision: original_provision,
            pcr_genesis: genesis,
            accountability: original_accountability,
            profile: original_profile,
        },
        service_resolution: resolution,
        current: ManagedIdentityCurrent {
            profile: ManagedProfileCurrent {
                realm_id: authority.pcr_realm_id.clone(),
                result: ManagedIdentityResult {
                    selector: ManagedProfileSelector::ActorProfile {
                        actor_profile_id: profile_id,
                    },
                    source_stream_ref: profile_commit.stream_ref.clone(),
                    revision: CurrentRevision {
                        commit_id: profile_commit.commit_id.clone(),
                        stream_position: profile_commit.stream_position,
                    },
                    value: profile,
                },
                commit: profile_commit,
            },
            accountability,
            expires_at,
        },
    })
}

/// Qualify only the original endorsement's registered current key. Another
/// Realm or another normalized scope set never repairs this source.
pub(crate) async fn exact_accountability_current(
    conn: &mut AsyncPgConnection,
    original: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ManagedAccountabilityCurrent> {
    let grant: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&original.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let scope = grant
        .accountability_scope
        .normalized_set()
        .map_err(denied)?;
    let digest = scope.digest().map_err(denied)?;
    let row = sql_query(
        "SELECT a.value,c.commit_json FROM identity_accountability_current_results a \
         JOIN realm_commits c ON c.commit_id=a.current_commit_id \
           AND c.realm_id=a.realm_id AND c.stream_position=a.current_stream_position \
         JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE a.realm_id=$1 AND a.issuer_id=$2 AND a.subject_id=$3 \
           AND a.scope_set_digest=$4 AND a.accountability_scope=$5 FOR SHARE OF a",
    )
    .bind::<Text, _>(original.realm_id.as_str())
    .bind::<Text, _>(grant.issuer_id.as_str())
    .bind::<Text, _>(grant.subject_id.as_str())
    .bind::<Text, _>(digest.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&scope).map_err(PersistenceError::database)?)
    .get_result::<ExactCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| denied("original exact accountability current is unavailable"))?;
    let value: AccountabilityProjection =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    let commit: RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    if value.issuer_id != grant.issuer_id
        || value.subject_id != grant.subject_id
        || value.accountability_scope != scope
        || !value.verifies_at(at)
    {
        return Err(denied(
            "original exact accountability is not currently active",
        ));
    }
    Ok(ManagedAccountabilityCurrent {
        realm_id: original.realm_id.clone(),
        result: ManagedIdentityResult {
            selector: ManagedAccountabilitySelector::IdentityAccountability {
                issuer_id: grant.issuer_id,
                subject_id: grant.subject_id,
                accountability_scope: scope,
            },
            source_stream_ref: commit.stream_ref.clone(),
            revision: CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            value,
        },
        commit,
    })
}

pub(crate) async fn retain_creation_service_history(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringUnitWrite,
    provision: &Event,
) -> PersistenceResult<()> {
    let source = input
        .creation_service_resolution
        .as_ref()
        .ok_or_else(|| denied("accepted managed creation lost its Service history"))?;
    let value = serde_json::to_value(source).map_err(PersistenceError::database)?;
    let inserted = sql_query(
        "INSERT INTO applet_managed_creation_service_sources(\
         provision_event_pk,service_id,service_resolution,accepted_at) \
         SELECT e.pk,$2,$3,$4 FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed' \
           AND e.kind='ak.applet.managed_actor.provision' \
           AND e.envelope=$5 AND c.committed_at=$4 \
         ON CONFLICT(provision_event_pk) DO NOTHING",
    )
    .bind::<Binary, _>(provision.event_id.token_bytes().to_vec())
    .bind::<Text, _>(input.package.service_id.as_str())
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(input.accepted_at)
    .bind::<Jsonb, _>(serde_json::to_value(provision).map_err(PersistenceError::database)?)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        let retained = read_creation_service_history(conn, &provision.event_id).await?;
        if retained != *source {
            return Err(denied("immutable creation Service history already differs"));
        }
    }
    Ok(())
}

pub(crate) async fn read_creation_service_history(
    conn: &mut AsyncPgConnection,
    provision: &EventId,
) -> PersistenceResult<AuthenticatedServiceResolution> {
    let row = sql_query(
        "SELECT s.service_id,s.service_resolution \
         FROM applet_managed_creation_service_sources s \
         JOIN canonical_events e ON e.pk=s.provision_event_pk \
         WHERE e.id=$1 AND e.state='committed' \
           AND e.kind='ak.applet.managed_actor.provision' FOR SHARE OF s",
    )
    .bind::<Binary, _>(provision.token_bytes().to_vec())
    .get_result::<StoredServiceSource>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| denied("original creation Service history is unavailable"))?;
    let source: AuthenticatedServiceResolution =
        serde_json::from_value(row.service_resolution).map_err(PersistenceError::database)?;
    if source.service_id.as_str() != row.service_id {
        return Err(denied(
            "retained creation Service source has a different issuer",
        ));
    }
    Ok(source)
}
