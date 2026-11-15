//! One authenticated delivery, one historical installation source tuple.
//! No writes or locks: actual accepting UOWs recheck the same facts under R.
use arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef;
use arkret_wire::{AppletId, DidCoreId, EventId, ScopeRef};
use diesel::sql_types::Nullable;

use super::*;

#[derive(Eq, PartialEq)]
pub(super) struct Source {
    scope: ScopeRef,
    registration_epoch: arkret_wire::Hash,
    pub(super) install_id: Option<String>,
}

/// Follow only accepted, immutable ancestry to the existing source table.
/// This locates provenance; it neither evaluates actions nor confers authority.
pub(super) async fn source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    applet: &AppletId,
    service: &DidCoreId,
    scope: ScopeRef,
) -> PersistenceResult<Source> {
    #[derive(diesel::QueryableByName)]
    struct Frozen {
        #[diesel(sql_type=Text)]
        registration_event_ref: String,
        #[diesel(sql_type=Nullable<Text>)]
        install_id: Option<String>,
    }
    let anchor = event
        .authorization_ref
        .as_ref()
        .ok_or_else(|| denied("delivery authorization source absent"))?
        .as_str()
        .parse::<GrantId>()
        .map_err(denied)?;
    let mut pending = vec![anchor];
    let mut seen = std::collections::BTreeSet::new();
    let mut selected = None;
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let original_id = EventId::from_token_bytes(id.token_bytes()).map_err(denied)?;
        let original = crate::applet_authority_material::accepted(conn, &original_id).await?;
        if original.event.kind != EventKind::CapabilityGrant
            || original.event.realm_id != event.realm_id
            || original.event.scope_ref != ScopeRef::realm(event.realm_id.clone())
        {
            return Err(denied("delivery source is not an accepted Realm Grant"));
        }
        let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
            serde_json::from_value(
                serde_json::to_value(&original.event.payload)
                    .map_err(PersistenceError::database)?,
            )
            .map_err(denied)?;
        let frozen = sql_query("SELECT registration_event_ref,install_id FROM applet_grant_registration_sources WHERE realm_id=$1 AND grant_id=$2 AND applet_id=$3 AND service_id=$4")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(id.as_str())
            .bind::<Text,_>(applet.as_str()).bind::<Text,_>(service.as_str())
            .get_result::<Frozen>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if let Some(frozen) = frozen {
            if !matches!(&payload.grant.subject,CapabilitySubject::Actor(actor) if actor==&ActorId::service(service.clone()))
                || !payload
                    .grant
                    .resources
                    .iter()
                    .any(|r| r.is_exact_scope(&scope))
            {
                return Err(denied(
                    "delivery parent does not bind the exact Service/effect scope",
                ));
            }
            let registration = frozen
                .registration_event_ref
                .parse::<EventId>()
                .map_err(denied)?;
            let original_registration =
                crate::applet_authority_material::accepted(conn, &registration).await?;
            let body: AppletRegistrationPayload = serde_json::from_value(
                serde_json::to_value(&original_registration.event.payload)
                    .map_err(PersistenceError::database)?,
            )
            .map_err(denied)?;
            if original_registration.event.kind != EventKind::AppletRegistration
                || original_registration.event.realm_id != event.realm_id
                || original_registration.event.scope_ref != ScopeRef::realm(event.realm_id.clone())
                || body.applet_id != *applet
                || body.service_id != *service
                || original_registration.commit.stream_ref != original.commit.stream_ref
                || original_registration.commit.stream_position >= original.commit.stream_position
                || !payload.grant.constraints.iter().any(|c| {
                    c.constraint_kind == GrantConstraintKind::AuthorityControl
                        && c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
                        && c.applet_id.as_ref() == Some(applet)
                        && c.executed_by.as_ref() == Some(&ActorId::service(service.clone()))
                        && c.registration_epoch.as_ref() == Some(&body.registration_epoch)
                })
            {
                return Err(denied(
                    "delivery source registration differs from its accepted parent",
                ));
            }
            let candidate = Source {
                scope: scope.clone(),
                registration_epoch: body.registration_epoch,
                install_id: frozen.install_id,
            };
            if selected.as_ref().is_some_and(|old| old != &candidate) {
                return Err(denied(
                    "delivery ancestry mixes historical installation sources",
                ));
            }
            selected = Some(candidate);
        } else {
            if payload.grant.issuer_id != ActorId::service(service.clone())
                || payload.grant.issuer_authority_refs.is_empty()
            {
                return Err(denied("delivery has no frozen Applet parent source"));
            }
            for reference in payload.grant.issuer_authority_refs {
                let IssuerAuthorityRef::Grant { grant_id } = reference else {
                    return Err(denied("delivery ancestry lacks an accepted Applet parent"));
                };
                pending.push(grant_id);
            }
        }
    }
    selected.ok_or_else(|| denied("delivery source tuple is unavailable"))
}

pub(crate) async fn preflight_transaction(
    conn: &mut AsyncPgConnection,
    events: &[Event],
    replay: &coland_storage::AppletTransactionReplayRecord,
    guard: &AppletEventProducerGuard,
) -> PersistenceResult<()> {
    // Authentication B is already checked by HTTP. An exact existing delivery
    // recovers its original outcome; it is not re-authorized as a new business
    // operation at today's installation. Concurrent first insertion still uses
    // the original unique begin/CAS after this read-only observation.
    if crate::applets::existing_transaction_replay(conn, replay)
        .await?
        .is_some()
    {
        return Ok(());
    }
    let applet = &replay.applet_id;
    let service = &replay.source_id.parse::<DidCoreId>().map_err(denied)?;
    let first = events
        .first()
        .ok_or_else(|| denied("delivery has no Event"))?;
    let mut grants = None;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut selected = None;
    for event in events {
        if event.realm_id != first.realm_id
            || event.applet_id.as_ref() != Some(applet)
            || event.executed_by.as_ref().unwrap_or(&event.actor_id)
                != &ActorId::service(service.clone())
        {
            return Err(denied("delivery producer/Applet/Realm binding differs"));
        }
        let scope = if let Some(original) =
            crate::applet_authority_material::optional_accepted(conn, &event.event_id).await?
        {
            // A new outer HTTP key B never rewrites or re-verifies an accepted
            // Event A against today's document. Retained Commit-bound key A is
            // independently verified, including the complete exact Event.
            if original.event != *event {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: accepted Event bytes differ".into(),
                ));
            }
            let fact = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
                conn,
                event,
                &original.commit,
            )
            .await?
            .ok_or_else(|| denied("accepted delivery signer fact unavailable"))?;
            let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(service_fact)=&fact else {
                return Err(denied("accepted delivery has a different producer kind"));
            };
            if service_fact.actor != ActorId::service(service.clone())
                || service_fact.key.applet_id != *applet
            {
                return Err(denied(
                    "accepted delivery signer is not this Service/Applet",
                ));
            }
            let suite = arkret_canonical::canonical::digest_suite(
                event.event_id.digest_suite_code().as_str(),
            )
            .map_err(denied)?;
            fact.validate_commit_binding(&original, suite)
                .map_err(denied)?;
            arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(event,&fact,suite).map_err(denied)?;
            // A single exact accepted Event is a receipt lookup, not a new
            // authorization. Missing historical installation qualification may
            // prevent a mixed batch, but never reclassifies this original.
            if events.len() == 1 {
                continue;
            }
            // The original accepting UOW proved every finite parent has this
            // same tuple and instance. Full Event/Commit/fact above binds that
            // conclusion; source rows are immutable, so the signed anchor is
            // its compressed locator, not a new current authorization claim.
            service_fact.key.effective_scope.clone()
        } else {
            if grants.is_none() {
                grants = Some(load_current_grants(conn, &first.realm_id, false).await?);
            }
            let (fact, _) = require_applet_producer_inner(
                conn,
                event,
                guard,
                at,
                None,
                grants
                    .as_ref()
                    .expect("fresh delivery loaded its current graph"),
            )
            .await?;
            fact.key.effective_scope
        };
        let candidate = source(conn, event, applet, service, scope).await?;
        if selected.as_ref().is_some_and(|old| old != &candidate) {
            return Err(denied(
                "one delivery must bind one historical installation source tuple",
            ));
        }
        selected = Some(candidate);
    }
    Ok(())
}
