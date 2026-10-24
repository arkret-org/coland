//! Authorization HTTP surface.
//!
//! Surfaces:
//! - `POST /_arkret/self/authz/check`             — evaluate one (actor, action, resource)
//! - `GET  /_arkret/self/authz/effective-grants`  — direct grants visible to a subject
//! - `GET  /_arkret/self/authz/invites`           — pending invites visible to the actor
//!
//! Grants and invites are read from their durable typed current results at one
//! cut (`src/authz.rs`, the Invite typed current store). This surface is a
//! local preflight/read; canonical Event admission remains authoritative.

use arkret_identifiers::RealmId;
use arkret_models_collaboration::governance::authorization::{
    AuthorizationInvitePage, EffectiveCapabilityGrantView, EffectiveGrantSnapshot,
};
use arkret_models_collaboration::governance::invite_addressing::InviteDelivery;
use arkret_models_collaboration::governance::operation_wire::Invite;
use arkret_wire::{
    AccountDataKey, AccountId, ActorId, AuthorizationDecision, DidCoreId, InviteState,
};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::oapi::endpoint;
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use serde_json::json;

use super::{now, query_param};
use crate::authz::CapabilityVerdict;
use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;
use crate::wire::{AuthorizationCheckRequestBody, AuthorizationCheckResponseBody};

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("authz/check").post(authz_check))
        .push(Router::with_path("authz/effective-grants").get(effective_grants))
        .push(Router::with_path("authz/invites").get(invites))
}

#[endpoint(
    operation_id = "ak.self.authz.read.check",
    summary = "Evaluate an authorization decision",
    tags("authz")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.read.check.v1"))]
async fn authz_check(
    aa: AuthArgs,
    body: JsonBody<AuthorizationCheckRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuthorizationCheckResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let session_actor_id =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    if let Some(outcome) = state
        .authority_commits()
        .owned_agent_authorization_check(&session_actor_id, &state.service_core_id(), &body)
        .await
        .map_err(|_| AppError::capability_denied("current authorization cannot be confirmed"))?
    {
        return json_ok(outcome);
    }
    if body.actor_id != session_actor_id {
        return Err(AppError::capability_denied(
            "authorization checks may only target the authenticated actor",
        ));
    }
    let now = now();
    let verdict = match body.resource.as_ref() {
        _ if crate::authz::validate_runtime_capability_action(&body.action).is_err() => None,
        Some(target) => match target.realm_id.as_ref() {
            Some(realm_id) => {
                let authorization =
                    crate::authz::actor_realm_authorization(state, realm_id, &body.actor_id, now)
                        .await?;
                Some(coland_services::authorization::evaluate(
                    &authorization,
                    &[body.action.as_str()],
                    target,
                    &coland_storage::OperationFacts::default(),
                ))
            }
            None => None,
        },
        None => None,
    };
    let reason_code = match &verdict {
        Some(verdict) if verdict.allowed() => None,
        Some(
            CapabilityVerdict::ConstraintsNotSatisfied
            | CapabilityVerdict::Quarantined
            | CapabilityVerdict::RequiresReview,
        ) => Some("constraints_not_satisfied"),
        _ => Some(
            crate::authz::validate_runtime_capability_action(&body.action)
                .err()
                .unwrap_or_else(|| crate::authz::default_deny_reason(&body.action)),
        ),
    };
    let matched_grants = match &verdict {
        Some(CapabilityVerdict::Granted(grants)) => grants
            .iter()
            .map(|effective| {
                json!({
                    "grant_id": effective.grant.id,
                    "subject": effective.grant.subject,
                    "actions": effective.grant.actions,
                    "resources": effective.grant.resources,
                })
                .as_object()
                .expect("diagnostic object literal")
                .clone()
            })
            .collect(),
        _ => Vec::new(),
    };
    // A matching `quarantine` / `require_review` constraint of a named grant
    // is its own decision (constraint-schema.md section 15.4); every other
    // refusal maps to the conservative terminal `hard_deny`.
    let decision = match &verdict {
        _ if reason_code.is_none() => AuthorizationDecision::Allow,
        Some(CapabilityVerdict::Quarantined) => AuthorizationDecision::Quarantine,
        Some(CapabilityVerdict::RequiresReview) => AuthorizationDecision::RequireReview,
        _ => AuthorizationDecision::HardDeny,
    };
    let policy_evaluations = vec![
        json!({
            "actor_id": body.actor_id,
            "action": body.action,
            "resource": body.resource,
            "reason_detail": match &verdict {
                Some(CapabilityVerdict::RealmOwner) => Some("realm_owner_aggregate"),
                Some(CapabilityVerdict::Granted(_)) => Some("explicit_grant"),
                _ => None,
            },
            "constraints": [],
            "missing_proofs": [],
            "cache": {
                "mode": "durable_current",
                "evaluated_at": arkret_canonical::format_timestamp_canonical(now),
            }
        })
        .as_object()
        .expect("diagnostic object literal")
        .clone(),
    ];
    json_ok(AuthorizationCheckResponseBody {
        decision,
        matched_grants,
        applied_constraints: Vec::new(),
        policy_evaluations,
        missing_proofs: Vec::new(),
        checkpoint: None,
        freshness_state: None,
        last_known_checkpoint_age_ms: None,
        authority_status: None,
        cache_expires_at: None,
        reason_code: reason_code.map(arkret_wire::ReasonCode::from_wire),
        retry_after_ms: None,
        obligations: Vec::new(),
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn effective_grants_query_preserves_explicit_actor_id_variant_and_credential_default() {
        let principal = super::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = super::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account =
            super::ActorId::account(super::AccountId::new(principal.clone(), station.clone()));
        let foreign = super::ActorId::account(super::AccountId::new(
            principal.clone(),
            super::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        ));
        let service = super::ActorId::service(principal);
        for actor in [&account, &foreign, &service] {
            let parsed =
                super::effective_grants_subject(Some(&actor.to_string()), false, &account).unwrap();
            assert_eq!(&parsed, actor);
            assert_eq!(
                super::effective_grants_subject(None, false, actor).unwrap(),
                *actor
            );
        }
        assert!(!super::effective_grants_subject_allowed(
            &foreign, &account, false
        ));
        assert!(!super::effective_grants_subject_allowed(
            &service, &account, false
        ));
        assert!(super::effective_grants_subject(None, true, &account).is_err());
        assert!(
            super::effective_grants_subject(Some(&foreign.to_string()), true, &account).is_err()
        );
        assert!(
            super::effective_grants_subject(
                Some(account.signing_principal_id().as_str()),
                false,
                &account
            )
            .is_err()
        );
    }

    #[test]
    fn effective_grants_query_rejects_same_principal_foreign_station_without_owner_scope() {
        let principal = super::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = super::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let other = super::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        for principal in [
            principal,
            super::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
        ] {
            let local =
                super::ActorId::account(super::AccountId::new(principal.clone(), station.clone()));
            let foreign = super::ActorId::account(super::AccountId::new(principal, other.clone()));
            let parsed =
                super::effective_grants_subject(Some(&foreign.to_string()), false, &local).unwrap();
            assert_eq!(parsed, foreign);
            assert!(!super::effective_grants_subject_allowed(
                &parsed, &local, false
            ));
            assert!(super::effective_grants_subject_allowed(
                &parsed, &local, true
            ));
            assert!(super::effective_grants_subject_allowed(
                &local, &local, false
            ));
        }
    }

    #[test]
    fn invite_query_requires_exact_account_or_authenticated_self() {
        let account = super::AccountId::new(
            super::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            super::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let actor = super::ActorId::account(account.clone());
        assert_eq!(
            super::invite_subject_account(None, None, &actor).unwrap(),
            account
        );
        assert!(
            super::invite_subject_account(Some(account.principal_id.to_string()), None, &actor)
                .is_err()
        );
        assert!(
            super::invite_subject_account(None, Some(account.station_id.to_string()), &actor)
                .is_err()
        );
        let foreign = super::invite_subject_account(
            Some(account.principal_id.to_string()),
            Some("ak:did_core:web:other.example".into()),
            &actor,
        )
        .unwrap();
        assert_ne!(foreign, account);
        assert_eq!(foreign.station_id.as_str(), "ak:did_core:web:other.example");
        assert!(
            super::invite_subject_account(
                None,
                None,
                &super::ActorId::service(account.principal_id)
            )
            .is_err()
        );
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.self.authz.grants.read.effective", tags("access"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.grants.read.effective.v1"))]
async fn effective_grants(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::JsonResult<EffectiveGrantSnapshot> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_read = req.headers().contains_key("source-service-id");
    let session_actor = if service_read {
        let service =
            crate::routing::extensions::applet_bridge::verify_self_service_grant_read(state, req)
                .await?;
        ActorId::service(service.service_id)
    } else {
        let session = aa.authenticated_session(state, req).await?;
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?
    };
    let unaccepted_subject_present = ["subject", "subject_station_id", "subject_account_id"]
        .iter()
        .any(|key| query_param(req, key).is_some());
    let subject_actor = effective_grants_subject(
        query_param(req, "subject_actor_id").as_deref(),
        unaccepted_subject_present,
        &session_actor,
    )?;
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| AppError::param_invalid("realm_id is required"))
        .and_then(|value| {
            RealmId::new(value).map_err(|_| AppError::param_invalid("realm_id is invalid"))
        })?;
    let evaluated_at = query_param(req, "at")
        .map(|value| {
            DateTime::parse_from_rfc3339(&value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| AppError::param_invalid("at is invalid"))
        })
        .transpose()?
        .unwrap_or_else(now);
    let caller_can_query_subject = effective_grants_subject_allowed(
        &subject_actor,
        &session_actor,
        !service_read && session_owns_realm(state, &session_actor, &realm_id).await?,
    );
    if !caller_can_query_subject {
        return Err(AppError::capability_denied(
            "effective-grants subject requires self or realm owner scope",
        ));
    }
    let authorization =
        crate::authz::actor_realm_authorization(state, &realm_id, &subject_actor, evaluated_at)
            .await?;
    let grants = authorization
        .grants
        .into_iter()
        .map(EffectiveCapabilityGrantView::from)
        .collect::<Vec<_>>();
    let state_digest = coland_storage::effective_capability_grant_state_digest(&grants)
        .map_err(|error| AppError::internal(format!("effective grant digest failed: {error}")))?;
    coland_http::result::json_ok(EffectiveGrantSnapshot {
        grants,
        state_digest,
        evaluated_at,
    })
}

fn effective_grants_subject(
    subject_actor_id: Option<&str>,
    unaccepted_subject_present: bool,
    session_actor: &ActorId,
) -> Result<ActorId, AppError> {
    if unaccepted_subject_present {
        return Err(AppError::param_invalid(
            "effective-grants accepts only subject_actor_id; subject, subject_station_id and subject_account_id are invalid",
        ));
    }
    match subject_actor_id {
        Some(value) => serde_json::from_str::<ActorId>(value)
            .map_err(|_| AppError::param_invalid("subject_actor_id must be a complete ActorId")),
        None => Ok(session_actor.clone()),
    }
}

fn effective_grants_subject_allowed(
    subject: &ActorId,
    session_actor: &ActorId,
    session_owns_realm: bool,
) -> bool {
    subject == session_actor || session_owns_realm
}

/// Whether `actor` holds the effective `ak.realm.owner` aggregate of
/// `realm_id` at this instant, read from the durable authorization cut.
async fn session_owns_realm(
    state: &AppState,
    actor: &ActorId,
    realm_id: &RealmId,
) -> Result<bool, AppError> {
    Ok(
        crate::authz::actor_realm_authorization(state, realm_id, actor, now())
            .await?
            .holds_realm_owner(),
    )
}

fn invite_subject_account(
    subject: Option<String>,
    station: Option<String>,
    session_actor: &ActorId,
) -> Result<AccountId, AppError> {
    match (subject, station) {
        (None, None) => session_actor
            .as_account_id()
            .cloned()
            .ok_or_else(|| AppError::param_invalid("invite subject requires an Account")),
        (Some(subject), Some(station)) => Ok(AccountId::new(
            DidCoreId::new(subject).map_err(|_| AppError::param_invalid("subject is invalid"))?,
            DidCoreId::new(station)
                .map_err(|_| AppError::param_invalid("subject_station_id is invalid"))?,
        )),
        _ => Err(AppError::param_invalid(
            "subject and subject_station_id must be supplied together",
        )),
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.self.authz.invites.read.list", tags("access"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.authz.invites.read.list.v1"))]
async fn invites(
    aa: crate::routing::system::extract::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::JsonResult<AuthorizationInvitePage> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let subject = invite_subject_account(
        query_param(req, "subject"),
        query_param(req, "subject_station_id"),
        &session_actor,
    )?;
    let subject_actor = ActorId::account(subject.clone());
    let realm_filter = query_param(req, "realm_id")
        .map(|value| {
            RealmId::new(value).map_err(|_| AppError::param_invalid("realm_id is invalid"))
        })
        .transpose()?;
    let subject_is_self = subject_actor == session_actor;
    let caller_owns_realm = match realm_filter.as_ref() {
        Some(realm_id) if !subject_is_self => {
            session_owns_realm(state, &session_actor, realm_id).await?
        }
        _ => false,
    };
    // invite-addressing.md §7: the accepted Realm Event establishes the
    // shared Invite lifecycle, but only the notify branch materializes the
    // holder-private invite delivery. Quarantined, dropped, and rejected
    // dispatches MUST therefore stay out of the holder's invite list even
    // though their shared `ak.invite.create` Event is already durable.
    let holder_delivery_ids = if subject_is_self {
        let delivery = state
            .account_data()
            .entry(
                &subject_actor.to_string(),
                AccountDataKey::ACCOUNT_INVITE_DELIVERY,
            )
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .map(|record| serde_json::from_value::<InviteDelivery>(record.payload))
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("invite delivery cell does not parse: {error}"))
            })?;
        Some(
            delivery
                .into_iter()
                .flat_map(|delivery| delivery.delivery_entries)
                .map(|entry| entry.invite_id)
                .collect::<std::collections::BTreeSet<_>>(),
        )
    } else {
        None
    };
    let now = now();
    let invite_list = state
        .persistence()
        .open_directed_invites_for_invitee(&subject, realm_filter.as_ref())
        .await
        .map_err(|error| AppError::internal(format!("invite current read failed: {error}")))?
        .into_iter()
        .filter(|invite| {
            invite.expires_at > now
                && holder_delivery_ids
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&invite.invite_id))
                && (subject_is_self || invite.inviter == session_actor || caller_owns_realm)
        })
        .map(directed_invite_to_sdk)
        .collect::<Result<Vec<_>, _>>()?;
    coland_http::result::json_ok(AuthorizationInvitePage {
        invites: invite_list,
        next_cursor: None,
        has_more: false,
    })
}

fn directed_invite_to_sdk(
    invite: coland_storage::DirectedInviteCurrent,
) -> Result<Invite, AppError> {
    let inviter_account_id = invite
        .inviter
        .as_account_id()
        .cloned()
        .ok_or_else(|| AppError::internal("stored Invite inviter is not an Account"))?;
    let pending = invite.state == InviteState::Pending;
    Ok(Invite {
        schema: arkret_wire::SchemaId::INVITE_V1.to_owned(),
        id: invite.invite_id,
        realm_id: invite.realm_id,
        inviter_account_id,
        invitee_account_id: Some(invite.invitee_account_id),
        introduction_evidence_digest: Some(invite.introduction_evidence_digest),
        third_party_invite: None,
        capability_grant_refs: Vec::new(),
        expires_at: invite.expires_at,
        state: invite.state,
        created_at: invite.created_at,
        updated_by: None,
        updated_at: (!pending).then_some(invite.state_updated_at),
    })
}
