//! Station-local inventory for independently scoped Applet widget credentials.
//! These records are internal persistence material, never SessionGrant wire data.

use arkret_models_integration::WidgetTokenScope;
use arkret_wire::{AppletId, EventId, Hash, ScopeRef};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Exact accepted install selected before issuance, inventory and invalidation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletWidgetInstallSelector {
    pub applet_id: AppletId,
    pub effective_scope: ScopeRef,
    pub registration_event_ref: EventId,
    pub registration_epoch: Hash,
}

/// The opaque token itself is returned only at issuance. Persist its hash and
/// scope; never persist or expose the host session token or device key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletWidgetTokenRecord {
    pub token_ref: String,
    pub install: AppletWidgetInstallSelector,
    pub token_digest: Hash,
    pub token_scope: WidgetTokenScope,
    pub consent_approved: bool,
    pub actor_id: arkret_wire::ActorId,
    pub authorization_ref: arkret_wire::GrantId,
    pub issued_at: DateTime<Utc>,
    pub invalidated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppletWidgetTokenInvalidation {
    Invalidated,
    AlreadyInvalidated,
}

/// Scope narrowing is shared with ordinary grant selector evaluation. Issuance
/// never upgrades a token to a user session or expands its signed scope.
pub fn validate_applet_widget_scope(
    declared: &WidgetTokenScope,
    requested: &WidgetTokenScope,
    install: &AppletWidgetInstallSelector,
    issued_at: DateTime<Utc>,
) -> super::PersistenceResult<()> {
    let reject = |detail: &str| super::PersistenceError::SchemaViolation(detail.into());
    if requested.actions.is_empty()
        || requested.resources.is_empty()
        || requested.expires_at <= issued_at
        || requested.expires_at > declared.expires_at
    {
        return Err(reject("widget token has empty or expired scope"));
    }
    if requested
        .actions
        .iter()
        .any(|action| !declared.actions.contains(action))
    {
        return Err(reject("widget token action exceeds its declaration"));
    }
    if let Some(maximum) = declared.max_ttl_seconds {
        let maximum =
            i64::try_from(maximum).map_err(|_| reject("widget maximum lifetime is too large"))?;
        let limit = issued_at
            .checked_add_signed(chrono::Duration::seconds(maximum))
            .ok_or_else(|| reject("widget maximum lifetime is outside the clock range"))?;
        if requested.expires_at > limit {
            return Err(reject("widget token exceeds its maximum lifetime"));
        }
    }
    let scope_resource = match &install.effective_scope {
        ScopeRef::Realm { realm_id } => arkret_wire::WireResourceSelector::realm(realm_id.clone()),
        _ => {
            return Err(reject(
                "widget token requires an exact Applet install scope",
            ));
        }
    };
    for requested_resource in &requested.resources {
        requested_resource
            .validate()
            .map_err(|error| reject(&error.to_string()))?;
        if !super::resource_selector_covers(&scope_resource, requested_resource)
            || !declared
                .resources
                .iter()
                .any(|parent| super::resource_selector_covers(parent, requested_resource))
        {
            return Err(reject(
                "widget token resource exceeds its declaration or install",
            ));
        }
    }
    let install_realm = scope_resource
        .realm_id
        .as_ref()
        .expect("scope resource carries its Realm");
    if requested.realm_ids.as_ref().is_some_and(|realms| {
        realms.is_empty() || realms.iter().any(|realm| realm != install_realm)
    }) || declared
        .realm_ids
        .as_ref()
        .is_some_and(|realms| !realms.contains(install_realm))
    {
        return Err(reject("widget token Realm exceeds its exact install"));
    }
    Ok(())
}

/// Internal same-cut widget narrowing attached alongside the original producer
/// guard. It never replaces a native Device or Applet producer proof.
#[derive(Clone, Debug)]
pub struct AppletWidgetTokenGateSelector {
    pub actor_id: arkret_wire::ActorId,
    pub authorization_ref: arkret_wire::GrantId,
    pub token_digest: Hash,
    pub install: AppletWidgetInstallSelector,
    pub action: String,
    pub target: arkret_wire::WireResourceSelector,
}

pub fn validate_applet_widget_token_use(
    record: &AppletWidgetTokenRecord,
    gate: &AppletWidgetTokenGateSelector,
    at: DateTime<Utc>,
) -> super::PersistenceResult<()> {
    if record.install != gate.install
        || record.token_digest != gate.token_digest
        || record.actor_id != gate.actor_id
        || record.authorization_ref != gate.authorization_ref
    {
        return Err(super::PersistenceError::Conflict(
            "applet_registration_unauthorized: widget token does not match its exact install"
                .into(),
        ));
    }
    if record.invalidated_at.is_some() {
        return Err(super::PersistenceError::Conflict(
            "applet_revoked: widget token was invalidated".into(),
        ));
    }
    if at < record.issued_at
        || at >= record.token_scope.expires_at
        || !record.token_scope.actions.contains(&gate.action)
        || !record
            .token_scope
            .resources
            .iter()
            .any(|selector| super::resource_selector_covers(selector, &gate.target))
    {
        return Err(super::PersistenceError::Conflict(
            "capability_denied: widget token does not authorize the requested operation".into(),
        ));
    }
    Ok(())
}
