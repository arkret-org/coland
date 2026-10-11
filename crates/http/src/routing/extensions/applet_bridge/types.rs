//! Wire and storage types for the applet bridge surface.

use std::collections::BTreeSet;
use std::ops::Deref;

use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope,
    AccountabilityScopeKind,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, GrantConstraintSubkind, IssuerAuthorityRef,
};
use arkret_models_integration::{
    AppletInstallEffectiveStatus, AppletInstallOutcome, AppletManagedActorProvisionPayload,
    AppletManagedActorRole, AppletPackage, GhostExternalTuple,
};
use arkret_wire::{
    ActorId, ActorKind, AppletId, DidCoreId, Event, EventId, GrantId, Hash, RealmId,
    ResourceMatchScope, ScopeRef, WireResourceSelector,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) const COLAND_EDGE_APPLET_ID: &str = "ak:applet:00000000-0000-7000-8000-000000000000";

fn event_payload_value(event: &Event) -> Value {
    Value::Object(event.payload.clone().into_iter().collect())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletIdentityRecord {
    pub applet_id: AppletId,
    pub registry_id: DidCoreId,
    pub target_station_id: DidCoreId,
    pub initial_package: AppletPackage,
    pub initial_owner_actor_id: ActorId,
    pub initial_effective_scope: ScopeRef,
    pub initial_registration_event: Event,
    pub initial_capability_grant_refs: Vec<GrantId>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub globally_fenced_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct AppletRecord {
    pub identity: AppletIdentityRecord,
    pub applet_id: AppletId,
    pub owner_actor_id: ActorId,
    pub portal_realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub capabilities: Vec<String>,
    pub package: AppletPackage,
    pub ghost_actors_allowed: bool,
    pub status: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub idempotency_key: String,
    pub install_body_digest: Hash,
    pub install_id: String,
    pub install_response: AppletInstallOutcome,
    pub registration_event: Event,
    pub capability_grant_events: Vec<Event>,
    pub install_execution: Value,
    pub revoke_execution: Option<Value>,
    pub bots: Vec<BotActorRecord>,
    pub ghosts: Vec<GhostActorRecord>,
}

/// Exact per-scope durable projection. Managed-actor identity anchors live in
/// the independent `(applet_id, target_station_id)` winner record and
/// are deliberately not serialized into every installation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AppletInstallationRecord {
    pub applet_id: AppletId,
    pub target_station_id: DidCoreId,
    pub owner_actor_id: ActorId,
    pub portal_realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub capabilities: Vec<String>,
    pub package: AppletPackage,
    pub ghost_actors_allowed: bool,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub idempotency_key: String,
    pub install_body_digest: Hash,
    pub install_id: String,
    pub install_response: AppletInstallOutcome,
    pub registration_event: Event,
    pub capability_grant_events: Vec<Event>,
    pub install_execution: Value,
    #[serde(default)]
    pub revoke_execution: Option<Value>,
    pub bots: Vec<BotActorRecord>,
    pub ghosts: Vec<GhostActorRecord>,
}

impl AppletRecord {
    pub(super) fn from_stored(
        identity: AppletIdentityRecord,
        installation: AppletInstallationRecord,
    ) -> Self {
        Self {
            identity,
            applet_id: installation.applet_id,
            owner_actor_id: installation.owner_actor_id,
            portal_realm_id: installation.portal_realm_id,
            effective_scope: installation.effective_scope,
            capabilities: installation.capabilities,
            package: installation.package,
            ghost_actors_allowed: installation.ghost_actors_allowed,
            status: installation.status,
            registered_at: installation.registered_at,
            revoked_at: installation.revoked_at,
            idempotency_key: installation.idempotency_key,
            install_body_digest: installation.install_body_digest,
            install_id: installation.install_id,
            install_response: installation.install_response,
            registration_event: installation.registration_event,
            capability_grant_events: installation.capability_grant_events,
            install_execution: installation.install_execution,
            revoke_execution: installation.revoke_execution,
            bots: installation.bots,
            ghosts: installation.ghosts,
        }
    }

    pub(super) fn stored_installation(&self) -> AppletInstallationRecord {
        AppletInstallationRecord {
            applet_id: self.applet_id.clone(),
            target_station_id: self.identity.target_station_id.clone(),
            owner_actor_id: self.owner_actor_id.clone(),
            portal_realm_id: self.portal_realm_id.clone(),
            effective_scope: self.effective_scope.clone(),
            capabilities: self.capabilities.clone(),
            package: self.package.clone(),
            ghost_actors_allowed: self.ghost_actors_allowed,
            status: self.status.clone(),
            registered_at: self.registered_at,
            revoked_at: self.revoked_at,
            idempotency_key: self.idempotency_key.clone(),
            install_body_digest: self.install_body_digest.clone(),
            install_id: self.install_id.clone(),
            install_response: self.install_response.clone(),
            registration_event: self.registration_event.clone(),
            capability_grant_events: self.capability_grant_events.clone(),
            install_execution: self.install_execution.clone(),
            revoke_execution: self.revoke_execution.clone(),
            bots: self.bots.clone(),
            ghosts: self.ghosts.clone(),
        }
    }
}

impl Deref for AppletRecord {
    type Target = AppletIdentityRecord;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

pub(crate) fn registration_epoch_evidence_from_event(
    event: &Event,
) -> Result<arkret_models_integration::AppletRegistrationEpochEvidence, String> {
    let evidence = event
        .payload
        .get("manifest")
        .and_then(Value::as_object)
        .and_then(|manifest| manifest.get("registration_epoch_evidence"))
        .cloned()
        .ok_or_else(|| {
            "registration Event payload.manifest.registration_epoch_evidence is missing".to_owned()
        })?;
    serde_json::from_value(evidence)
        .map_err(|error| format!("registration Event epoch evidence is invalid: {error}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotActorRecord {
    pub bot_actor_id: ActorId,
    pub request_id: String,
    pub request_digest: Hash,
    pub managed_actor_provision_event: Event,
    pub pcr_genesis_event: Event,
    pub accountability_grant_event: Event,
    pub profile_event: Event,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhostActorRecord {
    pub ghost_actor_id: ActorId,
    pub external_ref: arkret_models_integration::GhostExternalTuple,
    #[serde(default)]
    pub display_name: Option<String>,
    pub request_digest: Hash,
    pub managed_actor_provision_event: Event,
    pub pcr_genesis_event: Event,
    pub accountability_grant_event: Event,
    pub profile_event: Event,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl GhostActorRecord {
    pub(crate) fn provision_payload(
        &self,
    ) -> Result<arkret_models_integration::AppletManagedActorProvisionPayload, String> {
        serde_json::from_value(event_payload_value(&self.managed_actor_provision_event))
            .map_err(|error| format!("stored Ghost provision payload is invalid: {error}"))
    }

    pub(crate) fn principal_control_realm_id(&self) -> RealmId {
        RealmId::from_event_id(&self.pcr_genesis_event.event_id)
    }
}

fn validate_stored_event(event: &Event, label: &str) -> Result<(), String> {
    let digest_suite = event
        .event_id
        .event_digest()
        .digest_suite()
        .map_err(|error| format!("stored {label} Event digest suite is invalid: {error}"))?;
    event
        .validate_for_submit_structural()
        .map_err(|error| format!("stored {label} Event envelope is invalid: {error}"))?;
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|error| format!("stored {label} Event identity is invalid: {error}"))?;
    event
        .validate_proof_bindings_with_digest_suite(digest_suite)
        .map_err(|error| format!("stored {label} Event proof binding is invalid: {error}"))
}

fn validate_registration_epoch_proof_method(
    event: &Event,
    verification_method: &str,
    label: &str,
) -> Result<(), String> {
    if event
        .producer_proof
        .as_ref()
        .is_some_and(|proof| proof.verification_method != verification_method)
    {
        return Err(format!(
            "stored {label} Event proof is outside the Applet registration epoch"
        ));
    }
    Ok(())
}

fn exact_role_ref(event: &Event, role: &str, event_id: &EventId) -> bool {
    event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == role)
        .collect::<Vec<_>>()
        .as_slice()
        .first()
        .is_some_and(|reference| {
            event
                .semantic_refs
                .iter()
                .filter(|item| item.role == role)
                .count()
                == 1
                && reference.critical
                && reference.id == event_id.as_str()
        })
}

fn validate_managed_actor_unit(
    record: &AppletRecord,
    role: AppletManagedActorRole,
    actor_id: &ActorId,
    station_id: &DidCoreId,
    external_ref: Option<&GhostExternalTuple>,
    provision_event: &Event,
    pcr_event: &Event,
    accountability_event: &Event,
    profile_event: &Event,
) -> Result<AppletManagedActorProvisionPayload, String> {
    let label = match role {
        AppletManagedActorRole::Bot => "Bot",
        AppletManagedActorRole::Ghost => "Ghost",
    };
    let authority_package = &record.package;
    let authority_scope = &provision_event.scope_ref;
    let authority_realm_id = authority_scope.realm_id();
    let service_actor_id = arkret_wire::ActorId::service(authority_package.service_id.clone());
    validate_stored_event(provision_event, "managed provision")?;
    validate_stored_event(pcr_event, "managed PCR genesis")?;
    validate_stored_event(accountability_event, "managed accountability")?;
    validate_stored_event(profile_event, "managed profile")?;

    let provision: AppletManagedActorProvisionPayload =
        serde_json::from_value(event_payload_value(provision_event))
            .map_err(|error| format!("stored {label} provision payload is invalid: {error}"))?;
    provision
        .validate()
        .map_err(|error| format!("stored {label} provision payload is invalid: {error}"))?;
    if provision.actor_role != role
        || provision.applet_id != record.applet_id
        || provision.service_id != authority_package.service_id
        || &provision.actor_id != actor_id
        || !matches!(&provision.actor_id, ActorId::Account { .. })
        || provision.actor_id.route_service_id() != station_id
        || provision.external_ref.as_ref() != external_ref
        || provision_event.kind.as_str() != "ak.applet.managed_actor.provision"
        || provision_event.actor_id != service_actor_id
        || &provision_event.realm_id != authority_realm_id
        || &provision_event.scope_ref != authority_scope
        || provision_event.applet_id.as_ref() != Some(&record.applet_id)
        || provision_event.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
    {
        return Err(format!(
            "stored {label} provision anchor drifts from the accepted Applet authority"
        ));
    }

    let pcr_realm_id = RealmId::from_event_id(&pcr_event.event_id);
    let genesis: arkret_models_collaboration::events_payloads::RealmGenesis =
        serde_json::from_value(
            pcr_event
                .payload
                .get("object")
                .cloned()
                .ok_or_else(|| format!("stored {label} PCR genesis object is missing"))?,
        )
        .map_err(|error| format!("stored {label} PCR genesis object is invalid: {error}"))?;
    if pcr_event.kind != arkret_wire::EventKind::RealmCreate
        || &pcr_event.actor_id != actor_id
        || pcr_event.executed_by.as_ref() != Some(&service_actor_id)
        || pcr_event.actor_id.route_service_id() != station_id
        || pcr_event.applet_id.as_ref() != Some(&record.applet_id)
        || pcr_event.authorization_ref.as_deref() != Some(provision.applet_authority_ref.as_str())
        || pcr_event.realm_id != pcr_realm_id
        || pcr_event.scope_ref != ScopeRef::RealmGenesis
        || !exact_role_ref(
            pcr_event,
            "applet_managed_actor_provision",
            &provision_event.event_id,
        )
        || genesis.purpose
            != arkret_models_collaboration::events_payloads::RealmPurpose::AppletManagedControl
        || genesis.initial_resolution.as_ref() != Some(&provision.initial_resolution)
    {
        return Err(format!(
            "stored {label} PCR genesis drifts from its immutable provision"
        ));
    }

    let registration_method = provision_event
        .producer_proof
        .as_ref()
        .ok_or_else(|| "managed provenance has no producer proof".to_owned())?
        .verification_method
        .as_str();
    for event in [accountability_event, profile_event] {
        validate_registration_epoch_proof_method(event, registration_method, label)?;
    }
    let accountability: AccountabilityGrantPayload =
        serde_json::from_value(event_payload_value(accountability_event)).map_err(|error| {
            format!("stored {label} accountability payload is invalid: {error}")
        })?;
    accountability
        .canonical_proof_binding_bytes()
        .map_err(|error| format!("stored {label} accountability proof is invalid: {error}"))?;
    if accountability_event.kind != arkret_wire::EventKind::IdentityAccountabilityGrant
        || accountability_event.actor_id != service_actor_id
        || accountability_event.executed_by.is_some()
        || &accountability_event.realm_id != authority_realm_id
        || &accountability_event.scope_ref != authority_scope
        || accountability_event.applet_id.as_ref() != Some(&record.applet_id)
        || accountability_event.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
        || accountability.schema != AccountabilityGrantPayload::SCHEMA
        || accountability.issuer_id != authority_package.service_id
        || &accountability.subject_id != actor_id.signing_principal_id()
        || accountability.accountability_scope
            != AccountabilityScope::Single(AccountabilityScopeKind::ContractedService)
        || accountability.grant_status != AccountabilityGrantStatus::Active
        || accountability.proof.verification_method != registration_method
        || accountability
            .expires_at
            .is_some_and(|expires_at| expires_at <= accountability.not_before)
    {
        return Err(format!(
            "stored {label} accountability grant is not the accepted contracted-service authority"
        ));
    }

    let profile: arkret_models_collaboration::events_payloads::ActorProfileCreatePayload =
        serde_json::from_value(event_payload_value(profile_event))
            .map_err(|error| format!("stored {label} profile payload is invalid: {error}"))?;
    let profile = profile.object;
    let expected_external_ref = external_ref
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| format!("stored {label} external_ref cannot be encoded: {error}"))?;
    let expected_actor_kind = match role {
        AppletManagedActorRole::Bot => ActorKind::Bot,
        AppletManagedActorRole::Ghost => ActorKind::Integration,
    };
    if profile_event.kind != arkret_wire::EventKind::ProfileCreate
        || &profile_event.actor_id != actor_id
        || profile_event.executed_by.as_ref() != Some(&service_actor_id)
        || profile_event.actor_id.route_service_id() != station_id
        || profile_event.realm_id != pcr_realm_id
        || profile_event.scope_ref
            != (ScopeRef::Realm {
                realm_id: pcr_realm_id.clone(),
            })
        || profile_event.applet_id.as_ref() != Some(&record.applet_id)
        || profile_event.authorization_ref.as_deref()
            != Some(provision.applet_authority_ref.as_str())
        || !exact_role_ref(
            profile_event,
            "accountability",
            &accountability_event.event_id,
        )
        || profile.principal_id != *actor_id.signing_principal_id()
        || profile.actor_kind != expected_actor_kind
        || profile.accountable_principal_ids.as_slice() != [authority_package.service_id.clone()]
        || profile
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(record.applet_id.as_str())
        || profile.profile_fields.get("external_ref") != expected_external_ref.as_ref()
    {
        return Err(format!(
            "stored {label} profile is not the exact managed-actor projection"
        ));
    }
    Ok(provision)
}

impl AppletRecord {
    pub(crate) fn validate_stored_bindings(&self) -> Result<(), String> {
        let original_status = match self.install_response.effective_status {
            AppletInstallEffectiveStatus::Installed => "installed",
            AppletInstallEffectiveStatus::PartiallyInstalled => "partially_installed",
        };
        if self.applet_id != self.package.applet_id
            || self.applet_id != self.identity.initial_package.applet_id
            || self.applet_id != self.install_response.applet_id
            || self.registry_id != self.package.controller_principal_id
            || self.package.controller_principal_id == self.package.service_id
            || self.package.controller_principal_id
                != self.identity.initial_package.controller_principal_id
            || self.package.service_id != self.identity.initial_package.service_id
            || &self.portal_realm_id != self.effective_scope.realm_id()
            || self.install_id != self.install_response.install_id
            || self.install_response.registration_epoch != self.package.registration_epoch
            || !applet_lifecycle_mirrors_match(
                self.status.as_str(),
                self.revoked_at.is_some(),
                original_status,
            )
            || (self.status == "revoking" && self.revoke_execution.is_none())
        {
            return Err(
                "stored Applet record coordinate mirrors drift from the accepted package/outcome"
                    .to_owned(),
            );
        }
        validate_stored_event(
            &self.identity.initial_registration_event,
            "initial registration",
        )?;
        let initial_registration: arkret_models_integration::AppletRegistrationPayload =
            serde_json::from_value(event_payload_value(
                &self.identity.initial_registration_event,
            ))
            .map_err(|error| {
                format!("stored initial registration Event payload is invalid: {error}")
            })?;
        let initial_evidence =
            registration_epoch_evidence_from_event(&self.identity.initial_registration_event)?;
        self.identity
            .initial_package
            .validate_with_epoch_evidence(&initial_evidence)
            .map_err(|error| format!("stored initial Applet package is invalid: {error}"))?;
        let expected_initial_registration = self
            .identity
            .initial_package
            .to_registration(&initial_evidence)
            .map_err(|error| {
                format!("stored initial Applet package cannot derive registration: {error}")
            })?;
        if self.identity.initial_registration_event.kind
            != arkret_wire::EventKind::AppletRegistration
            || self.identity.initial_registration_event.actor_id
                != self.identity.initial_owner_actor_id
            || self.identity.initial_registration_event.scope_ref
                != self.identity.initial_effective_scope
            || self.identity.initial_registration_event.realm_id
                != *self.identity.initial_effective_scope.realm_id()
            || initial_registration != expected_initial_registration
        {
            return Err("stored Applet identity bootstrap registration is invalid".to_owned());
        }
        validate_stored_event(&self.registration_event, "registration")?;
        let registration: arkret_models_integration::AppletRegistrationPayload =
            serde_json::from_value(event_payload_value(&self.registration_event)).map_err(
                |error| format!("stored registration Event payload is invalid: {error}"),
            )?;
        let evidence = registration_epoch_evidence_from_event(&self.registration_event)?;
        self.package
            .validate_with_epoch_evidence(&evidence)
            .map_err(|error| format!("stored Applet package is invalid: {error}"))?;
        let expected_registration = self.package.to_registration(&evidence).map_err(|error| {
            format!("stored Applet package cannot derive registration: {error}")
        })?;
        if self.registration_event.kind != arkret_wire::EventKind::AppletRegistration
            || self.registration_event.actor_id != self.owner_actor_id
            || self.registration_event.realm_id != self.portal_realm_id
            || self.registration_event.scope_ref != self.effective_scope
            || registration != expected_registration
            || self.install_response.registration_event_ref != self.registration_event.event_id
        {
            return Err(
                "stored registration Event is not the exact accepted Applet package projection"
                    .to_owned(),
            );
        }
        let expected_resource = match &self.effective_scope {
            ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => {
                let mut selector =
                    WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
                selector.match_scope = Some(ResourceMatchScope::Exact);
                selector
            }
            _ => return Err("stored Applet effective scope is unsupported".to_owned()),
        };
        let expected_constraint = GrantConstraint::applet_authority(
            self.applet_id.clone(),
            arkret_wire::ActorId::service(self.package.service_id.clone()),
            self.package.registration_epoch.clone(),
        );
        let requested_actions = self
            .package
            .requested_scopes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut projected_actions = BTreeSet::new();
        let mut grant_event_ids = BTreeSet::new();
        let mut accepted_grants = Vec::with_capacity(self.capability_grant_events.len());
        if self.capability_grant_events.is_empty() {
            return Err("stored Applet has no accepted capability grant Event".to_owned());
        }
        for event in &self.capability_grant_events {
            validate_stored_event(event, "capability grant")?;
            if event.kind != arkret_wire::EventKind::CapabilityGrant
                || event.actor_id != self.owner_actor_id
                || event.realm_id != self.portal_realm_id
                || event.scope_ref != self.effective_scope
                || !grant_event_ids.insert(event.event_id.clone())
            {
                return Err("stored capability grant Event envelope is invalid".to_owned());
            }
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                serde_json::from_value(event_payload_value(event)).map_err(|error| {
                    format!("stored capability grant payload is invalid: {error}")
                })?;
            let grant = payload.grant;
            let applet_authority_constraints = grant
                .constraints
                .iter()
                .filter(|constraint| {
                    constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
                })
                .collect::<Vec<_>>();
            let authority_root_is_exact = matches!(
                grant.issuer_authority_refs.as_slice(),
                [IssuerAuthorityRef::RealmRoot { realm_id, .. }]
                    if realm_id == &self.portal_realm_id
            );
            if grant.schema != "ak.schema.capability.v1"
                || grant.issuer_id != self.owner_actor_id
                || grant.realm_id.as_ref() != Some(&self.portal_realm_id)
                || !matches!(&grant.subject, CapabilitySubject::Actor(subject)
                if subject == &ActorId::service(self.package.service_id.clone()))
                || grant.resources.as_slice() != [expected_resource.clone()]
                || applet_authority_constraints.as_slice() != [&expected_constraint]
                || grant.actions.is_empty()
                || !authority_root_is_exact
            {
                return Err(
                    "stored capability grant authority, resource, or constraint is invalid"
                        .to_owned(),
                );
            }
            for action in grant.actions {
                if !requested_actions.contains(&action) || !projected_actions.insert(action) {
                    return Err(
                        "stored capability grant actions are duplicated or were not requested"
                            .to_owned(),
                    );
                }
            }
            accepted_grants.push(GrantId::from_event_id(&event.event_id));
        }
        if accepted_grants != self.install_response.capability_grant_refs
            || self.capabilities != projected_actions.into_iter().collect::<Vec<_>>()
            || self.ghost_actors_allowed
                != self
                    .capabilities
                    .iter()
                    .any(|action| action == arkret_wire::CapabilityActionId::APPLET_GHOST_PROVISION)
        {
            return Err(
                "stored capability grant Events drift from the install outcome or projection"
                    .to_owned(),
            );
        }

        let mut all_event_ids = BTreeSet::from([self.registration_event.event_id.clone()]);
        for event in &self.capability_grant_events {
            if !all_event_ids.insert(event.event_id.clone()) {
                return Err("stored Applet Event set reuses an Event id".to_owned());
            }
        }
        let mut managed_actor_ids = BTreeSet::new();
        let mut bot_requests = BTreeSet::new();
        for bot in &self.bots {
            if !managed_actor_ids.insert(bot.bot_actor_id.clone())
                || !bot_requests.insert(&bot.request_id)
            {
                return Err("stored Bot identity or request id is duplicated".to_owned());
            }
            validate_managed_actor_unit(
                self,
                AppletManagedActorRole::Bot,
                &bot.bot_actor_id,
                &self.target_station_id,
                None,
                &bot.managed_actor_provision_event,
                &bot.pcr_genesis_event,
                &bot.accountability_grant_event,
                &bot.profile_event,
            )?;
            for event in [
                &bot.managed_actor_provision_event,
                &bot.pcr_genesis_event,
                &bot.accountability_grant_event,
                &bot.profile_event,
            ] {
                if !all_event_ids.insert(event.event_id.clone()) {
                    return Err("stored Bot fixed Event set reuses an Event id".to_owned());
                }
            }
        }
        let mut external_refs = BTreeSet::new();
        for ghost in &self.ghosts {
            if ghost.ghost_actor_id.route_service_id() != &self.target_station_id
                || ghost.ghost_actor_id.signing_principal_id() == &self.package.service_id
                || ghost.ghost_actor_id.signing_principal_id()
                    == &self.package.controller_principal_id
                || !managed_actor_ids.insert(ghost.ghost_actor_id.clone())
                || !external_refs.insert((
                    ghost.external_ref.protocol.clone(),
                    ghost.external_ref.instance_id.clone(),
                    ghost.external_ref.external_id.clone(),
                ))
            {
                return Err(
                    "stored Ghost authority pair is invalid or reuses an existing Applet authority"
                        .to_owned(),
                );
            }
            validate_managed_actor_unit(
                self,
                AppletManagedActorRole::Ghost,
                &ghost.ghost_actor_id,
                ghost.ghost_actor_id.route_service_id(),
                Some(&ghost.external_ref),
                &ghost.managed_actor_provision_event,
                &ghost.pcr_genesis_event,
                &ghost.accountability_grant_event,
                &ghost.profile_event,
            )?;
            for event in [
                &ghost.managed_actor_provision_event,
                &ghost.pcr_genesis_event,
                &ghost.accountability_grant_event,
                &ghost.profile_event,
            ] {
                if !all_event_ids.insert(event.event_id.clone()) {
                    return Err("stored Ghost fixed Event set reuses an Event id".to_owned());
                }
            }
        }
        Ok(())
    }
}

fn applet_lifecycle_mirrors_match(
    status: &str,
    has_revoked_at: bool,
    original_status: &str,
) -> bool {
    if has_revoked_at {
        matches!(status, "revoking" | "revoked")
    } else {
        status == original_status
    }
}

#[derive(salvo::oapi::ToSchema, Clone, Debug, Serialize, Deserialize)]
pub struct AppletRevokeRecordOutcome {
    pub applet_id: AppletId,
    pub status: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub bot_actor_ids: Vec<String>,
    pub ghost_actor_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, ProducerEventProof};
    use serde_json::json;

    use super::*;

    fn structural_only_fixture_event() -> Event {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x51; 32],
        ));
        let mut event = arkret_wire::test_support::raw_event(
            "ak.test.stored_record_fixture",
            ScopeRef::Realm { realm_id },
            DidCoreId::new("ak:did_core:webvh:z6mkstoredactor").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkstoredserver").unwrap(),
            json!({"content": {"kind": "ak.content.text", "body": "stored"}}),
        )
        .unwrap();
        let event_digest = Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.producer_proof = Some(
            ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkstoredactor:example.test#key-1".to_owned(),
                )
                .unwrap(),
                event_digest: event_digest.clone(),
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: arkret_wire::test_support::structural_only_detached_jws(&event_digest),
            }
            .into(),
        );
        event
    }

    #[test]
    fn stored_event_validation_rejects_canonical_content_tampering() {
        let event = structural_only_fixture_event();
        validate_stored_event(&event, "fixture").unwrap();

        let mut tampered = event;
        tampered.payload.insert("tampered".to_owned(), json!(true));
        let error = validate_stored_event(&tampered, "fixture")
            .expect_err("stored canonical Event content must be immutable");
        assert!(error.contains("identity") || error.contains("proof binding"));
    }

    #[test]
    fn stored_fixed_role_ref_rejects_extra_or_noncritical_refs() {
        let mut event = structural_only_fixture_event();
        let target = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x52; 32]);
        event.semantic_refs = vec![arkret_wire::SemanticRef::new(
            target.as_str(),
            "accountability",
        )];
        assert!(exact_role_ref(&event, "accountability", &target));

        event.semantic_refs.push(arkret_wire::SemanticRef::new(
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x53; 32]).as_str(),
            "accountability",
        ));
        assert!(!exact_role_ref(&event, "accountability", &target));
    }

    #[test]
    fn stored_applet_lifecycle_accepts_only_closed_durable_states() {
        for original_status in ["installed", "partially_installed"] {
            assert!(applet_lifecycle_mirrors_match(
                original_status,
                false,
                original_status
            ));
            assert!(applet_lifecycle_mirrors_match(
                "revoking",
                true,
                original_status
            ));
            assert!(applet_lifecycle_mirrors_match(
                "revoked",
                true,
                original_status
            ));

            for (status, has_revoked_at) in [
                (original_status, true),
                ("revoking", false),
                ("revoked", false),
                ("unknown", false),
                ("unknown", true),
            ] {
                assert!(!applet_lifecycle_mirrors_match(
                    status,
                    has_revoked_at,
                    original_status
                ));
            }
        }
    }
}
