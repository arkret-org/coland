//! Wire and storage types for the applet bridge surface.

use std::collections::BTreeSet;
use std::ops::Deref;

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, GrantConstraintSubkind, IssuerAuthorityRef,
};
use arkret_models_integration::{
    AppletInstallEffectiveStatus, AppletInstallOutcome, AppletPackage,
};
use arkret_wire::{
    ActorId, AppletId, DidCoreId, Event, GrantId, Hash, RealmId, ResourceMatchScope, ScopeRef,
    WireResourceSelector,
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
            bots: Vec::new(),
            ghosts: Vec::new(),
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

#[derive(Clone, Debug)]
pub struct BotActorRecord {
    pub bot_actor_id: ActorId,
    pub creation_ref: arkret_wire::CommittedEventRef,
}
#[derive(Clone, Debug)]
pub struct GhostActorRecord {
    pub ghost_actor_id: ActorId,
    pub external_ref: arkret_models_integration::GhostExternalTuple,
    pub display_name: Option<String>,
    pub creation_ref: arkret_wire::CommittedEventRef,
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
            || self.package.service_id != self.install_response.service_id
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
            .to_registration(
                &initial_evidence,
                initial_registration.expected_revision.clone(),
            )
            .map_err(|error| {
                format!("stored initial Applet package cannot derive registration: {error}")
            })?;
        if self.identity.initial_registration_event.kind
            != arkret_wire::EventKind::AppletRegistration
            || self.identity.initial_registration_event.actor_id
                != self.identity.initial_owner_actor_id
            || self.identity.initial_registration_event.scope_ref
                != arkret_wire::ScopeRef::realm(
                    self.identity.initial_effective_scope.realm_id().clone(),
                )
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
        let expected_registration = self
            .package
            .to_registration(&evidence, registration.expected_revision.clone())
            .map_err(|error| {
                format!("stored Applet package cannot derive registration: {error}")
            })?;
        if self.registration_event.kind != arkret_wire::EventKind::AppletRegistration
            || self.registration_event.actor_id != self.owner_actor_id
            || self.registration_event.realm_id != self.portal_realm_id
            || self.registration_event.scope_ref != ScopeRef::realm(self.portal_realm_id.clone())
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
            if grant.schema != arkret_wire::SchemaId::CAPABILITY_V1
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

#[cfg(test)]
mod tests {
    use arkret_wire::{DidUrl, EventId, ProducerEventProof};
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
