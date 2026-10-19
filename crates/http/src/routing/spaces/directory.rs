//! Public Realm metadata directory handlers.
//!
//! Directory indexes only direct, verified public Realm metadata. It is not an
//! identity, membership, join, object-preview, handle, or private-contact
//! authority.

use arkret_models_discovery::{
    DirectoryRealmSearchOutcome, DirectoryResolveRealmRequestBody, DirectoryResourceKind,
    DirectorySearchRealmsRequestBody, PublicRealmDirectoryEntry, PublicRealmMetadata,
    ServiceDescribe, ServiceProtocolVersion,
};
use chrono::{DateTime, Utc};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use salvo::prelude::*;

use crate::state::{AppState, RealmDirectoryEntry};

mod handles;
pub(crate) mod realm_resolution;

pub(crate) use handles::signed_handle_claim_value;
use realm_resolution::{resolve_realm, search_realms};

fn public_directory_entry(
    entry: &RealmDirectoryEntry,
    at: DateTime<Utc>,
) -> Option<PublicRealmDirectoryEntry> {
    let metadata = entry.public_metadata.as_ref()?;
    if !entry.public || metadata.expires_at <= at {
        return None;
    }
    Some(PublicRealmDirectoryEntry {
        realm_id: entry.realm_id.clone(),
        public_metadata: PublicRealmMetadata {
            display_name: metadata.display_name.clone(),
            summary: metadata.summary.clone(),
            public_locator: metadata.public_locator.clone(),
            avatar_blob_ref: metadata.avatar_blob_ref.clone(),
        },
        indexed_at: metadata.indexed_at,
        expires_at: metadata.expires_at,
    })
}

const DIRECTORY_RESOURCE_KINDS: &[DirectoryResourceKind] = &[DirectoryResourceKind::Realm];
pub(crate) const DIRECTORY_OPERATION_BUNDLES: &[&str] = &[
    arkret_wire::OperationBundleDescriptor::DIRECTORY_SERVICE_DESCRIBE_V1,
    arkret_wire::OperationBundleDescriptor::DIRECTORY_SERVICE_PUBLIC_READ_V1,
];

pub(crate) fn protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("directory/describe").get(directory_describe))
        .push(Router::with_path("directory/search-realms").post(search_realms))
        .push(Router::with_path("directory/resolve-realm").post(resolve_realm))
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.describe", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.describe.v1"))]
async fn directory_describe(depot: &mut Depot) -> JsonResult<ServiceDescribe> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let service_resolution = state.service_resolution_commitment();
    let service_id =
        arkret_wire::project_did_to_core_id(&service_resolution.did).map_err(|error| {
            AppError::internal(format!("service resolution projection failed: {error}"))
        })?;
    let description = ServiceDescribe {
        service_id,
        service_resolution: service_resolution.as_ref().clone(),
        trust_domain: state.config().trust_domain.clone(),
        service_kind: arkret_wire::ServiceKind::DirectoryService,
        protocol_version: ServiceProtocolVersion::V1,
        supported_profiles: vec![arkret_wire::ProfileId::DIRECTORY_SERVICE_V1.to_owned()],
        profile_bindings: Default::default(),
        supported_operation_bundles: DIRECTORY_OPERATION_BUNDLES
            .iter()
            .map(|bundle| (*bundle).to_owned())
            .collect(),
        transport_bindings: vec![arkret_models_discovery::TransportBinding::http_json(format!(
            "{}/",
            state.config().public_base_url.trim_end_matches('/')
        ))],
        supported_features: Vec::new(),
        calendar_tzdb_versions: Vec::new(),
        auth_metadata: arkret_models_discovery::service_description::AuthMetadata::minimal(),
        limits: Default::default(),
        plaintext_visibility: arkret_models_discovery::service_description::PlaintextVisibility::none(),
        receive_policy_constraints: None,
        verified_profiles: Vec::new(),
        interop_surfaces: Vec::new(),
        invite_addressing: None,
        development_mode: state.config().development_mode,
        rate_limit_policy: Some(arkret_models_discovery::service_description::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(arkret_models_discovery::service_description::EgressNetworkPolicy::deny_private_defaults()),
        resource_kinds: DIRECTORY_RESOURCE_KINDS.to_vec(),
        extensions: Default::default(),
    };
    description
        .validate()
        .map_err(|error| AppError::internal(format!("invalid directory describe: {error}")))?;
    json_ok(description)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_describe_only_advertises_public_realm_metadata() {
        assert_eq!(DIRECTORY_RESOURCE_KINDS, &[DirectoryResourceKind::Realm]);
        assert_eq!(
            DIRECTORY_OPERATION_BUNDLES,
            &[
                "ak.operation_bundle.directory_service.describe.v1",
                "ak.operation_bundle.directory_service.public_read.v1",
            ]
        );
    }

    #[test]
    fn directory_query_requires_unexpired_direct_publication() {
        let realm_id = arkret_identifiers::RealmId::new(
            "ak:realm:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
        )
        .unwrap();
        let mut entry = RealmDirectoryEntry::new(
            realm_id,
            "private reducer title",
            coland_services::events::DirectoryProvenance::LocalOnly,
        );
        entry.public = true;
        let at = Utc::now();
        assert!(public_directory_entry(&entry, at).is_none());

        entry.public_metadata = Some(coland_services::events::PublicRealmMetadataRecord {
            display_name: "Published Realm".to_owned(),
            summary: Some("Public summary".to_owned()),
            public_locator: Some("https://realm.example".to_owned()),
            avatar_blob_ref: None,
            indexed_at: at,
            expires_at: at + chrono::Duration::minutes(5),
        });
        let projected = public_directory_entry(&entry, at).expect("published entry");
        let value = serde_json::to_value(projected).expect("serialize public entry");
        assert_eq!(value["public_metadata"]["display_name"], "Published Realm");
        for forbidden in [
            "members",
            "join_candidates",
            "join_rule",
            "source_refs",
            "policy_revision",
            "authority",
        ] {
            assert!(value.get(forbidden).is_none(), "leaked {forbidden}");
        }
    }
}
