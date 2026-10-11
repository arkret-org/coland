use std::collections::BTreeSet;

use serde_json::Value;

pub const PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF: &str =
    coland_domain::artifacts::PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF;

pub fn pq_hybrid_tls_required_group() -> &'static str {
    coland_domain::artifacts::pq_hybrid_tls_required_group()
}

pub fn registry_summary() -> Value {
    coland_domain::artifacts::registry_summary()
}

pub fn missing_operation_surface_groups(groups: &[&str]) -> Vec<String> {
    coland_domain::artifacts::missing_operation_surface_groups(groups)
}

pub fn missing_operation_ids(ids: &[&str]) -> Vec<String> {
    coland_domain::artifacts::missing_operation_ids(ids)
}

pub fn operation_ids_for_surface_groups(groups: &[&str]) -> Vec<String> {
    coland_domain::artifacts::operation_ids_for_surface_groups(groups)
}

pub fn registered_operation_ids(ids: &[&str]) -> Vec<String> {
    coland_domain::artifacts::registered_operation_ids(ids)
}

pub fn operation_ids() -> &'static BTreeSet<String> {
    coland_domain::artifacts::operation_ids()
}

pub fn active_local_operation_event_kinds() -> &'static BTreeSet<String> {
    coland_domain::artifacts::active_local_operation_event_kinds()
}

pub fn active_durable_event_kinds() -> &'static BTreeSet<String> {
    coland_domain::artifacts::active_durable_event_kinds()
}

pub fn schema_ids() -> BTreeSet<String> {
    coland_domain::artifacts::schema_ids()
}
