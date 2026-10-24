//! Coland I/O adapter for cotest's `verified-profiles.json` artifact.

use std::path::Path;
use std::sync::Arc;

pub use arkret_models_discovery::VerifiedProfileArtifactEntry;
use arkret_models_discovery::parse_verified_profiles_artifact;

pub const VERIFIED_PROFILES_ARTIFACT_ENV: &str = "COLAND_VERIFIED_PROFILES_ARTIFACT";
pub const COLAND_SERVICE_ROLE: &str = "station";

/// Load the descriptors named by the configured artifact path.
///
/// The path arrives from `AppConfig::verified_profiles_artifact`; this module
/// used to read `COLAND_VERIFIED_PROFILES_ARTIFACT` itself, which made the
/// artifact the one piece of deployment configuration that did not appear in
/// `AppConfig` at all.
pub fn load_from_configured_path(path: Option<&str>) -> Arc<Vec<VerifiedProfileArtifactEntry>> {
    let Some(path) = path.filter(|value| !value.is_empty()) else {
        tracing::debug!(
            target: "verified_profiles",
            env_var = VERIFIED_PROFILES_ARTIFACT_ENV,
            "verified-profiles artifact env var unset; verified_profiles=[]"
        );
        return Arc::new(Vec::new());
    };
    Arc::new(load_from_path(path))
}

pub fn load_from_path(path: impl AsRef<Path>) -> Vec<VerifiedProfileArtifactEntry> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path.display(),
                %error,
                "verified-profiles artifact is unreadable; verified_profiles=[]"
            );
            return Vec::new();
        }
    };
    let report = match parse_verified_profiles_artifact(&bytes, COLAND_SERVICE_ROLE) {
        Ok(report) => report,
        Err(error) => {
            tracing::warn!(
                target: "verified_profiles",
                path = %path.display(),
                %error,
                "verified-profiles artifact is malformed; verified_profiles=[]"
            );
            return Vec::new();
        }
    };
    for dropped in &report.dropped {
        tracing::warn!(
            target: "verified_profiles",
            profile_id = %dropped.profile_id,
            reason = dropped.reason,
            "dropping invalid verified-profile entry"
        );
    }
    tracing::info!(
        target: "verified_profiles",
        path = %path.display(),
        version = report.version.as_deref().unwrap_or(""),
        run_id = report.run_id.as_deref().unwrap_or(""),
        loaded = report.entries.len(),
        total_in_artifact = report.total_entries,
        service_role = COLAND_SERVICE_ROLE,
        "loaded verified-profile entries from artifact"
    );
    report.entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_env_var_yields_empty() {
        assert!(load_from_configured_path(None).is_empty());
    }

    #[test]
    fn malformed_json_yields_empty() {
        let path = std::env::temp_dir().join(format!(
            "coland-verified-profiles-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_from_path(path).is_empty());
    }

    #[test]
    fn filters_to_station_role() {
        let path = std::env::temp_dir().join(format!(
            "coland-verified-profiles-role-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            br#"{"verified":[
                {"profile_id":"principal","claim_kind":"conformance_verified","verification_run_id":"run","service_role":"station","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact_ref":"file:///artifact","verifier_id":"ak:did_core:web:cotest.example","signature":"signature","verified_at":"2026-05-20T00:00:00.000Z"},
                {"profile_id":"push","claim_kind":"conformance_verified","verification_run_id":"run","service_role":"push_gateway","artifact_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifact_ref":"file:///artifact","verifier_id":"ak:did_core:web:cotest.example","signature":"signature","verified_at":"2026-05-20T00:00:00.000Z"}
            ]}"#,
        )
        .unwrap();
        let entries = load_from_path(path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].profile_id, "principal");
    }
}
