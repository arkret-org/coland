//! Deployment-private Account Authority -> Station projection contract.
//!
//! This edge materializes an already verified account binding before an initial
//! session grant may escape the Account Authority. It is deliberately outside
//! the interoperable `/_arkret/` surface and must not be advertised as
//! `ak.gate.account.command.register.v1`, which is owned by the Account
//! Authority registration flow.

use arkret_identifiers::{DeviceId, Did, DidCoreId};
use serde::{Deserialize, Serialize};
use url::Url;

pub const ACCOUNT_PROJECTION_PATH: &str = "/_coland/gate/account/project";

/// Route below the deployment-private `/_coland` root used to synchronize an
/// Account Authority's localpart projection into its Station.
///
/// The Station router consumes this template directly. HTTP clients should use
/// [`account_localparts_endpoint`] so the typed principal id remains one URL
/// path segment even if its valid opaque payload contains percent characters.
pub const ACCOUNT_LOCALPARTS_ROUTE: &str = "accounts/{account_principal_id}/localparts";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountLocalpartsBaseUrlError;

impl std::fmt::Display for AccountLocalpartsBaseUrlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("account localparts endpoint requires a base URL")
    }
}

impl std::error::Error for AccountLocalpartsBaseUrlError {}

/// Build the deployment-private account-localparts endpoint from a Station
/// base URL, clearing any input path/query/fragment and encoding the principal
/// id as exactly one path segment.
pub fn account_localparts_endpoint(
    mut station_base: Url,
    principal_id: &DidCoreId,
) -> Result<Url, AccountLocalpartsBaseUrlError> {
    station_base.set_query(None);
    station_base.set_fragment(None);
    let mut segments = station_base
        .path_segments_mut()
        .map_err(|_| AccountLocalpartsBaseUrlError)?;
    segments.clear().push("_coland");
    for segment in ACCOUNT_LOCALPARTS_ROUTE.split('/') {
        if segment == "{account_principal_id}" {
            segments.push(principal_id.as_str());
        } else {
            segments.push(segment);
        }
    }
    drop(segments);
    Ok(station_base)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountProjectionRequestBody {
    pub principal_id: DidCoreId,
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
}

impl AccountProjectionRequestBody {
    pub fn validate(&self) -> Result<(), String> {
        let projected = arkret_identifiers::project_did_to_core_id(&self.did)
            .map_err(|error| format!("did cannot be projected: {error}"))?;
        if projected != self.principal_id {
            return Err("did must project to principal_id".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localparts_endpoint_uses_route_contract_and_one_encoded_id_segment() {
        let base = Url::parse("https://station.example/ignored/path?query=1#fragment").unwrap();
        let principal_id = DidCoreId::new("ak:did_core:web:station.example%2Falice").unwrap();

        let endpoint = account_localparts_endpoint(base, &principal_id).unwrap();

        assert_eq!(
            endpoint.as_str(),
            "https://station.example/_coland/accounts/ak:did_core:web:station.example%252Falice/localparts"
        );
        assert_eq!(
            ACCOUNT_LOCALPARTS_ROUTE,
            "accounts/{account_principal_id}/localparts"
        );
    }
}
