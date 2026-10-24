//! Deployment-local account handle projection contracts.
//!
//! These DTOs belong to the product-private coauth -> coland synchronization
//! edge. They are not part of the `/_arkret/` protocol surface.

use arkret_identifiers::DidCoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountLocalpartView {
    pub id: String,
    pub localpart: String,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountLocalpartsView {
    pub account_principal_id: DidCoreId,
    pub primary_localpart: Option<String>,
    pub localparts: Vec<AccountLocalpartView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountLocalpartAddRequestBody {
    pub localpart: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountLocalpartUpdateResponseBody {
    pub localpart: AccountLocalpartView,
}
