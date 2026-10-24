use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminHandleView {
    pub id: String,
    pub canonical_uri: String,
    pub aliases: Vec<String>,
    pub issuer_id: arkret_identifiers::DidCoreId,
    pub subject_id: arkret_identifiers::DidCoreId,
    pub assigned_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_reassignment_at: Option<String>,
    pub status: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminHandleAuditEvent {
    pub id: String,
    pub action: String,
    pub actor_id: Option<String>,
    pub timestamp: Option<String>,
    pub reason: Option<String>,
    pub previous_subject_id: Option<String>,
    pub new_subject_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminHandlePage {
    pub data: Vec<AdminHandleView>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminHandleAuditPage {
    pub data: Vec<AdminHandleAuditEvent>,
    pub total: u64,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminHandleReassignBody {
    pub new_subject_id: arkret_identifiers::DidCoreId,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminHandleRevokeBody {
    #[serde(default)]
    pub reason: Option<String>,
}
