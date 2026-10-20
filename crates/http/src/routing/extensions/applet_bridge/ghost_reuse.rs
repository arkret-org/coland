//! Existing mappings are read from accepted Realm creation originals.
use arkret_models_integration::{ExistingManagedActor, GhostExternalTuple};
use coland_http::error::AppError;

use super::types::{AppletRecord, GhostActorRecord};
use crate::state::AppState;

pub(super) fn anchors(ghost: &GhostActorRecord) -> ExistingManagedActor {
    ExistingManagedActor {
        ghost_actor_id: ghost.ghost_actor_id.clone(),
        creation_ref: ghost.creation_ref.clone(),
    }
}
pub(super) async fn find_existing(
    _state: &AppState,
    installation: &AppletRecord,
    external: &GhostExternalTuple,
) -> Result<Option<GhostActorRecord>, AppError> {
    let mut matches = installation
        .ghosts
        .iter()
        .filter(|ghost| &ghost.external_ref == external);
    let result = matches.next().cloned();
    if matches.next().is_some() {
        return Err(AppError::conflict(
            "Realm/Applet tuple has conflicting accepted identities",
        ));
    }
    Ok(result)
}
