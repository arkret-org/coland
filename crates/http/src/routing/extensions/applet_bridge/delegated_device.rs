//! Applet-managed delegated device authority.
//!
//! Creation provenance is immutable. New business use is bounded by the
//! current installation at the actual scope, separately from native PCR control.

use arkret_wire::{AppletId, DidCoreId, EventId, RealmId, ScopeRef};
use coland_http::error::AppError;

use super::record::applet_records;
use super::types::AppletRecord;
use crate::state::AppState;

/// The exact Applet install that provisioned one Applet-managed principal.
pub struct ManagedPrincipalAuthority {
    /// `applet_id` the delegated device's payload MUST carry verbatim.
    pub applet_id: AppletId,
    /// Scope half of the install's unique `(applet_id, effective_scope)` key.
    pub effective_scope: ScopeRef,
    /// The principal's own `applet_managed_control` PCR, the only Realm a
    /// delegated `ak.device.authorize` may be submitted to.
    pub principal_control_realm_id: RealmId,
    /// Accepted `ak.applet.managed_actor.provision` that created the principal.
    pub provision_event_id: EventId,
    /// Accepted `applet_managed_control` `ak.realm.create` genesis.
    pub pcr_genesis_event_id: EventId,
    /// `applet-integration.md` 4b revoke fence, globally or for this install.
    pub fenced: bool,
}

/// 4b fence state of one exact install.
///
/// The global identity fence and the per-scope revoke are both fences: the
/// first covers the Applet's last active install being revoked, the second this
/// exact `(applet_id, effective_scope)` row. `revoking` is already fenced --
/// 4b fences future writes from the first accepted revoke Event, not from saga
/// completion.
fn install_fenced(record: &AppletRecord) -> bool {
    record.revoked_at.is_some()
        || !matches!(record.status.as_str(), "installed" | "partially_installed")
}

/// Resolve the exact install that provisioned `principal_id`, or `None` when
/// the principal is not Applet-managed at all.
pub async fn managed_principal_authority(
    state: &AppState,
    principal_id: &DidCoreId,
) -> Result<Option<ManagedPrincipalAuthority>, AppError> {
    let records = applet_records(state).await?;
    for record in &records {
        let anchors = record
            .bots
            .iter()
            .find(|bot| bot.bot_actor_id.signing_principal_id() == principal_id)
            .map(|bot| (&bot.managed_actor_provision_event, &bot.pcr_genesis_event))
            .or_else(|| {
                record
                    .ghosts
                    .iter()
                    .find(|ghost| ghost.ghost_actor_id.signing_principal_id() == principal_id)
                    .map(|ghost| {
                        (
                            &ghost.managed_actor_provision_event,
                            &ghost.pcr_genesis_event,
                        )
                    })
            });
        if let Some((provision, pcr)) = anchors {
            return Ok(Some(ManagedPrincipalAuthority {
                applet_id: record.applet_id.clone(),
                effective_scope: provision.scope_ref.clone(),
                principal_control_realm_id: RealmId::from_event_id(&pcr.event_id),
                provision_event_id: provision.event_id.clone(),
                pcr_genesis_event_id: pcr.event_id.clone(),
                fenced: !records.iter().any(|candidate| {
                    candidate.applet_id == record.applet_id && !install_fenced(candidate)
                }),
            }));
        }
    }
    Ok(None)
}

/// `device-lifecycle.md` 15 install revoke fence, required by the MLS surfaces.
///
/// An Applet-managed principal can only ever hold delegated devices: its
/// `applet_managed_control` genesis is forbidden from carrying a founding
/// device, `accepted_device` needs an accepted device it can never obtain
/// first, `pcr_recovery` is closed to it, and a delegated device MUST NOT
/// authorize another one. So "this device belongs to an Applet-managed
/// principal" is exactly "this is a delegated device", and the fence follows
/// the principal without a second device-to-install mapping table -- which is
/// what 5.2.3 means by making `applet_id` the revocation fence carrier.
///
/// A principal that is not Applet-managed is unaffected.
pub async fn ensure_delegated_device_not_fenced(
    state: &AppState,
    principal_id: &DidCoreId,
) -> Result<(), AppError> {
    let Some(authority) = managed_principal_authority(state, principal_id).await? else {
        return Ok(());
    };
    if authority.fenced {
        return Err(AppError::capability_denied(
            "Applet install has been revoked; its delegated device may not publish KeyPackages, \
             enter a group or sign durable receipts",
        )
        .with_wire_code(arkret_wire::ErrorCode::APPLET_REVOKED));
    }
    Ok(())
}
