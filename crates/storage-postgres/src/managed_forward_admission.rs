//! Explicit per-Event source carried through the accepting transaction.
use arkret_wire::{AccountId, AppletId, DidCoreId, Event};
use coland_storage::{
    AppletManagedDeviceScopeGuard, ForwardedManagedActorSource, PersistenceError, PersistenceResult,
};

#[derive(Clone, Copy)]
pub(crate) enum Source<'a> {
    Local(&'a AppletManagedDeviceScopeGuard),
    Forwarded(&'a ForwardedManagedActorSource),
}
impl<'a> From<coland_storage::ManagedMlsRefusalSource<'a>> for Source<'a> {
    fn from(source: coland_storage::ManagedMlsRefusalSource<'a>) -> Self {
        match source {
            coland_storage::ManagedMlsRefusalSource::Local(guard) => Self::Local(guard),
            coland_storage::ManagedMlsRefusalSource::Forwarded(source) => Self::Forwarded(source),
        }
    }
}
impl<'a> Source<'a> {
    pub(crate) fn account(self) -> &'a AccountId {
        match self {
            Self::Local(g) => &g.authority.account_id,
            Self::Forwarded(g) => g.verified().account(),
        }
    }
    pub(crate) fn applet(self) -> &'a AppletId {
        match self {
            Self::Local(g) => &g.authority.applet_id,
            Self::Forwarded(g) => &g.provision().applet_id,
        }
    }
    pub(crate) fn service(self) -> &'a DidCoreId {
        match self {
            Self::Local(g) => &g.authority.source_service_id,
            Self::Forwarded(g) => &g.provision().service_id,
        }
    }
    pub(crate) fn document(self) -> &'a arkret_identity::DidDocument {
        match self {
            Self::Local(g) => &g.service_did_document,
            Self::Forwarded(g) => g.service_did_document(),
        }
    }
    pub(crate) fn forwarded(self) -> Option<&'a ForwardedManagedActorSource> {
        match self {
            Self::Local(_) => None,
            Self::Forwarded(g) => Some(g),
        }
    }
    pub(crate) fn ensure_event(
        self,
        event: &Event,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        match self {
            Self::Local(g) => {
                if event.scope_ref != g.effective_scope
                    || !g.authority.scopes.permits(
                        &event.scope_ref,
                        &crate::applet_device_admission::device_actions(event)?,
                    )
                {
                    return Err(PersistenceError::Conflict(
                        "device_unauthorized: native Event exceeds the original Device pair".into(),
                    ));
                }
            }
            Self::Forwarded(g) => g.ensure_event(event, at)?,
        }
        if event.actor_id.as_account_id() != Some(self.account())
            || event.executed_by.is_some()
            || event.applet_id.as_ref() != Some(self.applet())
        {
            return Err(PersistenceError::Conflict(
                "signature_invalid: native Event differs from its verified Account source".into(),
            ));
        }
        Ok(())
    }
}
