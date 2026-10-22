//! Native Realm Device source carried through the accepting transaction.
use arkret_wire::{ActorId, AppletId, Event};
use coland_storage::{AppletManagedDeviceScopeGuard, PersistenceError, PersistenceResult};
#[derive(Clone, Copy)]
pub(crate) enum Source<'a> {
    Local(&'a AppletManagedDeviceScopeGuard),
}
impl<'a> From<coland_storage::ManagedMlsRefusalSource<'a>> for Source<'a> {
    fn from(value: coland_storage::ManagedMlsRefusalSource<'a>) -> Self {
        match value {
            coland_storage::ManagedMlsRefusalSource::Local(guard) => Self::Local(guard),
        }
    }
}
impl<'a> Source<'a> {
    pub(crate) fn guard(self) -> &'a AppletManagedDeviceScopeGuard {
        let Self::Local(guard) = self;
        guard
    }
    pub(crate) fn actor(self) -> &'a ActorId {
        &self.guard().authority.actor_id
    }
    pub(crate) fn applet(self) -> &'a AppletId {
        &self.guard().authority.applet_id
    }

    pub(crate) fn ensure_event(
        self,
        event: &Event,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let guard = self.guard();
        if &event.actor_id != self.actor()
            || event
                .actor_id
                .as_realm_actor_id()
                .is_none_or(|actor| actor.realm_id != event.realm_id)
            || event.executed_by.is_some()
            || event.applet_id.as_ref() != Some(self.applet())
            || event.scope_ref != guard.effective_scope
            || !guard.authority.scopes.permits(
                &event.scope_ref,
                &crate::applet_device_admission::device_actions(event)?,
            )
        {
            return Err(PersistenceError::Conflict(
                "device_unauthorized: Event differs from its original Realm Device and exact scope"
                    .into(),
            ));
        }
        Ok(())
    }
}
