//! Private call-scoped identity coordinates; never an authorization source.

use arkret_models_collaboration::call_invitation::CallMediaRosterIdentity;
use arkret_wire::{ActorId, CallId, DeviceId, RealmId};
use async_trait::async_trait;

#[async_trait]
pub trait CallMediaSubjectStore: Send + Sync {
    async fn accepted_binding_key(
        &self,
        realm: &RealmId,
        call: &CallId,
        digest: &arkret_wire::Hash,
        issuer: &arkret_wire::DidUrl,
    ) -> crate::PersistenceResult<Option<[u8; 32]>>;

    async fn establish_identity(
        &self,
        realm: &RealmId,
        call: &CallId,
        actor: &ActorId,
        device: &DeviceId,
        candidate: &CallMediaRosterIdentity,
    ) -> crate::PersistenceResult<CallMediaRosterIdentity>;
}
