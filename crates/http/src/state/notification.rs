use std::sync::Arc;

/// Poison-free mutex for every [`crate::state::AppState`] shared surface.
///
/// `std::sync::Mutex` poisons itself when the holding thread panics: every
/// later `lock()` returns `Err` forever, which turned a single in-critical-
/// section panic into either a process-wide 500 storm or a silent fail-open
/// until restart. `parking_lot::Mutex` has no poisoning: `lock()` returns
/// the guard directly, so admission checks always run (fail-closed) and no
/// caller needs a failure branch.
pub use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

/// broadcast payload for the
/// [`crate::state::AppState`] live-notification channel. Subscribers filter by
/// `realm_id` first, then dispatch on `kind` to produce the right
/// NDJSON frame.
///
/// added control-frame variants alongside the original `Event`
/// (mid-stream control frames per spec):
///   - `EpochRotation` — committed public MLS epoch changed.
///   - `ResyncRequired` — server detected per-subscriber drift; client MUST drop local cache and
///     re-subscribe with `from=null`
///   - `Unauthorized` — subscriber's session token revoked / expired mid-stream; client MUST close
///   - `Signal` — a Signal Extension envelope was admitted onto the live relay; only
///     `signal/subscribe` acts on it, `events.subscribe` ignores it
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventNotification {
    pub realm_id: String,
    pub kind: EventNotificationKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventNotificationKind {
    /// Ordinary projection event (one `ak.message.create` etc.).
    Event {
        /// Stable cursor for the event — typically the canonical
        /// `event_id`. Clients use as resume position.
        cursor: String,
        /// Projection-event JSON (same shape as `projection_event_json`).
        event_payload: Value,
    },
    /// Public MLS epoch shift after a committed transition.
    EpochRotation {
        /// Previous public epoch, when known.
        previous_epoch: Option<Value>,
        /// Current public epoch after acceptance.
        new_epoch: Value,
    },
    /// Per-subscriber drift / corrupted-cursor signal. Clients SHOULD
    /// drop local cache + restart subscription with no `from`.
    ResyncRequired {
        reason: String,
        reconnect_after_ms: Option<u64>,
    },
    /// Session token invalidated mid-stream — client MUST close.
    Unauthorized { reason: String },
    /// A Signal was admitted onto the live relay (`sync/signal.md` §4). It
    /// carries only the server-visible `signal_class`: the envelope itself is
    /// read back from the relay by the subscriber, and no durable event
    /// stream may reuse this wakeup.
    Signal {
        signal_class: arkret_wire::SignalClass,
    },
    /// Durable account-private projection changed. The IDs are server-derived
    /// account context, never caller-supplied wire data.
    Account {
        account_id: arkret_wire::AccountId,
        recipient_id: arkret_wire::DidCoreId,
    },
}

#[derive(Clone)]
pub struct EventBroadcast {
    local: broadcast::Sender<EventNotification>,
    relay: Option<Arc<dyn EventNotificationRelay>>,
}

pub trait EventNotificationRelay: Send + Sync {
    fn publish(&self, notification: EventNotification);
}

impl EventBroadcast {
    pub fn new(capacity: usize) -> Self {
        let local = broadcast::channel::<EventNotification>(capacity).0;
        Self { local, relay: None }
    }

    pub fn new_with_relay(
        capacity: usize,
        build_relay: impl FnOnce(EventBroadcast) -> Arc<dyn EventNotificationRelay>,
    ) -> Self {
        let mut broadcast = Self::new(capacity);
        broadcast.relay = Some(build_relay(broadcast.clone()));
        broadcast
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventNotification> {
        self.local.subscribe()
    }

    pub fn send(
        &self,
        notification: EventNotification,
    ) -> Result<usize, broadcast::error::SendError<EventNotification>> {
        if let Some(relay) = &self.relay {
            relay.publish(notification.clone());
        }
        self.local.send(notification)
    }

    pub fn send_local(
        &self,
        notification: EventNotification,
    ) -> Result<usize, broadcast::error::SendError<EventNotification>> {
        self.local.send(notification)
    }
}

impl EventNotification {
    pub fn account(
        account_id: arkret_wire::AccountId,
        recipient_id: arkret_wire::DidCoreId,
    ) -> Self {
        Self {
            realm_id: String::new(),
            kind: EventNotificationKind::Account {
                account_id,
                recipient_id,
            },
        }
    }

    pub fn event(realm_id: String, cursor: String, event_payload: Value) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Event {
                cursor,
                event_payload,
            },
        }
    }

    pub fn epoch_rotation(
        realm_id: String,
        previous_epoch: Option<Value>,
        new_epoch: Value,
    ) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::EpochRotation {
                previous_epoch,
                new_epoch,
            },
        }
    }

    pub fn signal(realm_id: String, signal_class: arkret_wire::SignalClass) -> Self {
        Self {
            realm_id,
            kind: EventNotificationKind::Signal { signal_class },
        }
    }
}
