//! Server-private Account detail progress carried inside the opaque Account
//! stream cursor handle. None of it is a wire member.

use arkret_wire::{CommitStreamHead, Cursor};
use serde::{Deserialize, Serialize};

/// Progress of one Realm's frozen Account stream window.
///
/// `window_cursor` is the window identity the frame repeats as
/// `window_snapshot_cursor`. `expires_at_ms` is the window's consumable
/// deadline: it is exactly the `expires_at_ms` of the window's basis
/// reservation, and the Account cursor that carries this progress never
/// outlives it. `retained_revision` is the Account-summary revision frozen
/// with the window; the 0441 cursor floor keeps it readable for as long as the
/// cursor lives. `stream_heads` are the heads the window was frozen at;
/// `streams_limited` records when the default visible set exceeded the cap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDetailProgress {
    pub window_cursor: Cursor,
    pub expires_at_ms: i64,
    pub retained_revision: i64,
    pub governance_generation: u64,
    pub stream_heads: Vec<CommitStreamHead>,
    #[serde(default)]
    pub streams_limited: bool,
}

/// One consistent durable cut used to decide whether a detail window changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmStreamCut {
    pub governance_generation: u64,
    pub stream_heads: Vec<CommitStreamHead>,
}
