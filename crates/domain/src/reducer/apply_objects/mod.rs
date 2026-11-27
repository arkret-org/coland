//! `ProjectionState::apply_*` reducers for strand / morph / applet /
//! agent object families plus the read-only query helpers. Split out of
//! `reducer.rs` (SOL-07-005) — these are additional inherent-impl blocks on
//! `ProjectionState`; methods resolve by type, so cross-family
//! `self.apply_*` / `self.check_*` calls are unaffected.
//!
//! Structural-only split (one impl block per object family). Re-export the
//! parent `reducer` module glob so each sub-file's `use super::*;` resolves
//! the same names the original single-file `use super::*;` pulled in.

pub(crate) use super::*;

mod applet_agent;
mod morph;
mod queries;
pub use queries::DeferredParentMembershipAdmission;
mod sidecar;
mod strand;
