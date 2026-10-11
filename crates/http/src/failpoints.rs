//! Development-only fault injection registry.
//!
//! Durable workflows (recovery, rotation, upload) need a way to prove they are
//! crash-consistent: an attempt that persists part of its work and then fails
//! MUST be resumable without corrupting the transaction. Reproducing that from
//! the outside is unreliable, so the server exposes a *typed* injection point.
//!
//! Rules this module exists to enforce:
//!
//! - The registry is only ever non-empty when `development_mode` is on. A release deployment parses
//!   no failpoints at all, so no business step can observe one.
//! - Failpoint names are a closed enum resolved once at startup. A typo in the environment is a
//!   startup error, not a silently inert failpoint.
//! - Business code consumes a [`ScopedFailpoint`] bound to one request attempt. It cannot read the
//!   environment, cannot re-arm itself, and cannot leak the configuration into a response.
//! - Diagnostics name the failpoint id only — never the request, the transaction body, or any key
//!   material.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// Environment variable carrying the whole registry, e.g.
/// `COLAND_FAILPOINTS="backup_series_erase_durable_step=fail_after_durable_steps:1"`.
pub const FAILPOINTS_ENV: &str = "COLAND_FAILPOINTS";

/// The closed set of injection points. Adding a variant means adding the
/// matching consumer in the workflow it names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FailpointId {
    /// The rotation worker's `erase_old_material` — each successfully
    /// deleted old backup is one durable step.
    BackupSeriesEraseDurableStep,
    /// The rotation worker's decision of an admitted `ak.device.revoke`
    /// proposal — the terminal write is the one durable step. Armed on every
    /// attempt, so `fail_after_durable_steps:0` keeps the proposal pending
    /// until the transaction expires with its `rejected` result.
    SecurityRotationRevokeTerminal,
}

impl FailpointId {
    pub const fn as_str(self) -> &'static str {
        match self {
            FailpointId::BackupSeriesEraseDurableStep => "backup_series_erase_durable_step",
            FailpointId::SecurityRotationRevokeTerminal => "security_rotation_revoke_terminal",
        }
    }
}

impl fmt::Display for FailpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FailpointId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "backup_series_erase_durable_step" => Ok(FailpointId::BackupSeriesEraseDurableStep),
            "security_rotation_revoke_terminal" => Ok(FailpointId::SecurityRotationRevokeTerminal),
            other => Err(format!("unknown failpoint id {other:?}")),
        }
    }
}

/// What the failpoint does once armed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailpointTrigger {
    /// Let the first `count` durable steps of the attempt commit, then treat
    /// every remaining step as a storage failure. `count = 0` fails the attempt
    /// before it persists anything.
    FailAfterDurableSteps { count: usize },
}

impl FromStr for FailpointTrigger {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, argument) = value.split_once(':').unwrap_or((value, ""));
        match kind {
            "fail_after_durable_steps" => {
                let count = argument.parse::<usize>().map_err(|_| {
                    format!("fail_after_durable_steps needs a step count, got {argument:?}")
                })?;
                Ok(FailpointTrigger::FailAfterDurableSteps { count })
            }
            other => Err(format!("unknown failpoint trigger {other:?}")),
        }
    }
}

/// Startup-resolved failpoint configuration. Empty in every release build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailpointRegistry {
    entries: BTreeMap<FailpointId, FailpointTrigger>,
}

impl FailpointRegistry {
    /// The only registry a non-development deployment can hold.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Parse [`FAILPOINTS_ENV`] once at startup.
    ///
    /// Returns [`Self::disabled`] unless `development_mode` is on, so an
    /// environment variable left over in a production deployment cannot arm
    /// anything. A malformed entry is a hard error rather than a silent no-op:
    /// a test that believes it injected a fault but did not is worse than a
    /// failed startup.
    pub fn parse(raw: Option<&str>, development_mode: bool) -> anyhow::Result<Self> {
        let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(Self::disabled());
        };
        if !development_mode {
            anyhow::bail!(
                "{FAILPOINTS_ENV} is only honoured when COLAND_DEVELOPMENT_MODE is true; \
                 unset it or the deployment is running with fault injection configured"
            );
        }
        let mut entries = BTreeMap::new();
        for item in raw.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let (id, trigger) = item.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("{FAILPOINTS_ENV} entries must be `<id>=<trigger>`, got {item:?}")
            })?;
            let id = FailpointId::from_str(id.trim()).map_err(|error| anyhow::anyhow!(error))?;
            let trigger =
                FailpointTrigger::from_str(trigger.trim()).map_err(|e| anyhow::anyhow!(e))?;
            if entries.insert(id, trigger).is_some() {
                anyhow::bail!("{FAILPOINTS_ENV} lists failpoint {id} more than once");
            }
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bind `id` to the current request attempt.
    ///
    /// `arm` is the caller's attempt predicate — typically "this is the first
    /// attempt of the transaction" — so the retry that proves resumability
    /// runs the real code path instead of tripping again.
    pub fn scope(&self, id: FailpointId, arm: bool) -> ScopedFailpoint {
        let trigger = arm.then(|| self.entries.get(&id).copied()).flatten();
        if let Some(trigger) = trigger {
            tracing::warn!(failpoint = %id, ?trigger, "development failpoint armed");
        }
        ScopedFailpoint {
            id,
            trigger,
            durable_steps: 0,
        }
    }
}

/// A failpoint bound to one request attempt.
#[derive(Debug)]
pub struct ScopedFailpoint {
    id: FailpointId,
    trigger: Option<FailpointTrigger>,
    durable_steps: usize,
}

impl ScopedFailpoint {
    /// Must the next durable step be treated as a storage failure?
    ///
    /// Callers apply their own storage-failure path so the injected fault and
    /// a real one are indistinguishable to the rest of the workflow.
    pub fn trips_before_next_step(&mut self) -> bool {
        let Some(FailpointTrigger::FailAfterDurableSteps { count }) = self.trigger else {
            return false;
        };
        if self.durable_steps < count {
            return false;
        }
        tracing::warn!(
            failpoint = %self.id,
            durable_steps = self.durable_steps,
            "development failpoint tripped; failing this step as unavailable storage"
        );
        true
    }

    /// Record one durable step that actually committed.
    pub fn record_durable_step(&mut self) {
        if self.trigger.is_some() {
            self.durable_steps += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_registry_never_trips() {
        let registry = FailpointRegistry::disabled();
        let mut scoped = registry.scope(FailpointId::BackupSeriesEraseDurableStep, true);
        assert!(!scoped.trips_before_next_step());
        scoped.record_durable_step();
        assert!(!scoped.trips_before_next_step());
    }

    #[test]
    fn fail_after_durable_steps_lets_the_configured_prefix_commit() {
        let registry = FailpointRegistry {
            entries: BTreeMap::from([(
                FailpointId::BackupSeriesEraseDurableStep,
                FailpointTrigger::FailAfterDurableSteps { count: 1 },
            )]),
        };
        let mut scoped = registry.scope(FailpointId::BackupSeriesEraseDurableStep, true);
        assert!(!scoped.trips_before_next_step());
        scoped.record_durable_step();
        assert!(scoped.trips_before_next_step());
    }

    #[test]
    fn unarmed_scope_ignores_a_configured_trigger() {
        let registry = FailpointRegistry {
            entries: BTreeMap::from([(
                FailpointId::BackupSeriesEraseDurableStep,
                FailpointTrigger::FailAfterDurableSteps { count: 0 },
            )]),
        };
        let mut scoped = registry.scope(FailpointId::BackupSeriesEraseDurableStep, false);
        assert!(!scoped.trips_before_next_step());
    }

    #[test]
    fn unknown_id_and_trigger_are_startup_errors() {
        assert!(FailpointId::from_str("nope").is_err());
        assert!(FailpointTrigger::from_str("explode").is_err());
        assert!(FailpointTrigger::from_str("fail_after_durable_steps:x").is_err());
    }
}
