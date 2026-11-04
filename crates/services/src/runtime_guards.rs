use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;

const REALM_JOIN_BOOTSTRAP_WINDOW: Duration = Duration::seconds(60);
const REALM_JOIN_BOOTSTRAP_MAX_PER_WINDOW: u32 = 10;
const REALM_JOIN_BOOTSTRAP_TRACKER_MAX_ENTRIES: usize = 16_384;
/// `crypto-media/device-lifecycle.md` §2.1.1 clauses 5 and 8 require the
/// authenticated pairing-handoff surfaces to be rate limited per caller device,
/// per `AccountId` and for the service as a whole. The tiers are cumulative:
/// one noisy device cannot spend the account budget, and no account can spend
/// the service budget.
const DEVICE_PAIRING_HANDOFF_WINDOW: Duration = Duration::seconds(60);
const DEVICE_PAIRING_HANDOFF_MAX_PER_DEVICE_WINDOW: u32 = 10;
const DEVICE_PAIRING_HANDOFF_MAX_PER_ACCOUNT_WINDOW: u32 = 30;
const DEVICE_PAIRING_HANDOFF_MAX_PER_SERVICE_WINDOW: u32 = 600;
const DEVICE_PAIRING_HANDOFF_TRACKER_MAX_ENTRIES: usize = 32_768;
const KEY_BACKUP_DOWNLOAD_WINDOW: Duration = Duration::hours(24);
const KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES: usize = 16_384;
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT: u32 = 64;
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN: u32 = 16;
pub const KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBackupDownloadOutcome {
    pub rate_limited: bool,
    pub count: u32,
    pub retry_after_ms: i64,
}

#[derive(Clone)]
pub struct RuntimeGuardService {
    inner: Arc<RuntimeGuards>,
}

struct RuntimeGuards {
    realm_join_bootstraps: Mutex<BTreeMap<(String, String), WindowRecord>>,
    device_pairing_handoffs: Mutex<BTreeMap<String, WindowRecord>>,
    key_backup_downloads: Mutex<BTreeMap<String, WindowRecord>>,
    peer_device_lookups: Mutex<BTreeMap<String, WindowRecord>>,
}

#[derive(Clone, Copy)]
struct WindowRecord {
    count: u32,
    window_started_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

impl Default for RuntimeGuardService {
    fn default() -> Self {
        Self {
            inner: Arc::new(RuntimeGuards {
                realm_join_bootstraps: Mutex::new(BTreeMap::new()),
                device_pairing_handoffs: Mutex::new(BTreeMap::new()),
                key_backup_downloads: Mutex::new(BTreeMap::new()),
                peer_device_lookups: Mutex::new(BTreeMap::new()),
            }),
        }
    }
}

impl RuntimeGuardService {
    pub fn peer_device_lookup_rate_limited(
        &self,
        keys: &[String],
        limit: u32,
        window: Duration,
    ) -> bool {
        let mut records = self.inner.peer_device_lookups.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - window);
        let mut limited = false;
        for key in keys {
            limited |=
                record_window_attempt(&mut records, key.clone(), now, window, 32_768) > limit;
        }
        limited
    }

    /// Charge one authenticated device-pairing handoff attempt (finalize or
    /// code claim) against all three tiers. Every tier is charged on every
    /// call so a caller cannot dodge the account ceiling by rotating devices.
    pub fn device_pairing_handoff_rate_limited(
        &self,
        caller_device_id: &str,
        account_key: &str,
    ) -> bool {
        let mut records = self.inner.device_pairing_handoffs.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - DEVICE_PAIRING_HANDOFF_WINDOW);
        let tiers = [
            (
                format!("device:{caller_device_id}"),
                DEVICE_PAIRING_HANDOFF_MAX_PER_DEVICE_WINDOW,
            ),
            (
                format!("account:{account_key}"),
                DEVICE_PAIRING_HANDOFF_MAX_PER_ACCOUNT_WINDOW,
            ),
            (
                "service".to_owned(),
                DEVICE_PAIRING_HANDOFF_MAX_PER_SERVICE_WINDOW,
            ),
        ];
        let mut limited = false;
        for (key, ceiling) in tiers {
            let count = record_window_attempt(
                &mut records,
                key,
                now,
                DEVICE_PAIRING_HANDOFF_WINDOW,
                DEVICE_PAIRING_HANDOFF_TRACKER_MAX_ENTRIES,
            );
            limited |= count > ceiling;
        }
        limited
    }

    pub fn realm_join_bootstrap_rate_limited(
        &self,
        realm_id: &str,
        applicant_account_id: &str,
    ) -> bool {
        let mut records = self.inner.realm_join_bootstraps.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - REALM_JOIN_BOOTSTRAP_WINDOW);
        let key = (realm_id.to_owned(), applicant_account_id.to_owned());
        record_window_attempt(
            &mut records,
            key,
            now,
            REALM_JOIN_BOOTSTRAP_WINDOW,
            REALM_JOIN_BOOTSTRAP_TRACKER_MAX_ENTRIES,
        ) > REALM_JOIN_BOOTSTRAP_MAX_PER_WINDOW
    }

    pub fn record_key_backup_download(
        &self,
        principal_id: &str,
        limit: u32,
    ) -> KeyBackupDownloadOutcome {
        let mut records = self.inner.key_backup_downloads.lock();
        let now = Utc::now();
        prune_window_records(&mut records, now - KEY_BACKUP_DOWNLOAD_WINDOW);
        let count = record_window_attempt(
            &mut records,
            principal_id.to_owned(),
            now,
            KEY_BACKUP_DOWNLOAD_WINDOW,
            KEY_BACKUP_DOWNLOAD_TRACKER_MAX_ENTRIES,
        );
        let rate_limited = count > limit;
        let retry_after_ms = records
            .get(principal_id)
            .filter(|_| rate_limited)
            .map(|record| {
                (record.window_started_at + KEY_BACKUP_DOWNLOAD_WINDOW - now)
                    .num_milliseconds()
                    .max(0)
            })
            .unwrap_or_default();
        KeyBackupDownloadOutcome {
            rate_limited,
            count,
            retry_after_ms,
        }
    }
}

pub fn clamp_key_backup_daily_download_limit(configured: Option<u32>) -> u32 {
    configured
        .map(|value| {
            value.clamp(
                KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MIN,
                KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_MAX,
            )
        })
        .unwrap_or(KEY_BACKUP_DAILY_DOWNLOAD_LIMIT_DEFAULT)
}

fn prune_window_records<K: Ord>(
    records: &mut BTreeMap<K, WindowRecord>,
    expires_before: DateTime<Utc>,
) {
    records.retain(|_, record| record.last_seen_at >= expires_before);
}

fn record_window_attempt<K: Ord + Clone>(
    records: &mut BTreeMap<K, WindowRecord>,
    key: K,
    now: DateTime<Utc>,
    window: Duration,
    max_entries: usize,
) -> u32 {
    if !records.contains_key(&key) {
        evict_oldest_entries(records, max_entries, |record| {
            record.last_seen_at.timestamp_millis()
        });
    }
    let record = records.entry(key).or_insert(WindowRecord {
        count: 0,
        window_started_at: now,
        last_seen_at: now,
    });
    if now - record.window_started_at > window {
        record.count = 0;
        record.window_started_at = now;
    }
    record.count = record.count.saturating_add(1);
    record.last_seen_at = now;
    record.count
}

fn evict_oldest_entries<K: Ord + Clone, V>(
    records: &mut BTreeMap<K, V>,
    max_entries: usize,
    timestamp: impl Fn(&V) -> i64,
) {
    while records.len() >= max_entries {
        let Some(oldest_key) = records
            .iter()
            .min_by_key(|(_, record)| timestamp(record))
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        records.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeGuardService;

    #[test]
    fn key_backup_download_quota_is_scoped_per_principal() {
        let service = RuntimeGuardService::default();
        for count in 1..=4 {
            let outcome = service.record_key_backup_download("did:web:alice.example", 4);
            assert!(!outcome.rate_limited);
            assert_eq!(outcome.count, count);
        }
        assert!(
            service
                .record_key_backup_download("did:web:alice.example", 4)
                .rate_limited
        );
        assert!(
            !service
                .record_key_backup_download("did:web:bob.example", 4)
                .rate_limited
        );
    }

    #[test]
    fn realm_join_bootstrap_quota_is_scoped_per_realm_and_applicant() {
        let service = RuntimeGuardService::default();
        for _ in 0..10 {
            assert!(!service.realm_join_bootstrap_rate_limited("realm-a", "alice@station-a"));
        }
        assert!(service.realm_join_bootstrap_rate_limited("realm-a", "alice@station-a"));
        assert!(!service.realm_join_bootstrap_rate_limited("realm-b", "alice@station-a"));
        assert!(!service.realm_join_bootstrap_rate_limited("realm-a", "bob@station-a"));
    }
}
