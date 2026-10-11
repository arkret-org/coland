//! The Event digest preimage has one implementation, and it is in the SDK.
//!
//! `conformance/encoding.md` §6 excludes `proofs`, `unsigned` and
//! `event_id` from the digest preimage. Production ingest already goes through
//! it (`event_canonical_bytes` -> `Event::digest_payload`); the copy that
//! drifted was in this crate's own test helpers, where
//! `event_canonical_digest` kept `event_id` in the preimage and
//! stripped two slots that no longer exist on the envelope. Every digest it
//! produced was therefore one the server could never reach, which makes a
//! federation test assert against a value nothing computes.
//!
//! Removing `proofs` alone is deliberately not flagged: `PrincipalLocator`,
//! range-completeness attestations and DID documents all
//! legally strip their own `proofs` before signing, and none of them carries an
//! `event_id` to drop.

use std::fs;
use std::path::{Path, PathBuf};

const HAND_ROLLED_EXCLUSIONS: &[&str] = &[r#"remove("event_id")"#];

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_coland_source_hand_rolls_the_event_digest_preimage() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for tree in [
        "../http/src",
        "../domain/src",
        "../services/src",
        "../server",
        "src",
    ] {
        rust_sources(&manifest.join(tree), &mut sources);
    }
    assert!(!sources.is_empty(), "found no Rust sources to scan");

    let mut violations = Vec::new();
    for path in &sources {
        // This file names the forbidden shapes in order to search for them, the
        // same self-exclusion `scripts/stale-literal-scan.sh` takes.
        if path.file_name() == Path::new(file!()).file_name() {
            continue;
        }
        let source = fs::read_to_string(path).expect("read Rust source");
        for needle in HAND_ROLLED_EXCLUSIONS {
            if source.contains(needle) {
                violations.push(format!("{} deletes {needle}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "call arkret_wire::event_digest_preimage instead of deleting excluded members by hand \
         (encoding.md section 6):\n{}",
        violations.join("\n")
    );
}
