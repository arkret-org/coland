//! `cargo run --bin coland-keystore-snapshot -- ...`
//!
//! Service-identity KeyStore backup/restore helper.
//!
//! Exactly one mode is required:
//!
//! 1. `--export-only` — used by `scripts/backup-drill.sh`. Loads the KeyStore-persisted notary seed
//!    referenced by an SDK `DidCoreIdentityBundle` and writes a single-key JSON snapshot to
//!    `--output`.
//!
//! 2. `--import-only` — used by `scripts/restore-drill.sh`. Reads the JSON snapshot from `--input`
//!    and stores the seed back into the configured durable KeyStore under the same id.
//!
//! Both modes resolve the service DID and active signing `KeyRef` from a
//! verified SDK identity bundle:
//!   - `COLAND_SERVICE_IDENTITY_BUNDLE` (or `--identity-bundle`)
//!
//! The helper is self-contained and shares only the configured KeyStore
//! with the server process.

use std::collections::BTreeMap;
use std::process::ExitCode;

use base64::Engine as _;
use ed25519_dalek::SigningKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    ExportOnly,
    ImportOnly,
}

#[derive(Clone, Debug)]
struct Args {
    mode: Mode,
    identity_bundle: String,
    output: Option<String>,
    input: Option<String>,
}

fn parse_args(raw: &[String], values: &BTreeMap<String, String>) -> anyhow::Result<Args> {
    let mut mode = None;
    let mut identity_bundle = values
        .get("COLAND_SERVICE_IDENTITY_BUNDLE")
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let mut output = None;
    let mut input = None;

    let mut i = 1;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "--export-only" => {
                anyhow::ensure!(mode.replace(Mode::ExportOnly).is_none(), "choose one mode");
            }
            "--import-only" => {
                anyhow::ensure!(mode.replace(Mode::ImportOnly).is_none(), "choose one mode");
            }
            "--identity-bundle" => {
                i += 1;
                identity_bundle = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--identity-bundle needs a path"))?,
                );
            }
            "--output" => {
                i += 1;
                output = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--output needs a path"))?,
                );
            }
            "--input" => {
                i += 1;
                input = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("--input needs a path"))?,
                );
            }
            "--config" => {
                i += 1;
                anyhow::ensure!(raw.get(i).is_some(), "--config needs a path");
            }
            "--no-env-overrides" => {}
            value if value.starts_with("--config=") => {}
            "-h" | "--help" => {
                eprintln!(
                    "usage: coland-keystore-snapshot (--export-only | --import-only)\n\
                     \n\
                     mode flags (exactly one):\n\
                       --export-only    write KeyStore-persisted seed to --output\n\
                       --import-only    read seed from --input and write to KeyStore\n\
                     \n\
                     options:\n\
                       --identity-bundle <path>  validated SDK DidCoreIdentityBundle (required)\n\
                       --output <path>         destination JSON for --export-only\n\
                       --input <path>          source JSON for --import-only\n\
                    "
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
        i += 1;
    }
    let mode = mode.ok_or_else(|| anyhow::anyhow!("choose --export-only or --import-only"))?;
    let identity_bundle = identity_bundle.ok_or_else(|| {
        anyhow::anyhow!(
            "--identity-bundle (or COLAND_SERVICE_IDENTITY_BUNDLE) is required; the snapshot helper must not accept a configured service DID"
        )
    })?;
    Ok(Args {
        mode,
        identity_bundle,
        output,
        input,
    })
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().collect();
    let values = match coland::process_config::load(&raw) {
        Ok(values) => values,
        Err(error) => {
            eprintln!("[keystore-snapshot] config load failed: {error}");
            return ExitCode::from(2);
        }
    };
    let args = match parse_args(&raw, &values) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[keystore-snapshot] arg parse failed: {e}");
            return ExitCode::from(2);
        }
    };
    let identity = match load_service_identity(&args.identity_bundle) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("[keystore-snapshot] identity bundle rejected: {error}");
            return ExitCode::from(2);
        }
    };

    let result = match args.mode {
        Mode::ExportOnly => run_export_only(&args, &identity, &values),
        Mode::ImportOnly => run_import_only(&args, &identity, &values),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(DrillError::Io(e)) => {
            eprintln!("[keystore-snapshot] IO error: {e}");
            ExitCode::from(2)
        }
        Err(DrillError::Assertion(msg)) => {
            eprintln!("[keystore-snapshot] FAIL — {msg}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
enum DrillError {
    Io(String),
    Assertion(String),
}

use coland_http::config::SERVICE_IDENTITY_KEYSTORE_APP;

fn open_service_identity_key_store(
    values: &BTreeMap<String, String>,
) -> Result<Box<dyn arkret_keystore::KeyStore>, DrillError> {
    coland_http::config::KeyStoreConfig::from_values(values)
        .map_err(|error| DrillError::Io(format!("invalid KeyStore configuration: {error}")))?
        .open(SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|error| DrillError::Io(format!("durable KeyStore unavailable: {error}")))?
        .ok_or_else(|| {
            DrillError::Io(
                "COLAND_KEYSTORE_BACKEND must select a durable backend for this snapshot"
                    .to_owned(),
            )
        })
}

#[derive(Debug)]
struct ResolvedServiceIdentity {
    service_id: String,
    signing_key_ref: String,
    signing_key_multibase: String,
}

fn load_service_identity(path: &str) -> anyhow::Result<ResolvedServiceIdentity> {
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("read identity bundle {path}: {error}"))?;
    let bundle: arkret_identity::service_identity::DidCoreIdentityBundle =
        serde_json::from_slice(&bytes)
            .map_err(|error| anyhow::anyhow!("parse identity bundle {path}: {error}"))?;
    bundle
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid identity bundle {path}: {error}"))?;

    let identity = &bundle.identity.identity;
    if identity.did.method() != "webvh" {
        anyhow::bail!(
            "identity bundle service DID {} is not did:webvh",
            identity.did
        );
    }
    let signing_key_ref = identity.active_signing_key_ref.as_str();
    if signing_key_ref.starts_with("secret:") {
        anyhow::bail!(
            "active signing KeyRef {signing_key_ref} is an external secret; the KeyStore export/import drill requires a KeyStore-backed active signing key"
        );
    }
    let signing_key_multibase = bundle
        .identity
        .did_document
        .signing_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("identity bundle DID document has no assertion key"))?;

    Ok(ResolvedServiceIdentity {
        service_id: identity.did.to_string(),
        signing_key_ref: signing_key_ref.to_owned(),
        signing_key_multibase: signing_key_multibase.to_owned(),
    })
}

fn validate_seed_binding(
    identity: &ResolvedServiceIdentity,
    seed_bytes: &[u8],
) -> Result<[u8; 32], DrillError> {
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
        DrillError::Assertion(format!(
            "service signing seed must be 32 bytes (got {})",
            seed_bytes.len()
        ))
    })?;
    let actual = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
    );
    if actual != identity.signing_key_multibase {
        return Err(DrillError::Assertion(format!(
            "seed under active KeyRef {} does not match the service DID document",
            identity.signing_key_ref
        )));
    }
    Ok(seed)
}

// ── --export-only ───────────────────────────────────────────────────────

fn run_export_only(
    args: &Args,
    identity: &ResolvedServiceIdentity,
    values: &BTreeMap<String, String>,
) -> Result<(), DrillError> {
    let output = args
        .output
        .as_deref()
        .ok_or_else(|| DrillError::Io("--export-only requires --output".to_owned()))?;
    let key_id = &identity.signing_key_ref;
    let store = open_service_identity_key_store(values)?;
    let bytes = store
        .load(key_id)
        .map_err(|e| DrillError::Io(format!("KeyStore::load({key_id}): {e}")))?;
    validate_seed_binding(identity, &bytes)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let payload = serde_json::json!({
        "schema": "coland-rotate-drill.keystore-snapshot.v1",
        "service_id": identity.service_id,
        "key_id": key_id,
        "seed_b64": b64,
    });
    std::fs::write(output, serde_json::to_string_pretty(&payload).unwrap())
        .map_err(|e| DrillError::Io(format!("write {output}: {e}")))?;
    eprintln!("[keystore-snapshot] export OK -> {output} (key_id={key_id})");
    Ok(())
}

// ── --import-only ───────────────────────────────────────────────────────

fn run_import_only(
    args: &Args,
    identity: &ResolvedServiceIdentity,
    values: &BTreeMap<String, String>,
) -> Result<(), DrillError> {
    let input = args
        .input
        .as_deref()
        .ok_or_else(|| DrillError::Io("--import-only requires --input".to_owned()))?;
    let raw =
        std::fs::read_to_string(input).map_err(|e| DrillError::Io(format!("read {input}: {e}")))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| DrillError::Io(format!("parse {input} as JSON: {e}")))?;
    if parsed
        .get("skipped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        eprintln!("[keystore-snapshot] import skipped — snapshot has skipped=true");
        return Ok(());
    }
    let schema = parsed.get("schema").and_then(|v| v.as_str());
    if schema != Some("coland-rotate-drill.keystore-snapshot.v1") {
        return Err(DrillError::Assertion(format!(
            "snapshot schema is unsupported: {}",
            schema.unwrap_or("<missing>")
        )));
    }
    let snapshot_service_id = parsed
        .get("service_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing service_id".to_owned()))?;
    if snapshot_service_id != identity.service_id {
        return Err(DrillError::Assertion(format!(
            "snapshot service_id {snapshot_service_id} does not match identity bundle {}",
            identity.service_id
        )));
    }
    let snapshot_key_id = parsed
        .get("key_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing key_id".to_owned()))?;
    if snapshot_key_id != identity.signing_key_ref {
        return Err(DrillError::Assertion(format!(
            "snapshot key_id {snapshot_key_id} does not match identity bundle KeyRef {}",
            identity.signing_key_ref
        )));
    }
    let seed_b64 = parsed
        .get("seed_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DrillError::Io("snapshot missing seed_b64".to_owned()))?;
    let seed_bytes = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .map_err(|e| DrillError::Io(format!("seed_b64 decode: {e}")))?;
    validate_seed_binding(identity, &seed_bytes)?;
    let key_id = &identity.signing_key_ref;
    let store = open_service_identity_key_store(values)?;
    store
        .store(key_id, &seed_bytes)
        .map_err(|e| DrillError::Io(format!("KeyStore::store({key_id}): {e}")))?;
    eprintln!("[keystore-snapshot] import OK ({key_id})");
    Ok(())
}
