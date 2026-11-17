//! The actual operator CLI initializes exactly once across independent processes.
//! It uses an isolated encrypted file and explicit configuration, never the
//! developer's platform KeyStore or ambient service credentials.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use arkret_keystore::{EncryptedFileKeyStore, KeyStore as _};
use base64::Engine as _;
use coland_http::config::{SERVICE_CUSTODY_KEY_REF, SERVICE_IDENTITY_KEYSTORE_APP};

const MASTER: [u8; 32] = [147; 32];
const SIGNER_REF: &str = "arkret:signer:fixture-notary";

struct Deployment {
    directory: tempfile::TempDir,
    config: PathBuf,
    vault: PathBuf,
}

impl Deployment {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("operator.env");
        let vault = directory.path().join("service.keys");
        let configured_bundle = directory.path().join("unavailable-identity.json");
        std::fs::write(
            &config,
            format!(
                "COLAND_KEYSTORE_BACKEND=encrypted_file\nCOLAND_KEYSTORE_PATH='{}'\nCOLAND_KEYSTORE_MASTER_KEY={}\nCOLAND_SERVICE_IDENTITY_BUNDLE='{}'\n",
                vault.display().to_string().replace('\\', "/"),
                base64::engine::general_purpose::STANDARD.encode(MASTER),
                configured_bundle.display().to_string().replace('\\', "/"),
            ),
        )
        .unwrap();
        let deployment = Self {
            directory,
            config,
            vault,
        };
        deployment.store().store(SIGNER_REF, &[151; 32]).unwrap();
        deployment
    }

    fn store(&self) -> EncryptedFileKeyStore {
        EncryptedFileKeyStore::new(&self.vault, SERVICE_IDENTITY_KEYSTORE_APP, MASTER).unwrap()
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_coland-keystore-snapshot"))
            .arg("--config")
            .arg(&self.config)
            .arg("--no-env-overrides")
            .args(arguments)
            .current_dir(self.directory.path())
            .output()
            .unwrap()
    }
}

#[test]
fn explicit_cli_provision_has_one_cross_process_winner_and_no_key_export() {
    let deployment = Deployment::new();
    let barrier = std::sync::Barrier::new(4);
    let outputs = std::thread::scope(|scope| {
        let handles = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    deployment.run(&["--generate-custody-key"])
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.code() == Some(1))
            .count(),
        3
    );
    let store = deployment.store();
    let key = store.load(SERVICE_CUSTODY_KEY_REF).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(store.load(SIGNER_REF).unwrap().as_slice(), &[151; 32]);
    assert_eq!(store.list().unwrap().len(), 2);
    for output in &outputs {
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(&base64::engine::general_purpose::STANDARD.encode(&key)));
        assert!(!stderr.contains(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&key)));
    }
    let original = std::fs::read(&deployment.vault).unwrap();
    assert_eq!(
        deployment.run(&["--generate-custody-key"]).status.code(),
        Some(1)
    );
    assert_eq!(std::fs::read(&deployment.vault).unwrap(), original);
    assert_eq!(
        deployment
            .store()
            .load(SERVICE_CUSTODY_KEY_REF)
            .unwrap()
            .as_slice(),
        key.as_slice()
    );
}

#[test]
fn invalid_modes_cannot_initialize_or_export_and_seed_modes_still_require_verified_identity() {
    let deployment = Deployment::new();
    let original = std::fs::read(&deployment.vault).unwrap();
    let output = deployment.directory.path().join("must-not-be-written.json");
    let output_path = output.to_str().unwrap();
    let attempts = [
        vec!["--generate-custody-key", "--export-only"],
        vec!["--import-only", "--generate-custody-key"],
        vec!["--generate-custody-key", "--generate-custody-key"],
        vec!["--generate-custody-key", "--input", output_path],
        vec!["--generate-custody-key", "--output", output_path],
        vec!["--export-only", "--output", output_path],
        vec!["--import-only", "--input", output_path],
    ];
    for arguments in attempts {
        let refused = deployment.run(&arguments);
        assert_eq!(refused.status.code(), Some(2));
        assert!(!Path::new(output_path).exists());
        assert_eq!(std::fs::read(&deployment.vault).unwrap(), original);
        assert!(
            deployment
                .store()
                .load(SERVICE_CUSTODY_KEY_REF)
                .unwrap_err()
                .is_not_found()
        );
    }
}
