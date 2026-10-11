//! Generate a Coland encrypted-file KeyStore master key.
//!
//! The command is intentionally separate from the server startup path: an
//! operator must provision the master key explicitly, while local tooling may
//! use `--if-missing` for an idempotent development bootstrap.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine as _;
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const USAGE: &str = "usage: coland-keystore-keygen --output <path> [--if-missing]\n\
\n\
options:\n\
  --output <path>  destination for the base64-encoded 32-byte master key\n\
  --if-missing     succeed when an existing file contains a valid master key\n\
  -h, --help       print this help\n";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    output: PathBuf,
    if_missing: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Generate(Args),
    Help,
}

#[derive(Debug, PartialEq, Eq)]
enum GenerateOutcome {
    Created,
    ExistingValid,
}

fn parse_args(raw: impl IntoIterator<Item = String>) -> anyhow::Result<Command> {
    let mut output = None;
    let mut if_missing = false;
    let mut args = raw.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                anyhow::ensure!(output.is_none(), "--output may only be specified once");
                output = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--output needs a path"))?,
                ));
            }
            "--if-missing" => {
                anyhow::ensure!(!if_missing, "--if-missing may only be specified once");
                if_missing = true;
            }
            "-h" | "--help" => return Ok(Command::Help),
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    let output = output.ok_or_else(|| anyhow::anyhow!("--output <path> is required"))?;
    anyhow::ensure!(
        !output.as_os_str().is_empty(),
        "--output path must not be empty"
    );
    Ok(Command::Generate(Args { output, if_missing }))
}

fn validate_key_file(path: &Path) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", path.display()))?;
    let trimmed = raw.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{} is empty", path.display());

    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(trimmed.as_bytes())
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed.as_bytes())
            })
            .map_err(|error| anyhow::anyhow!("{} is not valid base64: {error}", path.display()))?,
    );
    anyhow::ensure!(
        decoded.len() == KEY_BYTES,
        "{} must decode to exactly {KEY_BYTES} bytes (got {})",
        path.display(),
        decoded.len()
    );
    Ok(())
}

fn open_new_key_file(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    options.open(path)
}

fn generate_key_file(path: &Path, if_missing: bool) -> anyhow::Result<GenerateOutcome> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
    }

    let mut file = match open_new_key_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && if_missing => {
            validate_key_file(path)?;
            return Ok(GenerateOutcome::ExistingValid);
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "refusing to overwrite existing key file {}; use --if-missing only for idempotent initialization",
                path.display()
            );
        }
        Err(error) => anyhow::bail!("create {}: {error}", path.display()),
    };

    let result = (|| -> anyhow::Result<()> {
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(&mut *key)
            .map_err(|error| anyhow::anyhow!("OS randomness failed: {error}"))?;
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.as_slice()));

        file.write_all(encoded.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| anyhow::anyhow!("write {}: {error}", path.display()))?;
        drop(file);
        validate_key_file(path)
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error);
    }

    Ok(GenerateOutcome::Created)
}

fn main() -> ExitCode {
    let command = match parse_args(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("[keystore-keygen] {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let Command::Generate(args) = command else {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    };

    match generate_key_file(&args.output, args.if_missing) {
        Ok(GenerateOutcome::Created) => {
            println!("created KeyStore master key at {}", args.output.display());
            ExitCode::SUCCESS
        }
        Ok(GenerateOutcome::ExistingValid) => {
            println!(
                "KeyStore master key already exists and is valid at {}",
                args.output.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[keystore-keygen] {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("coland-keystore-keygen-{}", uuid::Uuid::new_v4()));
            Self(path)
        }

        fn key_path(&self) -> PathBuf {
            self.0.join("nested").join("master-key")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_a_valid_random_master_key_without_overwriting_it() {
        let dir = TestDir::new();
        let path = dir.key_path();

        assert_eq!(
            generate_key_file(&path, false).unwrap(),
            GenerateOutcome::Created
        );
        validate_key_file(&path).unwrap();
        let original = fs::read(&path).unwrap();

        let error = generate_key_file(&path, false).unwrap_err();
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(fs::read(&path).unwrap(), original);

        assert_eq!(
            generate_key_file(&path, true).unwrap(),
            GenerateOutcome::ExistingValid
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn if_missing_rejects_an_invalid_existing_file() {
        let dir = TestDir::new();
        let path = dir.key_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "!!!\n").unwrap();

        let error = generate_key_file(&path, true).unwrap_err();
        assert!(error.to_string().contains("not valid base64"));
        assert_eq!(fs::read_to_string(path).unwrap(), "!!!\n");
    }

    #[test]
    fn parses_the_cross_platform_cli_contract() {
        assert_eq!(
            parse_args([
                "--output".to_owned(),
                "secrets/master-key".to_owned(),
                "--if-missing".to_owned(),
            ])
            .unwrap(),
            Command::Generate(Args {
                output: PathBuf::from("secrets/master-key"),
                if_missing: true,
            })
        );
        assert_eq!(parse_args(["--help".to_owned()]).unwrap(), Command::Help);
    }

    #[cfg(unix)]
    #[test]
    fn creates_the_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TestDir::new();
        let path = dir.key_path();
        generate_key_file(&path, false).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
