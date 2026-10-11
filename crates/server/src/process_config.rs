//! Process-facing deployment configuration input.
//!
//! Binaries own ambient environment, `.env`, command-line configuration files,
//! and secret-file indirection. Library crates receive only an explicit map of
//! resolved values and therefore remain independent of process-global state.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CONFIG_ARG: &str = "--config";
const NO_ENV_OVERRIDES_ARG: &str = "--no-env-overrides";
const FILE_BACKED_SECRETS: &[&str] = &[
    "COLAND_KEYSTORE_MASTER_KEY",
    "COLAND_LIVEKIT_API_SECRET",
    "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET",
    "COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
    "COLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER",
    "COLAND_TURN_SHARED_SECRET",
];

/// Read and resolve deployment configuration for a server process.
pub fn load(args: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut values = merge(args, ambient_environment())?;
    resolve_secret_files(&mut values)?;
    Ok(values)
}

fn merge(
    args: &[String],
    ambient: Vec<(String, String)>,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let Some(config_path) = config_path_from_args(args)? else {
        // A local `.env` is a development convenience. Ambient values retain
        // precedence, matching dotenvy's historical behaviour.
        if let Ok(iter) = dotenvy::dotenv_iter() {
            for entry in iter.flatten() {
                values.insert(entry.0, entry.1);
            }
        }
        values.extend(ambient);
        return Ok(values);
    };

    values.extend(read_config_file(&config_path)?);
    if !args.iter().any(|arg| arg == NO_ENV_OVERRIDES_ARG) {
        values.extend(ambient);
    }
    Ok(values)
}

fn resolve_secret_files(values: &mut BTreeMap<String, String>) -> anyhow::Result<()> {
    for name in FILE_BACKED_SECRETS {
        let file_name = format!("{name}_FILE");
        let resolved = resolve_value_or_file(
            name,
            &file_name,
            non_empty(values, name).as_deref(),
            non_empty(values, &file_name).as_deref(),
        )?;
        match resolved {
            Some(value) => {
                values.insert((*name).to_owned(), value);
            }
            None => {
                values.remove(*name);
            }
        }
    }
    Ok(())
}

fn resolve_value_or_file(
    name: &str,
    file_name: &str,
    direct: Option<&str>,
    file_path: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let file_value = match file_path {
        Some(path) => {
            let raw = std::fs::read_to_string(path).map_err(|error| {
                anyhow::anyhow!(
                    "{file_name} points to {path:?} but the file could not be read: {error}"
                )
            })?;
            let value = raw.trim();
            anyhow::ensure!(
                !value.is_empty(),
                "{file_name} points to an empty secret file"
            );
            Some(value.to_owned())
        }
        None => None,
    };
    match (direct.map(ToOwned::to_owned), file_value) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (Some(_), Some(_)) => {
            anyhow::bail!("{name} and {file_name} are both set; pick one")
        }
    }
}

fn ambient_environment() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| is_allowed_config_key(key))
        .collect()
}

/// Value of the `--name value` / `--name=value` command-line flag, if present.
///
/// Every binary in this crate parses its own flags this way; the one
/// implementation lives here next to the rest of the process-facing argument
/// handling so the two accepted spellings cannot drift apart.
pub fn arg_value(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().cloned();
        }
        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
}

fn config_path_from_args(args: &[String]) -> anyhow::Result<Option<PathBuf>> {
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == CONFIG_ARG {
            let value = args
                .get(index + 1)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("--config requires a file path"))?;
            return Ok(Some(PathBuf::from(value)));
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            anyhow::ensure!(!value.trim().is_empty(), "--config requires a file path");
            return Ok(Some(PathBuf::from(value)));
        }
        index += 1;
    }
    Ok(None)
}

fn read_config_file(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let mut values = Vec::new();
    for entry in dotenvy::from_path_iter(path)
        .map_err(|error| anyhow::anyhow!("failed to read config {}: {error}", path.display()))?
    {
        let (key, value) = entry.map_err(|error| {
            anyhow::anyhow!("failed to parse config {}: {error}", path.display())
        })?;
        anyhow::ensure!(
            is_allowed_config_key(&key),
            "config {} contains unsupported key {key}; expected COLAND_*, DATABASE_URL, or RUST_LOG",
            path.display()
        );
        values.push((key, value));
    }
    Ok(values)
}

fn is_allowed_config_key(key: &str) -> bool {
    key.starts_with("COLAND_") || matches!(key, "DATABASE_URL" | "RUST_LOG")
}

fn non_empty(values: &BTreeMap<String, String>, name: &str) -> Option<String> {
    values
        .get(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ambient(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn write_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "coland-process-config-{}-{name}",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write test file");
        path
    }

    #[test]
    fn ambient_wins_over_config_file() {
        let path = write_file("ambient-wins.env", "COLAND_TRUST_DOMAIN=from-file\n");
        let args = vec![
            "coland".into(),
            "--config".into(),
            path.display().to_string(),
        ];
        let values = merge(&args, ambient(&[("COLAND_TRUST_DOMAIN", "from-env")])).unwrap();
        assert_eq!(
            values.get("COLAND_TRUST_DOMAIN").map(String::as_str),
            Some("from-env")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn no_env_overrides_makes_file_authoritative() {
        let path = write_file("file-wins.env", "COLAND_TRUST_DOMAIN=from-file\n");
        let args = vec![
            "coland".into(),
            "--config".into(),
            path.display().to_string(),
            "--no-env-overrides".into(),
        ];
        let values = merge(
            &args,
            ambient(&[
                ("COLAND_TRUST_DOMAIN", "from-env"),
                ("COLAND_BIND", "from-env"),
            ]),
        )
        .unwrap();
        assert_eq!(
            values.get("COLAND_TRUST_DOMAIN").map(String::as_str),
            Some("from-file")
        );
        assert!(!values.contains_key("COLAND_BIND"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unsupported_config_key_is_rejected() {
        let path = write_file("bad-key.env", "NOT_COLAND_ANYTHING=1\n");
        let args = vec![
            "coland".into(),
            "--config".into(),
            path.display().to_string(),
        ];
        let error = merge(&args, Vec::new()).unwrap_err();
        assert!(error.to_string().contains("unsupported key"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_config_path_is_rejected() {
        let error = merge(&["coland".into(), "--config".into()], Vec::new()).unwrap_err();
        assert!(error.to_string().contains("--config requires a file path"));
    }

    #[test]
    fn secret_file_is_resolved_before_values_reach_library_crates() {
        let path = write_file("secret", "from-file\n");
        let mut values = BTreeMap::from([(
            "COLAND_TURN_SHARED_SECRET_FILE".to_owned(),
            path.display().to_string(),
        )]);
        resolve_secret_files(&mut values).unwrap();
        assert_eq!(
            values.get("COLAND_TURN_SHARED_SECRET").map(String::as_str),
            Some("from-file")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn direct_and_file_secret_sources_are_mutually_exclusive() {
        let path = write_file("conflicting-secret", "from-file\n");
        let mut values = BTreeMap::from([
            ("COLAND_TURN_SHARED_SECRET".to_owned(), "direct".to_owned()),
            (
                "COLAND_TURN_SHARED_SECRET_FILE".to_owned(),
                path.display().to_string(),
            ),
        ]);
        let error = resolve_secret_files(&mut values).unwrap_err();
        assert!(error.to_string().contains("both set"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn empty_secret_file_is_rejected() {
        let path = write_file("empty-secret", "  \n");
        let error = resolve_value_or_file(
            "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET",
            "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET_FILE",
            None,
            Some(path.to_str().unwrap()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("empty secret file"));
        let _ = std::fs::remove_file(path);
    }
}
