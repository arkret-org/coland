use std::process::Command;

#[test]
fn version_query_requires_no_deployment_configuration() {
    for flag in ["--version", "-V"] {
        assert_version_output(&mut version_command(flag));
    }
}

#[test]
fn version_query_ignores_invalid_deployment_configuration() {
    for flag in ["--version", "-V"] {
        assert_version_output(
            version_command(flag)
                .env("COLAND_DEVELOPMENT_MODE", "not-a-boolean")
                .env("COLAND_KEYSTORE_MASTER_KEY_FILE", "missing-secret-file")
                .env("DATABASE_URL", "not-a-database-url"),
        );
    }
}

fn version_command(flag: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_coland"));
    // Keep Windows system variables available for dependent DLL loading.
    let inherited_keys: Vec<_> = std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| {
            let key = key.to_string_lossy();
            key.starts_with("COLAND_") || matches!(key.as_ref(), "DATABASE_URL" | "RUST_LOG")
        })
        .collect();
    for key in inherited_keys {
        command.env_remove(key);
    }
    command.arg(flag);
    command.current_dir(std::env::temp_dir());
    command
}

fn assert_version_output(command: &mut Command) {
    let output = command.output().expect("run coland version query");
    assert!(
        output.status.success(),
        "version query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 version output")
            .trim(),
        format!("coland {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        output.stderr.is_empty(),
        "version query emitted startup logs"
    );
}
