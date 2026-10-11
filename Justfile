set dotenv-load := true

bind := env_var_or_default("COLAND_BIND", "127.0.0.1:8698")
database_url := env_var_or_default("DATABASE_URL", "")
local_database_url := env_var_or_default("COLAND_LOCAL_DATABASE_URL", "postgres://coland:coland@localhost:5432/coland")
keystore_backend := env_var_or_default("COLAND_KEYSTORE_BACKEND", "")
keystore_path := env_var_or_default("COLAND_KEYSTORE_PATH", "")
keystore_master_key_file := env_var_or_default("COLAND_KEYSTORE_MASTER_KEY_FILE", "")
dev_keystore_path := env_var_or_default("COLAND_KEYSTORE_PATH", "./.local/keystore/coland.v1")
dev_keystore_master_key_file := env_var_or_default("COLAND_KEYSTORE_MASTER_KEY_FILE", "./.local/secrets/coland-keystore-master-key")
postgres_container := env_var_or_default("COLAND_POSTGRES_CONTAINER", "coland-postgres")
postgres_image := env_var_or_default("COLAND_POSTGRES_IMAGE", "postgres:16")
postgres_port := env_var_or_default("COLAND_POSTGRES_PORT", "5432")
postgres_user := env_var_or_default("COLAND_POSTGRES_USER", "coland")
postgres_password := env_var_or_default("COLAND_POSTGRES_PASSWORD", "coland")
postgres_db := env_var_or_default("COLAND_POSTGRES_DB", "coland")
# Cargo parallelism for the local gate. Windows and low-memory runners OOM the
# linker at full parallelism: rustc fails to mmap an rlib with `os error 1455`
# (the pagefile is too small), which surfaces as a *test* failure and sends
# everyone chasing a bug that is not there. One job removes it. Raise this on a
# machine with headroom.
gate_jobs := env_var_or_default("COLAND_GATE_JOBS", "1")
gate_dir := env_var_or_default("COLAND_GATE_DIR", "target/gate")
export DATABASE_URL := database_url
export COLAND_KEYSTORE_BACKEND := keystore_backend
export COLAND_KEYSTORE_PATH := keystore_path
export COLAND_KEYSTORE_MASTER_KEY_FILE := keystore_master_key_file
export COLAND_DEVELOPMENT_MODE := env_var_or_default("COLAND_DEVELOPMENT_MODE", "true")
export RUST_LOG := env_var_or_default("RUST_LOG", "coland=info")

# List available recipes.
default:
    @just --list

# Create a local .env from .env.example if it does not already exist.
init-env:
    @if test -f .env; then echo ".env already exists"; else cp .env.example .env && echo "created .env"; fi

# Provision the local PostgreSQL KeyStore key idempotently; invalid files fail.
init-dev:
    cargo run --quiet -p coland-keystore-keygen -- --output "{{ dev_keystore_master_key_file }}" --if-missing

# Run coland locally. DATABASE_URL must be configured; use `just dev-db` to
# start the managed local PostgreSQL container first.
dev: init-dev
    CARGO_TARGET_DIR=target/dev cargo run -- --bind {{ bind }}

# Alias for `dev`.
start: dev

# Run the local Caddy reverse proxy defined in Caddyfile.
caddy:
    caddy run --config Caddyfile

# Start a local Postgres container, wait for it, then run coland against it.
dev-db: init-dev db-up db-ready
    just --set database_url "{{ local_database_url }}" --set keystore_backend "encrypted_file" --set keystore_path "{{ dev_keystore_path }}" --set keystore_master_key_file "{{ dev_keystore_master_key_file }}" dev

# Alias for `dev-db`.
start-db: dev-db

# Start the local Postgres container, creating it on first use.
db-up:
    docker start {{ postgres_container }} >/dev/null 2>&1 || docker run --name {{ postgres_container }} -e POSTGRES_USER={{ postgres_user }} -e POSTGRES_PASSWORD={{ postgres_password }} -e POSTGRES_DB={{ postgres_db }} -p {{ postgres_port }}:5432 -d {{ postgres_image }}

# Wait until the local Postgres container is accepting connections.
db-ready:
    @until docker exec {{ postgres_container }} pg_isready -U {{ postgres_user }} -d {{ postgres_db }} >/dev/null 2>&1; do sleep 1; done

# Stop the local Postgres container.
db-down:
    docker stop {{ postgres_container }}

# Follow local Postgres logs.
db-logs:
    docker logs -f {{ postgres_container }}

# Open psql inside the local Postgres container.
db-shell:
    docker exec -it {{ postgres_container }} psql -U {{ postgres_user }} -d {{ postgres_db }}

# Print the local development DATABASE_URL.
db-url:
    @echo "{{ local_database_url }}"

# Scoped to this repository's own packages on purpose. The Arkret SDK is a
# sibling path dependency in this workspace, and `cargo fmt --all` reaches into
# that repository and rewrites its sources.
fmt:
    cargo +nightly fmt -p coland -p coland-contracts -p coland-domain -p coland-http -p coland-keystore-keygen -p coland-services -p coland-storage -p coland-storage-postgres -p coland-test-support -p xtask

# Scoped to this repository's own packages on purpose. The Arkret SDK is a
# sibling path dependency in this workspace, and `cargo fmt --all` reaches into
# that repository and rewrites its sources.
fmt-check:
    cargo +nightly fmt -p coland -p coland-contracts -p coland-domain -p coland-http -p coland-keystore-keygen -p coland-services -p coland-storage -p coland-storage-postgres -p coland-test-support -p xtask -- --check

# Check the default Cargo targets.
check:
    cargo check --locked

# Run clippy on default Cargo targets.
clippy:
    cargo clippy --locked

# Run the Rust test suite.
test:
    SSL_CERT_FILE="$PWD/crates/server/tests/fixtures/outbox-test-ca.pem" CARGO_TARGET_DIR=target/test cargo test --locked
    CARGO_TARGET_DIR=target/test cargo test --locked -p coland-keystore-keygen

# Run the HTTP API integration suite in an isolated target directory so a
# long-running `just dev` process cannot lock its test binary on Windows.
test-http-api:
    CARGO_TARGET_DIR=target/http-api cargo test --locked -p coland --test http_api --no-fail-fast

# Run the local test gate with bounded parallelism and saved artifacts.
#
# The logic lives in `scripts/gate.sh` so it can be run and tested without
# `just` installed; this recipe only supplies the tuning knobs. Read
# `{{ gate_dir }}/summary.txt` for the verdict, never the terminal tail.
#
# Extra arguments go to `cargo test`:
#
#     just gate -p coland --test extensions_smoke
gate *args:
    COLAND_GATE_JOBS={{ gate_jobs }} COLAND_GATE_DIR={{ gate_dir }} sh scripts/gate.sh {{ args }}

# Query the default health endpoint.
health:
    curl -fsS http://{{ bind }}/health
