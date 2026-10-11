# Contributing to coland

Thanks for considering a contribution! coland is a reference Arkret v1
Station; the protocol contract lives in
[`arkret-spec`](https://github.com/arkret-org/arkret-spec) and the Rust SDK
in [`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk).

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` plus `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/` is missing or you want a
richer hook, copy `.githooks/pre-commit` from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk) and
adapt to your local toolchain.

## Repository layout

coland depends on the `arkret` SDK at a sibling path. The CI workflows clone
both repositories side by side; reproduce the same layout locally:

```
arkret/
├── arkret-rust-sdk/
│   └── crates/
└── coland/                # this repo
    ├── crates/
    ├── xtask/
    └── Cargo.toml
```

The `arkret-*` Cargo `path = "../arkret-rust-sdk/crates/<name>"` references
assume this layout. If you check out into a different structure, override the
dependencies locally with a `[patch.crates-io]` entry in
`~/.cargo/config.toml` rather than editing `Cargo.toml`.

## Toolchain

- Rust **stable** (MSRV: see `rust-version` in `Cargo.toml`).
- `cargo fmt`, `cargo clippy`, `cargo deny` all run in CI; install them with
  `rustup component add rustfmt clippy` and `cargo install cargo-deny`.
- PostgreSQL is required to exercise the persistence layer end to end, but
  unit tests and the in-memory integration suite run without a DB.

## Workflow

1. Fork and create a topic branch (`fix/short-description` or
   `feat/short-description`).
2. Run the local checks before pushing:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --locked
   ```

3. Open a PR; CI runs `Rust`, `Docker`, `Typos`, and `Supply chain` (cargo-deny)
   workflows. All must be green before review.
4. Describe the change and its verification in the PR description.

## Coding conventions

- Match the `.rustfmt.toml` style — `cargo fmt` enforces it.
- No `unsafe` anywhere in the workspace; there is currently no approved
  exception.
- Prefer typed errors via `crate::error::ErrorCode` over hand-typed strings;
  this is the F3 migration path.
- Keep handlers as `#[endpoint]` (Salvo OpenAPI variant). When you add a new
  route, mount it in
  [`crates/http/src/routing/router_build.rs`](crates/http/src/routing/router_build.rs)
  and, for a `/_coland/*` path, record it in
  [`noncanonical-route-inventory.jsonl`](noncanonical-route-inventory.jsonl)
  so `noncanonical_route_boundary` still passes.
- Don't introduce new `serde_json::Value` blobs at the wire boundary if a
  typed `wire::*` shape would do — the OpenAPI doc improves alongside this.

## Tests

- Unit tests live next to the code (`crates/<crate>/src/<module>.rs::tests`).
- HTTP integration tests live in the `crates/server/tests/http_api/`
  integration-test binary, split into per-domain modules with `main.rs` as the
  entry point.
- `crates/http/tests/noncanonical_route_boundary.rs` is load-bearing — adding
  or removing a `/_coland/*` route needs a matching
  `noncanonical-route-inventory.jsonl` update, including the metadata
  `current_private_path_count`.

The sibling Cotest process harness launches a prebuilt Coland executable.
Before running cross-repository conformance scenarios, build the current
source with `cargo build --locked --bin coland --features conformance-harness -j 2`
and set `COLAND_BIN` to that executable's absolute path. Compiling Coland as a
dependency of `cargo test` does not refresh the standalone executable; an older
binary can otherwise report behavior that the current source already rejects.

## Reporting bugs

Use a regular GitHub issue for non-security bugs. For vulnerabilities, see
[SECURITY.md](SECURITY.md).

## License

All contributions are licensed under Apache-2.0 (see [LICENSE](LICENSE)).
By submitting a PR you agree your contribution is licensed under the same
terms.
