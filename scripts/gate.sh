#!/usr/bin/env sh
# Run the local test gate and leave machine-readable evidence behind.
#
# Three things this exists to fix, all of which have cost real debugging time:
#
#   * `--quiet` — the per-test log runs to thousands of lines. A terminal
#     scrollback that truncates it hides the failure summary, which is at the
#     end.
#   * bounded `--jobs` — at full parallelism a low-memory or Windows runner
#     fails to mmap an rlib (`os error 1455`, the pagefile is too small). That
#     surfaces as a *test* failure and sends people chasing a bug that is not
#     there. One job removes it; raise `COLAND_GATE_JOBS` on a machine with
#     headroom.
#   * saved artifacts — the exit status and an extracted summary are written to
#     files, so the verdict never depends on what happened to still be on
#     screen. Read `$COLAND_GATE_DIR/summary.txt`, not the terminal tail.
#
# Runs with `--no-fail-fast` so one early failure does not hide the rest.
# Exits with cargo's status.
#
# Usage:
#   scripts/gate.sh                                  # whole workspace
#   scripts/gate.sh -p coland --test extensions_smoke
#
# Every argument is forwarded to `cargo test`, so a narrow re-run keeps the same
# quiet output, the same bounded parallelism and the same artifacts.

set -eu

jobs="${COLAND_GATE_JOBS:-1}"
gate_dir="${COLAND_GATE_DIR:-target/gate}"
# A separate target dir keeps a long-running `just dev` from holding a lock on
# the test binaries on Windows.
target_dir="${COLAND_GATE_TARGET_DIR:-target/test}"

mkdir -p "$gate_dir"
log="$gate_dir/test.log"
summary="$gate_dir/summary.txt"
status="$gate_dir/status.txt"

echo "gate: jobs=$jobs target=$target_dir log=$log"

# Cheap checks first: a retired protocol literal is a fixture bug the compiler
# cannot see, and finding it after a 15-minute test run wastes the run. The
# scanner proves itself before it is trusted, same as the secret scan does.
sh "$(dirname -- "$0")/tests/stale-literal-scan.tests.sh"
sh "$(dirname -- "$0")/stale-literal-scan.sh"
# A test-only accessor or module that lost its `#[cfg]` compiles into the
# release binary and no test fails for it. Repository Actions are switched off
# here by decision, so `.github/workflows/ci.yml` running this check guarantees
# nothing — the local gate is where it has to run.
python "$(dirname -- "$0")/check-test-support-surface.py"

set +e
SSL_CERT_FILE="$PWD/crates/server/tests/fixtures/outbox-test-ca.pem" CARGO_TARGET_DIR="$target_dir" cargo test --locked --quiet \
    --jobs "$jobs" --no-fail-fast "$@" > "$log" 2>&1
code=$?
set -e

echo "$code" > "$status"

# Keep only the lines a reviewer acts on: per-suite results, the failure roster
# *and its entries*, each failing test's header, and compiler errors. Everything
# else stays in the full log.
#
# The roster-entry alternative matches an indented `path::to::test` and nothing
# else, so indented panic detail ("    at src/lib.rs:10") and cargo's own
# indented status lines ("    Finished test profile") stay out: both contain a
# space where a `::` segment would have to be.
grep -E '^(test result:|failures:|---- .* ----|error(\[E[0-9]+\])?:|    [A-Za-z_][A-Za-z0-9_]*(::[A-Za-z0-9_]+)+$)' "$log" \
    > "$summary" || true

echo "--- $summary ---"
cat "$summary"
echo "--- exit $code (full log: $log) ---"
exit "$code"
