#!/usr/bin/env bash
# coland production restore drill.
#
# Inverse of `backup-drill.sh`. Accepts a tarball produced by that script,
# restores the database, identity bundle, and keystore.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: restore-drill.sh <tarball>" >&2
    exit 2
fi

TARBALL="$1"
if [ ! -f "$TARBALL" ]; then
    echo "[restore-drill] FATAL: tarball not found: $TARBALL" >&2
    exit 2
fi

DATABASE_URL="${COLAND_DATABASE_URL:-${DATABASE_URL:-}}"
BUNDLE_DIR="${COLAND_SERVICE_IDENTITY_BUNDLE_DIR:-}"
KEYSTORE_BACKEND="${COLAND_KEYSTORE_BACKEND:-}"
WORKDIR="$(mktemp -d -t coland-restore-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

if [ -z "$DATABASE_URL" ]; then
    echo "[restore-drill] FATAL: COLAND_DATABASE_URL or DATABASE_URL is unset" >&2
    exit 2
fi
if [ -z "$BUNDLE_DIR" ]; then
    echo "[restore-drill] FATAL: COLAND_SERVICE_IDENTITY_BUNDLE_DIR is unset" >&2
    exit 2
fi
case "$KEYSTORE_BACKEND" in
    platform|encrypted_file) ;;
    *)
        echo "[restore-drill] FATAL: COLAND_KEYSTORE_BACKEND must be platform or encrypted_file" >&2
        exit 2
        ;;
esac

for cmd in pg_restore psql sha256sum tar jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[restore-drill] FATAL: missing prerequisite '$cmd'" >&2
        exit 2
    fi
done

echo "[restore-drill] tarball=$TARBALL workdir=$WORKDIR"
tar -xzf "$TARBALL" -C "$WORKDIR"

MANIFEST="$WORKDIR/manifest.json"
if [ ! -f "$MANIFEST" ]; then
    echo "[restore-drill] FATAL: tarball missing manifest.json" >&2
    exit 1
fi

declare -A EXPECTED_SHA
while IFS=$'\t' read -r name sha; do
    EXPECTED_SHA[$name]="$sha"
done < <(jq -r '.artifacts | to_entries[] | "\(.key)\t\(.value.sha256)"' "$MANIFEST")

for name in coland-database.dump service-identity-bundle.json keystore.json; do
    f="$WORKDIR/$name"
    if [ ! -f "$f" ]; then
        echo "[restore-drill] FATAL: tarball missing artifact '$name'" >&2
        exit 1
    fi

    actual="$(sha256sum "$f" | awk '{print $1}')"
    expected="${EXPECTED_SHA[$name]:-}"
    if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
        echo "[restore-drill] FATAL: checksum mismatch on '$name'" >&2
        echo "  expected=$expected actual=$actual" >&2
        exit 1
    fi
done
echo "[restore-drill] manifest checksums verified"

BUNDLE_PATH="$WORKDIR/service-identity-bundle.json"
SERVICE_ID="$(jq -er '.identity.identity.did | select(startswith("did:webvh:"))' "$BUNDLE_PATH")" || {
    echo "[restore-drill] FATAL: identity bundle has no did:webvh did" >&2
    exit 1
}
MANIFEST_SERVICE_ID="$(jq -er '.service_id' "$MANIFEST")"
if [ "$SERVICE_ID" != "$MANIFEST_SERVICE_ID" ]; then
    echo "[restore-drill] FATAL: identity bundle service_id does not match manifest" >&2
    exit 1
fi
BUNDLE_BACKEND_FILE="$(jq -er '.identity_bundle_backend_file' "$MANIFEST")"
case "$BUNDLE_BACKEND_FILE" in
    ""|"."|".."|*/*|*\\*)
        echo "[restore-drill] FATAL: unsafe identity_bundle_backend_file in manifest" >&2
        exit 1
        ;;
esac
MANIFEST_KEYSTORE_BACKEND="$(jq -er '.keystore_backend' "$MANIFEST")"
case "$MANIFEST_KEYSTORE_BACKEND" in
    platform|encrypted_file) ;;
    *)
        echo "[restore-drill] FATAL: backup manifest has unsupported keystore_backend=$MANIFEST_KEYSTORE_BACKEND" >&2
        exit 1
        ;;
esac
echo "[restore-drill] service_id=$SERVICE_ID identity_bundle_backend_file=$BUNDLE_BACKEND_FILE keystore_backend=$MANIFEST_KEYSTORE_BACKEND->$KEYSTORE_BACKEND"

echo "[restore-drill] step 1/3: pg_restore (clean+if-exists)"
pg_restore --clean --if-exists --no-owner --no-acl \
    --dbname="$DATABASE_URL" "$WORKDIR/coland-database.dump"

echo "[restore-drill] step 2/3: restore SDK identity bundle"
mkdir -p "$BUNDLE_DIR"
cp "$BUNDLE_PATH" "$BUNDLE_DIR/$BUNDLE_BACKEND_FILE"

echo "[restore-drill] step 3/3: keystore restore via coland-keystore-snapshot --import-only"
cargo run --quiet --bin coland-keystore-snapshot -- \
    --import-only \
    --identity-bundle "$BUNDLE_PATH" \
    --input "$WORKDIR/keystore.json"

echo "[restore-drill] RESTORE PASS"
