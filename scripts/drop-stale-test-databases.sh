#!/usr/bin/env sh
# Drop the leased test-database slots that belong to a superseded schema.
#
# `crates/storage-postgres/src/test_database.rs` names every slot
# `<base>_s<fingerprint>_slot<NN>`, where the fingerprint is eight hex
# characters of `sha256(migrations/00000000000000_initial/up.sql)`. This
# repository rewrites that migration in place, and Diesel only applies
# migrations it has not seen, so a slot created under an older revision would
# otherwise keep its old schema forever. Renaming the family fixes that; this
# script reclaims the families nothing will lease again.
#
# A database with an open connection cannot be dropped: PostgreSQL refuses,
# this reports it and moves on, so a concurrent run is never disturbed.
#
# Usage:
#   COLAND_TEST_DATABASE_URL=postgres://postgres:root@localhost/coland_dev \
#     scripts/drop-stale-test-databases.sh          # report only
#   ... scripts/drop-stale-test-databases.sh --drop # actually drop

set -eu

url="${COLAND_TEST_DATABASE_URL:-${DATABASE_URL:-}}"
if [ -z "$url" ]; then
    echo "set COLAND_TEST_DATABASE_URL or DATABASE_URL to the base database" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
migration="$root/crates/storage-postgres/migrations/00000000000000_initial/up.sql"
[ -f "$migration" ] || { echo "no migration at $migration" >&2; exit 2; }

# Must agree with `fingerprint_of` in test_database.rs: bare lowercase hex of
# sha256 over the file bytes, first eight characters.
current=$(sha256sum "$migration" | cut -c1-8)

# `<scheme>://<authority>/<database>[?query]` -> base name, and an admin URL on
# the same authority. `postgres` is the database CREATE/DROP connect to.
scheme=${url%%://*}
authority=${url#*://}
base=${authority#*/}
base=${base%%\?*}
authority=${authority%%/*}
admin="$scheme://$authority/postgres"

echo "base database : $base"
echo "current schema: $current"

# psql prints CRLF on Windows and CR is not in IFS, so it would survive word
# splitting and break every glob below. `_` is a single-character wildcard in
# LIKE, so the SQL only narrows the set; the shape is decided by the globs.
list=$(psql "$admin" -Atqc \
    "SELECT datname FROM pg_database WHERE datname LIKE '${base}%slot%' ORDER BY datname" \
    | tr -d '\r')

stale=""
for name in $list; do
    case "$name" in
        # Current scheme: <base>_s<8 hex>_slot<NN>.
        "$base"_s????????_slot[0-9][0-9])
            tail=${name#"${base}_s"}
            if [ "${tail%%_slot*}" = "$current" ]; then
                continue
            fi
            ;;
        # Pre-fingerprint scheme: <base>_slot<NN>. Stale by construction --
        # nothing will ever lease that name again.
        "$base"_slot[0-9][0-9]) ;;
        *) continue ;;
    esac
    stale="$stale $name"
done

if [ -z "$stale" ]; then
    echo "no slot databases from a superseded schema"
    exit 0
fi

if [ "${1:-}" != "--drop" ]; then
    echo "superseded slot databases (re-run with --drop to remove):"
    for name in $stale; do echo "  $name"; done
    exit 0
fi

for name in $stale; do
    if psql "$admin" -qc "DROP DATABASE \"$name\"" >/dev/null 2>&1; then
        echo "dropped $name"
    else
        echo "in use, kept $name"
    fi
done
