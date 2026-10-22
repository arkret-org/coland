#!/usr/bin/env bash
set -euo pipefail

# Cargo reads every sibling workspace manifest, even when a consumer only
# builds a Coland leaf crate. Preserve the same layout as checkout-workspace.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd -- "$script_dir/../.." && pwd)"
server="${GITHUB_SERVER_URL:-https://github.com}"
owner="${GITHUB_REPOSITORY_OWNER:-arkret-org}"

clone_missing() {
  local repository="$1" destination="$2" ref="$3"
  if [ -f "$destination/Cargo.toml" ] || [ -e "$destination/.git" ]; then
    return
  fi
  if [ -e "$destination" ]; then
    echo "::error::Incomplete dependency checkout: $destination" >&2
    exit 1
  fi
  mkdir -p -- "$(dirname -- "$destination")"
  if [ -n "${CI_REPO_TOKEN:-}" ]; then
    local auth
    auth="$(printf 'x-access-token:%s' "$CI_REPO_TOKEN" | base64 | tr -d '\n')"
    git -c "http.${server}/.extraheader=AUTHORIZATION: basic ${auth}" \
      clone --depth 1 --branch "$ref" "$server/$repository.git" "$destination"
  else
    git clone --depth 1 --branch "$ref" "$server/$repository.git" "$destination"
  fi
}

for repository in arkret-rust-sdk floria arkret-spec garth bridges; do
  clone_missing "$owner/$repository" "$workspace/$repository" "${SIBLING_REF:-main}"
done
clone_missing savfox-ai/savfox "$(dirname -- "$workspace")/savfox-ai/savfox" main
