#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
server="${GITHUB_SERVER_URL:-https://github.com}"
owner="${GITHUB_REPOSITORY_OWNER:-arkret-org}"
token="${CI_REPO_TOKEN:-}"
source_file="$script_dir/release-sources.json"
workspace="$(cd -- "$script_dir/../.." && pwd)"

checkout_exact() {
  local repository="$1" destination="$2" revision="$3" url actual_root actual_remote
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo "Expected an immutable commit for $repository" >&2; return 1; }
  [[ ! -L "$destination" ]] || { echo "Dependency destination cannot be a symlink" >&2; return 1; }
  url="${server}/${owner}/${repository}.git"
  if [ -e "$destination" ]; then
    actual_root="$(git -C "$destination" rev-parse --show-toplevel)" || return 1
    actual_root="$(cd "$actual_root" && pwd -P)" || return 1
    [[ "$actual_root" == "$(cd "$destination" && pwd -P)" ]] || { echo "Destination is not its own Git repository" >&2; return 1; }
    actual_remote="$(git -C "$destination" remote get-url origin)" || return 1
    actual_remote="${actual_remote%/}"
    [[ "${actual_remote%.git}" == "${url%.git}" ]] || { echo "Dependency origin differs from its declared repository" >&2; return 1; }
    [[ -z "$(git -C "$destination" status --porcelain=v1 --untracked-files=all)" ]] || { echo "Dependency checkout contains local changes" >&2; return 1; }
    [[ "$(git -C "$destination" rev-parse HEAD)" == "$revision" ]] || { echo "Dependency checkout is not the pinned commit; keep it unchanged" >&2; return 1; }
    return
  fi
  mkdir -p -- "$(dirname -- "$destination")"
  git init --quiet "$destination"
  git -C "$destination" remote add origin "$url"
  if [ -n "$token" ]; then
    local auth
    auth="$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')"
    git -c "http.${server}/.extraheader=AUTHORIZATION: basic ${auth}" -C "$destination" fetch --depth 1 origin "$revision"
  else
    git -C "$destination" fetch --depth 1 origin "$revision"
  fi
  git -C "$destination" -c advice.detachedHead=false checkout --detach FETCH_HEAD
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$revision" ]] || { echo "Fetched commit differs from the pinned revision" >&2; return 1; }
}

revision_for() {
  node - "$source_file" "$1" <<'JS'
const fs = require('node:fs');
const [filename, name] = process.argv.slice(2);
const sources = JSON.parse(fs.readFileSync(filename, 'utf8'));
const aliases = {'arkret-rust-sdk': 'sdk', 'arkret-spec': 'spec'};
const revision = sources[name] ?? sources[aliases[name]];
if (typeof revision !== 'string' || !/^[0-9a-f]{40}$/.test(revision)) {
  throw new Error(`No immutable source registered for ${name}`);
}
process.stdout.write(revision);
JS
}

for repository in arkret-rust-sdk floria arkret-spec garth bridges; do
  checkout_exact "$repository" "$workspace/$repository" "$(revision_for "$repository")"
done
