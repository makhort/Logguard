#!/bin/bash
# Installs a git pre-push hook that runs scripts/ci.sh, so nothing that fails the checks
# is pushed (skip once with `git push --no-verify`). Run again after moving the repository.
set -euo pipefail
cd "$(dirname "$0")/.."
hooks=$(git rev-parse --git-path hooks)
hook="$hooks/pre-push"
marker="# logguard pre-push hook"
if [ -e "$hook" ] && ! grep -q "$marker" "$hook"; then
    echo "$hook exists and isn't ours; add this line to it instead:" >&2
    echo "  \"\$(git rev-parse --show-toplevel)/logguard/scripts/ci.sh\"" >&2
    exit 1
fi
mkdir -p "$hooks"
cat > "$hook" <<'HOOK'
#!/bin/sh
# logguard pre-push hook (installed by logguard/scripts/install-hooks.sh)
# Runs the logguard checks when the pushed commits touch logguard/.
root=$(git rev-parse --show-toplevel)
zero=0000000000000000000000000000000000000000
run=no
while read -r _local_ref local_sha _remote_ref remote_sha; do
    [ "$local_sha" = "$zero" ] && continue            # deleting a branch
    if [ "$remote_sha" = "$zero" ] || ! git cat-file -e "$remote_sha^{commit}" 2> /dev/null; then
        run=yes                                       # new branch, or remote commits not fetched: check it
    elif [ -n "$(git diff --name-only "$remote_sha" "$local_sha" -- ":(top)logguard" ":(top).github" 2> /dev/null)" ]; then
        run=yes
    fi
done
[ "$run" = yes ] || exit 0
echo "pre-push: running logguard/scripts/ci.sh (skip with git push --no-verify)"
exec "$root/logguard/scripts/ci.sh"
HOOK
chmod +x "$hook"
echo "Installed $hook"
