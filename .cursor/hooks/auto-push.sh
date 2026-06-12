#!/bin/bash
# After agent session: push commits that are ahead of origin.
root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

branch=$(git symbolic-ref --short HEAD 2>/dev/null) || exit 0
remote=$(git config "branch.${branch}.remote" 2>/dev/null)
[ -z "$remote" ] && remote=origin

if ! git rev-parse --abbrev-ref "@{upstream}" >/dev/null 2>&1; then
  git push -u "$remote" "$branch" 2>/dev/null || true
  exit 0
fi

ahead=$(git rev-list --count "@{upstream}..HEAD" 2>/dev/null || echo 0)
if [ "${ahead:-0}" -gt 0 ]; then
  git push "$remote" "$branch" 2>/dev/null || true
fi

exit 0
