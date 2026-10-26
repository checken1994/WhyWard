#!/usr/bin/env bash
set -euo pipefail

REPO_NAME="${1:-whyward}"
VISIBILITY="${2:-private}"
OWNER="${3:-}"

if [[ "$VISIBILITY" != "private" && "$VISIBILITY" != "public" ]]; then
  echo "Visibility must be private or public" >&2
  exit 2
fi
command -v git >/dev/null
command -v gh >/dev/null
[[ -f pyproject.toml && -d src/whyward ]] || {
  echo "Run this script from the WhyWard repository root" >&2
  exit 2
}

find . -type d -name __pycache__ -prune -exec rm -rf {} +
rm -rf .whyward-demo .whyward-runtime

if [[ ! -d .git ]]; then
  git init -b main
fi

git add .
if [[ -n "$(git status --porcelain)" ]]; then
  git commit -m "Initial WhyWard boundary control plane"
fi

REPO="$REPO_NAME"
if [[ -n "$OWNER" ]]; then
  REPO="$OWNER/$REPO_NAME"
fi

if git remote get-url origin >/dev/null 2>&1; then
  git push -u origin main
else
  gh repo create "$REPO" "--$VISIBILITY" --source=. --remote=origin --push \
    --description "WhyWard — an evidence-gated boundary control plane for AI workers"
fi

gh repo view "$REPO" --web
