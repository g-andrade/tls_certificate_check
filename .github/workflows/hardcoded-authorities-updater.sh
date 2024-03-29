#!/usr/bin/env bash

set -eux

#
# inspired by:
# * https://github.com/elixir-mint/castore/tree/v0.1.11/.github/workflows
#

git config user.name "GitHub Actions"
git config user.email "actions@users.noreply.github.com"

BASE_BRANCH=master
git fetch origin
git checkout "${BASE_BRANCH}"
git reset --hard "origin/${BASE_BRANCH}"
git clean -ffdx

make hardcoded-authorities-update
if [[ -z $(git status -s) ]]; then
    # no update
    exit
fi

DATE=$(date -r tmp/cacerts.pem '+%Y/%m/%d') # linux-specific
BRANCH=automation/hardcoded-authorities-update/$DATE
if git branch -a | grep "${BRANCH}" >/dev/null; then
    # branch already created
    exit
fi

REMOTE=origin
PR_TITLE="Update bundled CAs to latest as of $DATE"
git checkout -b "$BRANCH"
git add .
git commit -a -m "${PR_TITLE}"
git push "$REMOTE" "$BRANCH"

PR_LABEL="hardcoded authorities update"
if ! gh pr list --state open --label "$PR_LABEL" | grep "${PR_TITLE}" >/dev/null; then
    gh pr create --fill \
        --title "${PR_TITLE}" \
        --body "Stay safe 🔐" \
        --label "${PR_LABEL}" \
        --reviewer "g-andrade"
fi
