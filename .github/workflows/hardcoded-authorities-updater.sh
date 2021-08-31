#!/usr/bin/env bash

set -eux

#
# inspired by:
# * https://github.com/elixir-mint/castore/tree/v0.1.11/.github/workflows
#

#git config user.name "GitHub Actions"
#git config user.email "actions@users.noreply.github.com"

BASE_BRANCH=test/automation-of-hardcoded-authorities-update
git checkout "${BASE_BRANCH}"
git reset --hard
git clean -ffdx

make hardcoded-authorities-update
if [[ -z $(git status -s) ]]; then
    # no update
    exit
fi

DATE=$(date -r tmp/cacerts.pem '+%Y/%m/%d') # linux-specific
BRANCH=automation/hardcoded-authorities-update/$(DATE)
if git branch -a | grep "${BRANCH}" >/dev/null; then
    # update branch already open
    exit
fi

PR_TITLE="[test] Update bundled CAs to latest as of $(DATE)"
git checkout -b "$BRANCH"
git add .
git commit -a -m "${PR_TITLE}"
git push --force origin "$BRANCH"

PR_LABEL="hardcoded authorities update"
if gh pr list --label "$PR_LABEL" | grep -v "${PR_TITLE}" >/dev/null; then
    gh pr create --fill \
        --title "${PR_TITLE}" \
        --label "${PR_LABEL}" \
        --reviewer "g-andrade"
fi
