#!/usr/bin/env bash

set -eux

#
# inspired by:
# * https://github.com/elixir-mint/castore/tree/v0.1.11/.github/workflows
#

#git config user.name "GitHub Actions"
#git config user.email "actions@users.noreply.github.com"

# this mirrors "util/tls_certificate_check_hardcoded_authorities_updater.erl"
UPDATED_STATUS_CODE=42

UPDATE_STATUS=$((make hardcoded-authorities-update 1>&2 && echo 0) || echo $?)

if [ ! $UPDATE_STATUS -eq $UPDATED_STATUS_CODE ]; then
    exit $UPDATE_STATUS
fi

DATE=$(date -r tmp/cacerts.pem '+%Y/%m/%d') # linux-specific
BASE_BRANCH=test/automation-of-hardcoded-authorities-update
BRANCH=automation/hardcoded-authorities-update/$(DATE)
PR_TITLE="[test] Update bundled CAs to latest as of $(DATE)"

git checkout -b "$BRANCH" "${BASE_BRANCH}"
git add .
git commit -m "${PR_TITLE}"
git push --force origin "$BRANCH"

PR_LABEL="hardcoded authorities update"
if gh pr list --label "$PR_LABEL" | grep -v "${PR_TITLE}" >/dev/null; then
    gh pr create --fill \
        --title "${PR_TITLE}" \
        --label "${PR_LABEL}" \
        --reviewer "g-andrade"
fi
