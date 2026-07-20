# Branch protection for `main` — P3 posture (2026-07-20)

`main` was **intentionally UNPROTECTED** through merges #193–#197 (every merge
landed UNSTABLE). This doc records the P3 governance change: turn on classic
branch protection requiring ONLY the checks that are BOTH (a) reliably green in
real CI **and** (b) run on **every** PR to `main` (no `paths:` filter).

Confirmed via `gh api repos/spannella/testlogon/branches/main/protection` -> 404
"Branch not protected"; no rulesets (`/rulesets` = `[]`), no branch rules.

## The path-filter footgun (why the required set is small)

A **required** status check that does **not run** for a given PR (because its
workflow is `paths:`-filtered and the PR touched none of those paths) is
reported by GitHub as **"Expected -- waiting for status"** and **BLOCKS THE
MERGE INDEFINITELY**. GitHub does NOT auto-pass a check whose workflow never
triggered.

This was verified empirically in P3 with throwaway PR **#198** (docs-only change
to `ops/ci-p3-validate-throwaway.md`, targeting `main`). Only these 4 checks
triggered -- every `paths:`-gated workflow was silent:

    browser-ssh-backend-tests
    payment-incident-backend-matrix (required)
    payment-incident-frontend-e2e (required)
    policy-matrix

NOT triggered on that PR (all `paths:`-gated): `Build + unit tests`,
`Android unit tests (money/ecom/dispute/core)`, `fullstack-e2e`,
`contract-tests`, `release-gate`, `web-e2e`.

CONCLUSION: requiring any `paths:`-gated check in **classic** branch protection
would permanently block legitimate PRs that touch none of its paths (a pure docs
or pure-backend PR would be blocked on the android gate). Per the governance
rules ("NEVER require a check that would block a legitimate merge"), those are
NOT put in the classic required set. They still RUN and gate the PRs that touch
their areas -- they just are not listed as unconditionally-required contexts.

## REQUIRED set (applied) -- 4 always-run, reliably-green contexts

Exact context strings as GitHub records them (note the `(required)` suffix on
the payment-incident jobs -- this comes from the job `name:` and MUST be matched
verbatim; the earlier BRANCH_PROTECTION.md draft omitted it and would not have
matched):

    payment-incident-backend-matrix (required)
    payment-incident-frontend-e2e (required)
    browser-ssh-backend-tests
    policy-matrix

All four ran + were reported on the android-heavy PR #197, the web-heavy PR #196,
and the docs-only PR #198 -- i.e. they run on EVERY PR. They are the established
backend/policy gate and are reliably green.

## NOT required (deliberately) -- and why

- `Build + unit tests` (android.yml) -- reliably green (3/3: 29704339987,
  29708461753, 29734830004) BUT `paths:`-gated to `android/**`. Requiring it
  would block every non-android PR. It runs + gates on android PRs already.
- `Android unit tests (money/ecom/dispute/core)` (android-unit-money.yml) --
  reliably green (4/4, 433 tests / 0 fail) and P3 PROMOTED to ALWAYS-RUN on PRs
  touching `android/**` (label guard removed). Still `paths:`-gated to
  `android/**`, so same footgun -- not in the classic required set.
- `fullstack-e2e` -- green after the P1 drive-mock quarantine (29708266870) but
  `paths:`-gated to a narrow calendar/signing/drive path set; would block PRs
  outside those paths.
- `contract-tests`, `release-gate` (broadcast-*) -- `paths:`-gated; block
  non-broadcast PRs.
- `web-e2e` -- NOT reliably green (irreducible ~1% shifting flake floor after the
  P2 soak; best run 3 failed / 406). Requiring a flaky check blocks EVERY merge.
  Stays label-gated (`run-web-e2e`) + dispatch, informational.
- `Instrumented tests (emulator)` (android.yml) -- DETERMINISTIC RED (5
  InputsDaoTest Room-DAO instrumented tests fail every run). Separate work item.

## Applied command (classic protection, reversible)

    gh api -X PUT repos/spannella/testlogon/branches/main/protection --input - <<JSON
    {
      "required_status_checks": {
        "strict": false,
        "contexts": [
          "payment-incident-backend-matrix (required)",
          "payment-incident-frontend-e2e (required)",
          "browser-ssh-backend-tests",
          "policy-matrix"
        ]
      },
      "enforce_admins": false,
      "required_pull_request_reviews": null,
      "restrictions": null,
      "required_linear_history": false,
      "allow_force_pushes": false,
      "allow_deletions": false
    }
    JSON

- `strict:false` -- a branch need not be up-to-date before merge (avoids re-run
  churn on a busy default branch).
- `enforce_admins:false` -- keeps a break-glass so the owner can emergency-merge.
- No review requirement / no push restrictions (matches the repo's current
  single-maintainer flow; add later if desired).

## How to ALSO enforce the android/e2e gates without the footgun (owner, optional)

Classic protection cannot say "require only when relevant". Two GitHub-native
options if the owner wants the `paths:`-gated gates to be hard-required:

1. **Repository ruleset with a required workflow** (Settings -> Rules ->
   Rulesets). Rulesets can require a specific *workflow file* to pass; a workflow
   skipped by its own `paths:` filter is treated as met (unlike a classic
   required *context*). This is the correct mechanism to require `android.yml`
   (`Build + unit tests`), `android-unit-money.yml`, and `fullstack-e2e` without
   blocking unrelated PRs. NOT applied here (needs a ruleset, a bigger change);
   documented for the owner.
2. **Merge queue** -- checks run against the queued merge commit, so path filters
   evaluate against the actual diff. Heavier; only if the repo adopts a queue.

## Revert (fully reversible)

    gh api -X DELETE repos/spannella/testlogon/branches/main/protection

To drop a single context, re-PUT the JSON above with that context removed.
