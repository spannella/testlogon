# Branch protection for main -- SUPERSEDED by ops/ci-branch-protection.md

This P2 draft has been SUPERSEDED by the P3 posture in
[`ops/ci-branch-protection.md`](../ops/ci-branch-protection.md), which was
applied 2026-07-20.

Two corrections the P3 work made to this draft:

1. **Context strings were wrong.** The payment-incident contexts are recorded by
   GitHub as `payment-incident-backend-matrix (required)` and
   `payment-incident-frontend-e2e (required)` (with the ` (required)` suffix from
   the job `name:`). The bare names in this draft would not have matched.

2. **The `paths:`-filter footgun.** This draft proposed requiring
   `Build + unit tests`, `Android unit tests (money/ecom/dispute/core)`, and
   `fullstack-e2e`. All three are `paths:`-gated, so a required context for them
   would BLOCK any PR that touches none of their paths (verified empirically with
   throwaway PR #198 -- a docs-only PR triggered none of them). Requiring them in
   classic protection would block legitimate merges.

The applied required set is therefore the 4 checks that run on EVERY PR and are
reliably green: `payment-incident-backend-matrix (required)`,
`payment-incident-frontend-e2e (required)`, `browser-ssh-backend-tests`,
`policy-matrix`. See ops/ci-branch-protection.md for the exact command, the
NOT-required rationale, and the ruleset path to also enforce the android/e2e
gates without the footgun.
