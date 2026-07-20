# Branch protection for main -- recommended settings (owner action)

main is currently UNPROTECTED (gh api repos/spannella/testlogon/branches/main/protection
returns 404; no rulesets/rules either). Every merge #193-#197 landed with no gate.
This doc is the exact, reversible command to turn on protection using ONLY the
checks SOAKED and proven reliably green in real CI (P2, 2026-07-20).

## Require ONLY these contexts (all proven reliably green in real CI)

- "Build + unit tests" (android.yml -> build-and-unit-test): green 3/3
  (29704339987, 29708461753, 29734830004); ~4540 tests.
- "Android unit tests (money/ecom/dispute/core)" (android-unit-money.yml): green 4/4,
  deterministic 433 tests / 0 fail (29708461150, 29708530861, 29710811003, 29734828584).
- "fullstack-e2e" (fullstack-e2e.yml): green after P1 drive-mock quarantine (29708266870).

## DO NOT require (would block every merge -- known reds/flakes)

- "Instrumented tests (emulator)" (android.yml): DETERMINISTIC RED -- 5 InputsDaoTest
  instrumented tests (core-data Room DAO) fail every run. Separate work item.
- "Web E2E (vertical + money gate)" (web-e2e.yml): SOAKED + hugely stabilised in P2
  (messaging backend-wedge fixed, seed + timeout fixed, deterministic offenders
  quarantined) but still has an irreducible ~1% shifting flake floor (best run
  29734184730 = 3 failed / 406). Requiring a flaky check blocks every merge. Keep it
  label-gated (run-web-e2e) + workflow_dispatch, informational, until per-spec DB
  isolation lands.

## Apply (needs admin; the CI token has admin:true)

    gh api -X PUT repos/spannella/testlogon/branches/main/protection --input - <<JSON
    {
      "required_status_checks": {
        "strict": false,
        "contexts": [
          "Build + unit tests",
          "Android unit tests (money/ecom/dispute/core)",
          "fullstack-e2e"
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

Notes:
- strict:false = branches need not be up-to-date before merge (avoids re-run churn).
- enforce_admins:false keeps a break-glass for the owner.
- money-unit + web-e2e only RUN on PRs carrying their opt-in label (run-android-unit /
  run-web-e2e). A required check must run on EVERY PR, so either add the label to PRs
  or flip that job if: guard to if: true. money-unit is fast (~10min) + deterministic
  and safe to make always-run; web-e2e is NOT.

## Revert (fully reversible)

    gh api -X DELETE repos/spannella/testlogon/branches/main/protection
