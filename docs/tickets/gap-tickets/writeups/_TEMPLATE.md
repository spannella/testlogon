# <GAP-ID>: <Title> — Remediation Write-up

> ~5 pages. Fix-oriented. Read the real code before writing; cite `file:line`. Build on the
> investigation doc (docs/tickets/gap-tickets/investigations/<GAP-ID>.md) if it exists.

## 1. Summary & Classification
- Plain-English statement of the bug/gap. Severity, source ticket, status, owning area.
- Verdict from investigation (Confirmed / Partially / etc.) and one-line impact.
- Related GAP/SEC tickets and dependencies.

## 2. Current-State Investigation (root cause)
- Walk the exact code path today with `file:line` + short code quotes. Why it's broken.
- What's present vs missing; how the bug manifests at runtime (dev vs prod).

## 3. Impact / Exploit / Blast Radius
- Who/what is affected; for security/money: concrete exploit walkthrough + worst case.
- Data integrity, financial, availability, or compliance consequences.

## 4. Fix Design (code-level)
- Precise change: functions/endpoints/models/tables to add or edit, with the intended code.
- Dev/Prod parity (SECOPS-007): mock/dev vs AWS path, flag-selected, same code path.
- Backward-compat / migration / feature flag; alternatives considered + why rejected.

## 5. Testing, Verification & Rollout
- Regression test that fails-before/passes-after (pytest offline + Playwright as needed).
- Manual QA steps; metrics/observability; rollback; risks; effort (S/M/L); sequencing.
