# <TICKET-ID>: <Title> — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification
- One-paragraph plain-English statement of the problem/feature.
- Type (security-fix | feature | hardening | infra), Priority/Severity, Status, owning area.
- Who is affected / attacker class (for SEC: 🌐 any-user / 🛡️ admin-abuse / ⚙️ config), or user persona (for features).
- Cross-referenced tickets ([[...]] links) and dependencies (esp. **SEC-008** trusted IP, **SECOPS-007** dev/prod parity).

## 2. Current-State Investigation (what exists today)
- Walk the relevant code paths with exact `file:line` (routers, services, models, frontend).
- For SEC: how the vulnerable path works today + a concrete exploit/PoC walkthrough.
- For features: what exists/partially exists, what's missing, the data model & endpoints in play.
- Note dev (no-AWS/mock) vs prod (AWS) behavior of the current code.

## 3. Gap / Threat Analysis
- SEC: full attack scenario(s), impact, blast radius, preconditions, why current controls fail.
- Feature: detailed requirements, edge cases, failure modes, abuse potential, compliance/legal notes.
- Enumerate every code site that must change.

## 4. Proposed Design / Fix
- Concrete, code-level plan: new/changed functions, endpoints, models, tables (GSIs, attr_types), middleware, frontend components.
- **Dev/Prod parity (SECOPS-007)**: the mock/dev backend (DDB Local, mock KMS, moto, mock GeoIP/LLM/AbuseIPDB) vs prod AWS, selected by `dev_mode`/flags. Same code path.
- Backward-compat / migration / feature-flag / rollout.
- Alternatives considered + why rejected.

## 5. Testing, Verification & Rollout
- pytest unit tests (list concrete cases) + Playwright E2E (spec file + scenarios), runnable offline with no AWS.
- Manual/QA steps; metrics/observability to add (tie to SECOPS-001 where relevant).
- Rollback plan; risks & open questions.
- Effort estimate (S/M/L) and suggested implementation order.
