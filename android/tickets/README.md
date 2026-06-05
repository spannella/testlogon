# TestLogon Android Port — Ticket Backlog

Full decomposition of the [port plan](../PORT_PLAN.md) and
[milestones/epics](../MILESTONES_AND_EPICS.md) into `AND-###` tickets.
Each ticket: **Type · Priority · Dependencies · Scope · Acceptance Criteria** (repo `TKT-###` style).

| Milestone | File | Epics | Tickets | Range |
|---|---|---|---|---|
| M1 — Auth foundation | [`M1-auth-foundation.md`](./M1-auth-foundation.md) | E01–E07 | 52 | AND-001–052 |
| M2 — App shell & read-only core | [`M2-app-shell-read-only-core.md`](./M2-app-shell-read-only-core.md) | E08–E17 | 67 | AND-053–119 |
| M3 — Messaging | [`M3-messaging.md`](./M3-messaging.md) | E18–E22 | 46 | AND-120–165 |
| M4 — Content consumption | [`M4-content-consumption.md`](./M4-content-consumption.md) | E23–E27 | 38 | AND-166–203 |
| M5 — Commerce | [`M5-commerce.md`](./M5-commerce.md) | E28–E33 | 47 | AND-204–250 |
| M6 — Creator tools | [`M6-creator-tools.md`](./M6-creator-tools.md) | E34–E38 | 37 | AND-251–287 |
| M7 — Specialized | [`M7-specialized.md`](./M7-specialized.md) | E39–E46 | 75 | AND-288–362 |
| M8 — Long tail & admin-lite | [`M8-long-tail-admin-lite.md`](./M8-long-tail-admin-lite.md) | E47–E53 | 44 | AND-363–406 |
| **Total** | | **53 epics** | **406** | AND-001–406 |

Priority: **P0** blocks the milestone · **P1** important · **P2** nice-to-have.
Cross-cutting epics (X1 accessibility, X2 observability, X3 release/distribution, X4 performance) are
tracked in the milestones/epics doc and attach to the milestone where the work lands.

**Recommended start:** M1 critical path — `AND-001 → 002 → 003 → {009,010} → 011 → {012,013} → 026 →
027 → 028 → 029 → {030,031} → {033…038} → {039,040}`.
