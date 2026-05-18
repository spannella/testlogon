# NFS-030 Final Readiness & GA Checklist — Newsfeed Scheduling

> Purpose: aggregate completion criteria across all scheduling tickets and provide a single **go / no-go** decision artifact for full rollout.

---

## 1) Ticket completion matrix (P0/P1)

Source ticket set: `newsfeed-scheduling-tickets.md`.

### P0 tickets (must be complete)

| Ticket ID | Area | Status | Evidence | Owner | Date |
|---|---|---|---|---|---|
| NF-SCHED-101 | Data model fields | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-102 | Create API immediate/scheduled | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-103 | Owner-only scheduled list API | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-104 | Edit scheduled API | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-105 | Cancel scheduled API | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-106 | Due-index query path | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-107 | Scheduler worker loop | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-201 | FE API/types | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-202 | Composer schedule UX | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-203 | Scheduled posts panel | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-204 | Edit dialog schedule UX | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-301 | Backend lifecycle tests | ☐ Complete | CI run: __________ | __________ | __________ |
| NF-SCHED-302 | Frontend unit tests | ☐ Complete | CI run: __________ | __________ | __________ |

### P1 tickets (must be complete for GA)

| Ticket ID | Area | Status | Evidence | Owner | Date |
|---|---|---|---|---|---|
| NF-SCHED-108 | Metering at publish-time | ☐ Complete | PR/tests link: __________ | __________ | __________ |
| NF-SCHED-303 | End-to-end workflow test | ☐ Complete | E2E run: __________ | __________ | __________ |
| NF-SCHED-401 | Feature flags + rollout controls | ☐ Complete | Runbook/link: __________ | __________ | __________ |

**GA Gate A — Ticket completion**
- [ ] All P0 tickets marked complete with evidence.
- [ ] All P1 tickets marked complete with evidence.

---

## 2) Final test readiness summary

### Required passing suites

- [ ] Backend schedule lifecycle tests pass in CI:
  - `tests/test_newsfeed_content_envelope.py`
  - `tests/test_newsfeed_scheduler_worker.py`
  - `tests/test_newsfeed_schedule_due_index_backfill.py`
- [ ] Frontend scheduling unit tests pass in CI (composer/edit/panel coverage).
- [ ] E2E scheduled publish scenario passes in CI/staging:
  - `frontend/e2e/feed-scheduled-publish.spec.ts`

### Required manual verification (staging)

- [ ] Create scheduled post (near future) succeeds.
- [ ] Scheduled post hidden from feed before due.
- [ ] Scheduled post appears after worker publish.
- [ ] Non-owner cannot list/edit/cancel another user's scheduled posts.
- [ ] Cancelled scheduled posts never publish.

**GA Gate B — Test quality**
- [ ] All required automated suites green.
- [ ] Manual staging checklist complete and recorded.

---

## 3) Monitoring & operational readiness

### Dashboards (required)

- [ ] Dashboard includes backlog gauge: `newsfeed_schedule_backlog_due`
- [ ] Dashboard includes publish throughput/outcomes: `newsfeed_schedule_operations_total`
- [ ] Dashboard includes publish lag histogram: `newsfeed_schedule_publish_lag_seconds`
- [ ] Dashboard includes alert counters: `newsfeed_schedule_alerts_total`

### Alerts (required)

- [ ] Error threshold alert configured (`error_threshold_breach`).
- [ ] Lag threshold alert configured (`lag_threshold_breach`).
- [ ] On-call routing + escalation policy verified.

### Runbooks (required)

- [ ] Deployment/migration runbook reviewed and approved:
  - `newsfeed-scheduling-deployment-runbook.md`
- [ ] Security review signed:
  - `newsfeed-scheduling-security-review.md`
- [ ] Rollout controls reviewed:
  - `newsfeed-scheduling-rollout.md`

**GA Gate C — Ops readiness**
- [ ] Monitoring and alerting live.
- [ ] Runbooks signed off by on-call owner.

---

## 4) Risk review (final)

### Open risks (must be empty or accepted)

| Risk | Severity | Mitigation | Owner | Accepted? |
|---|---|---|---|---|
| __________ | __________ | __________ | __________ | ☐ |
| __________ | __________ | __________ | __________ | ☐ |

- [ ] No unmitigated Sev-1/Sev-2 risks open.
- [ ] Any accepted risks documented with approval.

---

## 5) GA sign-off record

### Product sign-off
- Name: ____________________
- Decision: ☐ Approve GA ☐ Block GA
- Notes: ____________________
- Date: ____________________

### Engineering sign-off
- Name: ____________________
- Decision: ☐ Approve GA ☐ Block GA
- Notes: ____________________
- Date: ____________________

### Operations sign-off
- Name: ____________________
- Decision: ☐ Approve GA ☐ Block GA
- Notes: ____________________
- Date: ____________________

**Final Release Decision**
- [ ] **GO** — all gates (A/B/C) passed and all 3 sign-offs approved.
- [ ] **NO-GO** — unmet gate(s) or any sign-off blocks release.

---

## 6) Decision log

- Meeting date/time: ____________________
- Participants: ____________________
- Decision summary: ____________________
- Follow-up actions: ____________________
