# Content-Moderation — Rough-Edges Audit & Smoothing Plan

**Scope:** audit of the shipped MOD EPIC A–F content-moderation subsystem (report → non-destructive hide → 30-day poster-response hold → admin final-call state machine, guarded auto-hide, 6 categories, bans, DMCA). The core (33/33 prod, verify matrices 75/75) works. This document catalogs the ROUGH EDGES — the real gaps a user/moderator hits — and lays out a dependency-ordered ticketed plan to smooth them.

- **Repo/branch:** `~/dev/testlogon` @ `android-impl` `18a633cc` (dev reference clone; prod diverges on a few hot files per the divergence rule).
- **Method:** 6 dimension auditors (lifecycle, coverage, app-UX/appeals, admin-tooling, safety/abuse) + foundation map. Every finding grounded in file:line. This is an AUDIT — the only write is this plan.
- **Status:** AUDIT COMPLETE. Nothing below changes moderation behavior.

---

## 1. HEADLINE — how rough is it, really?

**Verdict: the engine is sound; the edges are sharp.** The state machine, non-destructive byte-for-byte hide/unhide, idempotent forward transitions, the 30-day `ByState` sweep, MOD-F1 fail-CLOSED enforcement, and `suspended`/`banned` gating are genuinely built and correct. What is rough is everything *around* the happy path: what happens on the **second** report, on the **wrong** content type, when the poster **defends themselves**, when a **troll** reports, and when a **web** moderator opens the queue. The subsystem behaves like a well-built core that was shipped before its second-order flows, its non-feed surfaces, and its human feedback loops were finished.

### The 3–5 load-bearing rough edges (fix these and most of the roughness goes away)

1. **Terminal cases are frozen forever → re-reports 500 and content becomes un-moderatable (correctness).** `case_id` is a deterministic hash of `(content_type, content_id)`; `dismissed`/`reinstated`/`deleted` map to empty transition sets (`moderation_case.py:42-44`). A re-report reuses the frozen terminal case, never re-auto-hides, yet still mints a fresh admin ticket whose every action calls `transition()` from a terminal state → `ValueError` → unhandled 500. Reinstated content re-reported by 100 users stays live; moderators get tickets they physically cannot resolve. This one bug explains the 500-on-re-report wedge AND the orphaned tickets.

2. **Weaponized takedown: one throwaway account instantly hides any target's content via a SEVERE category (safety/abuse).** `should_auto_hide` returns `(True,"severe_category")` on the **1st report from anyone logged in** — no distinct-reporter requirement, no reporter-trust floor, no target-protection tier (`moderation_case.py:129-142`). On a platform where visibility == revenue, a competitor registers a burner, taps "hate/sexual," and darkens a rival's post/video/profile-photo for up to 30 days. Product Decision #8 was never closed. LOWER categories are equally gameable because the threshold counts report **events**, not **distinct reporters** (one user, 3 reports 46s apart, trips it).

3. **`_finalize_delete` destroys content BEFORE the state guard and records violations unconditionally (correctness + fairness).** `mdel.delete_content(...)` runs first, then `transition()` (`moderation_lifecycle.py:132-140`). A final-delete on a non-`hold` case destroys the content, then 500s on the illegal transition — content gone, case inconsistent, no violation recorded. Overlapping finalizers (sweep + poster_close) each write a separate `content_violation` → double strikes → spurious bans. Compounding: hold-expiry by pure **poster inaction** defaults to permanent hard-delete + a ban-compounding strike, with `MODERATION` notifications Alerts-only (not push) — silent, punitive, and abusable.

4. **Two whole live surfaces silently fail enforcement: syndicate posts and profile photos (coverage).** Syndicate posts are filed as `feed_post` (`SyndicateOverviewScreen.kt:149`) so hide looks up `POST#{id}` in the feed table, misses, and no-ops — the entire `syndicate_post` backend branch is dead from the app. Profile-photo hide is a literal no-op (`moderation_hide.py:225-226`), so a reported abusive/sexual profile photo stays **publicly visible for the full 30-day hold** while the system reports it hidden. Both are worse than an honest "no button": the UI claims moderation that never happens.

5. **The human feedback loops are broken at both ends (UX/appeals + admin blindness).** (a) **Appeals are a double dead-end:** a banned user is 403'd on the appeal endpoint (`deps.py:147` gates every auth path; only ROOT/ADMIN skip), AND the form's required "Enforcement ID" is never surfaced anywhere in the app. (b) **The admin final call is made blind:** the poster's 30-day response statement is never returned to or rendered on the admin detail screen (`admin_moderation.py:715-733` omits `poster_response`), and `poster_respond` notifies no moderator — so the whole respond feature is decorative from the admin side.

Everything else is a satellite of these five.

---

## 2. PRIORITIZED PUNCH-LIST (deduped across dimensions)

Severity: **P1** = users/mods hit it routinely or it's a real abuse/legal exposure; **P2** = whole surface/flow degraded; **P3** = friction/perf/polish. Effort: **S** ≤1d, **M** ~2–4d, **L** ≥1wk. IDs map to §3 tickets.

### A. CORRECTNESS / SAFETY (state machine, auto-hide, bans, deletes, GSI)

| # | Rough edge | Sev | Impact | Fix shape | Eff | Ticket |
|---|---|---|---|---|---|---|
| A1 | Terminal cases frozen → re-report never re-hides + every action on the re-report ticket 500s; orphaned OPEN tickets accrue (sweep/poster_close never close the ticket) | P1 | Reinstated/dismissed content un-moderatable on re-report; mods get un-actionable tickets; ghost queue | Re-open terminal→`under_review` on a NEW report (reset hidden/hold_until) OR key cases by `(content_ref, resolution_epoch)`; `on_report_filed` re-evaluates auto-hide for terminal states; `_finalize_delete`/sweep/close tag linked ticket `closed` | M | MODX-1 |
| A2 | `_finalize_delete` deletes content BEFORE the transition guard; `record_violation` unconditional → illegal-state hard-deletes + double-strike races | P1 | Content destroyed then 500; inflated repeat-offender counts → wrongful bans | Transition FIRST, act only if it fired; return `changed` flag; gate `record_violation` on `changed` | S | MODX-2 |
| A3 | SEVERE auto-hide fires on 1st report from any account; no distinct-reporter / trust floor / target tier (weaponized takedown) | P1 | Troll/competitor darkens any creator's content up to 30d | Require ≥2 distinct reporters OR reporter-trust floor for severe 1st-report auto-hide; target-protection tier for established/verified; persist distinct-reporter set on the case | M | MODX-3 |
| A4 | LOWER threshold counts report EVENTS not DISTINCT reporters; 45s dedup only stops same-reporter bursts; one actor trips 3 at ~46s spacing | P1 | Lone/coordinated false-reporters mass-hide LOWER content; mods can't see brigade | Threshold on distinct `reporter_user_id` set; surface distinct-reporter count in admin detail | S | MODX-3 |
| A5 | Hold-expiry by pure poster INACTION defaults to permanent hard-delete + ban-compounding strike; no reminder; MODERATION notif not push-wired | P1 | Absent/inactive users silently lose content + accrue strikes; abusable (hide a busy user, let clock run) | Default expiry → auto-reinstate/soft-archive; if delete stays, no strike for no-response; add T-minus reminder | M | MODX-4 |
| A6 | `awaiting_final` has NO SLA/sweep/escalation — a poster who RESPONDED can be hidden indefinitely | P1 | Poster did the right thing, punished with indefinite silent hide; classic appeal dead-end | Add `awaiting_final` SLA sweep (auto-reinstate or escalate-to-senior after N days); surface queue-age on board | M | MODX-4 |
| A7 | Reporter reputation fields (`report_trust_score`, `report_false_rate`, `trusted_reporter`) are inert — nothing writes them; false-reporters never penalized | P2 | Serial false-reporters operate forever; the trust gate for LOWER auto-hide can never legitimately fire | On dismiss/reinstate decrement trust / bump false-rate; on confirm increment; feed back into `is_trusted_reporter` + rate budgets | M | MODX-5 |
| A8 | Ban keys on `user_sub` only — no device/email/IP fingerprint at signup or ban → trivially evadable | P2 | Bans are a speed bump; repeat offenders recycle accounts | Capture device/email/IP fingerprint at signup; link on ban; block/flag matching new registrations | L | MODX-6 |
| A9 | Permanent-ban "dual approval" is self-attested (any non-empty id ≠ self) AND flag-gated default-False → single senior can perma-ban unilaterally | P2 | Rogue/compromised senior mod perma-bans with no real second signature | Enable flag by default; validate approver exists + has SENIOR scope; require a real recorded approval token/action | M | MODX-7 |
| A10 | `admin_dismiss` un-hides + notifies "dismissed" BEFORE its conditional transition → lost race leaves content visible while case says HOLD | P2 | Confirmed-violation content pops back into public view; contradictory poster notif | Guarded transition first; unhide + notify only if it moved the case | S | MODX-2 |
| A11 | No CSAM / illegal-content escalation path at all (grep: no csam/ncmec/law_enforcement/preserve); gravest category rides the normal reinstate-eligible hold | P1 | Legal/compliance exposure; illegal content reinstate-eligible; no mandated-reporting hook | Add `illegal`/`csam` category: hard-block reinstate, preserve evidence, fire mandated-reporting hook, locked senior-only queue | L | MODX-8 |
| A12 | Rate limits are per-reporter/per-IP only — N accounts on N IPs never trip; no per-TARGET velocity guard | P2 | Amplifies A3/A4; false assurance against brigading | Per-content-ref report-velocity guard weighted by reporter age/trust; suppress auto-hide → route to human on low-trust burst | M | MODX-3 |
| A13 | No self-report/owner-report guard; no moderator conflict-of-interest guard on final-call | P3 | Self-reports pollute counts / can self-trigger hide; un-checked COI in admin action | Drop/flag `reporter==owner`; block admin final-call where they are owner/sole reporter | S | MODX-5 |
| A14 | API-key principal path returns before the ban check (`sessions.py:344-356` before `:360`) | P3 | Banned identity acting via API key not ban-gated on that path | Run `is_user_currently_banned` on resolved principal before returning from the api-key branch | S | MODX-2 |
| A15 | Offender-history GSI wedged: stale `offender_user_id` index stuck CREATING on AWS; every read pays a full base-table Query fallback (MOD-1) | P3 | Recidivism counts (drive ban decisions) computed off unbounded fallback; masks A2's strike inflation | Ops: let `create_gsi_userid.py` self-heal once AWS clears; finish deleting wedged index so `ByOffenderCreatedAt` is hot path | S(ops) | MODX-9 |

### B. COVERAGE (postable-but-unmoderatable surfaces)

| # | Rough edge | Sev | Impact | Fix shape | Eff | Ticket |
|---|---|---|---|---|---|---|
| B1 | Syndicate posts filed as `feed_post` → hide no-ops; whole `syndicate_post` backend branch dead from app | P1 | Abusive syndicate posts un-moderatable; mods act on a case that does nothing | App call-site → `ReportTarget.Content(postId,"syndicate_post")` + pass `syndicate_id`; add `syndicate_post` to `ReportFlow.moderationContentType()` | S | MODX-10 |
| B2 | Reported profile photos never actually hidden (hide primitive no-op); visible through entire 30-day hold | P1 | Most time-sensitive surface (public face/abusive image) gets weakest enforcement | Wire `_revert_profile_photo` into `moderation_hide._apply` profile_photo branch (flag + swap url on hide, restore on unhide) | M | MODX-10 |
| B3 | No account-level report; user with no profile photo → 404 on report (`moderation.py:197-199`); `User`→`profile_photo` alias | P2 | Can't report photoless abusive/impersonating accounts; no impersonation/username/bio intake | Add `user`/`account` content_type keyed on user not photo; add impersonation/username/bio reasons | M | MODX-11 |
| B4 | Products, listings, product reviews: zero report/hide/admin path (`catalog.py`) | P2 | Commerce surface is an open abuse vector (scams, hate reviews, stolen images) with no takedown | Add `catalog_item`+`catalog_review` content_types to hide/delete dispatch + app report actions | M | MODX-12 |
| B5 | Live/broadcast chat: only host-side mute/ban, no viewer report, no state machine, no appeal, per-session/evadable | P2 | Highest-velocity abuse surface has weakest tooling, no reporter agency, no offender history | Viewer report → `broadcast_message` content_type; at minimum feed host mute/ban into `record_violation`/offender history | M | MODX-12 |
| B6 | Stories, clips, audio-rooms postable but orphaned from moderation | P3 | More surfaces with no takedown; clips persist | Add `story`/`clip` content_types to dispatch + app actions; report-participant → offender history for audio-rooms | M | MODX-12 |

### C. UX / NOTIFICATIONS / APPEALS (human feedback loops)

| # | Rough edge | Sev | Impact | Fix shape | Eff | Ticket |
|---|---|---|---|---|---|---|
| C1 | Banned user 403'd on appeal endpoint (`deps.py:147`) → cannot appeal their own ban | P1 | Appeals structurally unreachable for banned accounts; due-process gap | Exempt appeals router (+ own-enforcement read) from `_enforce_not_banned` via `require_appellant` dep; app routes ban-403 to appeal affordance | M | MODX-13 |
| C2 | Appeal form requires "Enforcement ID" never surfaced anywhere in-app (Alerts renders only title, not `details.enforcement_id`) | P1 | Even non-banned users can't complete the form; in-app appeals non-functional | Replace free-text ID with dropdown of user's enforcement history; render `enforcement_id` on ban/removal alert + "Appeal this" deep-link with pre-fill | M | MODX-13 |
| C3 | Admin final-call screen never shows the poster's response statement (`ModerationTicketDetailOut` omits `poster_response`) | P1 | Final call made blind; respond feature decorative admin-side; poster effort wasted | Add `poster_response`+`responded_at` to DTO; render "Poster's response" card in final-call section | S | MODX-14 |
| C4 | `poster_respond` notifies no admin — responses sit unseen until someone browses the board | P2 | awaiting_final languishes; "moderator will decide" promise has no delivery | On `poster_respond` enqueue admin-facing notif / board badge | S | MODX-14 |
| C5 | Permanent-ban / dual-approval offered in app but impossible to complete (no second-approver field in `ModerationFinalCallReq`) | P2 | Perma-ban impossible from app when dual-approval on; mods fall to web | Add second-approver field to ban dialog + thread through, OR hide Permanent in app as web-only | M | MODX-14 |
| C6 | Moderation alerts deep-link to wrong/empty place: terminal-outcome alerts open `MyContentReview` (lists no terminal cases → empty state); ban alert not tappable | P2 | Notif→action bridge misfires exactly at the outcomes users care about most | Route terminal-outcome alerts to case-history/detail; add `moderation_ban` deep-link → Appeals w/ pre-filled id | M | MODX-15 |
| C7 | Reporter gets an ack but no outcome and no "reports I filed" surface (`_notify` is owner-only; report-received alert not tappable) | P3 | Fire-and-forget; learned helplessness / repeat reports | "Reports you filed" list (outcome buckets); outcome alert to reporter on terminal transition; optional withdraw while under_review | M | MODX-15 |
| C8 | `NotificationType.MODERATION` is Alerts-only ("reserved for future engine bridge") — no typed/push delivery for reported/confirmed/final events | P2 | Time-sensitive moderation events can be missed entirely (feeds A5 silent-delete) | Wire MODERATION type through the notifications engine incl. push; confirm owner report/confirm/final fire end-to-end | M | MODX-15 |
| C9 | `under_review` gives the poster NO action — recourse only begins at `hold`; auto-hidden-on-1-severe-report content sits contestable-only-after-admin | P2 | Innocently-reported user's content hidden indefinitely with no way to contest during admin backlog | Allow "dispute auto-hide" response in `under_review`, or auto-advance stale under_review auto-hides to `hold` | M | MODX-4 |
| C10 | `poster_close` from `awaiting_final` deletes poster's own content + records a strike (withdraw conflated with admit-violation) | P3 | User tidying own held content unknowingly accrues ban-eligible strike | Distinguish poster-initiated removal (no strike) from confirmed violation; or don't offer close after a response | S | MODX-4 |
| C11 | Report sheet doesn't identify target content; success copy sets no "what happens next" expectation | P3 | Mis-reports; uncertainty | One-line content descriptor in sheet header; expand success copy | S | MODX-15 |
| C12 | Admin action errors collapse to generic snackbars; backend `code`/`required_scope` not surfaced | P3 | Moderator friction / support load | Parse backend error code and render actionable inline message | S | MODX-16 |

### D. ADMIN TOOLING (triage, filters, bulk, audit, metrics, web parity)

| # | Rough edge | Sev | Impact | Fix shape | Eff | Ticket |
|---|---|---|---|---|---|---|
| D1 | The 30-day-hold state machine has NO web operator surface; web runs divergent legacy `resolve`/`decision` path that bypasses the machine | P1 | Headline behavior invisible/unenforceable on web; two mods on two surfaces reach conflicting outcomes on same ticket | Port dismiss/confirm/final-call panel to `ModerationBoardPage.tsx`; make legacy web calls thin wrappers over the case machine | L | MODX-17 |
| D2 | Video, video_comment, syndicate_post tickets fall to `general` queue which web has no tab for → invisible on web board | P1 | Whole content classes accumulate un-triaged reports no web mod can see | Add `general`/`all` queue tab + `video` mapping; let web list omit the queue filter | S | MODX-17 |
| D3 | Confirmed 30-day holds keep ticket `status="open"` → pollute SLA/backlog KPIs → spurious breach pages | P1 | On-call gets false SLA pages; backlog metrics meaningless; real breaches drown | Distinct `on_hold` status OR exclude `case_state in {hold,awaiting_final}` from open/backlog/oldest-age KPI sets | S | MODX-18 |
| D4 | No moderation ban management: no list, no unban/lift, no duration edit (only broadcast-chat has its own unban) | P1 | Wrongful/permanent bans irreversible from tooling; no active-enforcement roster; successful appeals have no "lift" button | `GET /admin/moderation/bans` roster + `POST .../bans/{user}/lift` (sets active, closes enforcement row, audits) on both boards | M | MODX-19 |
| D5 | Category filters wired to dead taxonomy (`Literal["sexual","extortion","criminal","spam","racist"]` vs live 6); API 422s on real categories | P1 | Can't triage by actual reasons; most useful filter mostly returns nothing | Replace Literal with live 6-category set (legacy aliases as server-side synonyms); update both dropdowns | S | MODX-18 |
| D6 | No decision audit-trail READ surface (`moderation_audit_log` write-only, 41 ln; no GET) | P2 | No in-tool accountability; disputes need CSV dump; can't answer "who reinstated this" | `GET .../tickets/{id}/audit` + `.../audit?actor=`; render timeline on both detail screens | M | MODX-20 |
| D7 | Web "Prior enforcement history" renders `undefined` rows (payload field mismatch: UI reads `ticket_id/decision/decided_by`, backend emits `source_ticket_id/enforcement_type/status/created_by_admin_user_id`) | P2 | Recidivism signal blank on web; repeat offenders look clean; React key collisions | Map UI to real projected fields | S | MODX-17 |
| D8 | Claim/assignee model advisory only — no enforcement, no unclaim, no TTL; stale claims wedge the assignee filter | P2 | Duplicate/conflicting decisions; abandoned claims hide tickets | Enforce `assignee==caller` (or explicit steal) on action routes; add `/unclaim`+reassign; claim TTL auto-release | M | MODX-20 |
| D9 | App board is status-only + first-page-only (drops queue/topic/assignee/cursor the API already supports) | P2 | At real volume the app queue silently truncates; can't find/prioritize reports | Thread `nextCursor` (infinite scroll) + add queue/topic/assignee filter controls | M | MODX-21 |
| D10 | Dead filter chips: app `in_review`/`resolved`, web `in_review` never match real `open`/`closed` statuses | P2 | Mods think filtered queue is empty when it isn't; app can't view closed tickets at all | Use real status set; drop `in_review`, map `resolved→closed` | S | MODX-21 |
| D11 | No bulk actions anywhere (every route per-ticket; no selection UI) | P2 | Backlog explodes under brigade/spam waves; slow triage feeds SLA problem | `POST .../tickets/bulk` (ids+action, per-item results) + multi-select in both boards | M | MODX-22 |
| D12 | KPIs computed but surfaced in NO board UI (only the alert cron reads `/kpis`) | P2 | No proactive triage; operators learn of SLA problems only when paged | KPI header strip on both boards (after D3 makes numbers trustworthy) | S | MODX-18 |
| D13 | KPI compute is a full-table SCAN of 3 tables on every call/alert-run | P3 | Cost/latency grow unbounded with history | Rolling counters or bounded time/state-GSI queries with lookback | M | MODX-9 |
| D14 | Ticket-detail open fan-out: `_linked_reports` filter-scans `ByCreatedAt` (no ticket-id index) + wedged-GSI offender fallback | P3 | Detail latency degrades with volume | Add `linked_ticket_id`-keyed GSI on `content_reports`; finish A15 GSI cleanup | M | MODX-9 |
| D15 | Reporting-surface feature flags gate only feed_*/message*/profile_photo; video/video_comment/syndicate_post have no kill-switch | P3 | Can't disable reporting on those surfaces in an incident | Extend `moderation_flags` scopes to cover all 9 content types | S | MODX-18 |
| D16 | No auto-hide threshold visibility/config in admin tooling (thresholds hardcoded; flags endpoint gives false sense of configurable) | P3 | Can't dial thresholds during an abuse wave; no insight into why content auto-hid | Threshold fields on moderation flags doc + read-only "auto-hide rules" panel | S | MODX-18 |

### E. PERF (grouped; mostly ride other tickets)
`E1` poster "My content under review" is a full-table SCAN of `ModerationCases` (`moderation.py:640`) → add `ByOwnerState` GSI (MODX-9). `E2` = D13/D14/A15 (MODX-9).

---

## 3. TICKETED PLAN (MODX-*) — dependency-ordered epics

Build sequence principle: **safety/correctness first** (stop the bleeding + close abuse vectors), **then coverage** (close silent-enforcement-failure surfaces), **then UX/appeals** (close the human loops), **then admin tooling** (make triage scale). Effort per ticket in header.

### EPIC 1 — CORRECTNESS: make the state machine safe under re-report, delete, and expiry

**MODX-1 — Un-freeze terminal cases + close orphaned tickets (M)**
- Scope: re-open `dismissed`/`reinstated`/`deleted` → `under_review` on a NEW report (reset `hidden`/`hold_until`, clear terminal marker), OR key cases by `(content_ref, resolution_epoch)`. `on_report_filed` re-evaluates auto-hide for terminal states. `_finalize_delete` + sweep + `poster_close` tag the linked ticket `closed`/`resolution=content_removed` (mirror admin path).
- Accept: re-reporting resolved content re-opens a case and re-auto-hides per policy; no admin action on any ticket 500s; no OPEN ticket survives a terminal case; `verify_moderation.py` still green + new re-report regression test.
- Covers: A1, lifecycle #1/#7.

**MODX-2 — Act-after-guard ordering + idempotent strikes + API-key ban gate (S)**
- Scope: in `_finalize_delete` transition FIRST, `delete_content` only if it fired; `transition()` returns a `changed` flag; gate `record_violation` on `changed`. Same act-after-guard fix in `admin_dismiss` (unhide/notify only if transition moved). Run ban check on api-key principal before early return (`sessions.py`).
- Accept: final-delete on a non-hold case is a clean 4xx with content intact; concurrent finalizers produce exactly one violation; dismiss race can't leave content visible under a HOLD case; banned api-key principal is blocked.
- Covers: A2, A10, A14, lifecycle #4/#6.

**MODX-3 — Distinct-reporter auto-hide + target protection + per-target velocity (M)**
- Scope: persist a distinct `reporter_user_id` set on the case. SEVERE 1st-report auto-hide requires ≥2 distinct reporters OR a trust-floored reporter; LOWER threshold counts distinct reporters not events. Target-protection tier (established/verified need corroboration). Per-content-ref velocity guard: burst of low-trust/new accounts → suppress auto-hide, route to human. Surface distinct-reporter count in admin detail DTO.
- Accept: a single account (or one account's repeated reports) can never auto-hide; N burner accounts on N IPs trigger a human-review flag instead of an auto-hide; verified-target content needs corroboration; admin detail shows distinct-reporter count.
- Covers: A3, A4, A12, safety #1/#3/#5. **Closes Product Decision #8.**

**MODX-4 — Humane expiry + awaiting_final SLA + under_review recourse (M)**
- Scope: hold-expiry default → auto-reinstate/soft-archive (not delete); if delete retained, no violation strike for pure no-response; add T-minus reminder notification. Add `awaiting_final` SLA sweep (auto-reinstate or escalate-to-senior after N days) + surface queue-age. Allow a "dispute auto-hide" poster action in `under_review` (or auto-advance stale under_review auto-hides to hold). `poster_close` after a response = poster-initiated removal, no strike.
- Accept: an inactive poster never silently loses content+strike on inaction; a responded case cannot sit hidden indefinitely; a poster can contest a fresh auto-hide before admin touches it; self-close carries no strike.
- Covers: A5, A6, C9, C10, lifecycle #2/#3/#8/#9.

**MODX-5 — Reporter reputation loop + self/COI guards (M)**
- Scope: on dismiss/reinstate decrement reporter trust / bump `report_false_rate`; on confirm increment; feed into `is_trusted_reporter` + rate-limit budgets. Drop/flag `reporter==owner` reports. Block admin final-call where actor is owner/sole reporter.
- Accept: a serially-dismissed reporter loses trust and can no longer trigger trusted-path auto-hide; self-reports don't count toward auto-hide; an admin cannot adjudicate their own content.
- Covers: A7, A13, safety #4/#8.
- Depends: MODX-3 (shares the reporter-identity persistence).

**MODX-8 — Illegal/CSAM escalation lane (L)**
- Scope: add `illegal`/`csam` category (or `sexual` sub-flag) that hard-blocks reinstate, preserves evidence (no hard-delete of the record), fires a mandated-reporting hook (NCMEC/hotline stub + ops runbook), and routes to a locked senior-only queue separate from the general board.
- Accept: CSAM-flagged content cannot be reinstated by poster_respond/final-reinstate; a preservation record + mandated-report event is written; only SENIOR scope sees/acts on the locked queue.
- Covers: A11, safety #2.

### EPIC 2 — BAN INTEGRITY

**MODX-6 — Ban-evasion fingerprinting (L)**
- Scope: capture device/email/IP fingerprint at signup; link on ban; block/flag new registrations matching an active-ban fingerprint (at minimum surface "likely evasion" to moderators).
- Accept: a new account created on a banned device/email is blocked or flagged as likely-evasion in the mod queue.
- Covers: A8, safety #6.

**MODX-7 — Real dual-approval for permanent bans (M)**
- Scope: enable `moderation_dual_approval_permanent_ban_enabled` by default; validate the second approver exists + holds `CONTENT_MODERATION_SENIOR`; require a real recorded approval token/action from that admin (not a caller-supplied string).
- Accept: a perma-ban with a fabricated/non-senior/absent approver id is rejected; the approval is an auditable second action.
- Covers: A9, safety #7. Pairs with C5 (app second-approver UI).

### EPIC 3 — COVERAGE: close silent-enforcement-failure surfaces

**MODX-10 — Fix syndicate + profile-photo enforcement (M)**
- Scope: app syndicate call-site → `syndicate_post` + pass `syndicate_id`; add `syndicate_post` to `ReportFlow.moderationContentType()`. Wire `_revert_profile_photo` into `moderation_hide._apply` for `profile_photo` (flag + url swap on hide, restore on unhide) so the state machine actually hides/restores.
- Accept: a reported syndicate post hides for non-owners and reinstates byte-for-byte; a reported profile photo is hidden within the review window and restored on reinstate; both appear correctly on the admin board.
- Covers: B1, B2, coverage RE-C1/RE-C2, lifecycle #5.

**MODX-11 — Account-level report (M)**
- Scope: add `user`/`account` content_type keyed on the user (not a photo); remove the photo-404 gate for user reports; add impersonation/username/bio reasons.
- Accept: an account with no profile photo can be reported; impersonation/username/bio reports open a user-keyed case.
- Covers: B3, RE-C3.

**MODX-12 — Commerce + live-chat + ephemeral coverage (L)**
- Scope: add content_types `catalog_item`, `catalog_review`, `broadcast_message`, `story`, `clip` to hide/delete dispatch + app report actions; feed broadcast host mute/ban into `record_violation`/offender history; report-participant path for audio-rooms.
- Accept: each surface has a working report → hide → admin-visible → appeal path (or, for live chat minimum, host actions accrue offender history and are appealable).
- Covers: B4, B5, B6, RE-C4/RE-C5/RE-C6.

### EPIC 4 — UX / APPEALS / NOTIFICATIONS: close the human loops

**MODX-13 — Make appeals actually reachable (M)**
- Scope: exempt appeals router (+ own-enforcement read) from `_enforce_not_banned` (`require_appellant` dep); app detects ban-403 → routes to appeal affordance. Replace free-text Enforcement ID with a dropdown of the user's enforcement history; render `enforcement_id` on the ban/removal alert with an "Appeal this" deep-link that pre-fills the id.
- Accept: a banned user can open and submit an appeal; the Enforcement ID is selectable/pre-filled, never hand-typed.
- Covers: C1, C2, appux #1/#2.

**MODX-14 — Un-blind the admin final call (M)**
- Scope: add `poster_response`+`responded_at` to `ModerationTicketDetailOut` + DTO; render "Poster's response" card in the final-call section. On `poster_respond` enqueue an admin-facing notification / board badge. Add a second-approver field to the app ban dialog when Permanent is selected (thread to `ModerationFinalCallReq`), or hide Permanent in-app as web-only.
- Accept: the admin final-call screen shows the poster's statement; a poster response surfaces proactively to moderators; permanent ban is either completable in-app or clearly web-only.
- Covers: C3, C4, C5, appux #3/#4/#5. Pairs with MODX-7.

**MODX-15 — Notifications & reporter feedback (M)**
- Scope: wire `NotificationType.MODERATION` through the typed notifications engine incl. push; confirm owner report/confirm/final events fire end-to-end. Route terminal-outcome alerts to a case-history/detail view (not the empty open-cases list); add `moderation_ban` deep-link → Appeals. Add a "Reports you filed" list + reporter outcome alert on terminal transition; optional withdraw while `under_review`. Report-sheet target descriptor + expanded success copy.
- Accept: moderation events push (not Alerts-only); tapping any moderation alert lands somewhere non-empty and correct; reporters can see outcomes of reports they filed.
- Covers: C6, C7, C8, C11, appux #6/#7/#9, foundation-map #2.

**MODX-16 — Admin error legibility (S)**
- Scope: parse backend error `code`/`required_scope` and render actionable inline messages in the app board.
- Accept: scope vs approver vs stale-state failures show distinct guidance.
- Covers: C12, appux #8.

### EPIC 5 — ADMIN TOOLING: make triage trustworthy & scalable

**MODX-17 — Web board parity with the state machine (L)**
- Scope: port dismiss/confirm/final-call panel (with hold countdown, offender history, ban picker) to `ModerationBoardPage.tsx`; make legacy `resolve`/`decision` thin wrappers over the case machine (or deprecate). Add a `general`/`all` queue tab + `video` queue mapping; let web list omit queue. Fix prior-enforcement field mapping (`source_ticket_id`/`enforcement_type`/`status`/`created_by_admin_user_id`/`created_at`).
- Accept: a web moderator drives the full lifecycle with no divergence from app; video/syndicate tickets appear; prior-enforcement rows render real data.
- Covers: D1, D2, D7, admintool P1-1/P1-2/P2-7.

**MODX-18 — KPI trust + real filters + config visibility (M)**
- Scope: give holds a distinct `on_hold` status (or exclude `hold`/`awaiting_final` from open/backlog/oldest-age KPI sets). Replace the dead category `Literal` with the live 6-category set + legacy synonyms; fix both dropdowns. Add a KPI header strip to both boards. Extend `moderation_flags` scopes to all 9 content types + a read-only auto-hide-rules/threshold panel.
- Accept: parked holds don't page on-call; filtering by any live category returns the right tickets; boards show backlog/oldest-age/latency; every surface has a reporting kill-switch.
- Covers: D3, D5, D12, D15, D16, admintool P1-3/P1-5/P2-12/P3-15.

**MODX-19 — Ban management surface (M)**
- Scope: `GET /admin/moderation/bans` (active-enforcement roster) + `POST .../bans/{user}/lift` (sets `account_state.status=active`, closes enforcement row, audit event), surfaced on both boards.
- Accept: moderators can list active bans, review one, and lift a wrongful/permanent ban; a successful appeal has an operator "lift" button.
- Covers: D4, admintool P1-4.

**MODX-20 — Audit-trail read + claim enforcement (M)**
- Scope: `GET .../tickets/{id}/audit` + `.../audit?actor=` reading `moderation_audit_log`; timeline on both detail screens. Enforce `assignee==caller` (or explicit steal) on action routes; add `/unclaim`+reassign; claim TTL auto-release.
- Accept: a ticket's who/when/why decision history is viewable in-tool; claiming reserves the ticket and stale claims auto-release.
- Covers: D6, D8, admintool P2-6/P2-8.

**MODX-21 — App queue pagination + real filters (M)**
- Scope: thread `nextCursor` into the app board VM (infinite scroll); add queue/topic/assignee filter controls (API already supports them). Use the real `open`/`closed` status set; drop `in_review`, map `resolved→closed`.
- Accept: the app board reaches beyond page 1; category/queue/assignee filters work; no dead filter chip returns a misleading empty.
- Covers: D9, D10, admintool P2-9/P2-10.

**MODX-22 — Bulk actions (M)**
- Scope: `POST /admin/moderation/tickets/bulk` (list of ids + action, per-item results) + multi-select in both boards.
- Accept: a brigade wave can be dismissed/confirmed in one action with per-item outcomes.
- Covers: D11, admintool P2-11.

### EPIC 6 — PERF / OPS (parallelizable, low urgency)

**MODX-9 — Index & scan cleanup (M + S ops)**
- Scope: add `ByOwnerState` GSI on `ModerationCases` (owner_user_id HASH) and query it from `/cases/mine` (kill the full-table scan). Add a `linked_ticket_id`-keyed GSI on `content_reports` (kill the detail fan-out scan). Replace KPI full-table scans with rolling counters or bounded time/state-GSI queries. Ops: let `create_gsi_userid.py` self-heal once AWS clears the wedged `offender_user_id` index; finish deleting it so `ByOffenderCreatedAt` is the hot offender-history path.
- Accept: `/cases/mine`, ticket-detail, and `/kpis` are index-bound not scan-bound; offender-history no longer pays a base-table fallback.
- Covers: A15, D13, D14, E1, E2, lifecycle #11/#12, admintool P3-13/P3-14.

---

## 4. RECOMMENDED BUILD SEQUENCE

**Wave 0 — stop the bleeding (fast correctness wins):** MODX-2 (S, act-after-guard + strikes + api-key gate) → MODX-1 (M, un-freeze terminal cases + close orphaned tickets). These two kill the 500-on-re-report wedge, the double-strike inflation, and the un-moderatable-on-re-report gap — the highest-leverage fixes.

**Wave 1 — close the abuse vectors:** MODX-3 (distinct-reporter/target-protection/velocity — closes Decision #8) → MODX-4 (humane expiry + awaiting_final SLA + under_review recourse) → MODX-5 (reporter reputation + COI). Then the legal lane MODX-8 (CSAM escalation) and ban integrity MODX-7 (real dual-approval), MODX-6 (evasion fingerprinting, L, can run in parallel).

**Wave 2 — coverage (stop silent enforcement failures):** MODX-10 (syndicate + profile-photo — content that *claims* to be moderated but isn't) FIRST, then MODX-11 (account-level report), then MODX-12 (commerce/live-chat/ephemeral, L).

**Wave 3 — human loops:** MODX-13 (reachable appeals) → MODX-14 (un-blind admin final call) → MODX-15 (notifications + reporter feedback) → MODX-16 (error legibility, S).

**Wave 4 — admin tooling at scale:** MODX-18 (KPI trust + real filters) and MODX-19 (ban management) FIRST (they make the queue trustworthy), then MODX-17 (web parity, L), MODX-20 (audit + claims), MODX-21 (app pagination/filters), MODX-22 (bulk).

**Parallel track — perf/ops:** MODX-9 any time after Wave 0; the GSI self-heal (A15) is an ops action to start now.

**Rationale:** Waves 0–1 remove the ways the system actively harms users (wrongful hides, silent strike-bearing deletes, un-resolvable tickets) and the ways it can be weaponized. Wave 2 closes surfaces where the UI *lies* about enforcement. Wave 3 restores the feedback loops that make moderation feel fair. Wave 4 makes moderators effective at volume. Perf rides alongside.

---

*Audit artifact only. No moderation behavior was changed. Cites are dev clone `android-impl @ 18a633cc`; prod diverges on hot files per the divergence rule — confirm hot-file line numbers against prod before implementing.*
