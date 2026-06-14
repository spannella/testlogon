# M8 — Long Tail & Admin-Lite — Tickets

Decomposition of milestone **M8** (epics **E47–E53**). Format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**.

**Milestone exit criteria:** boost/sponsorship usable; tickets/projects; trust & safety flows; public
surfaces; read-only webhooks/analytics. Full admin/agents/infra remain out of scope (E53; see
decision record AND-405 at `android/docs/decisions/AND-405-scope-admin-agents-infra.md`).

---

## Epic E47 — Ads (mobile subset)

### AND-363 — Ads accounts API
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `/ui/ads/accounts*` DTOs (accounts, billing, campaigns read).
**Acceptance:** Ads account payloads map (tested).

### AND-364 — Content boost
**Type:** Feature · **Priority:** P1 · **Deps:** AND-363, AND-031
**Scope:** `contentBoost.ts`; boost a post (create/detail), budget + payment.
**Acceptance:** Boost creates + shows status.

### AND-365 — Sponsorship inbox
**Type:** Feature · **Priority:** P1 · **Deps:** AND-363
**Scope:** `sponsorshipDeals.ts`; inbox of sponsorship offers.
**Acceptance:** Inbox lists offers.

### AND-366 — Sponsorship manage / deal detail
**Type:** Feature · **Priority:** P2 · **Deps:** AND-365
**Scope:** Accept/decline/negotiate; deal detail.
**Acceptance:** Deal actions work.

### AND-367 — Ad billing / deposit
**Type:** Feature · **Priority:** P2 · **Deps:** AND-363, AND-031
**Scope:** account billing + deposit (read + deposit).
**Acceptance:** Deposit + invoices render.

### AND-368 — Ad analytics (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-363, AND-255
**Scope:** Campaign analytics dashboards (read).
**Acceptance:** Analytics render.

### AND-369 — Ads ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-363
**Scope:** State.
**Acceptance:** Unit-tested.

### AND-370 — Ads tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-369
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E48 — Tickets & projects

### AND-371 — Tickets API
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `tickets.ts`, ticket-spaces members/messages DTOs.
**Acceptance:** Ticket payloads map (tested).

### AND-372 — Ticket spaces + threads
**Type:** Feature · **Priority:** P1 · **Deps:** AND-371
**Scope:** Spaces list, ticket list, ticket thread.
**Acceptance:** Spaces/tickets render.

### AND-373 — Ticket messages / reply
**Type:** Feature · **Priority:** P1 · **Deps:** AND-372, AND-126
**Scope:** Post messages on tickets; members.
**Acceptance:** Reply posts + renders.

### AND-374 — Projects
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `projects.ts` list/detail (+ Google Drive provider start/callback).
**Acceptance:** Projects render; detail opens.

### AND-375 — Tickets/projects ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-371
**Scope:** State.
**Acceptance:** Unit-tested.

### AND-376 — Tickets/projects tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-375
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E49 — Helpdesk agent tools

### AND-377 — Helpdesk agent dashboard
**Type:** Feature · **Priority:** P2 · **Deps:** AND-161
**Scope:** Agent dashboard (queue, metrics).
**Acceptance:** Dashboard renders for agent role.

### AND-378 — Claim / assignment management
**Type:** Feature · **Priority:** P2 · **Deps:** AND-377
**Scope:** Claim/assign/transfer conversations.
**Acceptance:** Claim/assign actions work.

### AND-379 — Agent availability / online state
**Type:** Feature · **Priority:** P2 · **Deps:** AND-145
**Scope:** Online/available toggle (gates claims).
**Acceptance:** Availability toggle affects claim eligibility.

### AND-380 — Helpdesk ViewModel
**Type:** Feature · **Priority:** P2 · **Deps:** AND-377
**Scope:** State.
**Acceptance:** Unit-tested.

### AND-381 — Helpdesk tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-380
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E50 — Trust, safety & privacy

### AND-382 — Block / unblock
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `blocking.ts`; block/unblock embedded in profile/messages.
**Acceptance:** Block hides content + prevents contact (tested).

### AND-383 — Report flows
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** Report user/content/message with reasons (ties to AND-163).
**Acceptance:** Report submits + confirms.

### AND-384 — DMCA submit
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `dmca.ts` takedown submission.
**Acceptance:** DMCA request submits.

### AND-385 — Privacy / data export
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `/ui/privacy/account-deletion/export(+download)`, requests list.
**Acceptance:** Export requested + downloadable.

### AND-386 — Account deletion request
**Type:** Feature · **Priority:** P1 · **Deps:** AND-385
**Scope:** request/cancel deletion; strong multi-step confirmation.
**Acceptance:** Deletion request + cancel work with explicit confirms.

### AND-387 — Account closure / suspend / reactivate
**Type:** Feature · **Priority:** P1 · **Deps:** AND-082
**Scope:** `/ui/account/closure/start|finalize`, `suspend`, `reactivate`, `status`.
**Acceptance:** Closure/reactivate flows work with confirmations.

### AND-388 — Trust & safety ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-382
**Scope:** State + irreversible-action guards.
**Acceptance:** Unit-tested.

### AND-389 — Trust & safety tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-388
**Scope:** Repo + UI tests (confirmation gating).
**Acceptance:** Pass.

---

## Epic E51 — Public / unauthenticated surfaces

### AND-390 — Public profile polish
**Type:** Feature · **Priority:** P2 · **Deps:** AND-073
**Scope:** `/u/:identifier` deep-link + share polish (unauth state).
**Acceptance:** Public profile opens unauthenticated.

### AND-391 — Public event
**Type:** Feature · **Priority:** P2 · **Deps:** AND-272
**Scope:** `/event/:calendarId/:eventId` public view.
**Acceptance:** Public event opens via link.

### AND-392 — Public download
**Type:** Feature · **Priority:** P2 · **Deps:** AND-335
**Scope:** `/share/:linkId` public download page.
**Acceptance:** Public download works.

### AND-393 — Public donation
**Type:** Feature · **Priority:** P2 · **Deps:** AND-031
**Scope:** `/donate/:fundraiserId` donation flow (unauth-capable).
**Acceptance:** Donation completes (test).

### AND-394 — Public clip
**Type:** Feature · **Priority:** P2 · **Deps:** AND-196
**Scope:** `/c/:clipId` public clip view.
**Acceptance:** Public clip plays.

### AND-395 — Public questionnaire respond
**Type:** Feature · **Priority:** P2 · **Deps:** AND-349
**Scope:** Public respondent (unauth) entry.
**Acceptance:** Public respondent submits.

### AND-396 — App Links verification + routing
**Type:** Chore · **Priority:** P1 · **Deps:** AND-022
**Scope:** assetlinks.json/App Links verification; central deep-link router.
**Acceptance:** Verified App Links open the app directly.

### AND-397 — Public surfaces tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-396
**Scope:** Deep-link routing tests.
**Acceptance:** Pass.

---

## Epic E52 — Webhooks & analytics (read)

### AND-398 — Webhooks config (light)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `webhooks.ts` list/view (+ light create).
**Acceptance:** Webhooks render.

### AND-399 — Analytics dashboards (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027, AND-255
**Scope:** `analytics.ts` read-only dashboards.
**Acceptance:** Analytics render.

### AND-400 — SEO metadata (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `seoMetadata.ts` view (creator).
**Acceptance:** SEO metadata renders.

### AND-401 — Webhooks/analytics ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-398
**Scope:** State.
**Acceptance:** Unit-tested.

### AND-402 — Webhooks/analytics tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-401
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E53 — Admin-lite (optional / scoped)

> **Out of scope (mobile):** full admin consoles, agent/bot fleet management,
> compute/k8s/EC2/instance ops, SSH bastion, VNC, and internal devtools are
> excluded from the Android port per the scope decision **AND-405**
> (`android/docs/decisions/AND-405-scope-admin-agents-infra.md`). The only
> in-scope exceptions are the read-only, role-gated views **AND-403** and
> **AND-404**. There are no open implementation tickets for the excluded
> categories; reversing any exclusion requires a superseding ADR referencing AND-405.

### AND-403 — Read-only admin alerts/dashboards
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** Scoped read-only admin alerts/metrics only (no mutations).
**Acceptance:** Admin sees read-only alerts (role-gated).

### AND-404 — Admin email/SMS dashboards (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-403
**Scope:** `/ui/admin/email|sms/dashboard/*` read-only.
**Acceptance:** Dashboards render (read).

### AND-405 — Scope decision: admin/agents/infra
**Type:** Chore · **Priority:** P1 · **Deps:** None
**Scope:** Document confirmation that full admin, agents/bots fleet, compute/k8s/ec2, SSH bastion, VNC,
devtools are **out of scope for mobile**; capture any exceptions.
**Acceptance:** Decision recorded in repo; backlog reflects exclusions.

### AND-406 — Admin-lite tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-403
**Scope:** Role-gating + read-only tests.
**Acceptance:** Pass.

---

### M8 ticket count: 44 (E47:8, E48:6, E49:5, E50:8, E51:8, E52:5, E53:4)
**Running total through M8:** 406 tickets (AND-001…AND-406).

---

## Backlog complete
- **8 milestones · 53 feature epics (+4 cross-cutting) · 406 tickets (AND-001…AND-406).**
- Out of scope for mobile (per E53 / decision record AND-405,
  `android/docs/decisions/AND-405-scope-admin-agents-infra.md`): full admin consoles, agent/bot
  fleet management, compute/k8s/EC2/instance monitoring, SSH bastion, VNC, internal devtools.
  In-scope exceptions: read-only role-gated AND-403 / AND-404 only.
