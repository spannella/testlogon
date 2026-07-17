# DISP E2 — app + web dispute surfaces (DISP-020..025)

Ships the surface layer on top of the E0/E1/E3/E4 backend (which already reconciles the ledger
correctly). Nothing here reinvents money logic — the surfaces call the shipped resolver/dispatcher.

## What landed

### Backend (app/)
- app/auth/roles.py — new AdminScope.PAYMENT_DISPUTES (+ in CANONICAL_ADMIN_SCOPES). A GENERAL admin
  profile still passes (admin_profile_has_scope returns True for GENERAL) so there is no regression to
  the six smoothed subsystems; a SCOPED admin must now hold payment_disputes.
- app/core/settings.py — dispute_dual_approval_threshold_cents (default 5000) +
  dispute_dual_approval_enabled (default ON).
- app/models.py — CreatorDisputeRespondIn; DisputeResolveIn.second_approver_admin_user_id.
- app/services/billing_disputes.py — DISP-021 list_creator_disputes (pages the actionable status GSIs,
  filters by creator_id; no schema change) + creator_respond (authorizes the counterparty, delegates to
  dispute_lifecycle.record_creator_response); DISP-022 admin_dispute_view = _to_out + _rail_preview
  (money-safe resolve_charge read: rail name, clawback amount, gross, partial-supported) +
  _linked_incident (the linked processor PaymentIncident) + rebuttal thread + serial-disputer flag.
- app/routers/billing_disputes.py —
  - DISP-020 payer: POST/GET /ui/billing/disputes, GET /ui/billing/disputes/{id}, .../withdraw.
  - DISP-021 creator: GET /ui/creator/disputes, GET /ui/creator/disputes/{id},
    POST /ui/creator/disputes/{id}/respond.
  - DISP-022 admin (behind require_admin_scope(PAYMENT_DISPUTES)): GET /ui/admin/disputes (queue + rail
    preview + linked incident), GET /ui/admin/disputes/{id} (full admin view), .../respond, .../resolve
    (dual-approval gate on a money-moving resolve at/above threshold — real, non-self-attested second
    approver validated against the users table), .../sweep.

### Web (frontend/) — tsc 0, npm run build green, vitest delta 0 (81 pre-existing failures unchanged)
- src/api/types.ts — DisputeRailPreview/DisputeLinkedIncident/DisputeResponseEntry; extended
  DisputeOut; CreatorDisputeRespondIn; DisputeResolveIn (refunded|partial|denied + override + second
  approver).
- src/api/endpoints/billingDisputes.ts — payer/creator/admin endpoints incl. admin detail + sweep.
- src/pages/admin/AdminDisputeQueuePage.tsx — new resolution vocab, rail-preview panel + clawback,
  linked processor incident, serial-disputer badge, dual-approval field, creator rebuttal.
- src/pages/creator/CreatorDisputesPage.tsx (new) — inbound queue + rebuttal composer + countdown.
- src/App.tsx — registers creator/disputes.

### App (android/) — :app:assembleDebug GREEN
- data/disputes/* — creator endpoints + DTOs; extended Dispute/DisputeStatus (needs_response /
  escalated / withdrawn); CreatorRespondInput/Result; repository methods.
- feature/disputes/CreatorDisputesScreen.kt + CreatorDisputesViewModel.kt (new, DISP-024) — inbound
  queue + respond dialog (validated, snackbar, list re-fetch on success).
- navigation/DisputesNavigation.kt + MoreRoutes.kt (route + REGISTERED set) + feature/more/MoreCatalog.kt
  + res/values/strings.xml — "Disputes to respond to" Wallet-hub entry.
- feature/disputes/DisputesFormat.kt — exhaustive status label mapping for the new states.

## Live verification (real HTTP against the running server)
verify_e2.py (in ~/disp_work) — synthetic users + multi-type charges, auto-cleaned (0 residue).
- DEV (localhost:8000): 21/21 PASS.
- PROD (this fold, localhost:8000 via SSM): 21/21 PASS.
Covers: creator inbound queue + counterparty-only detail/respond (404 to strangers), in-window respond
-> under_review + rebuttal recorded, PAYMENT_DISPUTES scope gate (deny scoped-without / allow
scoped-with / allow general), admin queue rail_preview (rail=tip, clawback), admin detail rebuttal +
linked_incident key, resolve refunded moves money + buyer sees resolved+refunded, dual-approval
(required / self / fabricated -> 403; valid second approver -> 200 + money moves; no premature move on
403; idempotent re-resolve).

## On-device (A15 SM-A156U, prod backend)
Seeded a real quality tip dispute against the logged-in Crash Test creator -> Wallet > "Disputes to
respond to" shows $12.00 / Needs response / quality — Stream quality was poor... -> Respond -> typed
rebuttal -> "Your response was submitted" snackbar + chip flips Needs response -> Under review + inline
"Your response: ...". Prod backend confirmed under_review + creator_response + responses_count=1. Full
flow closed (admin resolve refunded, buyer sees resolved+refunded) and ALL synthetic prod rows swept —
FINAL RESIDUE: [].

## Prod fold
apply_e2_prod.py — verbatim copy of roles.py / service / router (dev pre-E2 == prod pre-E2,
md5-confirmed) + anchor patches for settings.py / models.py (anchors md5-confirmed), backups to
.bak_disp_e2_<ts>, chown ubuntu:ubuntu, root-uvicorn-kill + restart, openapi 200, routes present.
