# TestLogon Content Moderation — Deep Audit, Target Design & Implementation Plan

Status: PLAN (for review). Grounded in a 4-area parallel re-read of `android-impl @ 1ca4a089` on dev host `192.168.0.249` (`~/dev/testlogon`), backend running on prod EC2 `i-08f937fc705ebea75`.

> **Prod-divergence rule.** Every citation below is the **dev reference clone**. Prod diverges on a handful of hot files (`app/main.py`, `app/routers/messaging.py`, `app/services/sessions.py`, `broadcast_ads.py`, `broadcast_store.py`) per `adtip-build-progress.md`. The moderation/DMCA/appeals stack shipped as parity batch **B5** (`90dbeb9c`) and is **not** in the known-diverged set, but its DDB tables (`content_reports`, `moderation_tickets`, `user_enforcement_history`, `appeals`, `account_state`, `dmca_claims`) and the fetch-filter line numbers (`newsfeed.py:5435/5941/4241`, `messaging.py:3523`, `sessions.py:356`, `deps.py:147`) must be **re-confirmed against prod via SSM** before landing code. Every backend change lands as an `android-impl` commit AND (for anything already live) a re-apply artifact in `ops/prod-hotfixes/`. Two-device on-device verification per user-facing ticket (Galaxy A15 / Pixel 7a; admin acct `crash1782189692@` role=admin per `android-test-fleet-admin.md`).

---

## 1. VERDICT

**The current system is a well-built but INVERTED and DISJOINT collection of primitives — it is NOT the workflow the requirements describe.** Three separate pipelines exist (general content-reports, DMCA/licensing, admin upload-review video queue) that share no state machine or content vocabulary. The single most load-bearing requested behavior — **report → auto-HIDE (not delete) → admin confirm → 30-day poster-response hold → final call (reinstate/delete)** — **does not exist anywhere**. What exists is the mirror image of the requirement: content is hidden **only at admin resolution**, hiding for comments/messages is **destructive** (content nulled/overwritten, so "show again if poster is right" is impossible), the reported user is **not notified at report time**, and the entire consumer-facing **Report button is dead code** for feed posts, comments, and videos (only user-profile and DM-message reporting are wired in the app).

What IS strong and reusable: the **ban model + per-request enforcement** (fixed/permanent, auto-expiry on read), **violation tracking** (`user_enforcement_history` + `account_state`), the **admin moderation board** (queue/claim/decision/resolve), the **DMCA/licensing pipeline** (the only path that auto-hides on submission AND notifies the target, with strike-counting + repeat-infringer auto-ban), and a **generic, target-parameterized `ReportSheet` UI engine** that just needs to be wired to call sites.

**Net:** roughly 55% of the requirement surface is either missing or inverted. This is a real build (state machine + non-destructive hide + owner-visible-while-hidden + 30-day timer + video/syndicate surfaces + report-button wiring + poster-response UX), not a polish pass — but it can lean heavily on existing hide-filter plumbing, the appeals pattern, the DMCA admin, and the report engine.

---

## 1a. COVERAGE MATRIX (requirement × status × cite)

| # | Requirement | Backend | App UI | Key evidence / gap |
|---|---|---|---|---|
| **1** | Report newsfeed posts (main + group + syndicate) w/ text + categories | **PARTIAL** | **MISSING** | Backend: `feed_post` reportable w/ 5 topics + reason (`moderation.py:31,38-56`). Main feed filters removal (`newsfeed.py:5435`); **group feed does NOT filter** the shared `POST#` flag (`group_feed.py:139-243`); **syndicate posts use a different table `T.syndicate_posts`** and are **not reportable / not hideable** (`syndicate_feed.py:89-233`). UI: engine ready (`ReportTarget.Content`) but **zero call sites** — `PostActionBar.kt:356-401` offers only Edit/Hide/Not-interested. |
| **2** | Report messenger messages | **EXISTS** | **EXISTS** | Backend `content_type∈{message,message_media}` (`moderation.py:105-108`); UI `ThreadScreen.kt:489` + messaging `ReportSheet`. Caveat: admin hide is **destructive** (text→`"[removed by moderation]"`, `moderation_content_removal.py:107-146`). |
| **3** | Report videos + comments on videos + comments on posts | **PARTIAL** | **MISSING** | Post comments `feed_comment` reportable (`moderation.py:39`) but **no UI**; **videos NOT a reportable content_type**, no removal branch; **video comments have ZERO moderation surface** — `video_comments.py` row has no hidden/deleted field, `list_comments` (`:78-117`) unfiltered, delete is hard author-only (`:153-193`). |
| **4** | Reported user is NOTIFIED of report | **MISSING** | **MISSING** | `_create_report` alerts only the **reporter** (`moderation.py:305,354`); owner is alerted only on later admin action (`moderation_policy_engine.py:20,42,92`). App `NotificationType` has **no** moderation/enforcement type (`NotificationDomain.kt:14-15`). |
| **5** | On report → HIDDEN not deleted (immediately) | **MISSING** | n/a | Hiding is triggered **only** at admin `/resolve content_removed` (`admin_moderation.py:892`), never at report time. `_create_report` writes a ticket only. DMCA is the *only* path that auto-hides on submission (`dmca_content_operations.py:65-85`). |
| **6** | Confirm→hold HIDDEN 30d→poster RESPONDS→admin FINAL CALL (reinstate/delete); no response→delete; stays hidden until final call | **MISSING** | **MISSING** | Ticket lifecycle is binary `open→closed` (`admin_moderation.py:716,793`). No hold state, no timer/TTL, no poster-response-on-content, no restore-vs-delete final call. Removal is a soft-hide never escalated to delete; for comments/messages it is destructive so restore is impossible. Appeals (`appeals.py`) is enforcement-keyed, not content-keyed, no 30-day window. |
| **7** | Poster can CLOSE response → content immediately DELETED | **MISSING** | **MISSING** | No poster action on hidden content; `withdraw_appeal` (`appeals_service.py:333`) withdraws an enforcement appeal, does not delete content. |
| **8** | Track violations; ban fixed-duration or permanent; enforce | **EXISTS** | **PARTIAL** | Backend STRONG: `apply_ban` fixed+permanent (`moderation_policy_engine.py:60-113`, `0`=permanent), auto-expiry on read (`:116-129`), enforced on **every** auth path (`sessions.py:356`, `deps.py:147-299`), `user_enforcement_history` + `account_state`. App: **no ban-duration/permanent picker** — `ModerationDetailScreen.kt:216-256` Ban button sends only a note; offender history is read-only. Residuals: fail-open on DDB error (`:119-122`); only `status=="banned"` enforced (deactivated/suspended not gated); offender summary is a table scan (`admin_moderation.py:427`). |
| **9a** | UX to REPORT | **PARTIAL** | **PARTIAL** | Only user-profile (`PublicProfileScreen.kt:285-296`) + DM message (`ThreadScreen.kt:489`) wired. |
| **9b** | User-level report mgmt (respond/close; reports I filed) | **MISSING** | **PARTIAL** | Nearest is Appeals (`AppealsScreen.kt`) — keyed to an `enforcement_id`, not a hidden-content item; no 30-day window, no "reports I filed" list (message report status is device-local only, `ReportDomain.kt:24-33`). |
| **9c** | Admin decisions (queue, agree/dismiss, final call, bans) | **EXISTS** | **PARTIAL** | Full queue+claim+decision+resolve (`admin_moderation.py:540-970`; `ModerationAdminApi.kt`). Gaps: `decision="remove"` does NOT hide (only `/resolve content_removed` does, `:892`); **no ban-duration UI, no final-call/restore action, no 30-day-hold representation** in app. |
| **10** | Licensing-violation type tied to DMCA/licensing | **EXISTS (parallel)** | **PARTIAL** | Deepest real infra: DMCA claim auto-hides + notifies + strike-counts + auto-bans repeat infringers (`dmca_claims.py:197-282`, `dmca_content_operations.py:65-102`); admin DMCA (`admin_dmca.py`); full licensing suite (`license_compliance.py`, `license_requests.py`, `issued_licenses.py`, `syndicate_open_licensing.py`). **But disconnected** — "licensing/copyright" is not a report topic; DMCA form is a standalone URL-paste (`DmcaSubmitScreen.kt`), not a per-content "report as licensing violation" action. |

---

## 2. TARGET DESIGN

### 2.1 The report state machine (the core net-new asset)

A single **content moderation state machine** keyed to a `(content_type, content_id)` ref, stored on a new `moderation_hold` record co-located with the existing `moderation_tickets` aggregation, plus a small set of **non-destructive** flags on each content row.

```
                      user files report
   VISIBLE ─────────────────────────────────────────▶ HIDDEN_PENDING_REVIEW
   (content shown)   (auto-hide; content RETAINED;      (public: hidden;
                      owner NOTIFIED; owner still sees    owner: sees + banner)
                      it with a "reported / under review"
                      banner)
                              │
                 admin triage │ (moderation board)
              ┌───────────────┴───────────────────┐
       DISMISS │ (no violation)          CONFIRM │ (violation)
              ▼                                   ▼
           VISIBLE                       HELD_HIDDEN_30D
        (un-hidden;                   (hold_until = now+30d; owner may RESPOND once;
         owner + reporter               owner NOTIFIED "confirmed, respond within 30d";
         optionally notified)           content still RETAINED + owner-visible)
                                                  │
                    ┌──────────────┬──────────────┴───────────────┐
        poster RESPONDS │   poster CLOSES │        30d elapse, no response │
        within 30d      │   response      │                              │
              ▼         ▼ (opt-out)       ▼                              ▼
        AWAITING_FINAL_CALL      DELETED (immediate,           DELETED (auto sweep;
        (admin reviews response)  poster-initiated)             TTL/cron)
              │
     admin FINAL CALL
     ┌────────┴─────────┐
  REINSTATE │        UPHOLD │
     ▼                  ▼
  VISIBLE            DELETED
  (poster was right) (hard delete + record violation on user)
```

**Invariants:**
- Content is **HIDDEN from the public the moment a report is filed** and **stays hidden until a terminal state** (`VISIBLE` via dismiss/reinstate, or `DELETED`). No visible-while-under-review window for the public.
- Content is **RETAINED** (never nulled/overwritten) until a terminal `DELETED`, so reinstatement is always possible. This **replaces** the current destructive nulling for comment/message/media in `moderation_content_removal.py:58-74,107-146`.
- The **owner can always see their own hidden content** (with a status banner) — the fetch filters become owner-aware (skip-for-non-owner-non-admin) instead of the current unconditional `continue`/`return False`.
- `DELETED` performs the real hard delete (reusing each surface's existing hard-delete path) AND records a violation on the user.

**State/field additions per content row** (non-destructive, uniform across surfaces): `mod_state` (enum: `visible|hidden_pending|held_30d|awaiting_final|deleted`), `mod_report_ticket_id`, `mod_hidden_at`, `mod_hold_until` (epoch; DDB TTL candidate), `mod_owner_response` (text, nullable), `mod_owner_responded_at`, `mod_final_by_admin_user_id`. These live alongside — and supersede — the existing `moderation_removed`/`moderation_hidden` booleans (which we keep writing for backward-compat with current filters during migration).

### 2.2 Reportable surfaces (target)

| Surface | Storage | Today | Target work |
|---|---|---|---|
| Newsfeed post — main | `POST#{id}/META` | reportable, hide list-only | fix single-GET leak (`newsfeed.py:4241`); owner-aware filter |
| Newsfeed post — group | shared `POST#` + `GROUPFEED#` | flag written, **not filtered** | filter in `list_group_feed` (`group_feed.py:139-243`) |
| Newsfeed post — syndicate | `T.syndicate_posts` (`SYND#/POST#`) | **not reportable/hideable** | add `syndicate_post` content_type + removal branch writing to `T.syndicate_posts`; filter in `list_syndicate_posts` (`syndicate_feed.py:163-233`) |
| Newsfeed-post comment | `POST#{id}#COMMENTS` | reportable, **destructive hide** | non-destructive hide (stop nulling body, `moderation_content_removal.py:58-74`) |
| Message (DM) | `Messages` table | reportable, **destructive hide** | non-destructive hide (stop overwriting text, `:107-146`); owner/party visibility decision (see Open Decisions) |
| Video | `video_metadata` | **not reportable** | add `video` content_type + removal branch reusing `status`/`visibility`/`gallery_status` (`models_video.py:10-20`, `video_gallery.py:264-341`) |
| Video comment | `video_comments` (`VIDEO#/COMMENT#`) | **no moderation surface at all** | add hidden field to row; filter `list_comments` (`video_comments.py:78-117`); add `video_comment` content_type |

### 2.3 Category set (proposed — see Open Decisions)

Keep the existing 5 abuse topics (already coded end-to-end: `moderation.py:31`, `ReportDomain.kt:10-22`) and add exactly one IP special type that **routes differently**:

- **Abuse categories** (general ticket pipeline): `sexual`, `extortion`, `criminal`, `spam`, `racist` — *(proposed: rename/expand to `sexual_content`, `harassment_or_extortion`, `illegal_or_dangerous`, `spam_or_scam`, `hate_speech`, plus `misinformation` and `other` — final wording is an Open Decision).*
- **Licensing / IP violation** (special type, req 10): a report with category `licensing_ip` does **not** create a general ticket — it **routes into the existing DMCA pipeline** (`file_dmca_claim`, `dmca_claims.py`), pre-filling the content ref so the user does not paste a URL. This gives req 10 a per-content "Report → licensing violation" entry point while reusing all DMCA strike/auto-hide/repeat-infringer infra.

### 2.4 Notification points (req 4 + 6)

Add a `MODERATION` (and/or `ENFORCEMENT`) `NotificationType` (`NotificationDomain.kt:14-15`) + a deep-link target (`NotificationUi.kt:55-60`) that lands the poster on the new **per-content response screen**. All deliveries reuse `write_alert` (`alerts.py:356`, already does in-app row + push):

1. **On report filed** → alert content owner: "Your {post/comment/video/message} was reported and is hidden pending review." (NEW — req 4.)
2. **On dismiss** → optionally alert owner "restored" + reporter "no violation found."
3. **On confirm (held 30d)** → alert owner: "A violation was confirmed. Your content is hidden. Respond within 30 days or it will be deleted." (deep-link to response screen.)
4. **On final call** → alert owner: reinstated OR deleted (+ violation recorded). (Reuses existing `notify_content_removal`/`moderation_content_removed` pattern, `moderation_policy_engine.py:42`.)
5. **On warn/ban** → existing `moderation_warning`/`moderation_ban` alerts (`moderation_policy_engine.py:20,92`).
6. **DMCA/licensing** → existing infringer alerts (`dmca_claims.py:231`).

### 2.5 Violation tracking + ban model + enforcement (req 8)

Reuse the strong existing spine:
- Every terminal `UPHOLD/DELETE` (and every warn/ban) writes `user_enforcement_history` (`admin_moderation.py:475-497`) and, for bans, `account_state` via `apply_ban` (`moderation_policy_engine.py:60-113`).
- **Ban model:** fixed-duration (`enforcement_duration_days` 1..3650) or permanent (`0`); auto-expiry on read (`:116-129`); enforced on every auth path (`sessions.py:356`, `deps.py:147-299`).
- **Hardening (small):** fix fail-open on DDB error (`:119-122`); optionally gate `deactivated`/suspended statuses; replace the offender-summary table scan with a GSI (`admin_moderation.py:427`).
- **Ban presets** surfaced in the app (see Open Decisions for the preset list).

### 2.6 The three UX areas (req 9)

- **(a) Report** — wire the existing `ReportSheet(ReportTarget.Content(...))` into `PostActionBar` overflow, `CommentsSection`/`GroupCommentsSheet` comment rows, `VideoDetailScreen` + video comments; add the `licensing_ip` category that routes into the DMCA form pre-filled.
- **(b) User report-management** — a NEW **"My content under review"** screen (content-keyed, distinct from the enforcement-keyed Appeals screen): shows each hidden item, its state, the 30-day countdown when `held_30d`, a **Respond** action (one free-text response), and a **Close & delete my content** action (req 7). Optionally a "Reports I filed" list.
- **(c) Admin decisions** — extend `ModerationDetailScreen`: dismiss(un-hide) / confirm(→30d hold) on triage; a **Final Call** panel showing the poster's response with **Reinstate / Delete** buttons; a **ban-duration picker** (fixed presets + permanent) wired to `apply_ban`; surface offender history for ban decisions.

---

## 3. EPIC PLAN (dependency-ordered, MOD-* tickets)

Effort key: **S** ≤1d, **M** 2–3d, **L** 4–6d, **XL** 1–2wk. Every backend ticket also produces a `ops/prod-hotfixes/` re-apply artifact.

### EPIC A — Backend state machine + non-destructive hide primitive (FOUNDATION, blocks everything)

**MOD-A1 (backend, M)** — Content moderation state model + store.
- Deps: none. Cites: `moderation_tickets_store.py:61-155`, `content_reports_store.py:30-82`.
- Add `moderation_hold` record + `mod_state`/`mod_hold_until`/`mod_owner_response`/… fields; enum + transitions helper. DDB TTL on `mod_hold_until` OR a scheduled sweep (Open Decision).
- AC: state transitions unit-tested (visible→hidden_pending→held_30d→awaiting_final→{visible,deleted}); illegal transitions rejected.

**MOD-A2 (backend, M)** — Non-destructive, owner-aware hide primitive.
- Deps: A1. Cites: `moderation_content_removal.py:28-169`, `newsfeed.py:5435/5941/4241`, `messaging.py:3523/3529`, `group_feed.py:139-243`, `syndicate_feed.py:163-233`, `video_comments.py:78-117`.
- Refactor `apply_content_removal` to set state/flags **without nulling content**; add `restore_content` (inverse). Convert all fetch filters from unconditional hide to **owner/admin-aware** hide. Fix single-post GET leak (`newsfeed.py:4241`). Add group-feed filter. Add syndicate + video + video-comment branches.
- AC: hidden content invisible to public on **every** read path (list + single-GET) for all 7 surfaces; visible to owner+admin with banner flag; restore returns original content byte-for-byte; message/comment bodies retained.

**MOD-A3 (backend, S)** — Auto-hide + notify on report (req 4 + 5).
- Deps: A1, A2. Cites: `moderation.py:266-368` (`_create_report`), `alerts.py:356`.
- In `_create_report`, after ticket upsert, call hide primitive → `hidden_pending` and `write_alert` to the **content owner**. Keep reporter alert.
- AC: filing a report hides the content immediately and delivers an owner alert; reporter still gets receipt.

**MOD-A4 (backend, M)** — Admin triage + 30-day hold + final-call endpoints.
- Deps: A1–A3. Cites: `admin_moderation.py:675-970`.
- Add `POST /tickets/{id}/dismiss` (→ un-hide/visible), `POST /tickets/{id}/confirm` (→ held_30d, set `hold_until`, notify owner), `POST /tickets/{id}/final-call` (`reinstate|delete`). `delete` performs hard delete via each surface's existing delete path + records violation. Keep legacy resolve for back-compat.
- AC: confirm sets a 30-day timer + owner notification; final-call reinstate restores; final-call delete hard-deletes + writes `user_enforcement_history`.

**MOD-A5 (backend, S)** — Poster response + close-to-delete endpoints (req 6 + 7).
- Deps: A4. Cites: `appeals_service.py` (pattern), `moderation_content_removal.py`.
- `POST /moderation/holds/{id}/respond` (one owner response → `awaiting_final`), `POST /moderation/holds/{id}/close` (owner opt-out → immediate hard delete + violation). Owner-auth only.
- AC: response moves ticket to awaiting_final + notifies admins; close deletes immediately.

**MOD-A6 (backend, S)** — 30-day expiry sweep.
- Deps: A4. Cites: A1 `mod_hold_until`.
- DDB-TTL handler OR scheduled job: any `held_30d` past `hold_until` with no response → hard delete + violation + owner alert.
- AC: expired holds auto-delete; a hold with a response is NOT swept (it is `awaiting_final`).

### EPIC B — Licensing/IP integration (req 10)

**MOD-B1 (backend, S)** — Licensing report route.
- Deps: A3. Cites: `dmca_claims.py:33-282`, `dmca_content_operations.py:65-102`, `moderation.py:39`.
- Add `licensing_ip` category; when present, route to `file_dmca_claim` (pre-fill content ref) instead of the general ticket. DMCA already auto-hides + notifies + strikes.
- AC: a licensing_ip report creates a DMCA claim (not a general ticket), hides content, notifies owner, increments strike.

### EPIC C — App: report call-site wiring (req 1, 3, 9a)

**MOD-C1 (app, M)** — Wire `ReportTarget.Content` into feed + comments.
- Deps: A3 (backend live). Cites: `PostActionBar.kt:356-401`, `CommentsSection.kt`, `GroupCommentsSheet.kt`, `feature/report/ReportSheet.kt:70-140`, `ReportFlowRepository.kt:63-127`.
- Add Report to post overflow + comment rows (main + group). Engine already supports `feed_post`/`feed_comment`/`media_index`.
- AC: reporting a post/comment posts to `moderation/reports` and content disappears from the reporter's feed on refresh.

**MOD-C2 (app, M)** — Wire video + video-comment reporting.
- Deps: A2 (video/video_comment content types), C1. Cites: `VideoDetailScreen.kt`, video comment list.
- AC: report action on a video and on a video comment succeeds end-to-end.

**MOD-C3 (app, S)** — Licensing-violation category → DMCA.
- Deps: B1, C1. Cites: `DmcaSubmitScreen.kt`, `DmcaApi.kt:81-88`.
- Add "Licensing / IP violation" as a report choice that opens the DMCA form pre-filled with the content ref.
- AC: licensing_ip path files a DMCA claim from a per-content action.

### EPIC D — App: user report-management + notifications (req 4, 6, 7, 9b)

**MOD-D1 (app, S)** — Moderation NotificationType + deep-link.
- Deps: A3. Cites: `NotificationDomain.kt:14-15`, `NotificationUi.kt:55-60`.
- Add `MODERATION`/`ENFORCEMENT` type + target resolver → response screen.
- AC: an owner report/confirm/final alert renders as a typed, tappable notification.

**MOD-D2 (app, M)** — "My content under review" screen (respond / close).
- Deps: A5, D1. Cites: Appeals screens as pattern (`AppealsScreen.kt`, `data/appeals/*`).
- List hidden items + state + 30-day countdown; **Respond** (one text response); **Close & delete my content** (req 7, confirm dialog). Optionally "Reports I filed."
- AC: respond and close both round-trip to A5 endpoints; countdown reflects `hold_until`.

### EPIC E — App: admin decisions + bans (req 6, 8, 9c)

**MOD-E1 (app, M)** — Admin triage + final-call UI.
- Deps: A4. Cites: `ModerationDetailScreen.kt:216-256`, `ModerationAdminApi.kt:36-65`.
- Dismiss / Confirm buttons on triage; a **Final Call** panel that shows the poster's response with **Reinstate / Delete**; show hold state + countdown.
- AC: admin can dismiss, confirm-to-hold, and make a final call from the board.

**MOD-E2 (app, S)** — Ban-duration picker + offender history.
- Deps: E1. Cites: `ModerationDetailScreen.kt` Ban button, `ModerationOffenderHistoryDto` (`ModerationAdminApi.kt:100-106`), `apply_ban` (`moderation_policy_engine.py:60-113`).
- Fixed-duration presets + permanent toggle wired to enforcement; render offender history for the decision.
- AC: admin issues a fixed or permanent ban with duration from the app; offender history visible.

### EPIC F — Hardening (req 8 residuals)

**MOD-F1 (backend, S)** — Enforcement hardening.
- Deps: none (independent). Cites: `moderation_policy_engine.py:119-122` (fail-open), `admin_moderation.py:427` (scan), `deps.py:147`.
- Fix fail-open on DDB error (fail closed or retry); add offender GSI; decide whether `deactivated`/suspended gate the request path.
- AC: DDB error does not admit a banned user; offender summary no longer scans.

**Ticket count: 15 MOD-* tickets** across 6 epics (A:6, B:1, C:3, D:2, E:2, F:1).

Critical path: **A1 → A2 → A3 → A4 → A5 → (C1/C2, D1/D2, E1/E2 in parallel)**; B1 and F1 are independent and can start immediately after A3 / at any time respectively.

---

## 4. OPEN DECISIONS (user must resolve before/at build start)

1. **Category set + wording.** Keep the 5 existing abuse topics as-is, or adopt the proposed 7 (`sexual_content, harassment_or_extortion, illegal_or_dangerous, spam_or_scam, hate_speech, misinformation, other`)? Renaming touches both backend enum (`moderation.py:31`) and app (`ReportDomain.kt:10-22`).
2. **Ban-duration presets.** What fixed presets to expose in the picker (e.g., 1d / 3d / 7d / 30d / 90d + Permanent)? Backend already supports any 1..3650 or 0=permanent.
3. **Message hide symmetry.** When a DM is reported/hidden, does it disappear for **both** parties or only the reporter's view? (Current admin hide is destructive-for-all; target is non-destructive but the visibility scope is a product choice.)
4. **Notification channel.** In-app alert only, or in-app + push for report/confirm/final events? (`write_alert` already does both; confirm we want push for "you were reported.")
5. **Licensing: auto-hide vs review.** Should the `licensing_ip` route keep DMCA's **auto-hide-on-submission** behavior (current DMCA) or go through admin review first like abuse reports? (Affects whether a single unverified user can hide someone's content instantly.)
6. **30-day timer mechanism.** DDB TTL (cheap, ~48h imprecise delete) vs a scheduled sweep job (precise, needs infra). TTL is fine if exact-day precision isn't required.
7. **Appeals reuse vs new flow.** Keep the existing enforcement-keyed Appeals system for ban appeals AND build the separate content-keyed response flow (recommended — they answer different questions), or try to unify them?
8. **Who counts as admin / auto-hide abuse guard.** Report auto-hide (req 5) lets any logged-in user hide any content instantly. Confirm the rate-limit/anti-spam guards already in `_create_report` (`moderation.py:174,224,250`) are sufficient, or add a trust threshold / reporter reputation before auto-hide fires.
9. **Owner-visible-while-hidden.** Confirm the owner should see their own hidden content with a banner (needed for the respond flow) vs it vanishing for them too (current behavior).
10. **Prod verification gate.** Before landing EPIC A, re-confirm the diverged fetch-filter line numbers + table existence on prod EC2 `i-08f937fc705ebea75` via SSM (per divergence rule).

---

*End of plan.*
