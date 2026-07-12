# Demo Video Coverage (Existing Features) — Implementation Tickets

These are RECORDING tasks (no product code): each ticket adds one new walkthrough-video segment for a feature that is already built but not yet shown. Every segment is a self-contained Playwright spec `frontend/e2e/demo/segNN-*.demo.ts` built from the helpers in `frontend/e2e/demo/_demo.ts` (`titleCard`, `caption`, `reveal` — which asserts `toBeInViewport` — `beat`, `injectAuth`/`reauth`, `api`, `py`), recorded by `scripts/record_all_demo.sh` (globs `seg*.webm`), narrated via `## SEGMENT NN` blocks in `docs/demo-video-script.md` (`scripts/render_voiceover.py`), and stitched by `scripts/assemble_voiced_video.sh` (globs `out/seg*.webm`). Current segments are seg01..seg23; new segments start at seg24.

## Milestone 1 — Live & Real-Time Video

### DMO-001: Segment 24 — Broadcast / Live Video
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- New spec `frontend/e2e/demo/seg24-broadcast.demo.ts`; `titleCard(page, 24, "Live Broadcasting", "Go live · viewers · recordings · live player")`.
- Broadcaster studio at route `/broadcast` (`frontend/src/pages/broadcast/BroadcastPage.tsx`, gated by `isBroadcastNavigationEnabled()` which defaults `true` — `frontend/src/lib/featureFlags.ts:115-118`; nav route `frontend/src/App.tsx:370`). Reveal the header `Broadcast` heading (`BroadcastPage.tsx:224`), the `New Profile` / `New Session` buttons (`:231-236`), and the `Sessions` / `Profiles` / `Audit Log` tabs.
- Reveal a `Live` session row + its stream key panel (`BroadcastPage.tsx:930` `streamKey`) and the status filter (`Live`, `:261`).
- Viewer side: route `/live/:sessionId` (`frontend/src/pages/broadcast/LivePlayer.tsx`, `App.tsx:292`) — reveal the live player surface after `POST /broadcast/sessions/{id}/playback-url` resolves (`LivePlayer.tsx:91-94`).
- Backend (router prefix `/broadcast`, `app/routers/broadcast.py:77`): seed a `live` session off-camera. Create profile + session via `api(page,"post","/broadcast/profiles",...)` and `api(page,"post","/broadcast/sessions",...)` (`broadcast.py:284,308`), then `POST /broadcast/sessions/{id}/start` (`:392`). Viewer count seedable via `POST /broadcast/sessions/{id}/viewers/join` + `.../heartbeat` (`:603,631`) so `GET /broadcast/sessions/{id}/viewers/count` (`:667`) returns a non-zero number to reveal.
- A real RTMP/HLS playback stream can't run headless — fulfil/stub the playback-url response (mirror seg14-vod's media handling) so the `LivePlayer` mounts; the segment demonstrates UI + flow, not pixel-level video.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg24-broadcast.demo.ts` records green and emits the webm to its `.artifacts/...seg24...` path.
- The `Broadcast` heading, a `Live` session row, and the `/live/:sessionId` player are each brought on-screen and asserted in-viewport via `reveal()`.
- Narration block `## SEGMENT 24` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

### DMO-002: Segment 25 — 1:1 & Group Video Chat
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- New spec `frontend/e2e/demo/seg25-group-calls.demo.ts`; `titleCard(page, 25, "Video Chat", "1:1 and group video — right in the conversation")`.
- MUST launch its own fake-media Chromium and record on the alice context — copy the dedicated-browser pattern from `frontend/e2e/demo/seg03-calls.demo.ts:29-93,330-345` (`FAKE_MEDIA_ARGS`, `recordVideo`, `injectCallAuth` with RTC-state pinning, artifact copy in `finally`). Real WebRTC/ICE can't complete headless, so drive state via the backend + SSE replay as seg03 does.
- 1:1 video: in a DM at `/messages/:conversationId`, reveal `Start video call` (the button seg03 already references) to show the `CallSessionOverlay` (`frontend/src/pages/messages/CallSessionOverlay.tsx`) in video mode.
- Group video: in a group conversation, reveal the `Start group call` button (`frontend/src/pages/messages/GroupCallOverlay.tsx:119` `aria-label="Start group call"`), then the active overlay strings `Active group call` (`:143`) and the participant tile grid; reveal `Join Call` (`:134`) / `Join` (`:156`) affordances.
- Backend (router prefix `/ui/calls/group`, `app/routers/group_calls.py:45`): seed an active group call off-camera via `POST /ui/calls/group/create` (`:127`), have a 2nd identity `POST /ui/calls/group/{id}/join` (`:142`), and confirm via `GET /ui/calls/group/active/{conversation_id}` (`:218`). Use `reauth(page, ...)` to act as the second participant (group conversation must already include both seeded identities — create it via `py()` or the messaging API).
- Pin `connectionState`/`iceConnectionState` to `connected` (seg03 `injectCallAuth:71-92`) so the overlay does not flicker closed.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg25-group-calls.demo.ts` records green; the recorded webm is copied to the seg25 artifact path in `finally`.
- A 1:1 video overlay AND a group-call overlay with at least two participant tiles are each asserted in-viewport via `reveal()`.
- Narration block `## SEGMENT 25` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

## Milestone 2 — Rich Messaging Content

### DMO-003: Segment 26 — Gallery Messages (multi-image / video)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- New spec `frontend/e2e/demo/seg26-gallery.demo.ts`; `titleCard(page, 26, "Gallery Messages", "Multi-image & video albums · free + locked items")`.
- Show a gallery message in a DM at `/messages/:conversationId`. Bubble rendering: `frontend/src/pages/messages/MessageBubble.tsx:1432` (`message.kind === "gallery"`) — reveal the free-items 3-col grid (`:1436`) and the locked-items section with the badge string `… locked item(s) · $X.XX` (`:1502-1505`) plus the `Unlock for $X.XX` button (`:1514`).
- Reveal the conversation-level gallery view `frontend/src/pages/messages/ConversationGallery.tsx` (opened from the conversation menu) to show images + videos collated.
- Backend: send a gallery message off-camera via `POST /messaging/conversations/{conversation_id}/messages/gallery` (`app/routers/messaging.py:8913`, model `CreateGalleryMessageIn` validated at `:2014`) using `api(page,"post",...)`; include both free and locked items so the lock badge renders for the recipient. Page the gallery via `GET /messaging/conversations/{conversation_id}/gallery` (`:7734`).
- Seed an S3-backed image/video object (or reuse seg02/seg09 media-seeding) so the grid thumbnails resolve in dev (`/mock/s3/...` URLs). Gating: feature flag `MESSAGING_GALLERY_ENABLED` (settings field `messaging_gallery_enabled`, `messaging.py:2199`) must be on.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg26-gallery.demo.ts` records green.
- The multi-item gallery grid (free items) AND the locked-items badge/`Unlock for` button are each asserted in-viewport via `reveal()`.
- Narration block `## SEGMENT 26` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

### DMO-004: Segment 27 — Lottery Messages
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- New spec `frontend/e2e/demo/seg27-lottery.demo.ts`; `titleCard(page, 27, "Lottery Messages", "A paid scratch-and-reveal outcome in chat")`.
- Recipient view in a DM at `/messages/:conversationId`. Bubble: `frontend/src/pages/messages/MessageBubble.tsx:1041-1140`. Reveal the locked card `Locked lottery` (`:1045`), the prompt `Unlock this lottery message to reveal your outcome.` (`:1052`), and the `Unlock outcome` button (`:1070`).
- Drive the reveal: click `Unlock outcome` → show the spinner/transition (`Unlocking…` / `Revealing…`, `:1065`) → reveal the result card `Lottery result` (`:1088`) and the `Outcome: …` line (`:1097`).
- Backend (DM only, 422 otherwise — `messaging.py:13042-13046`): seed the lottery message via `POST /messaging/messages/lottery` (`:13026`, model `CreateLotteryMessageIn` / `message_type: "lottery_dm"`, `:2303`) as the sender, then `reauth()` to the recipient. Drive the on-camera unlock through the real UI button (which calls `POST /messaging/messages/{id}/lottery/unlock`, `:13279`); fetch state via `GET /messaging/messages/{id}/lottery` (`:13422`). Gating: `MESSAGING_DM_LOTTERY_ENABLED` (`messaging_dm_lottery_enabled`, `messaging.py:2200`).
- Recipient needs a seeded payment method (lottery is paid) — reuse the billing-PM seeding pattern from seg07/the messaging specs so `Unlock outcome` is enabled.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg27-lottery.demo.ts` records green.
- The `Locked lottery` card AND the revealed `Lottery result` / `Outcome:` card are each asserted in-viewport via `reveal()` across the unlock transition.
- Narration block `## SEGMENT 27` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

## Milestone 3 — Discovery & Documents

### DMO-005: Segment 28 — Newsfeed Filtering & Search
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- New spec `frontend/e2e/demo/seg28-feed-filtering.demo.ts`; `titleCard(page, 28, "Feed Search & Filters", "Search posts · author · date range · media-only")`.
- The filter UI lives on the Profile "Posts" tab: route `/profile` → `frontend/src/pages/settings/ProfilePage.tsx` (`Posts` tab trigger `:22`, gated by `isProfilePostsFeedEnabled()` `:10`) → `frontend/src/pages/settings/ProfilePosts.tsx` (drives `FeedTimeline` with `authorId/q/from/to/hasMedia`). Reveal: the `Search posts` input `placeholder="Search your posts"` (`ProfilePosts.tsx:48,60`), the `From` / `To` date inputs (`:64,73`), and the `Media` select with `All posts` / `With media` / `Without media` (`:84,95-97`).
- Demonstrate the effect: type a query / pick `With media` and reveal the filtered `FeedTimeline` results re-render (results render via `frontend/src/pages/feed/FeedTimeline.tsx`).
- Backend filter contract: `GET /feed?author_id=&q=&from=&to=&has_media=` (`app/routers/newsfeed.py:5151-5159`; `from`/`to` are ISO and aliased query params). Seed several of the demo user's own posts off-camera — some with media, some without, across dates — via the post-create API (`POST` newsfeed create) or `py()` so author-scoped + media-only filtering returns distinct, visible result sets.
- (Optional) Caption note that the same filters power the API directly (`GET /feed`) for headless/API clients.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg28-feed-filtering.demo.ts` records green.
- The search input, the date-range inputs, and the `Media` filter select are each asserted in-viewport via `reveal()`, and a filtered timeline result is shown changing.
- Narration block `## SEGMENT 28` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

### DMO-006: Segment 29 — On-Camera Generated PDFs
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- New spec `frontend/e2e/demo/seg29-pdfs.demo.ts`; `titleCard(page, 29, "Documents & PDFs", "Signed packets · invoices · receipts · 1099 & tax summaries")`. The goal is to show the ACTUAL rendered PDFs on camera (open each in an in-page `<iframe>`/object tag from its blob/url so the page content is visible), not just the list rows.
- Signed final PDF: SigningPage at `/signing` (`frontend/src/pages/signing/SigningPage.tsx`). Seed a completed packet with a `ready` artifact off-camera, then fetch `GET /v1/signature-packets/{packet_id}/final-pdf` (`app/routers/signature_packets.py:920-953`, returns `application/pdf`) and render the bytes on-camera. Gating: `SIGNATURE_PDF_ENABLED`.
- Invoices: `/billing/invoices` (`frontend/src/pages/billing/InvoicesPage.tsx`, header `Invoices` `:64`). Reveal a row, then render `GET /ui/invoices/{invoiceNumber}/pdf` (`frontend/src/api/endpoints/invoices.ts:32-44` `downloadInvoicePdf`) on-camera.
- Receipts: render a transaction receipt via `GET /ui/purchase-history/transactions/{txn_id}/receipt` (`app/routers/purchase_history.py:155`; PDF rendered by `app/services/receipts.py:204-205`) — reachable from `/purchases` transaction detail (`frontend/src/pages/purchases/TransactionDetail.tsx`).
- 1099 form: `/billing/tax-forms` (`frontend/src/pages/billing/TaxForm1099Page.tsx`). Generate via `POST /ui/tax-forms/1099s/{year}/generate` then render `GET /ui/tax-forms/1099s/{year}/download` (`frontend/src/api/endpoints/taxForm1099.ts:17-21`).
- Tax summary: `/billing/tax-documents` (`frontend/src/pages/billing/TaxDocumentsPage.tsx`, `Download Summary PDF` `:94`) → render `downloadSummaryPdf({year})` output on-camera.
- All PDF generators are dependency-free pure-Python writers (per CLAUDE.md), so they work in dev. Seed the underlying ledger/invoice/packet rows via `py()` so each document has real content; reuse seg19 (Accounting & Taxes) seeding where it overlaps.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg29-pdfs.demo.ts` records green.
- At least the signed final PDF, an invoice PDF, a receipt PDF, and a 1099/tax-summary PDF are each rendered visibly on-camera and the rendered PDF surface is asserted in-viewport via `reveal()`.
- Narration block `## SEGMENT 29` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

## Milestone 4 — Trust & Safety Admin

### DMO-007: Segment 30 — Fraud & Risk Admin Dashboards
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- New spec `frontend/e2e/demo/seg30-fraud-risk.demo.ts`; `titleCard(page, 30, "Fraud & Risk", "Risk scoring dashboard · fraud review queue · freeze controls")`. Use a privileged identity — `injectAuth(page, "root")` (or admin) — mirroring seg16-admin.
- Risk Scoring Dashboard: route `/admin/risk` (`frontend/src/pages/admin/RiskDashboardPage.tsx`, `App.tsx:462`). Reveal the `Risk Scoring Dashboard` heading (`:108`), the tier distribution cards (`… Risk` `:42`), the `ScoreGauge`, and the `High-Risk Users` panel (`:171`). Reveal the score-override control.
- Fraud Review Queue: route `/admin/fraud` (`frontend/src/pages/admin/fraud/FraudReviewQueuePage.tsx`, `App.tsx:439`). Reveal the `Fraud Detection` heading (`:397`), the stats bar (`Pending Flags` / `Open Cases` / `Frozen Users` / `Avg Resolution Time`, `:58-61`), and the `Queue` / `Cases` / `Users` / `Config` / `Stats` tabs (`:402-414`). Reveal a flag row + its `Review` action (`:144`).
- Backend seeding: risk-scoring admin router prefix `/ui/admin/risk` (`app/routers/risk_scoring.py:79`) — seed scored users so `GET /ui/admin/risk/distribution` and `GET /ui/admin/risk/high-risk` return data (`frontend/src/api/endpoints/risk-scoring.ts:29,52`). Fraud router prefix `/v1/admin/fraud` (`app/routers/fraud_detection.py:34`) — seed a pending flag/case via `POST /v1/admin/fraud/cases` (`:118`) / a flag row, and a frozen user (`POST /v1/admin/fraud/users/{id}/freeze` `:83`) so the stats bar is non-zero. Seed via `py()` or the `api()` helper as the privileged identity.

**Acceptance Criteria**
- `npx playwright test -c playwright.demo.config.ts e2e/demo/seg30-fraud-risk.demo.ts` records green.
- The `Risk Scoring Dashboard` (with a populated High-Risk Users panel) AND the `Fraud Detection` queue (with a non-zero stats bar) are each asserted in-viewport via `reveal()`.
- Narration block `## SEGMENT 30` exists and the segment appears in the re-assembled video (DMO-008).

**Dependencies**
- None.

---

## Milestone 5 — Narration & Assembly

### DMO-008: Add narration blocks, re-render voiceover, re-assemble & re-host
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add one `## SEGMENT NN — <name>` narration block per new segment to `docs/demo-video-script.md` (parsed by `scripts/render_voiceover.py`): `## SEGMENT 24 — Live Broadcasting`, `25 — Video Chat`, `26 — Gallery Messages`, `27 — Lottery Messages`, `28 — Feed Search & Filters`, `29 — Documents & PDFs`, `30 — Fraud & Risk`. Match the prose tone of the existing blocks (see `## SEGMENT 23`).
- Update the script's closing summary paragraph (currently at the end of `## SEGMENT 23`) to mention the newly covered features (live video, video chat, gallery/lottery messages, document PDFs, fraud/risk).
- Record the new segments via `scripts/record_all_demo.sh` (auto-discovers `seg*.demo.ts`), re-render narration with `scripts/render_voiceover.py` (auto-discovers `## SEGMENT NN` → `out/voiceNN.mp3`), and re-assemble with `scripts/assemble_voiced_video.sh` (globs `out/seg*.webm` + `out/voiceNN.mp3`). No script edits are required since all three enumerate by glob/regex.
- Re-host/publish the final assembled video per the existing hosting step.

**Acceptance Criteria**
- `docs/demo-video-script.md` contains `## SEGMENT 24`..`## SEGMENT 30` blocks and an updated closing summary.
- `scripts/render_voiceover.py` produces `out/voice24.mp3`..`out/voice30.mp3`; `scripts/assemble_voiced_video.sh` runs clean and the final video includes seg24..seg30 with synced narration.
- The re-hosted video link is updated wherever the previous walkthrough video is referenced.

**Dependencies**
- DMO-001, DMO-002, DMO-003, DMO-004, DMO-005, DMO-006, DMO-007.

---
