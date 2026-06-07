# M4 — Content Consumption — Tickets

Decomposition of milestone **M4** (epics **E23–E27**). Format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**.

**Milestone exit criteria:** native HLS playback; interactive feed (incl. paywall unlock);
discovery/search; VOD/clips/videos; stories & gallery.

---

## Epic E23 — Media playback foundation

### AND-166 — Media3/ExoPlayer integration
**Type:** Feature · **Priority:** P0 · **Deps:** AND-003
**Scope:** Add Media3; `PlayerManager` wrapper; lifecycle-aware release; single-player reuse.
**Acceptance:** A progressive MP4 plays in a Compose surface (tested).

### AND-167 — HLS playback
**Type:** Feature · **Priority:** P0 · **Deps:** AND-166
**Scope:** HLS source support (replaces hls.js), live + VOD manifests.
**Acceptance:** An HLS stream plays with adaptive switching.

### AND-168 — Reusable player UI
**Type:** Feature · **Priority:** P0 · **Deps:** AND-166
**Scope:** Controls (play/seek/scrub/volume/fullscreen), buffering/error states, PiP.
**Acceptance:** Controls + fullscreen + PiP work.

### AND-169 — Adaptive quality / data-saver
**Type:** Feature · **Priority:** P1 · **Deps:** AND-167, AND-079
**Scope:** Quality selection, honor media preferences/data-saver.
**Acceptance:** Quality cap respected on metered networks.

### AND-170 — Watermark/overlay hooks
**Type:** Feature · **Priority:** P1 · **Deps:** AND-168
**Scope:** Dynamic user watermark overlay hook for protected content.
**Acceptance:** Overlay renders over playback when required.

### AND-171 — Playback analytics/heartbeat
**Type:** Feature · **Priority:** P2 · **Deps:** AND-166
**Scope:** View/heartbeat reporting hooks (per content/broadcast).
**Acceptance:** Heartbeats emit at intervals while playing.

### AND-172 — Media foundation tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-167, AND-168
**Scope:** Player state + UI tests.
**Acceptance:** Tests pass headlessly.

---

## Epic E24 — Feed interactions

### AND-173 — Like / unlike
**Type:** Feature · **Priority:** P0 · **Deps:** AND-099
**Scope:** Like toggle with optimistic update.
**Acceptance:** Like persists + reconciles (tested).

### AND-174 — Comments
**Type:** Feature · **Priority:** P1 · **Deps:** AND-100
**Scope:** Comment list + add (+ replies if supported); paging.
**Acceptance:** Comment posts + appears; paginates.

### AND-175 — Hide / not-interested
**Type:** Feature · **Priority:** P2 · **Deps:** AND-099
**Scope:** `postHide.ts`, `postInteresting.ts`; remove from feed.
**Acceptance:** Hidden post leaves feed; preference honored.

### AND-176 — Share / bookmark from feed
**Type:** Feature · **Priority:** P1 · **Deps:** AND-099, AND-092
**Scope:** Share sheet + bookmark/save toggle.
**Acceptance:** Save toggles; share opens sheet.

### AND-177 — Paywall unlock & entitlement
**Type:** Feature · **Priority:** P0 · **Deps:** AND-101, AND-031
**Scope:** Unlock paid content (purchase/entitlement), reveal on success.
**Acceptance:** Unlock flow reveals content; entitlement cached (tested w/ payment stub).

### AND-178 — Tips on posts
**Type:** Feature · **Priority:** P1 · **Deps:** AND-031
**Scope:** Tip action on a post.
**Acceptance:** Tip submits + confirms.

### AND-179 — Polls in feed
**Type:** Feature · **Priority:** P2 · **Deps:** AND-099
**Scope:** `polls.ts` render/vote in feed.
**Acceptance:** Vote updates results.

### AND-180 — Interaction ViewModel updates
**Type:** Feature · **Priority:** P0 · **Deps:** AND-102
**Scope:** Optimistic state + rollback for all interactions.
**Acceptance:** Optimistic/rollback unit-tested.

### AND-181 — Feed interaction tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-173, AND-177
**Scope:** Repo + UI tests.
**Acceptance:** Tests pass.

---

## Epic E25 — Discovery & search

### AND-182 — Discover screen
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027, AND-103
**Scope:** `discovery.ts`; curated/discover grid.
**Acceptance:** Discover renders + navigates.

### AND-183 — Tag pages
**Type:** Feature · **Priority:** P2 · **Deps:** AND-182
**Scope:** `discover/tags/:tag` listing + App Link.
**Acceptance:** Tag page loads content.

### AND-184 — Recommendations
**Type:** Feature · **Priority:** P2 · **Deps:** AND-182
**Scope:** `recommendations.ts` rows.
**Acceptance:** Recommended items render.

### AND-185 — Global search (multi-entity)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `search.ts` across users/content/etc.; tabs per entity.
**Acceptance:** Query returns categorized results (tested).

### AND-186 — Search filters/tabs
**Type:** Feature · **Priority:** P1 · **Deps:** AND-185
**Scope:** Filters, recent searches, empty/no-results states.
**Acceptance:** Filters refine results.

### AND-187 — Discovery/search ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-182, AND-185
**Scope:** Debounce, paging, state.
**Acceptance:** Unit-tested.

### AND-188 — Discovery/search tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-187
**Scope:** Repo + UI tests.
**Acceptance:** Tests pass.

---

## Epic E26 — VOD / videos / clips

### AND-189 — Videos library
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027, AND-103
**Scope:** `videos.ts` browse/grid.
**Acceptance:** Library renders + opens detail.

### AND-190 — Video detail + player
**Type:** Feature · **Priority:** P1 · **Deps:** AND-189, AND-168
**Scope:** Detail metadata + HLS playback.
**Acceptance:** Video plays from detail.

### AND-191 — VOD catalog
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `vod.ts` catalog + detail.
**Acceptance:** VOD list/detail render.

### AND-192 — VOD rental flow
**Type:** Feature · **Priority:** P2 · **Deps:** AND-191, AND-031
**Scope:** `vodRental.ts`; rent + access window.
**Acceptance:** Rental grants time-boxed access.

### AND-193 — VOD purchase tiers
**Type:** Feature · **Priority:** P2 · **Deps:** AND-191, AND-031
**Scope:** `vodPurchaseTiers.ts`; tiered purchase.
**Acceptance:** Tier purchase unlocks content.

### AND-194 — VOD ad-supported
**Type:** Feature · **Priority:** P2 · **Deps:** AND-191, AND-168
**Scope:** `/ui/vod/ad-supported/{video_id}/session`; ad-gated playback.
**Acceptance:** Ad-supported session plays with ad breaks.

### AND-195 — Watermark download
**Type:** Feature · **Priority:** P2 · **Deps:** AND-191, AND-170
**Scope:** `vodWatermarkDownload.ts`; watermarked download.
**Acceptance:** Download produces watermarked file.

### AND-196 — Clips viewer (+ public clip)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-168, AND-022
**Scope:** `clips.ts`; vertical clip viewer + public `/c/:clipId` App Link.
**Acceptance:** Clips swipe + play; public clip opens.

### AND-197 — VOD/video ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-189, AND-191
**Scope:** State + entitlement checks.
**Acceptance:** Unit-tested.

### AND-198 — VOD/video tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-197
**Scope:** Repo + UI tests.
**Acceptance:** Tests pass.

---

## Epic E27 — Stories & gallery

### AND-199 — Stories tray + viewer
**Type:** Feature · **Priority:** P1 · **Deps:** AND-168
**Scope:** `stories.ts`; tray + full-screen viewer.
**Acceptance:** Stories open + auto-advance.

### AND-200 — Story progress + reactions
**Type:** Feature · **Priority:** P2 · **Deps:** AND-199
**Scope:** Segment progress, tap nav, reactions/replies.
**Acceptance:** Progress + reactions work.

### AND-201 — Gallery browsing
**Type:** Feature · **Priority:** P2 · **Deps:** AND-103
**Scope:** `gallery.ts`; grid + lightbox.
**Acceptance:** Gallery renders + lightbox opens.

### AND-202 — Stories/gallery ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-199, AND-201
**Scope:** State + paging.
**Acceptance:** Unit-tested.

### AND-203 — Stories/gallery tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-202
**Scope:** UI smoke tests.
**Acceptance:** Tests pass.

---

### M4 ticket count: 38 (E23:7, E24:9, E25:7, E26:10, E27:5)
**Running total through M4:** 203 tickets (AND-001…AND-203).
