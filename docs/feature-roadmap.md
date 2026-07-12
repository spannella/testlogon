# Feature Roadmap — v2 Follow-ups

Derived from the 2026-06-08 brain dump, reality-checked against the codebase. This is a
**planning document** (no code changed). Status reflects what exists today; effort and
sequencing are estimates to be refined when each item is picked up.

**Effort legend:** S ≈ 0.5–1 day · M ≈ 2–4 days · L ≈ 1–2 weeks · XL ≈ multi-week (decompose first).
**Status legend:** ✅ built · 🟡 partial · ❌ net-new.

---

## 1. Bugs (small, do first)

| Item | Status | Effort | Notes / key files |
|---|---|---|---|
| Dark theme "does nothing" | 🟡 | S | Pipeline looks correct (`uiStore.setTheme` → `ThemeProvider` toggles `.dark` → `globals.css` `.dark` vars, Tailwind v4 via `@tailwindcss/vite`). Suspect a **hydration race** (server prefs vs persisted store) or a **Tailwind-v4 dark-variant** misconfig (v4 needs an explicit `@custom-variant dark`). Repro across surfaces + first-load vs after-reload. `ThemeProvider.tsx:88-115`, `uiStore.ts:62`. |
| Delegate "hide the via user" | 🟡 | S–M | Today `delegate_tag_enabled=false` only removes the inline text tag; `sent_by_delegate`/`delegate_display_name` still go to recipients and the FE badge still renders. Add a distinct **"hide attribution from recipients"** setting → filter those fields in `delegate_chat.py:378-380` for non-owner viewers → gate the badge in `DelegateConversationView.tsx:204-213`. |

---

## 2. Demo coverage — already-built features (recording-only, no code)

All exist and run in dev; each is ~S to record as a new walkthrough segment (reuse the `_demo.ts` harness).

| Feature | Where | 
|---|---|
| Broadcast / live video + watch + chat | `broadcast.py`, `BroadcastPage`/`LivePlayer` |
| 1:1 & group video chat (WebRTC) | `group_calls.py`, `CallSessionOverlay`/`GroupCallOverlay`, `callStateMachine.ts` |
| Gallery messages (multi image/video) | `messaging.py` `CreateGalleryMessageIn:2002`, `/messages/gallery` |
| Lottery messages / posts | `messaging.py:13026` `/messages/lottery` + unlock |
| Newsfeed filtering + search | `GET /feed?author_id,q,from,to,has_media`; `FeedTimeline` |
| On-camera PDFs: signed docs, 1099, tax docs, invoices, receipts | `signature_packet_renderer`, `tax_form_1099`, `consumer_tax_documents`, `invoices`, `receipts` (all real pure-python PDFs) |
| Fraud / risk / rate-limit dashboards | `fraud_detection.py`, `RiskDashboardPage`, `RateLimitDashboard` |

> Net-new items below also need demo segments **after** they're built (KYC disputes, honeypots, legal export, DocuSign UX, voice, recsys).

---

## 3. Net-new feature builds

### 3a. Messaging
| Item | Status | Effort | Notes |
|---|---|---|---|
| Compose "+" menu (compact widgets) | ❌ | M | `ComposeBar` refactor into a single overflow menu; responsive. Pure FE. |
| Message translation | ❌ | M | Anthropic translate endpoint + per-message cache + FE language toggle. |
| Voice → text (transcribe) | ❌ | M | Voice messages exist (`messaging.py:8525`). Add transcribe endpoint (Whisper/provider) + store transcript + FE. |
| Text → voice message (TTS) | ❌ | M | **Dep:** add ElevenLabs as a provider in `llm_provider_keys` (S). Then endpoint → synth → store audio → playback. |

### 3b. Signing / DocuSign UX overhaul (engine ✅, UX 🟡)
Decompose; the shareable-link core unblocks the rest.
| Item | Effort | Notes |
|---|---|---|
| Shareable / embeddable signing link | M | Public, tokenized, time-limited signing URL (mirror cart-recovery HMAC scheme) → opens the signing widget without a full login. `signature_packets.py`. |
| "Awaiting my signature" inbox page | S–M | Status `awaiting_your_signature` already tracked; promote to a first-class page. |
| Standalone request-creator widget | S–M | `SignaturePacketComposer` exists; give it a standalone entry. |
| Open-widget deep links from File Mgr / KYC / Messaging | M | "Send for signature" / "Open to sign" actions wired to the link core. |

### 3c. Helpdesk / ticketing
| Item | Status | Effort | Notes |
|---|---|---|---|
| Auto-redirect helpdesk chat → messenger when an admin is free | ❌ | M | Presence check → route the conversation to a live agent DM. |
| More intuitive client helpdesk UX | 🟡 | M | Simplify the client-side flow. |
| Ticket "spaces" → "boards" (Trello/Kanban) | 🟡 | M–L | Rename + Kanban board UI (columns, drag/drop, WIP). |

### 3d. Compute / remote / agents
| Item | Status | Effort | Notes |
|---|---|---|---|
| EC2/K8s "Open SSH/VNC/RDP terminal" deep-link | 🟡 | M | Hosts already auto-register (`GAP-0223/0226`). Add button on instance UI → prefill terminal via `host_id`. **Quick, high-value.** |
| LLM agents = registered Claude Code sessions via a special terminal | 🟡 | L | PTY-wrap the CLI on the worker + **reverse** the WS wiring (today `terminal_monitor` is one-way, `browser_ssh_terminal.py:959`) + session state. |
| Agents use SSH/VNC for QA | 🟡 | L | **Dep:** EC2→SSH deep-link + Claude-Code-session work. SSH client on worker + `agent_actions` API + credential injection from `host_inventory`/`ssh_key_manager` + output streaming. |

### 3e. Trust, safety & compliance
| Item | Status | Effort | Notes |
|---|---|---|---|
| KYC disputes / retry / resubmit-after-reject | ❌ | M | New dispute state + endpoints + admin review queue + FE. |
| Honeypots / honeytokens / IDS | ❌ | M–L | Fraud/rate-limit/risk tooling exists; add deception (decoy endpoints/tokens) + alerting + a unified security dashboard. |
| Legal / warrant / DSAR export | 🟡 | M | `audit_export` pipeline is the foundation; add legal-hold + a per-user data-export builder + intake/workflow. |

### 3f. Discovery & media
| Item | Status | Effort | Notes |
|---|---|---|---|
| Newsfeed recommendation / "for you" (posts) | 🟡 | M–L | Video recsys exists; feed is chronological own+following only. Needs ranking + likely a fan-out/index change + FE tab. |
| Subtler video watermarking | ✅(adjust) | S | One bold corner mark + keep forensic marks but faint (machine-detectable, human-unobtrusive). Tune the watermark service. |

---

## 4. Apache OFBiz — capability mapping (research initiative, XL)

Recommendation: **cherry-pick OFBiz capabilities, don't adopt OFBiz wholesale.** Mapping to what exists:

| OFBiz domain | Today | Gap to consider |
|---|---|---|
| Catalog / product | ✅ shop catalog | variants, categories depth |
| Order management | 🟡 cart + orders | returns/RMA, fulfillment states |
| Inventory / warehouse / facility | ❌ | stock, reservations, locations |
| Accounting (GL / AR / AP) | 🟡 billing ledger + invoices + tax | double-entry GL, AP, statements |
| Pricing / promotions | 🟡 discount codes | rules engine, tiered/bulk pricing |
| CRM / party | 🟡 contacts | party roles, opportunities |
| Manufacturing / MRP | ❌ | BOM, work orders |
| POS | ❌ | in-person checkout |
| Content / CMS | 🟡 newsfeed + files | structured CMS |
| Marketing | 🟡 ads + marketing agents | campaigns, segmentation |

Next step for OFBiz: a dedicated scoping pass to pick the 2–3 highest-value modules (likely **inventory**, **GL accounting depth**, **returns/RMA**) and spec them against the existing data model.

---

## 5. Suggested sequence

Independent tracks can run in parallel; this is a default ordering by value/effort and dependencies.

- **Wave 0 — Quick wins (this week):** dark-theme bug, delegate hide-attribution, watermark subtlety, EC2→SSH/VNC deep-link, messenger "+" menu. *(All S/M, independent; fixes a regression on the just-shipped theming demo.)*
- **Wave 1 — Demo coverage (no code):** record broadcast, video chat, gallery, lottery, feed search, and on-camera PDFs as new walkthrough segments. *(Parallel with Wave 0.)*
- **Wave 2 — Messaging intelligence:** ElevenLabs provider prereq → TTS + STT + translation.
- **Wave 3 — Signing/DocuSign overhaul:** shareable link core → awaiting-signature inbox → standalone creator → deep links.
- **Wave 4 — Helpdesk & ticketing UX:** auto-redirect to messenger, ticket boards (Kanban), client UX.
- **Wave 5 — Agent platform:** Claude Code session terminal → agents-use-SSH/VNC-for-QA (depends on Wave 0's deep-link).
- **Wave 6 — Trust/safety & compliance:** KYC disputes, honeypots/IDS, legal/DSAR export.
- **Wave 7 — Discovery:** newsfeed "for you" ranking.
- **Parallel research track:** OFBiz module scoping (feeds future commerce waves).

### Dependency highlights
- TTS → **ElevenLabs provider** added to `llm_provider_keys`.
- Agent SSH/VNC QA → **EC2→SSH deep-link** + **Claude Code session terminal**.
- DocuSign deep links → **shareable-link/widget core**.
- Demos of net-new features → those features built first.
- Newsfeed recsys → possible **feed fan-out/index** change (currently own+following only).
