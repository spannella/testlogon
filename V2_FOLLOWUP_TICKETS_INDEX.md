# v2 Follow-up Tickets — Index

Implementation-ready backlog for the 2026-06-08 follow-up brain dump, decomposed into **218 tickets
across 17 workstreams**. Each file is code-grounded (real file:line citations) and follows the repo's
standard ticket format. Sequencing references the waves in [`docs/feature-roadmap.md`](docs/feature-roadmap.md).

| Wave | Prefix | File | Tickets | Workstream |
|---|---|---|---:|---|
| 0 — Quick wins | THM | [THEME_DARKMODE_TICKETS.md](THEME_DARKMODE_TICKETS.md) | 7 | Fix dark theme (Tailwind v4 missing `@custom-variant dark`) + harden |
| 0 — Quick wins | DLP | [DELEGATE_PRIVACY_TICKETS.md](DELEGATE_PRIVACY_TICKETS.md) | 8 | Fully hide "via @delegate" attribution from recipients |
| 0 — Quick wins | WMK | [WATERMARK_SUBTLETY_TICKETS.md](WATERMARK_SUBTLETY_TICKETS.md) | 9 | One bold corner mark + faint machine-readable forensic marks |
| 0 — Quick wins | CTI | [COMPUTE_TERMINAL_INTEGRATION_TICKETS.md](COMPUTE_TERMINAL_INTEGRATION_TICKETS.md) | 12 | "Open SSH/VNC/RDP" from EC2/K8s instance UI (deep-link) |
| 0 — Quick wins | MCM | [MESSENGER_COMPOSE_MENU_TICKETS.md](MESSENGER_COMPOSE_MENU_TICKETS.md) | 9 | Compact ~18 compose actions into a "+" overflow menu |
| 1 — Demo coverage | DMO | [DEMO_COVERAGE_TICKETS.md](DEMO_COVERAGE_TICKETS.md) | 8 | Record already-built features (broadcast, video chat, gallery, lottery, feed search, PDFs, fraud) |
| 2 — Messaging AI | MVA | [MESSENGER_VOICE_AI_TICKETS.md](MESSENGER_VOICE_AI_TICKETS.md) | 12 | ElevenLabs provider + TTS + STT + translation |
| 3 — Signing UX | SUX | [SIGNING_UX_TICKETS.md](SIGNING_UX_TICKETS.md) | 18 | Shareable signing link, awaiting-signature inbox, creator widget, deep links |
| 4 — Helpdesk/ticketing | HMH | [HELPDESK_HANDOFF_TICKETS.md](HELPDESK_HANDOFF_TICKETS.md) | 14 | Auto-route helpdesk chat to a live agent + client UX |
| 4 — Helpdesk/ticketing | TKB | [TICKET_BOARDS_TICKETS.md](TICKET_BOARDS_TICKETS.md) | 18 | Rename spaces→boards + Trello-like Kanban |
| 5 — Agent platform | ACS | [AGENT_CLAUDE_CODE_SESSION_TICKETS.md](AGENT_CLAUDE_CODE_SESSION_TICKETS.md) | 12 | Registered Claude Code sessions via an interactive terminal |
| 5 — Agent platform | AQA | [AGENT_SSH_QA_TICKETS.md](AGENT_SSH_QA_TICKETS.md) | 12 | Agents use SSH/VNC to run QA on hosts |
| 6 — Trust & safety | KYD | [KYC_DISPUTE_TICKETS.md](KYC_DISPUTE_TICKETS.md) | 12 | KYC disputes / appeal / retry-resubmit |
| 6 — Trust & safety | HNY | [SECURITY_HONEYPOT_TICKETS.md](SECURITY_HONEYPOT_TICKETS.md) | 18 | Honeytokens, decoy endpoints, IDS, unified security dashboard |
| 6 — Trust & safety | LEX | [LEGAL_EXPORT_TICKETS.md](LEGAL_EXPORT_TICKETS.md) | 14 | DSAR full export, legal hold, law-enforcement/subpoena package |
| 7 — Discovery | NRS | [NEWSFEED_RECSYS_TICKETS.md](NEWSFEED_RECSYS_TICKETS.md) | 13 | "For You" newsfeed ranking + candidate generation/fan-out |
| Parallel research | OFB | [OFBIZ_COMMERCE_TICKETS.md](OFBIZ_COMMERCE_TICKETS.md) | 22 | OFBiz cherry-pick: inventory, returns/RMA, double-entry GL, pricing rules |

**Total: 218 tickets.**

## Notable findings surfaced during ticketing
- **Dark theme:** root cause is concrete — Tailwind v4 (no `tailwind.config.js`) never declares `@custom-variant dark` in `globals.css`, so every `dark:` utility falls back to OS `prefers-color-scheme` and ignores the `.dark` class the ThemeProvider correctly toggles. (THM-002 is the one-line-ish fix; rest is FOUC + sync hardening.)
- **Delegate hide:** attribution leak is confined to the delegate-chat API path (`_message_to_dict`), not the main message serializer — so the fix is contained.
- **Watermark:** faint-forensic settings (`watermark_opacity`/`font_size`/`crf`/`preset`) already exist in `settings.py` but are **orphaned** (no consumers) — WMK tickets wire them up.
- **Compute↔terminal:** `quick_connect` already emits a `/remote/ssh?...` deep-link **but that route doesn't exist** in `App.tsx` (broken today); VNC targets are hardcoded.
- **Agent terminal:** the raw-SSH input handler already calls `bridge.send_input`; the gap is a PTY-wrapped `claude` bridge + a session WS endpoint that preserves the monitor tap (one-way → two-way).
- **Legal export:** a partial GDPR export/deletion already exists (`gdpr_service.py`, ~12 subsystems, unsigned, silent gaps); no standalone legal-hold model or scoped LE export.
- **Newsfeed recsys:** the core gap is candidate generation — the `FEED#{user_id}` index holds only own/fanned-out posts and there's no global "popular" index; video recsys patterns are reusable.
- **OFBiz:** orders never progress past `pending_payment`; stock is a scalar `stock_count` with no reservations; ledger is single-entry (good derivation source for double-entry GL); refunds + promo codes exist but are flat-only.
