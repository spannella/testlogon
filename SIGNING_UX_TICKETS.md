# Signing / DocuSign UX — Implementation Tickets

The signature-packet engine is complete (create/send/fill/mark-done/final-pdf in `app/routers/signature_packets.py`, store in `app/services/signature_packet_store.py`, renderer in `app/services/signature_packet_renderer.py`), but the experience is unintuitive: there is no public/shareable signing link, no embeddable widget, no first-class "awaiting my signature" inbox, no standalone request creator, and no "send for signature" deep links from File Manager / KYC / Messaging. These tickets close that UX gap, reusing the cart-recovery HMAC tokenized-public-link pattern (`app/services/cart_reminders.py:150-245`, public endpoint `app/routers/shoppingcart.py:268`) as the security model for the public signing link.

## Milestone 1 — Link core (tokenized public signing link + public/embeddable widget)

### SUX-001: Settings + feature flag for public signing links
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `signature_packet_public_link_secret` and `signature_packet_public_link_ttl_days` (default 14) to the `Settings` dataclass next to the existing signing config (`app/core/settings.py:879-908`), mirroring `cart_recovery_link_secret` / `cart_recovery_link_ttl_days` (`app/core/settings.py:822-826`); secret falls back to `ui_access_token_secret` when unset (SECOPS-007 dev/prod parity).
- Add `signature_public_link_enabled` flag (default true) and document env vars in `.env.local.example`.
- Reuse `S.public_base_url` (`app/core/settings.py:349`) for building absolute URLs.

**Acceptance Criteria**
- New settings load from env with sane defaults; backend starts with no env changes.
- Flag gates the public-link endpoints (503/404 when disabled).
- No regression to existing `signature_packet_*` settings.

**Dependencies**
- None.

---

### SUX-002: HMAC tokenized public signing-link minter + verifier
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `app/services/signature_public_link.py` with `mint_signing_token(packet_id, signer_id, *, ttl_days=None)` and `verify_signing_token(token)`, copying the token scheme from `cart_reminders._sign_recovery_token` / `_verify_recovery_token` (`app/services/cart_reminders.py:150-185`): `b64url(payload).b64url(sig)`, HMAC-SHA256, payload `{packet_id, signer_id, jti, scope:"sign", iat, exp}`.
- `generate_signing_link(packet_id, signer_id)` returns `f"{S.public_base_url}/ui/sign/{token}"` (mirrors `generate_recovery_link`, `app/services/cart_reminders.py:214-224`).
- Token binds to a specific `packet_id` + `signer_id` (signer binding); verifier rejects bad signature, expiry, and wrong `scope`.

**Acceptance Criteria**
- Unit tests: round-trip mint→verify; tampered payload/sig rejected; expired token rejected; wrong-scope token rejected.
- PEM/secret never embedded in token; only opaque ids.
- Dev and prod use identical code path (no `dev_mode` branch).

**Dependencies**
- SUX-001.

---

### SUX-003: One-time-use + revocation token consumption store
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add consumption/revocation markers keyed by `jti`, mirroring `_is_token_consumed` / `_mark_token_consumed` conditional put (`app/services/cart_reminders.py:188-211`). Store rows in the existing `signature_packet_events` or a dedicated `SIGNLINK#CONSUMED#{jti}` partition; use `ConditionExpression="attribute_not_exists(...)"` for atomic single-use.
- Provide `consume_token(jti)` and `revoke_token(jti)`; verification path treats a completed signer as implicitly terminal (link no longer usable once `mark-done` recorded).

**Acceptance Criteria**
- Second use of the same link → rejected (one-time-use, like recovery `app/routers/shoppingcart.py:268`).
- Concurrent double-use guarded by the conditional put.
- Revoked link rejected even before expiry.

**Dependencies**
- SUX-002.

---

### SUX-004: Public (light-auth) signing endpoints
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add a public router (no `require_ui_session`) `app/routers/signature_public.py`, register in `app/main.py`. Endpoints all take `{token}` and resolve `packet_id`+`signer_id` via `verify_signing_token` (SUX-002): `GET /ui/sign/{token}` (packet detail scoped to that signer, reusing the shaping in `get_signature_packet_detail` `app/routers/signature_packets.py:502-582`), `POST /ui/sign/{token}/fields/{field_id}/fill`, `POST /ui/sign/{token}/acknowledge-legal-notice`, `POST /ui/sign/{token}/mark-done`, `GET /ui/sign/{token}/source-pdf`.
- The token's `signer_id` substitutes for `user_sub` everywhere the authenticated path uses it (signer is identified by `signer_id == user_sub` today — `app/routers/signature_packets.py:803-815`, store `get_packet_signer` `app/services/signature_packet_store.py:300-304`).
- `mark-done` consumes the token (SUX-003) on success.

**Acceptance Criteria**
- A signer can open, fill required fields, ack legal notice, and complete a packet using only the link — no login.
- Owner-only operations (edit fields, send) are NOT exposed on the public router.
- Field-fill enforces `is_assigned_to_viewer` for the token's signer; foreign-field fill → 403.
- Legal-notice gate identical to authenticated path (`app/routers/signature_packets.py:806`).

**Dependencies**
- SUX-002, SUX-003.

---

### SUX-005: "Create signing link" owner endpoint + audit
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `POST /v1/signature-packets/{packet_id}/signers/{signer_id}/link` (owner-only, `require_ui_session`) that calls `generate_signing_link` and returns `{url, expires_at}`. Validate owner via `_validate_packet_owner_and_draft` relaxed to allow `sent`/`partially_signed` (links only make sense after send).
- Emit `append_packet_event(event_type="signing_link_created", ...)` (`app/routers/signature_packets.py:280`) and `POST .../link/revoke` emitting `signing_link_revoked`.

**Acceptance Criteria**
- Only the packet owner can mint/revoke a signer's link; non-owner → 403.
- Link creation/revocation recorded in packet events (audit trail surfaces in `GET /{packet_id}/events`, `app/routers/signature_packets.py:899`).
- Revoke marks the prior `jti` revoked (SUX-003).

**Dependencies**
- SUX-003, SUX-005 depends on SUX-002.

---

### SUX-006: Public signing page + embeddable widget mode
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add public route `/sign/:token` in `frontend/src/App.tsx` (no auth, lazy-loaded, alongside the existing public `/event/:calendarId/:eventId` pattern) → new `frontend/src/pages/signing/PublicSigningPage.tsx` that loads the signer fill workflow.
- Refactor the signer-fill UI out of `SignaturePacketComposer` (`frontend/src/pages/files/SignaturePacketComposer.tsx:377-560`, the `signer-fill-panel` block) into a reusable `<SigningWidget>` driven by either an authenticated packetId or a public token.
- Add `?embed=1` mode: chromeless layout (no AppShell/header) so the widget can render inside an `<iframe>`; expose a stable container size and `postMessage` completion event for the host page.

**Acceptance Criteria**
- `/sign/:token` renders the PDF + assigned fields and lets a non-logged-in signer complete the packet.
- `?embed=1` hides app chrome and fits an iframe; on completion it posts a `signing:completed` message.
- Invalid/expired/used token shows a friendly terminal state, not a stack trace.
- Reuses existing field-fill components (no duplicate signature-capture logic).

**Dependencies**
- SUX-004.

---

## Milestone 2 — Awaiting-my-signature inbox

### SUX-007: "Awaiting my signature" list endpoint
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `GET /v1/signature-packets/awaiting` (`require_ui_session`) backed by the existing `list_packets_for_signer(signer_id, SignatureSignerStatus.PENDING)` GSI query (`app/services/signature_packet_store.py:88-102`, `SIGNER_STATUS_INDEX`). For each signer row, hydrate packet status via `get_signature_packet_progress_for_user` (`app/services/signature_packet_store.py:553-599`) so the `awaiting_your_signature` chip (`...:582`) is reused, not re-derived.
- Add a companion `GET /v1/signature-packets/sent` reusing `list_packets_by_sender` (`...:76-85`) and `GET /v1/signature-packets/completed-for-me` for the signer's done items.

**Acceptance Criteria**
- Returns only packets in `sent`/`partially_signed` where the caller is a non-completed signer.
- Pagination/limit honored; uses the GSI (no table scan).
- Each item carries `packet_id`, owner, source name, status chip/text, and `created_at`.

**Dependencies**
- None (engine exists).

---

### SUX-008: "Awaiting my signature" inbox page
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `frontend/src/pages/signing/SigningInboxPage.tsx` with three tabs: "Awaiting me", "Sent by me", "Completed", backed by SUX-007. Add route `/signing/inbox` in `frontend/src/App.tsx` and a sidebar nav entry with an unread-style count badge.
- Add `frontend/src/api/endpoints/signaturePackets.ts` wrappers `listAwaitingSignature()` / `listSentPackets()` / `listCompletedForMe()` (file currently has only per-packet calls, `frontend/src/api/endpoints/signaturePackets.ts:82-153`).
- Each "Awaiting me" row has an "Open to sign" button → opens the packet in the in-app `<SigningWidget>` (SUX-006) at `/signing/inbox/:packetId` (authenticated, no public token needed).

**Acceptance Criteria**
- Inbox lists awaiting/sent/completed correctly with status chips matching `get_signature_packet_progress_for_user`.
- "Open to sign" loads the widget and a successful `mark-done` removes the item from "Awaiting me".
- Badge count reflects awaiting items and updates after signing (React Query invalidation).

**Dependencies**
- SUX-006, SUX-007.

---

## Milestone 3 — Standalone signature-request creator

### SUX-009: First-class signature-request creator entry point
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Promote the composer to a standalone creator: add `frontend/src/pages/signing/CreateSignatureRequestPage.tsx` (route `/signing/new`) that wraps `SignaturePacketComposer` (`frontend/src/pages/files/SignaturePacketComposer.tsx:136`) in a guided flow: pick source PDF → add signers → place fields → send.
- Replace today's bare `SigningPage` (`frontend/src/pages/signing/SigningPage.tsx:1-11`, currently just stacks the composer + template manager) with a landing hub: "New request", "Awaiting me", "Sent", "Templates".
- Add a "Create signing link per signer" affordance in the creator's post-send step (calls SUX-005) with copy-to-clipboard.

**Acceptance Criteria**
- `/signing/new` walks a user from source PDF to a sent packet without leaving the page.
- Post-send, owner can copy a per-signer public link.
- `/signing` hub links to all four areas; existing composer behavior unchanged when embedded.

**Dependencies**
- SUX-005, SUX-008.

---

### SUX-010: Source-PDF picker reuse in the creator
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Wire the existing `FilePickerDialog` (used by ComposeBar/CreatePost per project memory) into the creator's source-PDF step, filtering to `application/pdf` (the create endpoint already rejects non-PDF, `app/routers/signature_packets.py:260-270`).
- Validate selection client-side before calling `createSignaturePacket` (`frontend/src/api/endpoints/signaturePackets.ts:82-83`).

**Acceptance Criteria**
- Only PDF files are selectable/sendable; clear error for non-PDF.
- Selecting a file pre-fills `source_path` and advances the flow.

**Dependencies**
- SUX-009.

---

## Milestone 4 — Deep links from File Manager, KYC, and Messaging

### SUX-011: "Send for signature" action from File Manager
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add a "Send for signature" row/context action on PDF files in `frontend/src/pages/files/` that deep-links to `/signing/new?source_path=<path>` (or opens the creator inline) pre-seeding the source PDF, then creating the packet via `createSignaturePacket` with `origin_channel="share"`.
- Disable the action for non-PDF files (mirror backend guard `app/routers/signature_packets.py:260-270`).

**Acceptance Criteria**
- Action appears only for PDF files and lands in the creator with the file pre-selected.
- Resulting packet records `origin_channel="share"` and links back to the source file.

**Dependencies**
- SUX-009.

---

### SUX-012: "Send for signature" / "Open to sign" from KYC case
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- KYC already creates/links packets with `origin_channel="kyc_document_template"` and `origin_ref=f"{case_id}:{slug}"` (`app/routers/kyc_cases.py:308-348`, creator `create_or_link_signature_packet` `:1707-1755`). Surface these in the KYC case UI: a "Send for signature" button (admin) and, for the subject, an "Open to sign" deep link into the inbox/widget (SUX-008) filtered by that case's `origin_ref`.
- For external/subject signers, generate a public signing link (SUX-005) instead of requiring login.

**Acceptance Criteria**
- KYC case view lists its signature packets with live status (reusing `get_signature_packet_progress_for_user`).
- Admin can send/resend; subject gets an "Open to sign" link.
- `origin_ref` filtering shows only the case's packets (matches `app/routers/kyc_cases.py:343-348`).

**Dependencies**
- SUX-006, SUX-008.

---

### SUX-013: "Send for signature" / "Open to sign" from Messaging
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Messaging already carries `signature_packet_id` on file payloads and renders signer progress via `get_signature_packet_progress_for_user` (`app/routers/messaging.py:3891-3894`, `:10613`, `:2272`). Add a "Send for signature" action on a shared PDF message (owner) that creates a packet with `origin_channel="message"` and `origin_ref=<conversation/message id>`, then attaches `signature_packet_id` to the message.
- Render an "Open to sign" CTA in the message bubble for the assigned signer that deep-links to the in-app widget (SUX-008) or, for non-participants, a public link (SUX-005).

**Acceptance Criteria**
- Sending a PDF in a DM/group offers "Send for signature"; the message then shows live status chips for both parties.
- The assigned recipient sees "Open to sign" and can complete from messaging.
- Packet records `origin_channel="message"` + `origin_ref`.

**Dependencies**
- SUX-006, SUX-008.

---

### SUX-014: Allow new origin channels in the API contract
**Type:** Chore  
**Priority:** P1  
**Estimate:** 0.5 day

**Description**
- Broaden `CreateSignaturePacketIn.origin_channel` from `Literal["share","message"]` (`app/routers/signature_packets.py:93`, `:102`) to also accept `"file_manager"` and `"kyc"` (KYC already passes `"kyc_document_template"` directly through the store, `app/routers/kyc_cases.py:308`, so the store tolerates free-form values — align the API model). Update the frontend `SignatureOriginChannel` union (`frontend/src/api/endpoints/signaturePackets.ts:4`).

**Acceptance Criteria**
- New origin values accepted without breaking existing `share`/`message` callers.
- Frontend types updated; no `any` casts introduced.

**Dependencies**
- None.

---

## Milestone 5 — Security, audit, and tests

### SUX-015: Security hardening — token scope, expiry, signer binding, rate limit
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Enforce on the public router (SUX-004): scope check (`scope=="sign"`), `packet_id`+`signer_id` binding (token cannot be replayed against a different packet/signer), expiry (SUX-001 TTL), and one-time-use on completion (SUX-003).
- Add rate limiting on public signing endpoints keyed by `jti`/token (reuse the DDB-backed `_bucket_limit` pattern referenced in the KYC partner-API limiter) to blunt brute-force/enumeration.
- Ensure the public router never exposes owner capabilities or other signers' fields; redact token in logs.

**Acceptance Criteria**
- Cross-packet / cross-signer token replay → 403/404.
- Expired or revoked token → terminal error, no packet data leaked.
- Public endpoints rate-limited with `Retry-After`.
- Security review confirms no privilege escalation from the public surface.

**Dependencies**
- SUX-004, SUX-005.

---

### SUX-016: Audit events for link + public-signing lifecycle
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Emit `append_packet_event` (`app/routers/signature_packets.py:257-285`) for: `signing_link_created`, `signing_link_revoked`, `signing_link_opened`, `public_field_filled`, `public_legal_notice_accepted`, `public_signer_completed` — recording the (light-auth) signer_id and source IP (mirror `_current_ip`, `app/routers/signature_packets.py:87`).
- Surface these in `GET /{packet_id}/events` so owners see the full chain of custody.

**Acceptance Criteria**
- Every public-link action appends a packet event with actor + IP.
- Owner's events feed shows link creation through completion.
- No PII beyond signer_id/IP recorded.

**Dependencies**
- SUX-004, SUX-005.

---

### SUX-017: Backend regression tests (public link + inbox + deep-link origins)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `tests/test_signing_public_link.py`: mint→verify→sign happy path; tampered/expired/wrong-scope/cross-signer rejection; one-time-use double-use rejection; revocation. Follow the offline/hermetic style used across the repo (moto tables bound to frozen `T.*` via `object.__setattr__`, frozen `S` flags toggled), e.g. `tests/test_gap_0286_0287_kyc_partner_api.py`.
- Add `tests/test_signing_inbox.py`: `awaiting`/`sent`/`completed-for-me` endpoints over seeded `SIGNER_STATUS_INDEX` rows.
- Add tests asserting `origin_channel` values for file/KYC/messaging-created packets.

**Acceptance Criteria**
- `.venv/bin/pytest` passes offline (no real AWS/network).
- Coverage for all token-rejection branches and inbox filters.

**Dependencies**
- SUX-007, SUX-015, SUX-016.

---

### SUX-018: E2E tests for the signing UX
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add `frontend/e2e/signing-ux.spec.ts` covering: owner creates a request in the creator (SUX-009), mints a per-signer public link (SUX-005), an isolated browser context (no auth) opens `/sign/:token` and completes signing (SUX-006), owner sees `completed` + final PDF; inbox "Awaiting me" → "Open to sign" → completes (SUX-008); deep links from File Manager / KYC / Messaging land in the creator/widget with source pre-seeded (SUX-011/012/013).
- Use the existing E2E session-injection helpers; for the public path use a fresh `browser.newPage()` context with no injected cookies.

**Acceptance Criteria**
- Public link sign-without-login flow passes end-to-end.
- Inbox open-to-sign and the three deep-link entry points pass.
- Used/expired link shows the terminal state in the browser.

**Dependencies**
- SUX-008, SUX-011, SUX-012, SUX-013.

---
