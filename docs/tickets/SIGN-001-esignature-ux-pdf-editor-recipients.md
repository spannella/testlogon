# SIGN-001: E-Signature UX — PDF Viewer, Drag-Drop Fields, Recipient Management, Drawing Canvas

**Ticket**: SIGN-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: High
**Estimated effort**: 12-18 days (sub-tickets a-f below)
**Dependencies**: signature packet backend (`app/routers/signature_packets.py`, `app/services/signature_packet_store.py`, `app/services/signature_packet_renderer.py`), files/S3, messaging/notifications (for invites)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The document-signing feature ("DocuSign-like", `SIGNATURE_PDF_ENABLED`) is a
**proof-of-concept skeleton**: the **backend is ~60% complete** (packet lifecycle,
field types, per-signer status, fill, events, completed-PDF render all exist),
but the **frontend UX is ~20% complete** and the two non-negotiable e-signature
actions — *add a recipient* and *place fields on a visible PDF* — are **not
reachable in the UI**. Users report it "very hard to use." Concretely:

1. **No PDF viewer.** The "PDF editor canvas" is a **dashed placeholder div**
   (`frontend/src/pages/files/SignaturePacketComposer.tsx:609-629`). Fields are
   placed blind — the user never sees the document, its pages, or where a field
   lands.
2. **No drag-and-drop field placement.** Fields are placed by clicking the empty
   placeholder; position is a computed 0-1 ratio with no visible box, snapping,
   resize, or preview (`SignaturePacketComposer.tsx:213-256`). `page` is
   hardcoded to `1` (no multi-page).
3. **No recipient/signer management — the hard blocker.** There is an "Assigned
   signer" dropdown (`:490-500`) populated from `packet.signers`, but **no UI to
   add a signer and no backend endpoint to create one**. `signature_packets.py`
   exposes create-packet, fields add/delete, send, get, and fill — but **no
   `POST /signers` or `/invite`**. The E2E tests prove the gap: they inject
   signers **directly into DynamoDB** (`frontend/e2e/signing.spec.ts` ~`injectSigner`).
   So a normal user literally cannot send a document for signature.
4. **Drawing a signature requires typing JSON** like `[[0.1,0.2],[0.2,0.3]]`
   (`:565`) — there is no drawing canvas.
5. **No guided signing** (signer sees a flat field list, no "next field", no
   document preview), **file path typed by hand** (no file picker), **no
   email/link invite**, **no template-to-packet workflow**, **no signing
   order/routing**, **minimal audit-log UI**.

### 1.2 How It Works (proposed)

Bring the frontend up to the backend's capability and add the missing recipient
API, in priority order (each independently shippable):

- **P1a — Recipient/signer management (API + UI):** add `POST
  /v1/signature-packets/{id}/signers` (and a remove endpoint) writing to
  `signature_packet_signers`; a frontend "Add signer" form (name/email/role) with
  a signer list + remove. Block "Send" until ≥1 signer. This is the minimum to
  make the feature functional.
- **P1b — Visual PDF viewer + drag-drop fields:** render the source PDF with
  `pdf.js`/`react-pdf`; overlay draggable/resizable field boxes (signature/
  initials/date/text) mapped to normalized coords; page navigation + zoom. Add a
  backend PDF-stream endpoint if needed (`GET /{id}/source-pdf`).
- **P1c — Signature drawing canvas:** replace the JSON input with an HTML5
  `<canvas>` capturing strokes → normalized points, with Clear/Apply + preview.
- **P2a — Guided signing + document preview:** signer flow highlights the current
  required field on the rendered PDF, "next field" navigation, hides non-editable
  fields.
- **P2b — Email/link invite:** on send, generate a per-signer signing link
  (`/sign/{packet_id}?signer=...`) and/or email via the notifications service;
  surface the link in the send confirmation.
- **P3 — Polish:** multi-page already covered by P1b; templates (apply a saved
  field layout to a new PDF), signing order/routing (sequential release), and an
  audit-log UI (per-signer timestamp/IP/capture-mode, already logged in events).

### 1.3 Design Principles

- **Visual-first:** every field placement and signature capture happens on the
  rendered document — no coordinates or JSON typed by a human.
- **Reuse the backend:** the packet/field/fill/event model and PDF renderer
  already exist; this ticket is mostly frontend + one missing recipient API.
- **Normalized coordinates:** keep the 0-1 coord model the backend already uses so
  rendering stays resolution-independent.

---

## 2. Implementation

### 2.1 Backend
- `app/routers/signature_packets.py`: add `POST /{packet_id}/signers` + `DELETE
  /{packet_id}/signers/{signer_id}`; (P2b) enhance `send` to mint per-signer
  invite links; optional `GET /{packet_id}/source-pdf` stream for the viewer.
- `app/services/signature_packet_store.py`: `add_packet_signer()` /
  `remove_packet_signer()`.
- (P3) signing-order release logic; template→packet apply.

### 2.2 Frontend (`frontend/src/pages/files/SignaturePacketComposer.tsx` + signing page)
- Add-signer form + signer list.
- Replace the placeholder canvas with a real PDF viewer (`react-pdf`/`pdf.js`)
  and draggable/resizable field overlays with page navigation.
- Drawing-canvas component for drawn signatures/initials.
- Guided signer experience with on-PDF field highlighting.
- File picker for the source document (reuse the existing FilePickerDialog).
- (P2b) public/standalone signing page at `/sign/:packetId`.

### 2.3 Settings
- `SIGNATURE_INVITE_LINKS_ENABLED`, `SIGNATURE_SIGNING_ORDER_ENABLED` (flag the
  bigger pieces).

---

## 3. Testing

- **E2E** (replace the DDB-injection workaround with real flows): create packet →
  **add signer via UI/API** → place fields on the rendered PDF → send → signer
  opens link → draws signature on canvas → guided through fields → completes →
  download final PDF. Multi-page placement; signing order (signer 2 blocked until
  signer 1 done); template apply.
- **pytest:** the new signers endpoints (add/remove, validation, dup guard),
  invite-link minting, signing-order release.

## 4. Sub-ticket Split

SIGN-001a Recipient management (P1, blocking) · SIGN-001b PDF viewer + drag-drop
fields (P1) · SIGN-001c Drawing canvas (P1) · SIGN-001d Guided signing (P2) ·
SIGN-001e Email/link invite (P2) · SIGN-001f Templates + signing order + audit UI
(P3).

---

## 5. Current-State Summary

| Aspect | Status |
|--------|--------|
| Packet lifecycle / field types / per-signer status / fill / events / final PDF | ✅ backend |
| Add a recipient (UI + API) | ❌ **missing — hard blocker** (tests inject to DDB) |
| Visual PDF viewer | ❌ placeholder div only |
| Drag-drop field placement | ❌ click-on-empty-div, hidden coords, page 1 only |
| Draw a signature | ❌ must type JSON |
| Guided signing / doc preview for signer | ❌ flat field list |
| Email/link invite, templates, signing order, audit UI | ❌ missing |
| Net | Backend ~60% done; frontend ~20% — not usable end-to-end by a real user yet |
