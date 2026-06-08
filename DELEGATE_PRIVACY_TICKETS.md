# Delegate Attribution Privacy — Implementation Tickets

Today, disabling the inline `via @delegate` text tag (`delegate_tag_enabled`) only strips the appended text; the delegate identity still leaks to recipients through the persisted/returned `sent_by_delegate` and `delegate_display_name` fields (`app/services/delegate_chat.py:237-239`, `:298-300`, `_message_to_dict` `:367-383`) and the frontend badge always renders (`frontend/src/pages/messages/DelegateConversationView.tsx:204-213`). These tickets add a distinct per-creator "fully hide delegate from recipients" setting that strips attribution for non-owner viewers while preserving it for the creator/delegate and the creator-only audit log.

## Milestone 1 — Backend setting + model

### DLP-001: Add `hide_delegate_from_recipients` creator setting
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add a new boolean per-creator setting `hide_delegate_from_recipients` (default `False`) distinct from `delegate_tag_enabled`. The tag flag controls inline text; this flag controls API/field-level attribution visibility to recipients.
- Wire it into the settings defaults and writer: `app/services/delegates.py` `get_creator_settings` (`:281-289`) and `update_creator_settings` (`:292-317`, add the kwarg and persist it at `:307-315`).
- Surface it in the per-delegate snapshot copied from settings if needed (`app/services/delegates.py:90-92` copies `delegate_tag_enabled`/`delegate_tag_format` onto the delegate item) so `send_message_as_creator` can read it without an extra round-trip.

**Acceptance Criteria**
- `get_creator_settings` returns `hide_delegate_from_recipients: False` for a creator with no SETTINGS row.
- `update_creator_settings(..., hide_delegate_from_recipients=True)` persists the value and a subsequent `get_creator_settings` returns `True`.
- Existing settings rows without the field read back as `False` (backward compatible).
- No change to `delegate_tag_enabled` / `delegate_tag_format` semantics.

**Dependencies**
- None.

---

### DLP-002: Add the setting to Pydantic request/response models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 0.5 day

**Description**
- Add `hide_delegate_from_recipients: bool = False` to `DelegateSettingsIn` (`app/models.py:4510-4515`) and `DelegateSettingsOut` (`app/models.py:4541-4546`).
- Thread the field through the settings router read/write handlers in `app/routers/delegates.py` (`:89-90` read path returns the settings out; `:102-103` write path passes the body fields into `update_creator_settings`).

**Acceptance Criteria**
- `GET` settings endpoint returns `hide_delegate_from_recipients` in the JSON body.
- `PUT`/`POST` settings endpoint accepts and persists `hide_delegate_from_recipients`.
- OpenAPI schema (`GET /openapi.json`) shows the new field on both models.

**Dependencies**
- DLP-001.

---

## Milestone 2 — Recipient-side attribution stripping

### DLP-003: Strip delegate attribution from `_message_to_dict` for non-owner viewers
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1.5 days

**Description**
- `_message_to_dict` (`app/services/delegate_chat.py:367-383`) unconditionally returns `sent_by_delegate`, `delegate_display_name`, and `delegate_tag`. Add a `viewer_id` (and `creator_id`) parameter so the serializer knows whether the viewer is the owner/creator, the delegate, or a plain recipient/other participant.
- Define "attribution-entitled viewer" = the creator (`viewer_id == creator_id`) OR the delegate who sent it (`viewer_id == m.get("sent_by_delegate")`). All other viewers are recipients.
- When `hide_delegate_from_recipients` is `True` AND the viewer is NOT attribution-entitled, blank out `sent_by_delegate`, `delegate_display_name`, and `delegate_tag` (return `None`) before responding. The message still appears to come from the creator (`sender_id == creator_id`), which is the intended public identity.
- Apply the same stripping in `send_message_as_creator`'s return dict (`app/services/delegate_chat.py:291-301`) when the caller is constructing a recipient-facing payload — note the sender is always the delegate here, so the send-response path keeps attribution (delegate is entitled); the stripping primarily guards read paths.
- Pass the viewer through `get_creator_conversation_messages` (`:143-184`, the per-message loop at `:177-181`) and any other call site of `_message_to_dict`.

**Acceptance Criteria**
- With `hide_delegate_from_recipients=True`, a recipient/other-participant reading the conversation gets `sent_by_delegate == null`, `delegate_display_name == null`, `delegate_tag == null`.
- With `hide_delegate_from_recipients=True`, the creator and the sending delegate still get the true `sent_by_delegate` / `delegate_display_name`.
- With `hide_delegate_from_recipients=False` (default), behavior is unchanged for all viewers.
- The `sender_id`/`text` (subject to existing encryption redaction at `:386-392`) are unaffected.

**Dependencies**
- DLP-001.

---

### DLP-004: Enforce stripping at the router boundary (`DelegatedMessageOut`)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 0.5 day

**Description**
- The delegate read/list routes (`app/routers/messaging.py:14673-14712`) serialize through `DelegatedMessageOut` (`app/models.py:4571-4583`) which carries `sent_by_delegate`/`delegate_display_name`/`delegate_tag`. Ensure the viewer-aware stripping from DLP-003 happens before model construction so a stripped dict yields `null` fields (not the raw persisted values).
- The list route (`list_delegated_messages`, `:14676-14692`) and the send route (`send_delegated_message`, `:14698-14712`) must pass the authenticated `user_id` (from `Depends(get_messaging_user_id)`) and the path `creator_id` into the service so the entitlement check has the real viewer.
- Confirm the main messaging serializer (`_message_out_from_item`, `app/routers/messaging.py:3885`) does NOT surface delegate fields on `MessageOut` (verified: it does not) so no parallel leak exists there; add a regression assertion in DLP-008 to lock that in.

**Acceptance Criteria**
- A recipient reading via the delegate list endpoint with the flag on receives `null` attribution fields in the HTTP response body.
- The creator reading the same conversation receives populated attribution fields.
- No delegate attribution fields appear on `MessageOut` from the standard `GET /.../messages` path.

**Dependencies**
- DLP-003.

---

## Milestone 3 — Audit integrity

### DLP-005: Guarantee the creator-only audit log always retains the true delegate
**Type:** Chore  
**Priority:** P0  
**Estimate:** 0.5 day

**Description**
- The audit write in `send_message_as_creator` (`app/services/delegate_chat.py:278-289`) records the real `delegate_id` via `_write_audit`; this MUST be unaffected by `hide_delegate_from_recipients` (the flag governs recipient visibility, never internal audit integrity).
- The audit reader `get_delegated_messages_audit` (`:304-348`) is already creator-only (403 for non-creators at `:315-316`); verify it never applies the recipient-stripping logic and always returns the true `delegate_id` / `actor_id`.
- Add a code comment at the audit write and read sites documenting that attribution-hiding is a recipient-facing presentation concern only.

**Acceptance Criteria**
- With `hide_delegate_from_recipients=True`, `_write_audit` still persists the true delegate, and `get_delegated_messages_audit` returns the true `delegate_id` to the creator.
- A non-creator calling the audit endpoint still gets 403.
- No branch in the audit path reads `hide_delegate_from_recipients`.

**Dependencies**
- DLP-003.

---

## Milestone 4 — Frontend

### DLP-006: Add the "Hide delegate from recipients" settings toggle + copy
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add a `hide_delegate_from_recipients` switch to the delegation settings card (`frontend/src/pages/delegates/DelegatesPage.tsx:460-503`, next to the existing "Delegate tag" switch at `:479-488`) with helper copy, e.g. "Fully hide that a delegate sent a message — recipients will see only your identity. You and your delegates still see attribution."
- Include the field in the `onSave` payload (`:489-500`).
- Add `hide_delegate_from_recipients?: boolean` to the relevant TS types in `frontend/src/api/types.ts` (settings in/out, near `:5134-5135` and `:5165-5166`).

**Acceptance Criteria**
- Toggling the switch and saving issues the settings request with `hide_delegate_from_recipients`.
- The toggle reflects the persisted value on reload.
- Copy clearly distinguishes this from the inline text tag.

**Dependencies**
- DLP-002.

---

### DLP-007: Make the delegate badge respect the hidden flag for recipient views
**Type:** Feature  
**Priority:** P1  
**Estimate:** 0.5 day

**Description**
- `DelegateConversationView.tsx` renders the badge whenever `message.sent_by_delegate` is truthy (`:204-213`), with no setting check. With backend stripping (DLP-003/004) the field is already `null` for recipients, so the badge naturally disappears — but this view is the creator/delegate-facing console, so the badge SHOULD still show here.
- Verify the badge logic correctly shows "Sent by you" / `via {name}` for the entitled viewer and renders nothing when the field is `null`, and that the inline `delegate_tag` span (`:211-213`) also disappears when `delegate_tag` is `null`.
- No new setting fetch is required in this component; correctness flows from the backend stripping. Add a guard so a `null`/empty `delegate_display_name` never renders an empty `via ` badge.

**Acceptance Criteria**
- Creator/delegate console still shows the attribution badge.
- When attribution fields are `null`, no badge and no inline tag span render.
- No empty/`via undefined` badge can appear.

**Dependencies**
- DLP-003.

---

## Milestone 5 — Tests

### DLP-008: Offline hermetic regression test for attribution privacy
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1.5 days

**Description**
- Add `tests/test_delegate_attribution_privacy.py` following repo test conventions (offline, hermetic; see CLAUDE.md and `tests/test_gap_0158_delegate_ban_via_api_key.py` for the moto + `object.__setattr__` table-injection pattern, or patch `tbl_msgs`/`tbl_parts`/settings on the `delegate_chat`/`delegates` module namespace directly).
- Cover, with `hide_delegate_from_recipients=True`: (a) a recipient/other-participant read returns `sent_by_delegate=None`, `delegate_display_name=None`, `delegate_tag=None`; (b) the creator read returns the true attribution; (c) the sending delegate read returns the true attribution.
- Cover, with the flag `False` (default): all viewers see attribution (current behavior preserved).
- Cover audit integrity: `_write_audit` persists the true delegate and `get_delegated_messages_audit` returns it to the creator regardless of the flag; non-creator gets 403.
- Cover separation from the text tag: with `delegate_tag_enabled=True` and `hide_delegate_from_recipients=True`, confirm the policy is coherent (the structured attribution fields are stripped for recipients per the chosen design) and document the expected interaction in the test.
- Assert the standard `MessageOut` path never exposes `sent_by_delegate` (lock-in for DLP-004).

**Acceptance Criteria**
- Test runs under `.venv/bin/pytest tests/test_delegate_attribution_privacy.py` with no network/real-AWS dependency and passes.
- All viewer-role × flag-state combinations above are asserted.
- Audit-integrity assertions pass for both flag states.

**Dependencies**
- DLP-003, DLP-004, DLP-005.

---
