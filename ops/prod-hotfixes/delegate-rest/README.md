# delegate-rest — remaining delegate kinds/actions + realtime + tips gate

LIVE PROD HOTFIX (folded here for re-apply; prod `/home/ubuntu/testlogon` diverges from
`android-impl`, so these are additive re-appliable artifacts, not branch merges).

Extends the shipped **delegate full-parity** wrapper (`delegate_fullparity_messaging.patch`)
so a delegate holding `chat_respond` can, attributed to the CREATOR (`sender_id=creator`,
`[via @delegate]`, audited), also use every REMAINING messaging kind/action, PLUS get the
creator's inbound conversation events live.

## What it adds (all under `/messaging/delegate/{creator_id}/…`, reusing the exact normal handler with `user_id=creator`)

Kinds (message-producing → `_delegate_stamp_and_audit`, `[via @delegate]` baked into text/caption where present):
- `POST …/conversations/{cid}/voice-message` (+ `/presign`)
- `POST …/conversations/{cid}/voicemail` (+ `/presign`)
- `POST …/conversations/{cid}/messages/gif`
- `POST …/conversations/{cid}/messages/sticker`
- `POST …/conversations/{cid}/messages/poll`            (arbitrary poll message)
- `POST …/conversations/{cid}/messages/calendar-event`
- `POST …/conversations/{cid}/messages/calendar-share`
- `POST …/conversations/{cid}/messages/find-datetime`
- Arbitrary-poll interaction: `POST …/polls/{poll_id}/vote|write-in|close`
  (resolves the poll's messaging conversation from `arbitrary_polls.get_snapshot(...).ref_id`
   for the participant check; votes/writes/closes AS the creator)
- Find-a-DateTime interaction: `POST …/messages/find-datetime/{poll_id}/availability|close`
  (conversation resolved from the poll META)

Actions (audited via `_write_audit`; call the exact normal handler with `user_id=creator`):
- `POST   …/conversations/{cid}/read`                       (mark-read / receipts)
- `POST   …/conversations/{cid}/typing`                     (typing indicator, not audited — high volume)
- `DELETE …/conversations/{cid}/messages/{mid}`             (delete-for-me; NOT revoke)
- `POST/DELETE …/conversations/{cid}/messages/{mid}/pin`    (pin / unpin)
- `POST/DELETE …/conversations/{cid}/messages/{mid}/hide`   (hide / unhide)

Realtime (B):
- `GET …/delegate/{creator_id}/events/poll` — authorizes the delegate (chat_respond, no
  conversation), then returns the **CREATOR's** per-user event queue projected exactly as
  `/events/poll` (same message:new flatten). So inbound arrives LIVE in delegate context
  (the app's ~600ms poll is interceptor-rewritten to this route while managing a creator).

## TIPS decision (D) — SAFE default chosen

Messaging tips are a `tip_amount_cents` FIELD on the send handlers (no separate route), so the
already-shipped delegate text/image/gallery/video/file wrappers would let a delegate spend the
CREATOR's wallet. Chosen safe option: **a per-delegate `can_tip` permission, default FALSE**,
enforced by `_delegate_guard_tip(creator_id, delegate_id, inp)` inserted into every tip-capable
delegate send (text/image/gallery/video/file/voice). Without `can_tip` a tipped delegate send
returns `403 delegate_tip_forbidden`. `can_tip` was added to `VALID_PERMISSIONS`
(`app/services/delegates.py`) so a creator may opt-in per delegate. Verified: default 403,
opens to 200 once `can_tip` granted.

## Cosmetic C2 (banner shows creator name)

`app/routers/delegates.py::_to_managed_creator` now resolves the CREATOR's profile display name
into `label` (falls back to the stored delegate label, then id). The app maps `label` ->
`DelegationContext.creatorName` -> banner "Managing <Creator>". No client change needed for the
banner. On-device confirmed: banner reads "Managing @Creator Cora".
(Cosmetic C1 — right-align own bubbles in delegate context — is an APP change in
`ThreadViewModel` / `DelegateRoutingInterceptor`, committed on `android-impl`, not a backend hotfix.)

## Files / how to re-apply
- `apply.sh`               — backs up + inserts `newblock_messaging.py.txt` after
  `delegate_edit_message`, inserts the `_delegate_guard_tip` call into the 5 shipped send
  wrappers, and adds `can_tip` to `VALID_PERMISSIONS`; offline `app.main.openapi()` gate.
- `newblock_messaging.py.txt` — the exact appended route block.
- `fix_c2_delegates_router.sh` — the `_to_managed_creator` creator-name enrichment.
- `.bak`s on prod: `messaging.py.bak_delegrest_1783444515`,
  `services/delegates.py.bak_delegrest_1783444515`, `routers/delegates.py.bak_delegc2_1783445051`.

## Verified (dev-bearer contract, prod localhost:8000)
text/gif/poll/poll-vote/find-datetime → `sender_id=creator` + `[via @…]`; mark-read/typing/unpin 200;
tip default → 403, +can_tip → 200; delegate `events/poll` delivers the recipient's inbound while the
delegate's OWN `events/poll` does not (isolation). Residual: `pin`/`unpin` DDB `conversation_pins`
GSI `Type mismatch for Index Key` is a PRE-EXISTING prod bug (the NORMAL pin route 500s identically) —
the delegate pin route is wired correctly and will work once the underlying pin bug is fixed.
Arbitrary-poll vote/write-in/close app-routing: backend-capable, but the app votes via `/ui/polls/*`
(not a `messaging/…` path) so the interceptor can't rewrite it — app-side residual.
