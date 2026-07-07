# Poll write-in orphan (B1) + Pin 500 GSI type-mismatch (B2) — LIVE PROD HOTFIX fold

Two backend bug fixes applied live to prod `/home/ubuntu/testlogon` on 2026-07-07.
Prod diverges from the `android-impl` branch, so these are re-apply artifacts
(apply against prod's real source). Pre-hotfix backups on prod:
`app/services/newsfeed_polls.py.bak_pollpin_1783447718` and
`app/routers/messaging.py.bak_pollpin_1783447718`.

Restart: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`; openapi 200 verified.

---

## B1 — Poll write-in leaves an orphaned zero-vote option when the vote is rejected

**File:** `app/services/newsfeed_polls.py` → `add_write_in`
(shared engine; reached by every surface: standalone `/ui/polls/{id}/write-in`,
messaging, group feed, syndicate feed, and newsfeed `/posts/{id}/write-in`, all
via `arbitrary_polls.write_in` → `newsfeed_polls.add_write_in`).

**Root cause:** `add_write_in` APPENDED the new write-in option to the poll
(a persisted `list_append` `update_item` on the DDB item) *before* calling
`cast_vote`. If `cast_vote` then rejected the vote — e.g. a `multi`
poll where the voter is already at `max_selections` → `HTTPException(400,
"Maximum N selections allowed")`, or a `single` poll with
`allow_vote_change=False` → `409 VOTE_CHANGE_DISABLED` — the appended option was
never rolled back, leaving a phantom zero-vote `is_write_in` option on the poll.

**Fix (make add+vote atomic by pre-validating):** right after the dedupe/
consolidation loop and BEFORE the append block, pre-validate the vote against the
same rules `cast_vote` enforces (multi `max_selections`, single vote-change,
closed already checked at the top). If the vote would be rejected we raise
*before* mutating the option list, so no orphan can be created. The under-cap and
dedupe paths are unchanged.

**Verified (service layer, real prod DDB):**
- multi `max_selections=2`, voter cast 2 votes (at cap): write-in →
  `400 "Maximum 2 selections allowed"` AND `total_options` unchanged at 3
  (no phantom option). PASS.
- normal under-cap write-in: adds the option (total 2→3) and casts the vote;
  a second voter's `"  zebra "` dedups onto the existing `"Zebra"` option
  (still 3 options, single `is_write_in` option, count 2). PASS.

## B2 — Pin a message 500s: conversation_pins GSI "Type mismatch for Index Key"

**File:** `app/routers/messaging.py` → `pin_message`
(the delegate route `delegate_pin_message` calls `pin_message(..., user_id=creator_id)`
directly, so it rides the same handler and is fixed by the same change).

**Root cause:** the `ConversationPins` table GSI `ByConversationActivePinnedAt`
declares its RANGE key `pinned_at` as **type `S` (String)** (confirmed via
`describe_table` — `_attribute_definitions` in `scripts/local-ddb-init.py`
defaults every key attribute to `"S"` and there is no numeric `attr_types`
override for ConversationPins). But `pin_message` wrote `":pinned_at": ts`
where `ts = now_ts()` is an **integer (Number)**. DynamoDB rejects any item write
whose GSI key attribute type differs from the declared type →
`ValidationException: Type mismatch for Index Key pinned_at` → 500 on every pin.

**Fix (coerce the index-key attr to the declared type):** write `pinned_at` as a
zero-padded string `f"{ts:013d}"` — matching the GSI's declared `S` type while
preserving newest-first ordering in `ByConversationActivePinnedAt` (the same
13-digit zero-pad already used for `latest_pin_sort`). All three readers already
`int(pin.get("pinned_at", 0) or 0)`, so a zero-padded numeric string reads back
identically. `unpin_message` does not write `pinned_at` (no change needed).

**Verified (HTTP, dev-bearer, normal DM):** pin → **200** (`{"action":"pinned"}`),
`GET /conversations/{cid}/pins` → 200 lists the message `is_active:true`, unpin →
**200** (`{"action":"unpinned"}`), pins list after unpin → message no longer
active. Delegate route shares the identical handler/write path.

## Files
- `app.services.newsfeed_polls.py.pollorphan.patch` — B1 unified diff (vs `.bak_pollpin_1783447718`).
- `app.routers.messaging.py.pintype.patch` — B2 unified diff (vs `.bak_pollpin_1783447718`).
- The B1 change is also reflected in the authoritative full-replace engine file
  `ops/prod-hotfixes/poll-writein/new/newsfeed_polls.py`.
