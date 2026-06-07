# BCAST-014: Lottery Messages in Broadcast Chat — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-014 adds interactive lottery-style draws to live broadcast chat. A broadcaster drops a `kind="lottery"` card into chat; viewers enter (optionally paying an entry fee); the broadcaster triggers a draw that assigns cryptographically-random weighted outcomes to all entrants and broadcasts results via SSE. The implementation reuses the DM-lottery RNG (`messaging_lottery_rng.py`) and outcome validation (`messaging_lottery_store.py`) while storing all lottery state as three co-located item types in the existing `BroadcastChatMessages` DynamoDB table.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Implemented — `app/services/broadcast_lottery.py` (600 lines), six API endpoints in `app/routers/broadcast.py`, E2E spec `frontend/e2e/broadcast-lottery.spec.ts`, frontend spec file present.
- **Owning area**: `app/services/broadcast_lottery.py`, `app/routers/broadcast.py` (lines ~3249–3450), `app/services/broadcast_chat_store.py:296` (extended), `app/services/messaging_lottery_rng.py`, `app/services/messaging_lottery_store.py`.
- **User personas**: Broadcasters (create/close/draw), viewers (enter, check results).
- **Cross-references**: [[SEC-025]] (broadcast IDOR + Q&A vote race — the lottery draw has an analogous concurrent-entry integrity concern), [[SEC-004]] (billing ledger — entry fee debit/credit pattern), BCAST-005 (SSE delivery via `broadcast_sse_publish`), [[SECOPS-007]] (dev = DDB Local, mock outcome RNG not needed — `secrets.randbelow()` is environment-agnostic).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/broadcast_lottery.py` (600 lines)

| Function | Line | Purpose |
|---|---|---|
| `_enforce_lottery_create_rate_limit()` | 41 | In-memory 30-second cooldown per broadcaster per session; prevents lottery spam. |
| `_enforce_lottery_entry_rate_limit()` | 59 | In-memory 2-second cooldown per viewer per session; prevents rapid re-entry attempts. |
| `create_lottery()` | 86 | Validates outcomes via `_normalized_outcomes()` from `messaging_lottery_store.py`; writes two DDB items: the `kind="lottery"` chat message (timestamp SK) and the `LOTTERY#{lottery_id}` config item; publishes `lottery:created` SSE. |
| `enter_lottery()` | 166 | Mute check; loads config; validates `status="open"`, `entry_count < max_entries`, `closes_at`; charges entry fee via `_charge_entry_fee()`; writes `LENTRY#{lottery_id}#{user_id}` item with `ConditionExpression=attribute_not_exists(sort_key)` for idempotency; atomically increments `entry_count`; publishes `lottery:entry` SSE. |
| `close_lottery_entries()` | 287 | Creator-only; transitions `open` → `entries_closed` via `_transition_lottery_status()`; publishes `lottery:closed` SSE. |
| `draw_lottery()` | 326 | Creator-only; loads all entry items via `_list_entries()` (paginated `begins_with("LENTRY#...")` query); for each entry calls `choose_weighted_outcome()` from `messaging_lottery_rng.py:33`; updates each entry with `outcome_id` and `rng_roll`; transitions to `"drawn"`; publishes `lottery:result` SSE with all results. Idempotent: if already `"drawn"`, returns stored results. |
| `get_lottery_config()` | 409 | `GetItem(session_id, "LOTTERY#{lottery_id}")`. |
| `get_lottery_entry()` | 417 | `GetItem(session_id, "LENTRY#{lottery_id}#{user_id}")`. |
| `_list_entries()` | 425 | Paginated query with `begins_with("LENTRY#{lottery_id}#")`, cap 1000 entries. |
| `_charge_entry_fee()` | 484 | Validates PM (or uses default PM from `BILLING` item); writes debit (viewer) and credit (broadcaster) `LEDGER#` entries directly to `T.billing` via `billing_tbl.put_item()`. |
| `get_lottery_status_for_viewer()` | 564 | Returns config + `has_entered` + `viewer_outcome` (personal result only, not other entrants'). |

### 2.2 DDB storage co-location in `BroadcastChatMessages`

Three item types share the `BroadcastChatMessages` table (PK `session_id`, SK `sort_key`):

| Item Type | SK Pattern | Notes |
|---|---|---|
| Chat message | `{ts_ms:016d}#{msg_id}` | `kind="lottery"`, `lottery_id` field. Appears in chat history. |
| Lottery config | `LOTTERY#{lottery_id}` | Mutable state. SK begins with uppercase `L` — lexicographically after all digit-prefixed chat SKs. |
| Entry record | `LENTRY#{lottery_id}#{user_id}` | One per entrant. Populated with `outcome_id` + `rng_roll` after draw. |

No new DDB table is created. This is explicitly noted in the ticket design: "No new table definition needed in `scripts/local-ddb-init.py`." The existing `BroadcastChatMessages` table at `scripts/local-ddb-init.py:~557` supports all three item types.

### 2.3 Chat store extension — `app/services/broadcast_chat_store.py:296`

`_chat_msg_out()` now includes `lottery_id` in the output dict:

```python
if item.get("lottery_id"):
    out["lottery_id"] = item["lottery_id"]
```

### 2.4 Router models and endpoints — `app/routers/broadcast.py` (lines ~3162–3450)

Pydantic models: `BroadcastLotteryCreateIn`, `BroadcastLotteryEntryIn`, `BroadcastLotteryConfigOut`, `BroadcastLotteryDrawOut`, `BroadcastLotteryEntryOut`, `BroadcastLotteryViewerStatusOut`, `BroadcastLotteryResultEntryOut`, `BroadcastLotteryOutcomeIn`, `BroadcastLotteryOutcomeOut`.

Endpoints:
- `POST /sessions/{id}/chat/lottery` (line ~3259) — create; broadcaster only.
- `POST /sessions/{id}/chat/lottery/{lottery_id}/enter` (line ~3342) — enter; any viewer.
- `POST /sessions/{id}/chat/lottery/{lottery_id}/close` (line ~3392) — close entries; broadcaster only.
- `POST /sessions/{id}/chat/lottery/{lottery_id}/draw` (line ~3410) — draw; broadcaster only; idempotent.
- `GET /sessions/{id}/chat/lottery/{lottery_id}` (line ~3430) — viewer status; any authenticated user.
- `GET /sessions/{id}/chat/lottery/{lottery_id}/results` (line ~3440) — full results; broadcaster only.

Feature-gated via `_require_broadcast_lottery_enabled()` which checks `S.broadcast_lottery_enabled` (setting at `app/core/settings.py:547`).

### 2.5 SSE stream extension — `app/routers/broadcast.py` (~line 1812)

The chat poll stream dispatch at line ~1812 now handles `kind="lottery"`:

```python
elif out.get("kind") == "lottery":
    event_type = "chat:lottery"
```

Lottery lifecycle events (`lottery:created`, `lottery:entry`, `lottery:closed`, `lottery:result`) are published via `broadcast_sse_publish()` and delivered through the in-memory pub/sub queue path (not the DDB poll path).

### 2.6 RNG — `app/services/messaging_lottery_rng.py`

`choose_weighted_outcome()` at line 33 uses `secrets.randbelow(10_000) + 1` for cryptographic randomness. It is stateless and accepts any sequence of outcome dicts with `weight_bps`. No modification was needed — the broadcast lottery service calls it directly.

### 2.7 Settings — `app/core/settings.py` (lines 547–550)

```python
broadcast_lottery_enabled: bool = ...
broadcast_lottery_max_outcomes: int = 10
broadcast_lottery_max_entry_fee_cents: int = 10000
broadcast_lottery_max_duration_seconds: int = 3600
```

### 2.8 Dev vs. Prod parity (SECOPS-007)

`secrets.randbelow()` is a standard library function — identical behavior in dev and prod. DDB writes go to DDB Local in dev. The billing `_charge_entry_fee()` function uses `T.billing` (via a local reference `ddb.Table(S.billing_table_name)` rather than `T.billing` directly — a minor inconsistency but functional). No AWS-specific services involved. Feature flag `broadcast_lottery_enabled` can be set to `"0"` in `.env.local` to test disabled path.

---

## 3. Gap / Threat Analysis

### 3.1 Entry fee billing atomicity (same pattern as BCAST-011/BCAST-012)

`_charge_entry_fee()` at `broadcast_lottery.py:484` writes debit and credit `put_item()` calls in separate `try/except Exception` blocks. Failure of the credit write after a successful debit silently logs an exception and returns the `fee_payment_id`. The viewer is charged but the broadcaster is not credited. This is the same money-path gap as BCAST-011 and BCAST-012.

### 3.2 Self-entry check after fee charge

In `enter_lottery()` at line 166, the broadcaster-cannot-enter guard at line ~430 executes **after** `_charge_entry_fee()` at line ~420. The order is: rate limit → mute check → load config → status check → max entries check → closes_at check → charge fee → then check `user_id == broadcaster_id`. A broadcaster who attempts to enter their own lottery (whether accidentally or intentionally) will be charged the entry fee before the `BROADCASTER_CANNOT_ENTER` 403 is returned. The fee write succeeds but the entry item is never written — the broadcaster is debited with no corresponding entry record.

**Fix**: Move the `user_id == config["broadcaster_id"]` check before `_charge_entry_fee()`.

### 3.3 SEC-025 Q&A vote-race analogy for entry count

The `entry_count` increment in `enter_lottery()` uses `update_item` with `entry_count = entry_count + 1`. This is a non-atomic read-modify-write in plain Python. Wait — actually the update expression `UpdateExpression="SET entry_count = entry_count + :one"` **is** an atomic DynamoDB expression that avoids the read-before-write race. This is fine. However, the pre-check `config["entry_count"] >= config["max_entries"]` (line ~398) reads a stale value from `get_lottery_config()` earlier in the function. Two concurrent entries near the max_entries limit could both pass this check and both increment. The max_entries guard should use a conditional write: `ConditionExpression=Attr("entry_count").lt(max_entries)` on the config item update rather than a pre-read check.

### 3.4 Draw with zero entries

`draw_lottery()` raises 409 `LOTTERY_NO_ENTRIES` if `_list_entries()` returns an empty list. However, `_list_entries()` only returns items with SK prefix `LENTRY#{lottery_id}#`. If entries exist but the `begins_with` query misses them due to a DDB pagination issue (e.g., exactly 1000 entries and the loop exits on the first page), the draw could fire with a truncated entry list. The `_list_entries()` loop exits when `LastEvaluatedKey` is None OR `len(entries) >= limit`. With `limit=1000`, a lottery with exactly 1000 entries will exit the loop on the first page if `len(entries) == 1000`, but the last page might have a `LastEvaluatedKey` that is not `None`. The condition should be `and len(entries) >= limit` → `or len(entries) >= limit` to handle this edge case correctly (exit only when both conditions are true).

### 3.5 Lottery card in public chat history

The `kind="lottery"` chat message item has a timestamp-based SK and therefore appears in the public chat history (`GET /sessions/{id}/chat`). Any viewer can see when a lottery was created. This is intentional — the lottery card is public. However, `_chat_msg_out()` at `broadcast_chat_store.py:296` now includes `lottery_id` in the response. Viewers can use this `lottery_id` to call `GET /sessions/{id}/chat/lottery/{lottery_id}` to check their entry status. This is the correct design.

### 3.6 Outcome data in full draw results (broadcaster endpoint)

`GET /sessions/{id}/chat/lottery/{lottery_id}/results` returns all entrants' outcomes including `text_content` and `media_asset_id`. The broadcaster-only check is enforced in the router. However, if an outcome has `payload_type="text"` with a discount code or exclusive content in `text_content`, that string is returned to the broadcaster in the full results list. The design intent is that each viewer sees only their own result via the viewer endpoint. The broadcaster seeing all results is correct for administration purposes (verifying the draw was fair).

---

## 4. Proposed Design / Fix

### 4.1 Fix self-entry check order in `enter_lottery()`

In `broadcast_lottery.py`, move the broadcaster check before `_charge_entry_fee()`:

```python
# Before _charge_entry_fee()
if user_id == config["broadcaster_id"]:
    raise HTTPException(403, {"code": "BROADCASTER_CANNOT_ENTER", ...})

# Then charge fee
if entry_fee_cents > 0:
    fee_payment_id = _charge_entry_fee(...)
```

This is a one-line reorder with no other changes needed.

### 4.2 Fix max_entries race with conditional write

Replace the pre-check `config["entry_count"] >= max_entries` with a conditional increment on the config item:

```python
from botocore.exceptions import ClientError
try:
    T.broadcast_chat_messages.update_item(
        Key={"session_id": session_id, "sort_key": f"LOTTERY#{lottery_id}"},
        UpdateExpression="SET entry_count = entry_count + :one",
        ConditionExpression=Attr("entry_count").lt(int(config.get("max_entries", 999999))),
        ExpressionAttributeValues={":one": 1},
    )
except ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        raise HTTPException(409, {"code": "LOTTERY_FULL", ...})
    raise
```

Remove the pre-check. The entry item write still follows this conditional increment.

### 4.3 Fix `_list_entries()` pagination exit condition

Change the loop exit condition to handle the edge case exactly at `limit`:

```python
while True:
    ...
    entries.extend(resp.get("Items", []))
    last_key = resp.get("LastEvaluatedKey")
    if not last_key:
        break  # Exhausted all items
    if len(entries) >= limit:
        break  # Hit our cap — may have missed some entries (log a warning)
```

Log a warning when `len(entries) >= limit and last_key` — this indicates more entries exist beyond the cap. For a draw, the broadcaster should be warned that not all entries were included.

### 4.4 Fix entry fee billing atomicity

Same fix as BCAST-011 and BCAST-012: use `TransactWriteItems` in `_charge_entry_fee()` to write debit and credit atomically. If the transaction fails, no entry fee is charged and `enter_lottery()` returns 500 instead of silently proceeding.

### 4.5 Dev/Prod parity (SECOPS-007)

`secrets.randbelow()` is environment-agnostic. DDB writes are the same path. The `billing_tbl = ddb.Table(S.billing_table_name)` reference in `_charge_entry_fee()` should be changed to `T.billing` for consistency with the rest of the codebase (minor cleanup, same behavior).

---

## 5. Testing, Verification & Rollout

### pytest unit tests — `tests/test_broadcast_lottery.py`

Concrete cases:
1. `test_create_lottery_validates_weight_sum` — outcomes with `weight_bps` not summing to 10000 → `LotteryConfigValidationError`.
2. `test_enter_lottery_idempotent` — enter twice → second returns `already_entered=True` with no duplicate entry in DDB.
3. `test_broadcaster_cannot_enter_before_fee_charged` — broadcaster entry attempt with fee > 0 → 403 with no debit in `T.billing`.
4. `test_max_entries_enforced_concurrent` — two concurrent entries against `max_entries=1` → exactly one succeeds.
5. `test_draw_assigns_outcomes_to_all_entrants` — 5 entrants, draw → all 5 have `outcome_id` and `rng_roll` in DDB.
6. `test_draw_idempotent` — draw twice → second returns same results with `idempotent=True`.
7. `test_viewer_sees_only_own_outcome` — `get_lottery_status_for_viewer()` → `viewer_outcome` contains only the requesting user's result.
8. `test_entry_fee_debit_credit_written` — enter with fee=100 → debit for viewer, credit for broadcaster in `T.billing`.
9. `test_draw_zero_entries_rejected` — attempt draw with no entries → 409 `LOTTERY_NO_ENTRIES`.
10. `test_create_rate_limit` — broadcaster creates two lotteries within 30 seconds → second returns 429.

### Playwright E2E — `frontend/e2e/broadcast-lottery.spec.ts` (exists)

Add scenarios:
- Full lifecycle: create → enter (3 viewers) → close → draw → verify `lottery:result` SSE with 3 outcome entries.
- Entry fee: create with `entry_fee_cents=100`, viewer enters → billing debit in `T.billing`.
- Broadcaster cannot enter: broadcaster attempts entry → 403.
- Max entries: create with `max_entries=2`, three viewers enter → third returns 409.

### Manual QA

1. As broadcaster, POST `/sessions/{id}/chat/lottery` with two outcomes (50/50 weight).
2. As 3 viewers, enter the lottery (no entry fee).
3. Broadcaster clicks draw → `lottery:result` SSE arrives with 3 results.
4. Each viewer calls `GET /sessions/{id}/chat/lottery/{id}` — verify `viewer_outcome.display_label` differs between viewers per weighting.
5. Check `BroadcastChatMessages` table — verify `LOTTERY#` item has `status="drawn"`, all three `LENTRY#` items have `outcome_id` populated.

### Rollout

- Feature flag `BROADCAST_LOTTERY_ENABLED` (setting at `settings.py:547`) defaults to `true`. Set to `"0"` for staged rollout.
- Fix 4.1 (self-entry order) and fix 4.2 (max entries race) are low-risk one-line changes — include in next patch release.
- Fix 4.4 (billing atomicity) is a behavioral change; include in the same release as BCAST-011 and BCAST-012 billing fixes for consistency.

**Effort**: Fixes 4.1+4.3: XS (<1 hour each). Fix 4.2: S (~2 hours). Fix 4.4: S (~2 hours, same as other billing fixes). New feature work: already complete.
