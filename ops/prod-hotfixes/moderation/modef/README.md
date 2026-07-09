# MOD-E/F backend hotfix — enforcement hardening + SYNDICATE-POST hide gap

Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM), folded here for
re-apply. Anchor-based, idempotent, per-file `.bak_modef_<ts>`.
Prod `.bak` set: `.bak_modef_1783620594`.

## What it fixes
### MOD-F1 enforcement hardening (`moderation_policy_engine.py`, `admin_moderation.py`)
- **Fail-CLOSED** — `is_user_currently_banned` previously returned `False` (ADMIT) on a
  DDB read error (fail-OPEN). Now `_load_account_state_or_fail_closed` retries 3x then
  raises **HTTP 503** — a transient DDB blip can no longer admit a banned user.
- **Status gating** — enforce `{banned, suspended}` (was `banned` only); timed entries
  still auto-expire via `ban_until`.
- **No unbounded scan** — `_offender_history_summary` no longer full-table `scan()`s
  `moderation_tickets`; it derives counts from the bounded Key query on
  `user_enforcement_history` (keyed by `user_id`).

### Syndicate-post hide gap (§2.2) — `syndicate_post` content_type
Group posts share the `POST#{id}/META` feed_post row and `list_group_feed` already
filters owner-aware, so group needs NO distinct type. Syndicate posts live in a DISTINCT
store `T.syndicate_posts` (`SYND#{sid}/POST#{pid}`, owner field `author_id`) and were
filed as generic `feed_post`, so the auto-hide never touched the real row. Now:
- `moderation_hide._hide_syndicate_post` / `resolve_owner` — non-destructive flag write +
  owner resolve on `T.syndicate_posts` (needs `syndicate_id` in metadata).
- `moderation_delete._delete_syndicate_post` — terminal hard-delete in that store.
- `syndicate_feed.list_syndicate_posts` — owner-aware moderation-hidden read filter.
- `routers/moderation.py` — accept `syndicate_post` + `syndicate_id`, validate via
  `syndicate_feed._get_post`, thread `syndicate_id` into the case metadata.

## Apply / verify / rollback
```
python3 apply_modef.py /home/ubuntu/testlogon          # PATCHED/SKIPPED/MISSING; MISSING => exit 1
# verify (in-process on prod DDB, as ubuntu under venv+env):
su - ubuntu -c "cd /home/ubuntu/testlogon && set -a && source .env.local; \
  export DEV_MODE=1 PYTHONPATH=/home/ubuntu/testlogon && set +a && .venv/bin/python _verify_modef.py"
# rollback: restore each .bak_modef_<ts>
```

## Verify matrix — 26/26 ALL_PASS (prod DDB, real seeded rows)
- **SYN** reported (severe/sexual) syndicate post auto-hides in `T.syndicate_posts`: non-owner
  cannot see it, owner CAN, body byte-for-byte intact; `resolve_owner`→poster (=> `/cases/mine`);
  case `under_review`; dismiss reinstates byte-for-byte; final delete hard-removes the row.
- **F1a** DDB read error -> HTTP 503 (fails CLOSED, does not admit).
- **F1b** permanent ban + suspended gate; expired timed ban auto-clears; active passes.
- **F1c** offender summary runs WITHOUT scanning `moderation_tickets` (query-only counts).
