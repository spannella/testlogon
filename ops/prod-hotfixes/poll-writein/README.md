# Poll WRITE-IN answers + newsfeed multi-select + results pagination — LIVE PROD HOTFIX fold

Adds optional, sender-controlled **write-in** answers to arbitrary polls on ALL
surfaces (newsfeed / messaging / group feed / syndicate feed / standalone), plus
sorted + paginated results, plus confirms newsfeed multi-select voting.

Applied live to prod `/home/ubuntu/testlogon` on 2026-07-07. Prod diverges from
this branch, so these are re-apply artifacts (apply against prod's real source).
Pre-hotfix backups on prod: `*.bak_pollwritein_1783440214`.

Builds on the earlier arbitrary-polls fold (`ops/prod-hotfixes/arbitrary-polls/`).

## What changed

### 1. `allow_write_in` threaded through EVERY create path (default false)
- `app/services/newsfeed_polls.py::create_poll_data` gains `allow_write_in`
  (per-question, stored on each processed question + a poll-level rollup). The
  poll-level flag is a **floor** (`per_question OR poll_level`) because surfaces
  like newsfeed send an explicit per-question default of `False` via
  `model_dump`, so a fallback default would be overridden.
- `app/services/arbitrary_polls.py::PollCreateIn` + `create_poll` gain
  `allow_write_in` (used by messaging / group / syndicate / standalone).
- `app/routers/newsfeed.py`: `PollQuestionIn` + `PollDataIn` gain
  `allow_write_in`; threaded into the `create_poll_data` call.
- `app/routers/messaging.py`: `CreatePollMessageIn.allow_write_in` → `create_poll`.
- `app/services/group_feed.py` / `app/services/syndicate_feed.py`: pass
  `allow_write_in=poll.get("allow_write_in", False)` into `create_poll`.

### 2. WRITE-IN action (engine + per-surface endpoints)
- `newsfeed_polls.add_write_in(post, post_id, question_id, text, user_sub)`:
  rejects with **403 WRITE_IN_DISABLED** when the question does not allow it;
  normalises text (trim + collapse whitespace + casefold); consolidates onto a
  matching existing option (seed or prior write-in) OR appends a new option
  (`is_write_in=True`, `author`=voter) via a nested `list_append` + pre-
  materialised count/votes paths, then casts the vote (honours single/multi +
  closed rules; a repeat multi write-in does not toggle-off).
- Shared (messaging/group/syndicate/standalone): `POST /ui/polls/{poll_id}/write-in {text, question_id?}`
  → `app/routers/polls.py` → `arbitrary_polls.write_in`.
- Newsfeed: `POST /posts/{post_id}/write-in {question_id, text}` (author-or-viewer
  gated) → returns the write-in result plus a top-5 `results` snapshot.

### 3. Results sorted-by-count-desc + PAGINATION
- `newsfeed_polls.get_poll_results(post, question_id, viewer_id, top_n=None, offset=0)`:
  options now carry `is_write_in` + `author`, are **sorted by count desc**
  (stable), and when `top_n` is given are paginated → adds `total_options`,
  `has_more`, `offset`, `top_n`, `next_offset`.
- `GET /ui/polls/{poll_id}/results?top_n=5&offset=` (API default `top_n=5`).
- `GET /posts/{post_id}/poll-results?top_n=&offset=` (engine default: no slice
  when `top_n` omitted → back-compatible for existing callers).

### 4. Newsfeed multi-select
- No code change needed: `POST /posts/{post_id}/vote` already routes through the
  multi-aware `cast_vote` and returns `my_votes`. Confirmed by verification.

## Files
- `new/newsfeed_polls.py`   → `app/services/newsfeed_polls.py`   (full replace)
- `new/arbitrary_polls.py`  → `app/services/arbitrary_polls.py`  (full replace)
- `new/polls.py`            → `app/routers/polls.py`             (full replace)
- `apply_targeted_edits.py` → idempotent, anchor-asserted string edits for
  `messaging.py` + `group_feed.py` + `syndicate_feed.py` + `newsfeed.py`.
- `*.poll-writein.patch`    → unified diffs (vs `.bak_pollwritein_1783440214`)
  of the 4 targeted files, for human review.

## Verified 2026-07-07 (two fresh users, prod localhost, 19/19 PASS)
Standalone `/ui/polls` (multi, write-in ON): A "Zebra" + B "zebra " DEDUP → count
2 `is_write_in` author=A; B "Yak" count 1; options sorted desc; total 3.
Gate OFF → write-in 403 WRITE_IN_DISABLED. Pagination: 9 options, top_n=5 →
page1 5 + has_more + next_offset=5, page2 offset=5 → 4 + has_more False.
Multi-select: 2 votes → my_votes has 2. Messaging: `CreatePollMessageIn`
threads `allow_write_in` + `/ui/polls/{id}/write-in` works + gate-off 403.
Newsfeed: poll post `allow_write_in`, `/posts/{id}/vote` multi (my_votes 2),
`/posts/{id}/write-in` add+DEDUP (Falcon count 2), gate-off 403.
