# Arbitrary text-option polls — LIVE PROD HOTFIX fold

Adds arbitrary (custom question + 2..N text options, single/multi-choice) polls
with vote / live counts / results / close to MESSAGING, GROUP feed and SYNDICATE
feed. NEWSFEED already had full arbitrary-poll support (unchanged; verified).

Applied live to prod `/home/ubuntu/testlogon` on 2026-07-07. Prod diverges from
this branch, so these are re-apply artifacts (apply against prod's real source).
Pre-hotfix backups on prod: `*.bak_polls_1783435257`.

## New files (copy verbatim)
- `new/arbitrary_polls.py`  -> `app/services/arbitrary_polls.py`
  Shared poll engine. Stores each poll as a detached `POST#{poll_id}/META` item
  in app_single_table and REUSES `app/services/newsfeed_polls.py` verbatim for
  validate/vote/close/results. Exposes `PollCreateIn` + create/get_snapshot/
  vote/unvote/close/results.
- `new/polls.py`            -> `app/routers/polls.py`
  Surface-agnostic router `/ui/polls/*` (create/get/vote/unvote/close/results).

## Patches (unified diff vs the .bak_polls_1783435257 backups)
- app.main.py            : register `polls_router`.
- app.models.py          : `poll` field on `SyndicatePostOut`.
- app.routers.messaging.py : MessageOut kind `"poll"` + `poll` field + projection
  in `_message_out_from_item` + new `POST /conversations/{cid}/messages/poll`.
- app.routers.group_feed.py / app.services.group_feed.py : `poll` on create +
  embed snapshot in feed output.
- app.routers.syndicate_feed.py / app.services.syndicate_feed.py : same.

Meeting-time (`meeting_poll`) and find-a-time (`find_datetime`) pickers are left
fully intact — the arbitrary text poll is a separate, additional kind.

## Contracts the app needs
- Create in messaging: `POST /messaging/conversations/{cid}/messages/poll`
  `{question, options[2..10], choice_mode:"single"|"multi", max_selections?, closes_at?, text?}`
  -> MessageOut kind="poll" with `poll` = live snapshot {poll_id, question, choice_mode, questions[{question_id, options[{option_id,text}]}], vote_counts, my_votes, total_votes, closed}.
- Create in group: `POST /ui/groups/{gid}/posts` with `{text, poll:{question,options,choice_mode,max_selections?,closes_at?}}` -> post out carries `poll` snapshot.
- Create in syndicate: `POST /ui/syndicates/feed/{sid}` with `{text, poll:{...}}` -> SyndicatePostOut carries `poll`.
- Vote/results/close (messaging+group+syndicate, ONE client):
  `POST /ui/polls/{poll_id}/vote {option_id, question_id?}`,
  `DELETE /ui/polls/{poll_id}/vote?question_id=`,
  `GET /ui/polls/{poll_id}/results?question_id=`,
  `POST /ui/polls/{poll_id}/close`, `GET /ui/polls/{poll_id}`.
- Newsfeed keeps its existing inline endpoints (`POST /posts` post_type=poll,
  `POST /posts/{id}/vote`, `GET /posts/{id}/poll-results`, `POST /posts/{id}/close-poll`).

## Verified 2026-07-07 (two users, prod, all PASS)
newsfeed/group/syndicate/messaging: create + vote(A,B) + results(count) + close;
syndicate exercised multi-select (A:1 + B:2 = total 3).
