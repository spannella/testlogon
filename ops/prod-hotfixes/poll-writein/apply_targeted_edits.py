#!/usr/bin/env python3
"""Apply write-in targeted edits to the 4 per-surface files on prod, in place.
Each edit asserts the anchor occurs exactly the expected number of times."""
import sys

BASE = "/home/ubuntu/testlogon"


def patch(path, old, new, expect=1):
    full = BASE + "/" + path
    with open(full, "r", encoding="utf-8") as f:
        src = f.read()
    n = src.count(old)
    if n != expect:
        print(f"FAIL {path}: anchor count {n} != {expect}")
        print("ANCHOR:\n" + old[:400])
        sys.exit(3)
    if new in src and new != old:
        print(f"SKIP {path}: replacement already present")
        return
    src = src.replace(old, new, 1)
    with open(full, "w", encoding="utf-8") as f:
        f.write(src)
    print(f"OK   {path}")


# ---- messaging.py : CreatePollMessageIn model + create_poll call ----
patch("app/routers/messaging.py",
      '    choice_mode: Literal["single", "multi"] = "single"\n'
      '    max_selections: Optional[int] = Field(default=None, ge=1, le=10)\n'
      '    closes_at: Optional[int] = Field(default=None)\n'
      '    text: Optional[str] = Field(default=None, max_length=2000)',
      '    choice_mode: Literal["single", "multi"] = "single"\n'
      '    max_selections: Optional[int] = Field(default=None, ge=1, le=10)\n'
      '    closes_at: Optional[int] = Field(default=None)\n'
      '    allow_write_in: bool = False\n'
      '    text: Optional[str] = Field(default=None, max_length=2000)')

patch("app/routers/messaging.py",
      '        closes_at=inp.closes_at, surface="messaging", ref_id=conversation_id,',
      '        closes_at=inp.closes_at, allow_write_in=inp.allow_write_in, surface="messaging", ref_id=conversation_id,')

# ---- group_feed.py service ----
patch("app/services/group_feed.py",
      '            anonymous=poll.get("anonymous", True), surface="group", ref_id=group_id)',
      '            anonymous=poll.get("anonymous", True), allow_write_in=poll.get("allow_write_in", False), surface="group", ref_id=group_id)')

# ---- syndicate_feed.py service ----
patch("app/services/syndicate_feed.py",
      '            anonymous=poll.get("anonymous", True), surface="syndicate", ref_id=syndicate_id)',
      '            anonymous=poll.get("anonymous", True), allow_write_in=poll.get("allow_write_in", False), surface="syndicate", ref_id=syndicate_id)')

# ---- newsfeed.py : PollQuestionIn + PollDataIn + create_poll_data + endpoints ----
patch("app/routers/newsfeed.py",
      'class PollQuestionIn(BaseModel):\n'
      '    text: str = Field(..., min_length=1, max_length=500)\n'
      '    choice_mode: Literal["single", "multi"] = "single"\n'
      '    options: List[PollOptionIn] = Field(..., min_length=2, max_length=10)\n'
      '    max_selections: Optional[int] = Field(default=None, ge=1, le=10)',
      'class PollQuestionIn(BaseModel):\n'
      '    text: str = Field(..., min_length=1, max_length=500)\n'
      '    choice_mode: Literal["single", "multi"] = "single"\n'
      '    options: List[PollOptionIn] = Field(..., min_length=2, max_length=10)\n'
      '    max_selections: Optional[int] = Field(default=None, ge=1, le=10)\n'
      '    allow_write_in: bool = False')

patch("app/routers/newsfeed.py",
      'class PollDataIn(BaseModel):\n'
      '    questions: List[PollQuestionIn] = Field(..., min_length=1, max_length=10)\n'
      '    closes_at: Optional[int] = Field(default=None, ge=0)\n'
      '    anonymous: bool = True\n'
      '    allow_vote_change: bool = True',
      'class PollDataIn(BaseModel):\n'
      '    questions: List[PollQuestionIn] = Field(..., min_length=1, max_length=10)\n'
      '    closes_at: Optional[int] = Field(default=None, ge=0)\n'
      '    anonymous: bool = True\n'
      '    allow_vote_change: bool = True\n'
      '    allow_write_in: bool = False')

patch("app/routers/newsfeed.py",
      '            allow_vote_change=req.poll_data.allow_vote_change,\n        )',
      '            allow_vote_change=req.poll_data.allow_vote_change,\n'
      '            allow_write_in=req.poll_data.allow_write_in,\n        )')

patch("app/routers/newsfeed.py",
      '@router.get("/posts/{post_id}/poll-results")\n'
      'def get_poll_results_endpoint(post_id: str, question_id: str = Query(...), user_id: UserIdDep = None):\n'
      '    """Get detailed poll results for a specific question."""\n'
      '    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})\n'
      '    if not post:\n'
      '        raise HTTPException(status_code=404, detail="Post not found")\n'
      '    if post.get("post_type") not in ("poll", "survey"):\n'
      '        raise HTTPException(status_code=400, detail="Post is not a poll")\n'
      '\n'
      '    from app.services.newsfeed_polls import get_poll_results\n'
      '    return get_poll_results(post=post, question_id=question_id, viewer_id=user_id)',
      '@router.get("/posts/{post_id}/poll-results")\n'
      'def get_poll_results_endpoint(\n'
      '    post_id: str,\n'
      '    question_id: str = Query(...),\n'
      '    top_n: Optional[int] = Query(default=None, ge=1, le=100),\n'
      '    offset: int = Query(default=0, ge=0),\n'
      '    user_id: UserIdDep = None,\n'
      '):\n'
      '    """Get detailed poll results for a specific question (sorted by count desc, paginated)."""\n'
      '    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})\n'
      '    if not post:\n'
      '        raise HTTPException(status_code=404, detail="Post not found")\n'
      '    if post.get("post_type") not in ("poll", "survey"):\n'
      '        raise HTTPException(status_code=400, detail="Post is not a poll")\n'
      '\n'
      '    from app.services.newsfeed_polls import get_poll_results\n'
      '    return get_poll_results(post=post, question_id=question_id, viewer_id=user_id, top_n=top_n, offset=offset)\n'
      '\n'
      '\n'
      'class PostWriteInIn(BaseModel):\n'
      '    question_id: str = Field(..., min_length=1, max_length=64)\n'
      '    text: str = Field(..., min_length=1, max_length=200)\n'
      '\n'
      '\n'
      '@router.post("/posts/{post_id}/write-in")\n'
      'def add_poll_write_in(post_id: str, body: PostWriteInIn, user_id: UserIdDep):\n'
      '    """Submit a write-in answer to a poll/survey post (only if the poll allows it)."""\n'
      '    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})\n'
      '    if not post:\n'
      '        raise HTTPException(status_code=404, detail="Post not found")\n'
      '    post_author = str(post.get("user_id") or "").strip()\n'
      '    if post_author and post_author != user_id and not can_view_post(user_id, post):\n'
      '        raise HTTPException(status_code=403, detail="Not authorized to view this post")\n'
      '    if post.get("post_type") not in ("poll", "survey"):\n'
      '        raise HTTPException(status_code=400, detail="Post is not a poll")\n'
      '\n'
      '    from app.services.newsfeed_polls import add_write_in, get_poll_results\n'
      '    result = add_write_in(post=post, post_id=post_id, question_id=body.question_id, text=body.text, user_sub=user_id)\n'
      '    refreshed = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()}) or post\n'
      '    poll_results = get_poll_results(post=refreshed, question_id=body.question_id, viewer_id=user_id, top_n=5, offset=0)\n'
      '    return {**result, "results": poll_results}')

print("ALL EDITS APPLIED")
