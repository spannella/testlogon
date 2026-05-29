# SOC-002: Fan-Out on Write for Newsfeed — Populate Follower Feed Indexes on Post Create

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-26  
**Priority**: High  
**Estimated effort**: 7-10 days

---

## 1. Overview & Motivation

### The Gap

The newsfeed system currently stores a `FEED#{user_id}` reference in GSI1 only for the **author's own feed**. When a post is created, the `_write_feed_ref_for_published_post` function (`app/routers/newsfeed.py`, line 1735) writes a single feed reference item:

```python
def _write_feed_ref_for_published_post(*, user_id: str, post_id: str, created_at: str) -> None:
    feed_item = {
        "pk": pk_post(post_id),
        "sk": f"FEEDREF#{user_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{user_id}",       # <-- Only the author's feed
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    ddb_put_item(feed_item)
```

The feed query (`GET /feed`, around line 4040) reads from GSI1 with `FEED#{viewer_user_id}`:

```python
resp = ddb_query(
    IndexName="GSI1",
    KeyConditionExpression="GSI1PK = :pk",
    ExpressionAttributeValues={":pk": f"FEED#{user_id}"},
    ...
)
```

This means **a user only sees their own posts in their feed**. Posts from followed users never appear because no `FEEDREF` item is written with `GSI1PK=FEED#{follower_id}`.

### Why This Is Needed

Without fan-out, the newsfeed is essentially a personal post archive. Users expect to see posts from people they follow in their feed — this is the fundamental social media interaction. The existing `author_filter` path (GSI2, `POST_AUTHOR#{user_id}`) lets you view a specific author's posts, but there is no aggregated timeline of all followed users' content.

### Architecture After This Change

```
Post Create Flow (Fan-Out on Write)
                                                                    
  Author creates post                                              
       |                                                            
       v                                                            
  +----------------------+     +-----------------------------+     
  | create_post()        |---->| _write_feed_ref_for_author  |     
  | (newsfeed router)    |     | GSI1PK=FEED#{author_id}     |     
  +----------------------+     +-----------------------------+     
       |                                                            
       v                                                            
  +----------------------+     +-----------------------------+     
  | fan_out_post_to_     |---->| For each follower_id:       |     
  | followers()          |     |   write FEEDREF item with   |     
  |                      |     |   GSI1PK=FEED#{follower_id} |     
  +----------------------+     +-----------------------------+     
       |                                                            
       +- sync path (<= 500 followers) -- batch_writer in-request  
       |                                                            
       +- async path (> 500 followers) -- background task / SQS    
                                                                    
Feed Read Flow (Unchanged)                                          
                                                                    
  Viewer opens feed                                                 
       |                                                            
       v                                                            
  +----------------------+     +-----------------------------+     
  | GET /feed            |---->| GSI1: FEED#{viewer_id}      |     
  |                      |     | Returns author's own posts   |     
  |                      |     | + fan-out refs from followed |     
  +----------------------+     +-----------------------------+     
       |                                                            
       v                                                            
  +------------------------------------------------------------+     
  | batch_get_item for each post_id -> full post items         |     
  | Filter: can_view_post(), is_hidden(), visibility check     |     
  +------------------------------------------------------------+     
```

---

## 2. Current State Analysis

### 2.1 Post Creation (`app/routers/newsfeed.py`, lines 2878-3090)

The `create_post()` function (line 2878) handles both immediate and scheduled posts. For immediate (non-scheduled) posts, the key write sequence is:

1. **Post item**: Written to `app_single_table` with `PK=POST#{post_id}`, `SK=POST` (around line 3076).
2. **Feed reference for author**: `_write_feed_ref_for_published_post()` called at the end of create, writing a single `FEEDREF` item targeting `FEED#{author_id}`.
3. **Post author index**: The post item itself has `GSI2PK=POST_AUTHOR#{user_id}` for per-author queries.

No follower fan-out occurs.

### 2.2 Feed Query (`app/routers/newsfeed.py`, lines 4028-4068)

The feed query has two paths:

1. **Author filter**: If `author_filter` is set, queries `GSI2` with `POST_AUTHOR#{author_filter}`.
2. **Default feed**: Queries `GSI1` with `FEED#{user_id}`, fetches `FEEDREF` items, then batch-gets full post records.

The default path only returns posts where a `FEEDREF` item exists with `GSI1PK=FEED#{viewer_id}`. Since only the author's feed ref is written today, only the author sees their posts in the feed.

The feed query also applies several filters per post (lines 4078-4098):
- `_resolve_post_lifecycle_fields()` — only `status == "published"` posts
- `moderation_removed` check
- `is_hidden(user_id, post_id)` check
- `post_matches_filters()` check
- `can_view_post()` — checks `is_following()` for `visibility="followers"` posts

### 2.3 Scheduled Post Publishing (`app/services/newsfeed_scheduler.py`)

The scheduler promotes scheduled posts to published status. It calls `_write_feed_ref_for_published_post()` for the author only. Fan-out must also be added to the scheduled publish path.

### 2.4 Post Deletion / Visibility Changes

Post deletion currently removes the post item and the author's `FEEDREF`. If fan-out refs exist for followers, deletion must also remove all fan-out refs. The current delete flow (`delete_post` in the newsfeed router) does not account for fan-out refs.

### 2.5 Post Edit Visibility Changes

A post's `visibility` can be changed from `public` to `followers` or vice versa. Currently this has no effect on feed refs since only the author's ref exists. With fan-out, changing visibility to `public` from `followers` may require writing additional refs (for non-followers who have the post shared with them), and changing to a more restrictive visibility may require removing refs.

### 2.6 Follow System (SOC-001 Dependency)

Fan-out depends on the follower list from SOC-001. The key query is: "given an author, get all follower user_ids" — this is the GSI5 query `FOLLOWERS#{author_id}` from SOC-001.

### 2.7 DynamoDB Write Throughput Considerations

The `app_single_table` is provisioned with on-demand capacity in dev mode. In production, fan-out to 10K followers means 10K `put_item` calls. At DynamoDB's per-partition write limit of 1000 WCU/s, writing 10K items (each ~200 bytes = 1 WCU) takes ~10 seconds if all items hash to the same partition. However, since each `FEEDREF` has a different `GSI1PK` (`FEED#{follower_id}`), the writes distribute across many partitions.

**Batch writer capacity**: DynamoDB `batch_write_item` processes up to 25 items per call. For 10K followers, that is 400 batch calls.

---

## 3. Technical Design

### 3.1 Fan-Out Function — Full Implementation

```python
# app/services/newsfeed_fanout.py (new file)

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.tables import T

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

SYNC_FANOUT_LIMIT = int(os.environ.get("NEWSFEED_SYNC_FANOUT_LIMIT", "500"))
FANOUT_BATCH_SIZE = 25  # DynamoDB batch_write_item limit
FANOUT_PAGE_SIZE = 500  # Followers query page size
FANOUT_ENABLED = os.environ.get("NEWSFEED_FANOUT_ENABLED", "true").lower() == "true"
BACKFILL_ON_FOLLOW = os.environ.get("NEWSFEED_FANOUT_BACKFILL_ON_FOLLOW", "true").lower() == "true"
BACKFILL_LIMIT = int(os.environ.get("NEWSFEED_FANOUT_BACKFILL_LIMIT", "50"))
MAX_FOLLOWERS = int(os.environ.get("NEWSFEED_FANOUT_MAX_FOLLOWERS", "100000"))


def fan_out_post_to_followers(
    *,
    author_id: str,
    post_id: str,
    created_at: str,
    visibility: str = "followers",
) -> Dict[str, Any]:
    """Write FEEDREF items for each of the author's followers.

    For <= SYNC_FANOUT_LIMIT followers, writes are done synchronously
    within the HTTP request. For larger follower counts, only the
    first batch is written synchronously and the rest is dispatched
    to the background worker.

    Returns:
        {"followers_written": int, "async_dispatched": bool}
    """
    if not FANOUT_ENABLED:
        return {"followers_written": 0, "async_dispatched": False}

    follower_ids = _get_all_follower_ids(author_id)

    # Remove author from follower list (edge case: self-follow)
    follower_ids.discard(author_id)

    if not follower_ids:
        return {"followers_written": 0, "async_dispatched": False}

    total = len(follower_ids)
    follower_list = list(follower_ids)

    if total <= SYNC_FANOUT_LIMIT:
        # Sync path: write all refs in-request
        written = _write_feedref_batch(
            follower_ids=follower_list,
            author_id=author_id,
            post_id=post_id,
            created_at=created_at,
        )
        return {"followers_written": written, "async_dispatched": False}
    else:
        # Async path: write first batch sync, dispatch rest
        sync_batch = follower_list[:SYNC_FANOUT_LIMIT]
        written = _write_feedref_batch(
            follower_ids=sync_batch,
            author_id=author_id,
            post_id=post_id,
            created_at=created_at,
        )
        remaining = follower_list[SYNC_FANOUT_LIMIT:]
        _dispatch_async_fanout(
            author_id=author_id,
            post_id=post_id,
            created_at=created_at,
            remaining_follower_ids=remaining,
        )
        return {"followers_written": written, "async_dispatched": True}


def fan_out_delete_post(*, author_id: str, post_id: str) -> Dict[str, Any]:
    """Remove all FEEDREF items for a deleted post.

    Scans POST#{post_id} partition for all FEEDREF#* sort keys.
    """
    deleted_count = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"POST#{post_id}"),
            "FilterExpression": Attr("Entity").eq("FeedRef"),
            "Limit": 500,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            with tbl.batch_writer() as bw:
                for item in items:
                    bw.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                    deleted_count += 1
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return {"deleted_count": deleted_count}


def fan_out_visibility_change(
    *,
    author_id: str,
    post_id: str,
    old_visibility: str,
    new_visibility: str,
    created_at: str,
) -> Dict[str, Any]:
    """Adjust fan-out refs when post visibility changes.

    - public -> followers: no change (followers already have refs)
    - followers -> public: no change (public posts are visible to all via can_view_post)
    - public/followers -> private: remove all fan-out refs
    - private -> public/followers: re-fan-out
    """
    if new_visibility == "private":
        return fan_out_delete_post(author_id=author_id, post_id=post_id)
    if old_visibility == "private" and new_visibility in ("public", "followers"):
        return fan_out_post_to_followers(
            author_id=author_id,
            post_id=post_id,
            created_at=created_at,
            visibility=new_visibility,
        )
    return {"action": "none"}


def backfill_feed_on_follow(
    *,
    follower_id: str,
    followed_id: str,
    limit: int = BACKFILL_LIMIT,
) -> Dict[str, Any]:
    """Write recent posts from followed user into new follower's feed.

    Called after follow_user() succeeds. Provides an immediate
    "catch-up" experience so the new follower sees existing content.
    """
    if not BACKFILL_ON_FOLLOW:
        return {"posts_backfilled": 0}

    # Query author's recent posts via GSI2
    resp = tbl.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"POST_AUTHOR#{followed_id}"),
        ScanIndexForward=False,
        Limit=limit,
    )
    posts = resp.get("Items", [])

    if not posts:
        return {"posts_backfilled": 0}

    count = 0
    with tbl.batch_writer() as bw:
        for post in posts:
            post_id = post.get("post_id")
            post_created_at = post.get("created_at", "")
            if not post_id:
                continue

            # Check post is published and not moderated
            status = post.get("status", "published")
            if status != "published":
                continue
            if post.get("moderation_removed"):
                continue

            feedref = {
                "pk": f"POST#{post_id}",
                "sk": f"FEEDREF#{follower_id}",
                "Entity": "FeedRef",
                "post_id": post_id,
                "owner_user_id": followed_id,
                "target_user_id": follower_id,
                "created_at": post_created_at,
                "GSI1PK": f"FEED#{follower_id}",
                "GSI1SK": f"{post_created_at}#POST#{post_id}",
                "fanout": True,
            }
            bw.put_item(Item=feedref)
            count += 1

    return {"posts_backfilled": count}


def _get_all_follower_ids(author_id: str, max_count: int = MAX_FOLLOWERS) -> Set[str]:
    """Paginated retrieval of all follower IDs from GSI5."""
    follower_ids: Set[str] = set()
    last_key = None
    while len(follower_ids) < max_count:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI5",
            "KeyConditionExpression": Key("GSI5PK").eq(f"FOLLOWERS#{author_id}"),
            "ProjectionExpression": "user_id",
            "Limit": FANOUT_PAGE_SIZE,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = tbl.query(**kwargs)
        for item in resp.get("Items", []):
            uid = item.get("user_id")
            if uid:
                follower_ids.add(uid)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return follower_ids


def _write_feedref_batch(
    *,
    follower_ids: List[str],
    author_id: str,
    post_id: str,
    created_at: str,
) -> int:
    """Batch-write FEEDREF items for the given follower IDs."""
    written = 0
    with tbl.batch_writer() as bw:
        for fid in follower_ids:
            feedref = {
                "pk": f"POST#{post_id}",
                "sk": f"FEEDREF#{fid}",
                "Entity": "FeedRef",
                "post_id": post_id,
                "owner_user_id": author_id,
                "target_user_id": fid,
                "created_at": created_at,
                "GSI1PK": f"FEED#{fid}",
                "GSI1SK": f"{created_at}#POST#{post_id}",
                "fanout": True,
            }
            bw.put_item(Item=feedref)
            written += 1
    return written


# -- Async Fan-Out Background Worker --

_fanout_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)


def _dispatch_async_fanout(
    *,
    author_id: str,
    post_id: str,
    created_at: str,
    remaining_follower_ids: List[str],
) -> None:
    """Queue a fan-out job for background processing."""
    job = {
        "author_id": author_id,
        "post_id": post_id,
        "created_at": created_at,
        "remaining_follower_ids": remaining_follower_ids,
    }
    try:
        _fanout_queue.put_nowait(job)
    except asyncio.QueueFull:
        logger.error("Fan-out queue full, dropping job for post %s", post_id)


async def fanout_worker():
    """Background coroutine that processes fan-out jobs."""
    while True:
        job = await _fanout_queue.get()
        try:
            _write_feedref_batch(
                follower_ids=job["remaining_follower_ids"],
                author_id=job["author_id"],
                post_id=job["post_id"],
                created_at=job["created_at"],
            )
            logger.info(
                "Async fan-out complete",
                extra={
                    "post_id": job["post_id"],
                    "followers_written": len(job["remaining_follower_ids"]),
                },
            )
        except Exception:
            logger.exception("Fan-out worker error", extra={"post_id": job.get("post_id")})
        finally:
            _fanout_queue.task_done()
```

### 3.2 Fan-Out FEEDREF Item Schema

Each fan-out FEEDREF item follows the same schema as the author's FEEDREF but targets a different user's feed:

| Attribute | Type | Value |
|-----------|------|-------|
| pk | S | `POST#{post_id}` |
| sk | S | `FEEDREF#{follower_user_id}` |
| Entity | S | `FeedRef` |
| post_id | S | The post ID |
| owner_user_id | S | The author's user_id (NOT the follower) |
| target_user_id | S | The follower's user_id |
| created_at | S | Post creation timestamp (ISO 8601) |
| GSI1PK | S | `FEED#{follower_user_id}` |
| GSI1SK | S | `{created_at}#POST#{post_id}` |
| fanout | BOOL | `True` (distinguishes fan-out refs from author's own ref) |

The `fanout: True` attribute allows queries to distinguish between "my own post" and "post from someone I follow" in the feed.

### 3.3 Sync vs Async Fan-Out Strategy

```
                    +------------------+
                    |  Post Created    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Count followers |
                    |  (GSI5 query)    |
                    +--------+---------+
                             |
                +------------+------------+
                |            |            |
         <= 500 followers   500-10K     > 10K
                |            |            |
         +------v------+  +-v--------+  +v-----------+
         | Sync fan-out|  | Async    |  | Async      |
         | (in-request)|  | (bg task)|  | (SQS/queue)|
         +-------------+  +----------+  +------------+
```

**Sync path** (<=`SYNC_FANOUT_LIMIT` followers):
- Query all followers from GSI5 (`FOLLOWERS#{author_id}`).
- Use `batch_writer()` to write FEEDREF items for each follower.
- Execute within the same HTTP request — adds ~50-200ms latency depending on follower count.

**Async path** (> `SYNC_FANOUT_LIMIT` followers):
- Write the author's own FEEDREF synchronously (ensures the author sees the post immediately).
- Dispatch a fan-out job to a background task queue.
- The fan-out job processes followers in chunks of `FANOUT_BATCH_SIZE`.
- Returns `async_dispatched: True` in the response.

**Background task implementation** (for dev/single-process mode):
```python
import asyncio

_fanout_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

async def _fanout_worker():
    """Background coroutine that processes fan-out jobs."""
    while True:
        job = await _fanout_queue.get()
        try:
            _execute_fanout_batch(job)
        except Exception:
            logger.exception("Fan-out worker error", extra=job)
        finally:
            _fanout_queue.task_done()
```

In production, this would be replaced by SQS + Lambda or a dedicated worker process.

### 3.4 Fan-Out on Post Delete

When a post is deleted, all FEEDREF items must be removed. The implementation scans the `POST#{post_id}` partition for all `FEEDREF#*` sort keys and deletes them. Since FEEDREF items are keyed under `POST#{post_id}`, this is an efficient partition scan (full implementation in section 3.1 `fan_out_delete_post`).

### 3.5 Fan-Out on Follow/Unfollow

When user A follows user B, A should see B's recent posts in their feed. Two strategies:

**Option 1: Backfill recent posts on follow** (recommended for <=50 posts):
- Query GSI2 for `POST_AUTHOR#{B}` to get B's recent N posts (e.g., N=50).
- Write FEEDREF items for each post into A's feed (`FEED#{A}`).
- This provides an immediate "catch-up" experience.

**Option 2: Lazy merge on feed read**:
- When reading A's feed, also query `POST_AUTHOR` for each followed user and merge results.
- More complex, higher read latency, but no backfill writes.

We choose **Option 1** for simplicity and write-once-read-many efficiency.

On **unfollow**, we do NOT immediately remove B's posts from A's feed (too expensive for large post histories). Instead, the feed query's existing `can_view_post()` filter (line 2146) checks `is_following()` for `visibility="followers"` posts, which will return false after unfollow. Public posts remain visible.

### 3.6 Integration with Post Create Flow

Modify `create_post()` in `app/routers/newsfeed.py` to call fan-out after writing the author's feed ref:

```python
# After _write_feed_ref_for_published_post() call (around line 3117)
if not is_scheduled:
    from app.services.newsfeed_fanout import fan_out_post_to_followers
    try:
        fanout_result = fan_out_post_to_followers(
            author_id=user_id,
            post_id=post_id,
            created_at=created_at,
            visibility=req.visibility or "followers",
        )
        logger.info(
            "Post fan-out complete",
            extra={"post_id": post_id, "followers_written": fanout_result.get("followers_written", 0)},
        )
    except Exception:
        logger.exception("Post fan-out failed (non-fatal)", extra={"post_id": post_id})
        # Fan-out failure is non-fatal — the author's own feed ref was already written.
        # Followers will see the post on next fan-out retry or via author profile browse.
```

### 3.7 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Optional


class FanOutStatus(BaseModel):
    """Returned as part of post create response to indicate fan-out state."""
    followers_written: int = Field(default=0, ge=0)
    async_dispatched: bool = False


class FanOutJobRecord(BaseModel):
    """Internal model for async fan-out queue items."""
    author_id: str
    post_id: str
    created_at: str
    visibility: str = "followers"
    follower_cursor: Optional[str] = None
    batch_index: int = 0
```

### 3.8 Configuration

```python
# Environment variables with defaults
NEWSFEED_SYNC_FANOUT_LIMIT = int(os.environ.get("NEWSFEED_SYNC_FANOUT_LIMIT", "500"))
NEWSFEED_FANOUT_ENABLED = os.environ.get("NEWSFEED_FANOUT_ENABLED", "true").lower() == "true"
NEWSFEED_FANOUT_BACKFILL_ON_FOLLOW = os.environ.get("NEWSFEED_FANOUT_BACKFILL_ON_FOLLOW", "true").lower() == "true"
NEWSFEED_FANOUT_BACKFILL_LIMIT = int(os.environ.get("NEWSFEED_FANOUT_BACKFILL_LIMIT", "50"))
NEWSFEED_FANOUT_MAX_FOLLOWERS = int(os.environ.get("NEWSFEED_FANOUT_MAX_FOLLOWERS", "100000"))
```

**Kill switch**: If `NEWSFEED_FANOUT_ENABLED=false`, `fan_out_post_to_followers()` returns immediately with `followers_written=0`. This allows disabling fan-out without a code deploy if it causes DDB throughput issues.

### 3.9 Feed Query Changes

The existing feed query (`GET /feed`) requires minimal changes. The query already reads from GSI1 and batch-fetches full post items. The only addition is:

1. **Source attribution**: The feed response should indicate whether a post is from the viewer ("own") or from a followed user ("following"). Add a `source` field to the feed item response:

```python
class FeedItem(BaseModel):
    # ... existing fields ...
    source: Literal["own", "following"] = "own"
```

Derived from the `fanout` boolean on the FEEDREF item.

2. **Deduplication**: If the viewer is also the author (they see their own post via the author ref AND a self-fan-out ref — which should not exist but might due to race conditions), deduplicate by post_id.

### 3.10 DynamoDB Cost Analysis

| Scenario | Writes per Post | Cost per Post (on-demand, $1.25/M WCU) |
|----------|----------------|------------------------------------------|
| 0 followers | 1 (author ref) | $0.00000125 |
| 100 followers | 101 | $0.000126 |
| 1,000 followers | 1,001 | $0.00125 |
| 10,000 followers | 10,001 | $0.0125 |
| 100,000 followers | 100,001 | $0.125 |

For a creator with 100K followers posting 10 times/day: ~$1.25/day in DDB write costs. This is acceptable for on-demand pricing but would benefit from provisioned capacity for high-volume creators.

### 3.11 Fan-Out Write Path Diagram

```
+-------------------------------------------------------------------+
|                     Fan-Out Write Path                              |
+-------------------------------------------------------------------+
|                                                                     |
|  create_post(user_id="alice", post_id="p_123", ...)                |
|       |                                                             |
|       v                                                             |
|  1. Write post item:                                                |
|     PK=POST#p_123, SK=POST                                         |
|     GSI2PK=POST_AUTHOR#alice (author index)                        |
|       |                                                             |
|       v                                                             |
|  2. Write author's FEEDREF:                                         |
|     PK=POST#p_123, SK=FEEDREF#alice                                |
|     GSI1PK=FEED#alice, GSI1SK=2026-05-26T14:00:00Z#POST#p_123     |
|     fanout=False                                                    |
|       |                                                             |
|       v                                                             |
|  3. fan_out_post_to_followers(author_id="alice", post_id="p_123")  |
|       |                                                             |
|       v                                                             |
|  4. _get_all_follower_ids("alice") via GSI5                        |
|     -> {bob, charlie, dave}  (3 followers, <= 500 = sync)          |
|       |                                                             |
|       v                                                             |
|  5. _write_feedref_batch():                                         |
|     batch_writer.put_item:                                          |
|       PK=POST#p_123, SK=FEEDREF#bob                                |
|       GSI1PK=FEED#bob, GSI1SK=2026-05-26T14:00:00Z#POST#p_123     |
|       fanout=True                                                   |
|     batch_writer.put_item:                                          |
|       PK=POST#p_123, SK=FEEDREF#charlie                            |
|       GSI1PK=FEED#charlie, GSI1SK=2026-05-26T14:00:00Z#POST#p_123 |
|       fanout=True                                                   |
|     batch_writer.put_item:                                          |
|       PK=POST#p_123, SK=FEEDREF#dave                               |
|       GSI1PK=FEED#dave, GSI1SK=2026-05-26T14:00:00Z#POST#p_123    |
|       fanout=True                                                   |
|       |                                                             |
|       v                                                             |
|  return {"followers_written": 3, "async_dispatched": False}        |
+-------------------------------------------------------------------+

Feed Read Path (after fan-out):

  Bob opens /feed
       |
       v
  GSI1 query: GSI1PK=FEED#bob
       |
       v
  Returns FEEDREF items:
    - FEEDREF#bob (from alice's post p_123, fanout=True)
    - FEEDREF#bob (from bob's own post p_456, fanout=False)
    - FEEDREF#bob (from charlie's post p_789, fanout=True)
       |
       v
  batch_get_item for full post records
       |
       v
  Filter: can_view_post(), is_hidden(), etc.
       |
       v
  Return timeline with source attribution:
    [
      {post_id: "p_789", author: "charlie", source: "following", ...},
      {post_id: "p_456", author: "bob", source: "own", ...},
      {post_id: "p_123", author: "alice", source: "following", ...},
    ]
```

---

## 4. Implementation Plan

### Step 1: Create Fan-Out Service Module

**File**: `app/services/newsfeed_fanout.py` (new file, ~400 lines)

Core functions:
- `fan_out_post_to_followers()` — Main fan-out function.
- `fan_out_delete_post()` — Delete all FEEDREF items for a post.
- `fan_out_visibility_change()` — Adjust refs on visibility change.
- `backfill_feed_on_follow()` — Write recent posts into new follower's feed.
- `_get_all_follower_ids()` — Paginated follower ID retrieval from GSI5.
- `_write_feedref_batch()` — Batch-write FEEDREF items.
- `_dispatch_async_fanout()` — Queue a fan-out job for background processing.
- `fanout_worker()` — Background task coroutine.

Full implementations provided in section 3.1.

### Step 2: Integrate Fan-Out into Post Create

**File**: `app/routers/newsfeed.py`

**Location**: After `_write_feed_ref_for_published_post()` call in `create_post()` (around line 3117).

**Changes**:
- Line 3117+: Add `from app.services.newsfeed_fanout import fan_out_post_to_followers`
- Line 3118+: Add try/except block calling `fan_out_post_to_followers()` with post details
- Line 3119+: Log fan-out result with `logger.info()`
- Fan-out failure is wrapped in try/except — it is non-fatal (author's own FEEDREF already written)

**Lines modified**: ~15

### Step 3: Integrate Fan-Out into Post Delete

**File**: `app/routers/newsfeed.py`

**Location**: In the post delete handler (search for `delete_post` or the DELETE endpoint).

**Changes**:
- After deleting the post item and author's FEEDREF, call `fan_out_delete_post()`.
- Non-fatal: if fan-out delete fails, log and continue.
- Import `fan_out_delete_post` from `newsfeed_fanout`

**Lines modified**: ~10

### Step 4: Integrate Fan-Out into Scheduled Post Publishing

**File**: `app/services/newsfeed_scheduler.py`

**Location**: After the scheduler promotes a post from `scheduled` to `published` and writes the author's feed ref.

**Changes**:
- Import `fan_out_post_to_followers` from `newsfeed_fanout`
- Call `fan_out_post_to_followers()` with the published post's details.
- Wrap in try/except (non-fatal)

**Lines modified**: ~10

### Step 5: Integrate Backfill on Follow

**File**: `app/services/social.py` (from SOC-001)

**Location**: In `follow_user()` after the follow record is written and counts incremented.

**Changes**:
- Import `backfill_feed_on_follow` from `newsfeed_fanout`
- Call backfill after a successful follow (not on `already_following`).
- Non-fatal: if backfill fails, log and continue.

**Lines modified**: ~10

### Step 6: Add Feed Source Attribution

**File**: `app/routers/newsfeed.py`

**Location**: In the feed query response builder (around line 4060).

**Changes**:
- When building the feed response from FEEDREF items (line 4049-4050), check if the FEEDREF item has `fanout=True`
- Set `source="following"` if fanout, `source="own"` otherwise
- Pass `source` through to the response dict for each post

**Lines modified**: ~10

### Step 7: Add Background Worker Startup

**File**: `app/main.py`

**Location**: In the app startup event handler.

**Changes**:
- Import `fanout_worker` from `app.services.newsfeed_fanout`
- In the `@app.on_event("startup")` handler (or lifespan), create an asyncio task: `asyncio.create_task(fanout_worker())`
- Register shutdown handler to cancel the task

**Lines modified**: ~10

### Step 8: Add Environment Variable Defaults

**File**: `.env.local.example`

```
NEWSFEED_FANOUT_ENABLED=true
NEWSFEED_SYNC_FANOUT_LIMIT=500
NEWSFEED_FANOUT_BACKFILL_ON_FOLLOW=true
NEWSFEED_FANOUT_BACKFILL_LIMIT=50
NEWSFEED_FANOUT_MAX_FOLLOWERS=100000
```

### Step 9: Update Frontend Feed Display

**File**: `frontend/src/pages/feed/PostCard.tsx`

**Changes**:
- If `source === "following"`, show a small "Followed" label or author attribution above the post card (e.g., "Alice posted").
- This helps distinguish between the viewer's own posts and posts from followed users.

**Lines modified**: ~15

### Step 10: Frontend Feed Type Updates

**File**: `frontend/src/api/types.ts`

Add `source?: "own" | "following"` to the `FeedPost` interface.

### Summary of Files Modified/Created

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/services/newsfeed_fanout.py` | New file | ~400 |
| `app/routers/newsfeed.py` | Integrate fan-out calls | ~40 |
| `app/services/newsfeed_scheduler.py` | Add fan-out on publish | ~10 |
| `app/services/social.py` | Add backfill on follow | ~10 |
| `app/main.py` | Start background worker | ~10 |
| `.env.local.example` | Add env vars | ~5 |
| `frontend/src/pages/feed/PostCard.tsx` | Source attribution | ~15 |
| `frontend/src/api/types.ts` | Add source field | ~2 |
| **Total** | | **~492** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_newsfeed_fanout.py`)

New file, ~500 lines. Tests the fan-out service layer with moto-mocked DynamoDB.

**Complete test function signatures**:

```python
import pytest
from moto import mock_dynamodb
from app.services.newsfeed_fanout import (
    fan_out_post_to_followers,
    fan_out_delete_post,
    fan_out_visibility_change,
    backfill_feed_on_follow,
    _get_all_follower_ids,
    _write_feedref_batch,
)

@pytest.fixture
def fanout_tables():
    """Create app_single_table with GSI1, GSI2, GSI5 and profiles table."""
    # Create tables, seed follower data
    ...

def test_sync_fanout_to_5_followers(fanout_tables):
    """Create author + 5 followers. Create post. Verify 5 FEEDREF items."""
    # Seed: create 5 follow records with GSI5PK=FOLLOWERS#author
    for i in range(5):
        _create_follow(f"follower_{i}", "author")
    result = fan_out_post_to_followers(
        author_id="author", post_id="p_1", created_at="2026-05-26T14:00:00Z"
    )
    assert result["followers_written"] == 5
    assert result["async_dispatched"] is False
    # Verify each FEEDREF exists
    for i in range(5):
        item = tbl.get_item(Key={"pk": "POST#p_1", "sk": f"FEEDREF#follower_{i}"}).get("Item")
        assert item is not None
        assert item["GSI1PK"] == f"FEED#follower_{i}"
        assert item["fanout"] is True

def test_author_feedref_unaffected(fanout_tables):
    """Verify the author's FEEDREF has fanout absent/False."""
    _create_follow("bob", "alice")
    # Write author's own FEEDREF (simulating _write_feed_ref_for_published_post)
    tbl.put_item(Item={
        "pk": "POST#p_1", "sk": "FEEDREF#alice",
        "Entity": "FeedRef", "GSI1PK": "FEED#alice",
        "GSI1SK": "2026-05-26T14:00:00Z#POST#p_1",
    })
    fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    author_ref = tbl.get_item(Key={"pk": "POST#p_1", "sk": "FEEDREF#alice"}).get("Item")
    assert author_ref.get("fanout") is not True  # Author's ref should not have fanout=True

def test_fanout_skips_self(fanout_tables):
    """Author should not get a fan-out ref if they follow themselves."""
    _create_follow("alice", "alice")  # Self-follow
    _create_follow("bob", "alice")
    result = fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    assert result["followers_written"] == 1  # Only bob, not alice

def test_fanout_visibility(fanout_tables):
    """Post visibility=followers fans out to all followers. Public also fans out."""
    _create_follow("bob", "alice")
    r1 = fan_out_post_to_followers(
        author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z", visibility="followers"
    )
    assert r1["followers_written"] == 1
    r2 = fan_out_post_to_followers(
        author_id="alice", post_id="p_2", created_at="2026-05-26T14:01:00Z", visibility="public"
    )
    assert r2["followers_written"] == 1

def test_sync_fanout_limit_triggers_async(fanout_tables, monkeypatch):
    """With 600 followers, verify async dispatch is triggered."""
    monkeypatch.setattr("app.services.newsfeed_fanout.SYNC_FANOUT_LIMIT", 500)
    for i in range(600):
        _create_follow(f"f_{i}", "popular")
    result = fan_out_post_to_followers(
        author_id="popular", post_id="p_1", created_at="2026-05-26T14:00:00Z"
    )
    assert result["followers_written"] == 500
    assert result["async_dispatched"] is True

def test_fanout_delete_removes_all_refs(fanout_tables):
    """Create post + fan-out, delete, verify all FEEDREF items removed."""
    for i in range(5):
        _create_follow(f"f_{i}", "alice")
    fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    tbl.put_item(Item={"pk": "POST#p_1", "sk": "FEEDREF#alice", "Entity": "FeedRef"})  # Author ref
    result = fan_out_delete_post(author_id="alice", post_id="p_1")
    assert result["deleted_count"] == 6  # 5 followers + 1 author

def test_fanout_on_scheduled_post_publish(fanout_tables):
    """Schedule a post, simulate publish, verify fan-out refs created."""
    _create_follow("bob", "alice")
    # Simulate scheduler publishing
    fan_out_post_to_followers(author_id="alice", post_id="p_sched", created_at="2026-05-26T15:00:00Z")
    item = tbl.get_item(Key={"pk": "POST#p_sched", "sk": "FEEDREF#bob"}).get("Item")
    assert item is not None

def test_backfill_on_follow(fanout_tables):
    """User B has 10 posts. User A follows B. Verify A's feed contains B's posts."""
    for i in range(10):
        _create_post("bob", f"p_{i}", f"2026-05-{20+i}T00:00:00Z")
    result = backfill_feed_on_follow(follower_id="alice", followed_id="bob")
    assert result["posts_backfilled"] == 10

def test_backfill_limit(fanout_tables):
    """User B has 100 posts, BACKFILL_LIMIT=50. Verify only 50 backfilled."""
    for i in range(100):
        _create_post("bob", f"p_{i}", f"2026-05-26T{i:02d}:00:00Z")
    result = backfill_feed_on_follow(follower_id="alice", followed_id="bob", limit=50)
    assert result["posts_backfilled"] == 50

def test_fanout_disabled_via_kill_switch(fanout_tables, monkeypatch):
    """Set FANOUT_ENABLED=false, verify followers_written=0."""
    monkeypatch.setattr("app.services.newsfeed_fanout.FANOUT_ENABLED", False)
    _create_follow("bob", "alice")
    result = fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    assert result["followers_written"] == 0

def test_feed_query_returns_fanout_posts(fanout_tables):
    """After fan-out, query follower's feed via GSI1. Verify posts appear."""
    _create_follow("bob", "alice")
    _create_post("alice", "p_1", "2026-05-26T14:00:00Z")
    fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    resp = tbl.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("FEED#bob"),
    )
    post_ids = [it.get("post_id") for it in resp.get("Items", [])]
    assert "p_1" in post_ids

def test_feed_source_attribution(fanout_tables):
    """Verify fan-out posts have fanout=True, own posts do not."""
    _create_follow("bob", "alice")
    fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    fanout_ref = tbl.get_item(Key={"pk": "POST#p_1", "sk": "FEEDREF#bob"}).get("Item")
    assert fanout_ref.get("fanout") is True

def test_concurrent_fanout(fanout_tables):
    """Two posts created simultaneously. Verify both fan out without interference."""
    _create_follow("bob", "alice")
    r1 = fan_out_post_to_followers(author_id="alice", post_id="p_1", created_at="2026-05-26T14:00:00Z")
    r2 = fan_out_post_to_followers(author_id="alice", post_id="p_2", created_at="2026-05-26T14:01:00Z")
    assert r1["followers_written"] == 1
    assert r2["followers_written"] == 1

def test_large_fanout_performance(fanout_tables):
    """Performance: 1000 followers, verify all refs written."""
    for i in range(1000):
        _create_follow(f"f_{i}", "popular")
    result = fan_out_post_to_followers(
        author_id="popular", post_id="p_1", created_at="2026-05-26T14:00:00Z"
    )
    assert result["followers_written"] >= 500  # At least sync batch
```

### 5.2 E2E Tests (`frontend/e2e/feed-fanout.spec.ts`)

New file, ~400 lines.

**Section 95: Fan-Out API (8 tests)**:

1. `Bob sees Alice's post in feed after following her` — Alice creates post, Bob follows Alice, Bob queries feed, verifies post appears.
2. `Bob does not see Alice's post before following` — Bob queries feed before following, verifies Alice's post absent.
3. `Fan-out post has source="following"` — Verify `source` field in feed response.
4. `Unfollow hides followers-only posts from feed` — Bob unfollows Alice, queries feed, verifies `visibility="followers"` post is filtered by `can_view_post()`.
5. `Public posts remain visible after unfollow` — Alice's `visibility="public"` post still appears in Bob's feed after unfollow (FEEDREF still exists, visibility check passes).
6. `Post delete removes from follower feeds` — Alice deletes post, Bob queries feed, verifies post gone.
7. `Backfill on follow` — Alice has 5 existing posts. Bob follows Alice. Bob's feed immediately contains all 5.
8. `Fan-out disabled returns empty` — Set `NEWSFEED_FANOUT_ENABLED=false`, create post, verify no FEEDREF items for followers.

**Section 96: Feed Timeline UI (5 tests)**:

1. `Following posts appear in feed timeline` — Alice creates post, Bob (following Alice) loads /feed, verifies post card visible.
2. `Author attribution shown on followed posts` — Verify "Alice posted" label above post card.
3. `Own posts show without attribution` — Bob's own posts show without "Bob posted" label.
4. `Feed loads both own and followed posts in chronological order` — Create interleaved posts from Alice and Bob, verify feed order.
5. `Infinite scroll loads older posts from followed users` — Verify pagination includes fan-out posts.

**Section 97: Fan-Out with Scheduled Posts (3 tests)**:

1. `Scheduled post does not fan out until published` — Alice creates scheduled post, Bob's feed does not contain it.
2. `Published scheduled post appears in follower feeds` — Trigger scheduler, verify post fans out.
3. `Cancelled scheduled post never fans out` — Cancel before publish_at, verify no FEEDREF items.

**Test Setup (beforeAll)**:
- Seed sessions for Alice and Bob via `e2e_admin_session_setup.py`.
- Alice follows Bob and Bob follows Alice (bidirectional follow for testing).
- Create a few baseline posts from each user.

### 5.3 Edge Cases

1. **Race condition: follow during fan-out** — User A follows B while B is creating a post. B's fan-out query may or may not include A. Acceptable: A will see the post on next feed load if backfill-on-follow catches it.

2. **Deleted user's fan-out refs** — If a user is deleted, their FEEDREF items remain as orphans in followers' feeds. The feed query's `batch_get_item` for the full post will return nothing for deleted posts. Handle gracefully by skipping items where the post lookup returns no result.

3. **Hot partition on popular creator** — A creator with 1M followers writing a fan-out FEEDREF for each. The writes target different GSI1PK partitions (`FEED#{follower_id}`), so the base table distributes well. However, reading the followers list from GSI5 (`FOLLOWERS#{creator_id}`) hits a single partition. Pagination with 500-item pages mitigates this.

4. **Double fan-out on retry** — If the fan-out call is retried (e.g., timeout + retry), duplicate FEEDREF items are harmless since `put_item` is idempotent for the same `pk+sk`.

5. **Feed size bloat** — A user following 1000 active creators who each post 10x/day generates 10K FEEDREF items/day. GSI1 queries remain efficient as DynamoDB paginates. The feed query already has a budget/timeout mechanism (`max_elapsed_ms`, line 4022) to prevent runaway queries.

6. **Unfollow does not delete fan-out refs** — By design, unfollowing does NOT remove existing FEEDREF items (too expensive). Instead, `can_view_post()` filters `visibility="followers"` posts at query time. This means:
   - Public posts from unfollowed users remain in feed (acceptable).
   - Followers-only posts are filtered out at read time (correct behavior).
   - Over time, stale FEEDREF items accumulate. A TTL mechanism or periodic cleanup job should garbage-collect FEEDREF items older than 90 days.

### 5.4 Performance Benchmarks

| Scenario | Expected Latency (added to post create) |
|----------|------------------------------------------|
| 0 followers (no fan-out) | +0ms |
| 10 followers (sync) | +30ms |
| 100 followers (sync) | +150ms |
| 500 followers (sync) | +500ms |
| 1000 followers (async) | +5ms (dispatch only) |
| 10K followers (async) | +5ms (dispatch only) |

Feed read latency is unchanged — GSI1 queries are O(page_size) regardless of total feed refs.

### 5.5 Monitoring

Add the following metrics to `app/metrics.py`:

```python
record_newsfeed_fanout_followers_written   # Counter: total FEEDREF items written
record_newsfeed_fanout_latency             # Histogram: time to complete fan-out
record_newsfeed_fanout_async_dispatched    # Counter: async fan-out jobs dispatched
record_newsfeed_fanout_error               # Counter: fan-out errors (by error_type)
record_newsfeed_fanout_backfill_posts      # Counter: posts backfilled on follow
```

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- Fan-out is triggered server-side as a side effect of `create_post()` — no direct API endpoint for fan-out. Users cannot trigger fan-out for arbitrary posts.
- The `backfill_feed_on_follow()` function is called from `follow_user()` which requires `require_ui_session` — no unauthenticated backfill.
- The feed query (`GET /feed`) requires `UserIdDep` auth — a user can only read their own feed (no reading other users' feeds).

### 6.2 Input Validation

- `fan_out_post_to_followers()` only accepts `author_id` and `post_id` that come from the authenticated post creation flow. No user input is directly passed.
- `backfill_feed_on_follow()` validates that posts exist and are published before creating FEEDREF items.

### 6.3 Abuse Vectors

- **Post spam to inflate feed**: A user creates hundreds of posts rapidly. Fan-out amplifies this. Mitigation: existing post creation rate limit (in `create_post()`) caps posts per user. Fan-out volume is a multiplier on post volume, not an independent attack vector.
- **Follow/unfollow cycling to spam backfill**: Each follow triggers backfill of up to 50 posts. Rapidly following and unfollowing generates many FEEDREF writes. Mitigation: SOC-001 rate limit (30 follows/minute) caps this to 1500 FEEDREF writes/minute per user.

### 6.4 Data Privacy

- FEEDREF items contain `owner_user_id` (author) and `target_user_id` (follower). These are internal system references, not exposed in the API response.
- The `fanout` boolean flag does not reveal sensitive information — it is only used for source attribution in the feed UI.

---

## 7. Migration & Rollback Plan

### 7.1 No Schema Changes Required

Fan-out uses the existing GSI1 index and existing `app_single_table`. No new tables or GSIs needed. The only prerequisite is SOC-001's GSI5 (for follower queries).

### 7.2 Data Backfill for Existing Posts

Existing posts have no fan-out FEEDREF items. A migration script must:

1. For each user U, get their following list (all users they follow).
2. For each followed user F, get F's recent N posts (e.g., N=100).
3. Write FEEDREF items into U's feed for each of F's posts.

This is a large batch operation. Estimate: 10K users * avg 50 followed * avg 20 recent posts = 10M FEEDREF items. At 1000 WCU/s, this takes ~2.8 hours.

```python
# scripts/migrate_fanout_backfill.py

def backfill_all_feeds():
    """One-time migration: create FEEDREF items for all existing follow relationships."""
    profiles_resp = T.profile.scan(ProjectionExpression="user_sub")
    users = [item["user_sub"] for item in profiles_resp.get("Items", [])]

    total_written = 0
    for user_id in users:
        # Get user's following list
        following_ids = _get_following_ids(user_id)
        for followed_id in following_ids:
            result = backfill_feed_on_follow(
                follower_id=user_id,
                followed_id=followed_id,
                limit=100,
            )
            total_written += result["posts_backfilled"]
        time.sleep(0.05)  # Throttle: 20 users/second

    return {"total_feedref_items_written": total_written}
```

**Migration approach**: Run as a background script during off-peak hours with throttling to avoid impacting production DDB throughput.

### 7.3 Feature Flag Rollout

1. Deploy code with `NEWSFEED_FANOUT_ENABLED=false` (default OFF).
2. Verify all unit and integration tests pass.
3. Enable on staging: `NEWSFEED_FANOUT_ENABLED=true`.
4. Run backfill migration on staging.
5. Monitor for 24 hours: check DDB throughput, feed latency, error rates.
6. Enable on production: `NEWSFEED_FANOUT_ENABLED=true`.
7. Run production backfill migration.

### 7.4 Rollback Steps

1. Set `NEWSFEED_FANOUT_ENABLED=false` — stops all new fan-out writes.
2. Existing FEEDREF items remain but are harmless (feed query still works, just shows more posts).
3. To fully revert, run a cleanup script that deletes all FEEDREF items where `fanout=True`.
4. No data loss — author's own FEEDREF items are never modified by fan-out code.

### 7.5 Zero-Downtime Deployment

Fan-out is additive — it writes new FEEDREF items without modifying existing data. The feed query handles both states (with and without fan-out) because it reads whatever FEEDREF items exist for the viewer. Deployment requires no downtime.

---

## 8. Operational Runbook

### 8.1 Metrics to Add

```python
# app/metrics.py additions
record_fanout_sync_written     # Counter: FEEDREF items written in sync path
record_fanout_async_dispatched # Counter: jobs sent to background worker
record_fanout_async_written    # Counter: FEEDREF items written by background worker
record_fanout_latency_ms       # Histogram: fan-out latency per post (sync path only)
record_fanout_error            # Counter: fan-out errors by error_type
record_fanout_queue_depth      # Gauge: current async queue depth
record_fanout_backfill_posts   # Counter: posts backfilled on follow
record_fanout_delete_count     # Counter: FEEDREF items deleted on post delete
```

### 8.2 Alerting Thresholds

| Metric | Threshold | Action |
|--------|-----------|--------|
| `fanout_latency_ms_p99` | > 1000ms | Investigate DDB throttling |
| `fanout_queue_depth` | > 500 | Background worker falling behind — scale workers |
| `fanout_error_rate` | > 0.1% | Check DDB health, GSI5 status |
| `fanout_sync_written` | > 50K/min | Unusual spike — possible spam attack |

### 8.3 Common Debugging Scenarios

**Posts not appearing in follower feeds**: Check: (1) Is `NEWSFEED_FANOUT_ENABLED=true`? (2) Does the author have followers in GSI5? (3) Is the follow record `state=following`? (4) Check if FEEDREF items were written: `query pk=POST#{post_id}, sk begins_with FEEDREF#`.

**Feed showing duplicate posts**: The deduplication logic in the feed query should prevent this. Check for duplicate FEEDREF items (same `pk+sk` should be impossible with DDB). If duplicates appear, verify the `post_id` dedup set in the feed query builder.

**Fan-out queue backing up**: Check `fanout_queue_depth` metric. If growing, the background worker may be stuck. Restart the backend process. If recurring, increase worker concurrency or move to SQS.

### 8.4 Log Patterns

```
INFO  newsfeed_fanout.fan_out_post_to_followers post_id=p_123 followers_written=42 async_dispatched=false latency_ms=150
INFO  newsfeed_fanout.fanout_worker post_id=p_456 followers_written=8500 (async batch complete)
ERROR newsfeed_fanout.fan_out_post_to_followers ClientError: ProvisionedThroughputExceededException post_id=p_789
WARN  newsfeed_fanout._dispatch_async_fanout Queue full, dropping job for post p_999
```

---

## 9. Performance & Capacity Planning

### 9.1 Expected Throughput

| Scenario | Posts/day | Fan-out writes/day | Total FEEDREF items |
|----------|----------|-------------------|---------------------|
| 1K users, avg 50 followers, 5 posts/day | 5,000 | 250,000 | 250K/day |
| 10K users, avg 200 followers, 5 posts/day | 50,000 | 10,000,000 | 10M/day |
| 100K users, avg 500 followers, 5 posts/day | 500,000 | 250,000,000 | 250M/day |

### 9.2 DDB Capacity Units

At on-demand pricing:
- 10K users scenario: 10M WCU/day = $12.50/day = $375/month
- Write costs scale linearly with (users * avg_followers * posts_per_day)

### 9.3 Hot Partition Analysis

**GSI1 (FEED#{user_id})**: Each user's feed partition receives one write per post from each followed creator. A user following 100 creators who each post 10x/day = 1000 writes/day to that partition. Well within DDB limits.

**GSI5 (FOLLOWERS#{author_id})**: Read-heavy during fan-out. A creator with 100K followers triggers a full scan of their FOLLOWERS partition. At 500 items/page, this is 200 paginated queries. Each query returns in ~5ms, so total GSI5 read time is ~1 second.

**Base table partitions**: Fan-out writes to `POST#{post_id}` partition (one item per follower). A post with 100K fan-out refs means the `POST#p_123` partition holds 100K items (~20MB). Below DDB's 10GB partition limit.

### 9.4 Caching Strategy

- **Follower ID list**: For the async fan-out path, the follower list is fetched once and passed to the background worker. No caching needed.
- **Feed query results**: Frontend uses React Query with `staleTime: 30_000`. No server-side caching of feed query results (DDB queries are fast enough).
- **Post data**: The feed query's `batch_get_item` for full posts benefits from DDB's internal caching (DAX would add a dedicated cache layer if needed).

### 9.5 FEEDREF TTL Cleanup

FEEDREF items from unfollowed users accumulate over time. Add a `ttl` attribute set to 90 days from creation. Enable DDB TTL on the `app_single_table` to automatically delete expired items.

```python
# In _write_feedref_batch():
feedref["ttl"] = int(time.time()) + (90 * 86400)  # 90 days from now
```

---

## 10. Dependency Analysis

### 10.1 Tickets This Is Blocked By

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| SOC-001 | GSI5 follower index | Fan-out queries GSI5 `FOLLOWERS#{author_id}` to get follower list |
| SOC-001 | `follow_user()` | Backfill on follow is called from `follow_user()` |

### 10.2 Tickets This Blocks

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| SOC-005 | Feed content | Profile post grid uses the same data that fans out |

### 10.3 Integration Points

- **`app/services/newsfeed_fanout.py::fan_out_post_to_followers()`** — called from `create_post()` in `app/routers/newsfeed.py`
- **`app/services/newsfeed_fanout.py::backfill_feed_on_follow()`** — called from `follow_user()` in `app/services/social.py`
- **`app/services/newsfeed_fanout.py::fan_out_delete_post()`** — called from the post delete handler in `app/routers/newsfeed.py`
- **`app/services/newsfeed_fanout.py::fanout_worker()`** — started as a background task in `app/main.py`

---

## 11. Acceptance Criteria

1. When a user creates a post, FEEDREF items are written for all followers within 2 seconds (sync for <=500 followers, async for more).
2. A follower's `GET /feed` returns the author's post after fan-out completes.
3. Each FEEDREF item has `fanout=True` to distinguish from the author's own ref.
4. The feed response includes `source: "following"` for fan-out posts and `source: "own"` for the user's own posts.
5. Deleting a post removes all FEEDREF items (both author's and followers').
6. When a new follow relationship is created, the follower's feed is backfilled with up to 50 recent posts from the followed user.
7. The `NEWSFEED_FANOUT_ENABLED=false` kill switch stops all fan-out writes without affecting existing data.
8. Fan-out failure is non-fatal — the author's own FEEDREF is always written regardless of fan-out outcome.
9. The feed query correctly deduplicates posts that might appear both as author refs and fan-out refs.
10. Fan-out latency adds less than 500ms to post creation for users with <=500 followers.

---

## 12. Error Handling Matrix

| Error Condition | HTTP Status | Error Code | User Message | Recovery |
|----------------|-------------|------------|--------------|----------|
| Fan-out DDB write failure | 200 (post created) | N/A (non-fatal) | N/A (post succeeds) | Retry via background worker |
| GSI5 query timeout | 200 (post created) | N/A (non-fatal) | N/A | Manual fan-out trigger |
| Async queue full | 200 (post created) | N/A (logged) | N/A | Increase queue size or add workers |
| Backfill on follow failure | 200 (follow succeeds) | N/A (non-fatal) | N/A | Manual backfill or wait for feed refresh |
| FEEDREF delete failure on post delete | 200 (post deleted) | N/A (logged) | N/A | Cleanup job removes orphans |
| Kill switch active | 200 (post created, no fan-out) | N/A | N/A | Enable `NEWSFEED_FANOUT_ENABLED` |
| DDB throughput exceeded | 200 (partial writes) | N/A (retried) | N/A | Scale DDB capacity |

---

## 13. Frontend Component Specifications

### 13.1 Feed Source Attribution

```typescript
// PostCard.tsx additions
interface PostCardProps {
  post: FeedPost;
  source?: "own" | "following";  // New prop
}

// Display logic:
{source === "following" && (
  <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
    <Avatar className="h-5 w-5">
      <AvatarImage src={post.author_photo_url} />
    </Avatar>
    <span>{post.author_display_name} posted</span>
  </div>
)}
```

### 13.2 React Query Key Structures

```typescript
// Feed query (existing, no change)
["feed", { author?: string, cursor?: string }]  // -> FeedResponse

// The source field is included in each post item returned by the feed query.
// No new React Query keys needed for fan-out — it is transparent to the frontend.
```

### 13.3 Loading States

- **Feed loading**: Existing skeleton loader. No change.
- **Fan-out in progress**: The post creation response may include `fanout: { async_dispatched: true }`. The frontend can show a subtle "Sharing with your followers..." toast if desired, but this is optional (fan-out is invisible to the author in most cases).

---

## 14. Internationalization Considerations

### 14.1 Translatable Strings

| Key | Default (English) | Notes |
|-----|-------------------|-------|
| `feed.source.following` | "{name} posted" | Author attribution on fan-out posts |
| `feed.source.shared` | "{name} shared" | Future: for re-shared posts |

### 14.2 RTL Support

The author attribution line ("Alice posted") should respect RTL direction. The avatar position flips to the right side in RTL layouts.

---

## Appendix A: One-Time Migration for Existing Posts

Existing posts have no fan-out FEEDREF items. A migration script must:

1. For each user U, get their following list (all users they follow).
2. For each followed user F, get F's recent N posts (e.g., N=100).
3. Write FEEDREF items into U's feed for each of F's posts.

This is a large batch operation. Estimate: 10K users * avg 50 followed * avg 20 recent posts = 10M FEEDREF items. At 1000 WCU/s, this takes ~2.8 hours.

**Migration approach**: Run as a background script during off-peak hours with throttling to avoid impacting production DDB throughput.

## Appendix B: Sequence Diagram — Post Create with Fan-Out

```
Author          Backend           DDB (app_single_table)       Background Worker
  |                |                       |                         |
  | POST /posts    |                       |                         |
  |--------------->|                       |                         |
  |                | put_item(POST#p_1)    |                         |
  |                |---------------------->|                         |
  |                | put_item(FEEDREF#     |                         |
  |                |   author, fanout=F)   |                         |
  |                |---------------------->|                         |
  |                | query GSI5            |                         |
  |                |  FOLLOWERS#author     |                         |
  |                |---------------------->|                         |
  |                |<-- [f1, f2, ..., fN]  |                         |
  |                |                       |                         |
  |   [N <= 500]   |                       |                         |
  |                | batch_write           |                         |
  |                |  FEEDREF#f1..fN       |                         |
  |                |  fanout=True          |                         |
  |                |---------------------->|                         |
  |                |                       |                         |
  |   [N > 500]    |                       |                         |
  |                | batch_write first 500 |                         |
  |                |---------------------->|                         |
  |                | dispatch(remaining)   |                         |
  |                |--------------------------------------->|        |
  |<-- 201 {ok}    |                       |               |        |
  |                |                       |               |        |
  |                |                       | batch_write   |        |
  |                |                       |<--------------|        |
  |                |                       |  remaining    |        |
  |                |                       |  FEEDREF#fN+1.|        |
```

## Appendix C: Related Tickets

- **SOC-001**: Follow system (provides follower list for fan-out queries)
- **SOC-003**: User search/discovery (may surface popular creators with many followers)
- **SOC-004**: Notification expansion (notifies followers of new posts)
- **SOC-005**: Public profile page (shows post grid from author's posts)

---

## Codebase References

### Backend — Services

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `newsfeed_fanout.py` (173 lines) | `app/services/newsfeed_fanout.py` | whole file | **Exists** — already implements fan-out on write |
| `fan_out_post_to_followers()` | `app/services/newsfeed_fanout.py` | 43 | **Verified** — called from `newsfeed.py:3314-3315` on post create |
| `_get_all_follower_ids()` | `app/services/newsfeed_fanout.py` | 21 | **Verified** — queries GSI5 `FOLLOWERS#{user_id}`, capped at `MAX_SYNC_FOLLOWERS` |
| `fan_out_delete_post()` | `app/services/newsfeed_fanout.py` | 78 | **Verified** — deletes FEEDREF items for deleted posts |
| `social.py` (follow graph) | `app/services/social.py` | 399 lines | **Exists** — `get_followers()` at line 142 provides paginated follower list |

### Backend — Newsfeed Router (`app/routers/newsfeed.py`)

| Reference | Line(s) | Status |
|-----------|---------|--------|
| `_write_feed_ref_for_published_post()` | 1818 | **Verified** (ticket says line 1735 — **INCORRECT**, actual is 1818) |
| Feed query `GET /feed` | 4192 | **Verified** — queries GSI1 with `FEED#{user_id}` at line 4267 (ticket says "around line 4040" — **INCORRECT**, actual is 4192/4267) |
| Fan-out call on post create | 3314-3315 | **Verified** — `fan_out_post_to_followers(author_id=user_id, post_id=post_id, created_at=created_at)` |
| Repost FEEDREF writes | 5303-5306 | **Verified** — reposts write own FEEDREF at line 5303 |
| Repost fan-out to followers | 5324-5344 | **Verified** — iterates `_get_all_follower_ids()` and writes `FEEDREF#{fid}#REPOST#{repost_id}` |
| `POST_AUTHOR#{user_id}` (GSI2) | 3248 | **Verified** — author index for per-user post queries |

### DynamoDB (`scripts/local-ddb-init.py`)

| Reference | Line | Status |
|-----------|------|--------|
| `app_single_table` definition | 222 | **Verified** |
| GSI1 (`GSI1PK` / `GSI1SK`) — feed refs | 227 | **Verified** |
| GSI2 (`GSI2PK` / `GSI2SK`) — post author | 228 | **Verified** |
| GSI5 (`GSI5PK` / `GSI5SK`) — followers | 231 | **Verified** |

### Frontend

| Reference | File | Status |
|-----------|------|--------|
| Feed query | `frontend/src/api/endpoints/newsfeed.ts` | **Exists** — calls `GET /feed` |
| Feed page | `frontend/src/pages/feed/FeedPage.tsx` | **Exists** |

### Corrections

1. **`_write_feed_ref_for_published_post` line**: Ticket says line 1735, actual is line 1818.
2. **Feed query line**: Ticket says "around line 4040", actual `GET /feed` endpoint is at line 4192, with the GSI1 query at line 4267.
3. **Fan-out is ALREADY IMPLEMENTED**: `app/services/newsfeed_fanout.py` (173 lines) already provides `fan_out_post_to_followers()`, `_get_all_follower_ids()`, and `fan_out_delete_post()`. The newsfeed router already calls the fan-out service at post creation (line 3314) and repost creation (line 5324). The ticket's scope may need to be re-evaluated to focus on remaining gaps (e.g., async fan-out for large follower counts, batch write optimization, fan-out monitoring/retries).
