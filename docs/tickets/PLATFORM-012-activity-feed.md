# PLATFORM-012: Unified Activity Feed & Notifications Center

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 12-16 days

---

## 1. Overview & Motivation

### The Gap

The platform has a mature alert/notification system spread across multiple backend modules and a basic frontend display. However, the current experience falls short of a true "activity feed" in several ways:

1. **Flat list, no grouping**: The `AlertCenter` component (`frontend/src/pages/alerts/AlertCenter.tsx`, line 29) <!-- VERIFIED: AlertCenter.tsx:29 --> displays alerts as a flat chronological list. When a post receives 20 reactions, the user sees 20 separate alert rows. The backend batching system (`app/services/social_alerts.py`, `_batch_alert` at line 307) <!-- VERIFIED: social_alerts.py:307 --> does batch by `batch_key`, but the frontend does not render batched alerts differently from individual ones --- it simply shows the latest title.

2. **No activity-centric language**: The current alert titles are generic security/system language ("Login", "Session revoked", "TOTP device added"). Social notifications use `_format_batch_title` (`social_alerts.py`, line 419) <!-- VERIFIED: social_alerts.py:419 --> which produces human-readable titles like "Alice and 3 others reacted to your post", but these are mixed in with security audit events in the same list.

3. **No interaction on the notification**: Clicking an alert row in `AlertCenter.tsx` only expands its JSON details (line 262, `toggleExpand`). There is no deep link to the relevant post, message, or ticket. The `url` field exists on search result items but not on alert objects.

4. **Limited bell popover**: The header bell popover (`Header.tsx`, line 325) <!-- CORRECTED: was "line 325", actually bell popover starts at line 324 (comment) / line 325 (Popover) --> shows the 10 most recent alerts with basic title + timestamp. It has no grouping, no action buttons, and no way to filter by type. The "Mark all read" button (line 350) <!-- CORRECTED: was "line 351", actually line 350 (onClick handler) --> exists but there is no per-item "mark read" in the popover.

5. **No follow/mention activity view**: The `SOCIAL_ALERT_TYPES` list (`social_alerts.py`, line 32) <!-- VERIFIED: social_alerts.py:32 --> includes `new_follower`, `post_liked`, `post_reaction`, `post_comment`, `comment_reply`, `mention`, `subscription_started`, `post_shared`, `post_tip`, `message_tip`, but there is no dedicated UI view that separates these social activities from security/system alerts.

6. **No aggregation by source**: Multiple events from the same post (like, comment, tip) should be grouped under a single "activity" card with action-specific counts. The current batch system groups by `batch_key` pattern (e.g., `reaction:{post_id}` at line 46) <!-- CORRECTED: was "line 48", actually BATCH_KEY_PATTERNS at line 45, "post_reaction" entry at line 46 -->, but batches of different types for the same post are separate records.

### Why This Is Needed

1. **Creator engagement**: Content creators need a clear view of how their posts, messages, and videos are performing. A unified activity feed that groups "5 likes, 2 comments, 1 tip on your post" into a single card dramatically improves the creator experience.
2. **Notification fatigue**: The flat alert list becomes overwhelming for active users. Grouping and filtering reduce the cognitive load.
3. **Actionable notifications**: Users should be able to click a notification to navigate directly to the relevant content --- the post they were mentioned in, the ticket that was assigned, the message they were tipped for.
4. **Separation of concerns**: Security events (login, MFA, session revoked) and social events (likes, comments, tips) serve different purposes and should be viewable separately.

### Architecture After This Change

```
Bell Icon (Header.tsx)
    |
    +--- Unread badge (existing: useAlertStream.ts line 24, unreadCount state) <!-- VERIFIED: useAlertStream.ts:24 -->
    |
    +--- Click -> Enhanced Popover
              |
              |--- Activity Tab (social events, grouped by source)
              |     |--- "Alice and 3 others reacted to your post" -> click -> /feed?post=xxx
              |     |--- "Bob tipped your message $5" -> click -> /messages/conv123
              |     |--- "New follower: Charlie" -> click -> /discover?user=charlie
              |
              |--- Security Tab (audit events)
              |     |--- "Login from new device" -> click -> /security/sessions
              |     |--- "API key created" -> click -> /security/api-keys
              |
              +--- "View all" -> /alerts (enhanced AlertsPage)

AlertsPage (enhanced)
    |
    +--- Tabs: All | Activity | Security | Mentions | Tips
    |
    +--- Activity view: grouped cards
    |     |--- PostActivityCard: aggregates likes/comments/tips/shares for a post
    |     |--- MessageTipCard: shows tip sender, amount, message preview
    |     |--- FollowerCard: shows new follower(s) with follow-back button
    |
    +--- Security view: existing AlertCenter (mostly unchanged)
    |
    +--- Mentions view: filtered to type="mention" only
    |
    +--- Tips view: filtered to type="post_tip" or "message_tip" with $ totals
```

### Data Flow --- Sequence Diagram

```
User Action                Backend                         DynamoDB               Frontend
   |                         |                                |                      |
   | Bob likes Alice's post  |                                |                      |
   |------------------------>|                                |                      |
   |                         |-- emit_social_alert() -------->|                      |
   |                         |   recipient=alice              |                      |
   |                         |   type=post_liked              |                      |
   |                         |   action_url=/feed?post=abc    |                      |
   |                         |   source_type=post             |                      |
   |                         |   source_id=abc                |                      |
   |                         |   category=activity            |                      |
   |                         |                                |                      |
   |                         |-- _batch_alert() ------------->|                      |
   |                         |   batch_key=liked:abc          |                      |
   |                         |   actors.append(bob)           |                      |
   |                         |   actor_count += 1             |                      |
   |                         |                                |                      |
   |                         |-- sse_publish_alert() -------->|-- SSE event -------->|
   |                         |                                |                      |
   |                         |                                |  useAlertStream      |
   |                         |                                |  updates unreadCount |
   |                         |                                |  invalidates queries |
   |                         |                                |                      |
   | Alice clicks bell       |                                |                      |
   |------------------------------------------------------------->                   |
   |                         |<--- GET /ui/alerts/activity ---|                      |
   |                         |                                |                      |
   |                         |-- query alerts (category=      |                      |
   |                         |   activity) ------------------>|                      |
   |                         |                                |                      |
   |                         |-- group by source_id --------->|                      |
   |                         |                                |                      |
   |                         |-- return grouped items ------->|                      |
   |                         |                                |                      |
   | Alice clicks "5 likes"  |                                |                      |
   |------------------------------------------------------------->                   |
   |                         |                                |  navigate to         |
   |                         |                                |  /feed?post=abc      |
```

---

## 2. Current State Analysis

### 2.1 Alert Data Model (`app/services/alerts.py`)

The `write_alert` function (line 266) <!-- VERIFIED: alerts.py:266 --> creates alert records with:

```python
item = {
    "user_sub": user_sub,
    "alert_id": alert_id,       # format: "{ts:010d}#{uuid4().hex}"
    "ts": ts,
    "event": event,
    "outcome": outcome,
    "title": title[:120],
    "details": safe_details,
    "read": False,
    "read_at": 0,
    "priority": priority,       # from alert_priority module
}
```

The `alert_id` is a composite of timestamp and UUID, ensuring chronological sort within a user's partition. The table uses `user_sub` as PK and `alert_id` as SK with `ScanIndexForward=False` for reverse-chronological ordering.

Notably, there is **no `url` or `action_url` field** on alerts. The frontend cannot deep-link to the relevant content because the alert record does not contain navigation information.

The `details` field is a `Dict[str, Any]` that contains event-specific data. For social alerts, it typically includes:

```python
{
    "actor_user_id": "bob-sub-123",
    "actor_display_name": "Bob",
    "post_id": "abc123",           # for post-related events
    "comment_id": "comment456",     # for comment-related events
    "message_id": "msg789",        # for message-related events
    "conversation_id": "conv012",  # for message-related events
    "amount_cents": 500,           # for tip events
}
```

This data is sufficient to construct `action_url` values, but the URL is not pre-computed and stored on the alert record.

### 2.2 Social Alert Batching (`app/services/social_alerts.py`)

The `emit_social_alert` function (line 167) <!-- VERIFIED: social_alerts.py:167 --> is the entry point for all social notifications. It handles:

1. Self-notification suppression (line 189) <!-- VERIFIED: social_alerts.py:189 -->: `if recipient_user_id == actor_user_id: return None`
2. Per-type preference check (line 193) <!-- VERIFIED: social_alerts.py:193 -->: `_is_alert_type_enabled(recipient_user_id, alert_type)`
3. Batch key-based grouping (line 198) <!-- VERIFIED: social_alerts.py:198 (line 197-198) -->: `_batch_alert(...)` uses DDB `update_item` with `list_append` to accumulate actors
4. Channel routing (line 222) <!-- CORRECTED: was "line 221", actually channels variable at line 221 and _dispatch_to_channels call at line 222 -->: `_dispatch_to_channels(...)` routes to push, email, SMS

The `BATCH_KEY_PATTERNS` dict (line 45) <!-- VERIFIED: social_alerts.py:45 --> defines grouping keys:

```python
BATCH_KEY_PATTERNS: Dict[str, str] = {
    "post_reaction": "reaction:{post_id}",
    "post_liked":    "liked:{post_id}",
    "post_comment":  "comment:{post_id}",
    "post_tip":      "tip:{post_id}",
    "new_follower":  "follower:{user_id}",
}
```

The `_format_batch_title` function (line 419) generates titles like "Alice and 3 others reacted to your post" using `templates_single` and `templates_plural` dictionaries.

Batch records are stored in the alerts table with `alert_id = f"BATCH#{batch_key}"` (line 329) <!-- VERIFIED: social_alerts.py:329 -->. The actor list is trimmed to `_BATCH_ACTORS_MAX = 10` entries (line 53) <!-- VERIFIED: social_alerts.py:53 -->.

**Critical limitation**: The batch system groups by `batch_key` pattern, which is `{type}:{entity_id}`. This means reactions and comments on the same post are stored as separate batch records (`reaction:abc123` and `comment:abc123`). The activity feed needs a higher-level grouping by `source_id` alone (aggregating across types for the same entity).

### 2.3 Alert SSE Stream (`app/services/alerts.py`, `app/routers/alerts.py`)

Real-time alerts use Server-Sent Events via `GET /ui/alerts/stream` (line 451 in `alerts.py` router) <!-- CORRECTED: was "line 452", actually line 451 -->. The `sse_subscribe` function (line 64 in `services/alerts.py`) <!-- VERIFIED: alerts.py:64 --> maintains an in-memory `asyncio.Queue` per user. The `sse_publish_alert` function (line 84) <!-- VERIFIED: alerts.py:84 --> fans out to all connected clients for a user.

On the frontend, `useAlertStream` (`frontend/src/hooks/useAlertStream.ts`, line 21) <!-- VERIFIED: useAlertStream.ts:21 --> opens an EventSource connection, handles `alert`, `hello`, and `heartbeat` events, and manages the `unreadCount` state.

The SSE system is single-process (in-memory `_SSE_SUBSCRIBERS` dict at line 61) <!-- VERIFIED: alerts.py:61 -->. For multi-process deployments, this would need to be replaced with Redis pub/sub or SQS. This is acceptable for the current single-worker dev mode.

### 2.4 Alert Preferences (`app/services/social_alerts.py`)

Per-type preferences are stored in the `alert_prefs` table with a `type_preferences` map attribute. The `update_type_preference` function (line 97) <!-- VERIFIED: social_alerts.py:97 --> supports `enabled`, `email`, `push`, `in_app`, and `sms` boolean flags per alert type.

The default preferences (`get_all_type_preferences`, line 149) <!-- VERIFIED: social_alerts.py:149 --> default to `enabled=True, email=True, push=True, in_app=True, sms=False` for all types.

The preference check in `_is_alert_type_enabled` (line 64) <!-- VERIFIED: social_alerts.py:64 --> uses an opt-out model:

```python
def _is_alert_type_enabled(user_sub: str, alert_type: str) -> bool:
    prefs = get_alert_prefs(user_sub)
    type_prefs: Dict[str, Any] = prefs.get("type_preferences", {})
    type_pref: Dict[str, Any] = type_prefs.get(alert_type, {})
    return type_pref.get("enabled", True)  # defaults to True
```

This means all alert types are enabled by default. The user must explicitly disable types they don't want.

### 2.5 Frontend Alert Center (`AlertCenter.tsx`)

The `AlertCenter` component (line 29) <!-- VERIFIED: AlertCenter.tsx:29 --> uses `useInfiniteQuery` for paginated alert loading (line 50) <!-- VERIFIED: AlertCenter.tsx:50 -->. It supports:

- Search via `searchAlerts(search)` (line 43)
- Type filtering via a `Select` dropdown (line 138)
- Bulk mark-read via checkboxes (line 88)
- Individual row expansion to show JSON details (line 105)

The component does NOT:
- Render batched alerts differently from individual ones
- Show deep-link navigation for alerts
- Group related alerts by source entity
- Separate social from security alerts

The rendering for each alert row:

```tsx
<div className="flex items-center gap-3">
  <Checkbox checked={selected.has(alert.alert_id)} onCheckedChange={() => toggleSelect(alert.alert_id)} />
  <div className="flex-1">
    <div className="flex items-center gap-2">
      <span className={cn("text-sm", !alert.read && "font-semibold")}>{alert.title}</span>
      {!alert.read && <Badge variant="default" className="text-[10px]">New</Badge>}
    </div>
    <span className="text-xs text-muted-foreground">{formatAlertDate(alert.ts)}</span>
  </div>
  <Button variant="ghost" size="sm" onClick={() => toggleExpand(alert.alert_id)}>
    {expanded.has(alert.alert_id) ? <ChevronUp /> : <ChevronDown />}
  </Button>
</div>
```

### 2.6 Header Bell Popover (`Header.tsx`)

The bell popover (line 325) <!-- VERIFIED: Header.tsx:325 --> fetches the 10 most recent alerts via `getAlerts({ limit: 10 })` (line 178-180) <!-- CORRECTED: was "line 178", actually useQuery at line 178, queryFn with getAlerts at line 180 -->. It displays:
- Unread indicator dot (line 374)
- Alert title (line 383)
- JSON details as truncated text (line 387)
- Relative timestamp via `formatAlertTime` (line 631) <!-- VERIFIED: Header.tsx:631 -->
- "Mark all read" button (line 350) <!-- CORRECTED: was "line 351", actually onClick at line 350 -->
- "View all notifications" footer link (line 404)

The bell icon uses a shake animation (`animate-bell-shake` at line 333) <!-- VERIFIED: Header.tsx:333 --> when `unreadCount` increases. The `prevUnreadRef` tracks the previous count to trigger the animation only on increases.

### 2.7 Alert Event Types (`app/services/alerts.py`)

The `ALERT_EVENT_TYPES` list (line 46) <!-- VERIFIED: alerts.py:46 --> contains 27 event types spanning:
- Security: `login_success`, `login_failure`, `mfa_success`, `session_revoked`, etc.
- Calendar: `calendar_event_created`, `calendar_event_updated`, `calendar_event_deleted`
- Tickets: `ticket_created`, `ticket_assigned`, `ticket_replied`, `ticket_status_changed`
- Social: `new_follower`, `post_liked`, `post_reaction`, `post_comment`, `mention`, etc.
- Commerce: `cart.abandoned`

The `_NO_ALERT_EVENTS` frozenset (line 29) <!-- VERIFIED: alerts.py:29 --> excludes high-frequency events like `messaging_presence_heartbeat_processed` and `messaging_message_viewed` from being persisted.

### 2.8 Alerts DynamoDB Table Schema

```
Table: alerts
  PK: user_sub (String)
  SK: alert_id (String)  — format: "{ts:010d}#{uuid4().hex}" or "BATCH#{batch_key}"

  Attributes:
    ts: int (Unix timestamp)
    event: str (event type from ALERT_EVENT_TYPES)
    outcome: str ("success" | "failure" | "info")
    title: str (max 120 chars)
    details: Map (event-specific data)
    read: bool
    read_at: int (Unix timestamp, 0 if unread)
    priority: str ("low" | "medium" | "high" | "critical")

  Batch alert additional attributes:
    actors: List[Map] — [{user_id, display_name}], max 10
    actor_count: int — total actors (may exceed len(actors))
    batch_key: str — grouping key (e.g., "reaction:abc123")

  GSIs:
    GSI1: user_sub (PK), ts (SK) — for time-range queries
```

---

## 3. Technical Design

### 3.1 Action URL on Alerts

Add an `action_url` field to every alert record. This enables deep-linking from any notification surface (bell popover, AlertCenter, push notification).

```python
# In write_alert() and _batch_alert()
item["action_url"] = action_url  # e.g., "/feed?post=abc123" or "/messages/conv123"
```

The `emit_social_alert` function gains an `action_url` parameter:

```python
def emit_social_alert(
    *,
    recipient_user_id: str,
    alert_type: str,
    actor_user_id: str,
    actor_display_name: str,
    batch_key: Optional[str] = None,
    title: str,
    details: Dict[str, Any],
    action_url: Optional[str] = None,   # NEW
) -> Optional[Dict[str, Any]]:
```

All existing call sites for `emit_social_alert` must be updated to pass the appropriate URL. Here is the mapping:

| Alert Type | `action_url` Template | Example |
|------------|----------------------|---------|
| `post_liked` | `/feed?post={post_id}` | `/feed?post=abc123` |
| `post_reaction` | `/feed?post={post_id}` | `/feed?post=abc123` |
| `post_comment` | `/feed?post={post_id}#comment-{comment_id}` | `/feed?post=abc123#comment-def456` |
| `comment_reply` | `/feed?post={post_id}#comment-{comment_id}` | `/feed?post=abc123#comment-ghi789` |
| `mention` | `/feed?post={post_id}` or `/messages/{conv_id}` | Depends on mention context |
| `new_follower` | `/discover?user={actor_user_id}` | `/discover?user=bob-sub` |
| `subscription_started` | `/subscriptions` | `/subscriptions` |
| `post_shared` | `/feed?post={post_id}` | `/feed?post=abc123` |
| `post_tip` | `/feed?post={post_id}` | `/feed?post=abc123` |
| `message_tip` | `/messages/{conversation_id}` | `/messages/conv123` |
| `login_success` | `/security/sessions` | `/security/sessions` |
| `login_failure` | `/security/sessions` | `/security/sessions` |
| `api_key_created` | `/security/api-keys` | `/security/api-keys` |
| `ticket_assigned` | `/tickets/{ticket_id}` | `/tickets/tkt789` |
| `ticket_replied` | `/tickets/{ticket_id}` | `/tickets/tkt789` |

**URL construction helper**:

```python
def _build_action_url(alert_type: str, details: Dict[str, Any]) -> Optional[str]:
    """Construct action_url from alert type and details."""
    post_id = details.get("post_id")
    comment_id = details.get("comment_id")
    conv_id = details.get("conversation_id")
    ticket_id = details.get("ticket_id")
    actor_id = details.get("actor_user_id")

    url_map = {
        "post_liked":       f"/feed?post={post_id}" if post_id else None,
        "post_reaction":    f"/feed?post={post_id}" if post_id else None,
        "post_comment":     f"/feed?post={post_id}" if post_id else None,
        "comment_reply":    f"/feed?post={post_id}" if post_id else None,
        "mention":          f"/feed?post={post_id}" if post_id else (f"/messages/{conv_id}" if conv_id else None),
        "new_follower":     f"/discover?user={actor_id}" if actor_id else None,
        "subscription_started": "/subscriptions",
        "post_shared":      f"/feed?post={post_id}" if post_id else None,
        "post_tip":         f"/feed?post={post_id}" if post_id else None,
        "message_tip":      f"/messages/{conv_id}" if conv_id else None,
        "login_success":    "/security/sessions",
        "login_failure":    "/security/sessions",
        "mfa_success":      "/security",
        "mfa_failure":      "/security",
        "api_key_created":  "/security/api-keys",
        "api_key_revoked":  "/security/api-keys",
        "session_revoked":  "/security/sessions",
        "ticket_created":   f"/tickets/{ticket_id}" if ticket_id else "/tickets",
        "ticket_assigned":  f"/tickets/{ticket_id}" if ticket_id else "/tickets",
        "ticket_replied":   f"/tickets/{ticket_id}" if ticket_id else "/tickets",
        "ticket_status_changed": f"/tickets/{ticket_id}" if ticket_id else "/tickets",
    }
    return url_map.get(alert_type)
```

### 3.2 Alert Categories

Introduce a `category` field on alert records:

```python
ALERT_CATEGORIES = {
    "activity": {"new_follower", "post_liked", "post_reaction", "post_comment",
                 "comment_reply", "mention", "subscription_started", "post_shared",
                 "post_tip", "message_tip"},
    "security": {"login_success", "login_failure", "mfa_success", "mfa_failure",
                 "api_key_created", "api_key_revoked", "session_revoked",
                 "totp_device_added", "totp_device_removed", "device_new",
                 "rate_limited", "access_denied", "security_event"},
    "updates":  {"calendar_event_created", "calendar_event_updated",
                 "ticket_created", "ticket_assigned", "ticket_replied",
                 "ticket_status_changed", "ticket_reopened"},
    "commerce": {"cart.abandoned"},
}

# Reverse lookup: event -> category
_EVENT_TO_CATEGORY: Dict[str, str] = {}
for cat, events in ALERT_CATEGORIES.items():
    for event in events:
        _EVENT_TO_CATEGORY[event] = cat

def get_alert_category(event: str) -> str:
    """Get the category for an alert event type."""
    return _EVENT_TO_CATEGORY.get(event, "security")  # default to security for unknown events
```

The `write_alert` function writes `category` based on the event type. The frontend can then filter alerts by category.

**Source entity fields**: Add `source_type` and `source_id` to alert records for grouping:

```python
def _determine_source(alert_type: str, details: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Determine the source entity type and ID for grouping."""
    if alert_type in ("post_liked", "post_reaction", "post_comment", "comment_reply",
                      "post_shared", "post_tip"):
        return "post", details.get("post_id")
    if alert_type in ("message_tip",):
        return "message", details.get("message_id")
    if alert_type in ("new_follower",):
        return "follower", details.get("actor_user_id")
    if alert_type in ("ticket_assigned", "ticket_replied", "ticket_status_changed"):
        return "ticket", details.get("ticket_id")
    return None, None
```

### 3.3 Activity Grouping by Source Entity

Introduce a server-side grouping endpoint that aggregates alerts by source entity (e.g., post_id):

```
GET /ui/alerts/activity?group_by=source&limit=20&cursor=...
```

The backend:
1. Queries the user's alerts filtered to `category=activity`
2. Groups consecutive alerts with the same source entity ID (from `details.post_id`)
3. Returns grouped activity items with aggregated counts

Implementation:

```python
@router.get("/activity")
def get_activity_feed(
    limit: int = Query(default=20, ge=1, le=50),
    cursor: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    """Get grouped activity feed for the current user."""
    user_sub = session["user_sub"]
    ts = now_ts()

    # Query alerts with category filter
    key_cond = Key("user_sub").eq(user_sub)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "ScanIndexForward": False,
        "Limit": limit * 5,  # Over-fetch to allow grouping
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
    if category:
        kwargs["FilterExpression"] = Attr("category").eq(category)

    resp = T.alerts.query(**kwargs)
    items = resp.get("Items", [])

    # Group by source entity
    groups: Dict[str, Dict[str, Any]] = {}  # source_key -> group
    group_order: List[str] = []

    for item in items:
        source_type = item.get("source_type")
        source_id = item.get("source_id")

        if not source_type or not source_id:
            # Non-groupable alert: treat as standalone
            key = f"standalone:{item['alert_id']}"
            groups[key] = {
                "source_type": item.get("event", "unknown"),
                "source_id": item.get("alert_id"),
                "action_url": item.get("action_url"),
                "aggregations": {},
                "latest_ts": int(item.get("ts", 0)),
                "title": item.get("title", ""),
                "unread": not item.get("read", False),
                "alert_ids": [item["alert_id"]],
            }
            group_order.append(key)
            continue

        key = f"{source_type}:{source_id}"
        if key not in groups:
            groups[key] = {
                "source_type": source_type,
                "source_id": source_id,
                "action_url": item.get("action_url"),
                "aggregations": {},
                "latest_ts": int(item.get("ts", 0)),
                "title": "",
                "unread": False,
                "alert_ids": [],
            }
            group_order.append(key)

        group = groups[key]
        event = item.get("event", "")
        if event not in group["aggregations"]:
            group["aggregations"][event] = {
                "count": 0,
                "latest_actor": None,
                "total_cents": 0,
            }
        agg = group["aggregations"][event]
        agg["count"] += 1
        if not agg["latest_actor"]:
            agg["latest_actor"] = item.get("details", {}).get("actor_display_name")
        if "amount_cents" in item.get("details", {}):
            agg["total_cents"] += int(item["details"]["amount_cents"])

        if not item.get("read", False):
            group["unread"] = True
        group["alert_ids"].append(item["alert_id"])

    # Build response with formatted titles
    result_items = []
    for key in group_order[:limit]:
        group = groups[key]
        group["title"] = _format_activity_title(group)
        result_items.append(group)

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])

    return {"items": result_items, "next_cursor": next_cursor}


def _format_activity_title(group: Dict[str, Any]) -> str:
    """Generate a human-readable title for a grouped activity item."""
    parts = []
    aggs = group.get("aggregations", {})

    for event_type, agg in aggs.items():
        count = agg["count"]
        actor = agg.get("latest_actor", "Someone")
        total_cents = agg.get("total_cents", 0)

        if event_type == "post_liked":
            parts.append(f"{count} like{'s' if count != 1 else ''}")
        elif event_type == "post_reaction":
            parts.append(f"{count} reaction{'s' if count != 1 else ''}")
        elif event_type == "post_comment":
            parts.append(f"{count} comment{'s' if count != 1 else ''}")
        elif event_type == "post_tip":
            total_str = f"${total_cents / 100:.2f}" if total_cents else ""
            parts.append(f"{count} tip{'s' if count != 1 else ''} {total_str}".strip())
        elif event_type == "post_shared":
            parts.append(f"{count} share{'s' if count != 1 else ''}")
        elif event_type == "message_tip":
            total_str = f"${total_cents / 100:.2f}" if total_cents else ""
            parts.append(f"tipped {total_str}")
        elif event_type == "new_follower":
            parts.append(f"{count} new follower{'s' if count != 1 else ''}")

    source_type = group.get("source_type", "")
    if source_type == "post":
        return f"Your post received {', '.join(parts)}" if parts else "Activity on your post"
    elif source_type == "message":
        return f"Your message was {', '.join(parts)}" if parts else "Activity on your message"
    elif source_type == "follower":
        return f"{', '.join(parts)}" if parts else "New follower"
    return ", ".join(parts) or group.get("title", "Activity")
```

**Response shape**:

```json
{
  "items": [
    {
      "source_type": "post",
      "source_id": "abc123",
      "action_url": "/feed?post=abc123",
      "aggregations": {
        "post_liked": { "count": 5, "latest_actor": "Alice", "total_cents": 0 },
        "post_comment": { "count": 2, "latest_actor": "Bob", "total_cents": 0 },
        "post_tip": { "count": 1, "latest_actor": "Charlie", "total_cents": 500 }
      },
      "latest_ts": 1771234567,
      "title": "Your post received 5 likes, 2 comments, 1 tip $5.00",
      "unread": true,
      "alert_ids": ["000173...", "000174...", ...]
    }
  ],
  "next_cursor": "..."
}
```

### 3.4 Enhanced Bell Popover

The bell popover gets a two-tab layout:

- **Activity tab**: Shows grouped activity items (from `/ui/alerts/activity`)
- **System tab**: Shows security/system alerts (existing `getAlerts` with `category=security`)

Each item is clickable and navigates to the `action_url`.

Implementation for the enhanced popover:

```tsx
function BellPopover({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<"activity" | "system">("activity");

  const activityQuery = useQuery({
    queryKey: ["alerts", "activity-feed"],
    queryFn: () => getActivityFeed({ limit: 10 }),
    enabled: open,
  });

  const securityQuery = useQuery({
    queryKey: ["alerts", "security-feed"],
    queryFn: () => getAlerts({ limit: 10, category: "security" }),
    enabled: open && activeTab === "system",
  });

  const handleItemClick = (actionUrl: string | undefined) => {
    if (actionUrl) {
      navigate(actionUrl);
      onOpenChange(false);
    }
  };

  return (
    <Popover open={open} onOpenChange={onOpenChange}>
      <PopoverContent className="w-96 p-0">
        {/* Tab bar */}
        <div className="flex border-b">
          <button
            className={cn("flex-1 px-4 py-2 text-sm font-medium",
              activeTab === "activity" && "border-b-2 border-primary text-primary"
            )}
            onClick={() => setActiveTab("activity")}
          >
            Activity
          </button>
          <button
            className={cn("flex-1 px-4 py-2 text-sm font-medium",
              activeTab === "system" && "border-b-2 border-primary text-primary"
            )}
            onClick={() => setActiveTab("system")}
          >
            Security
          </button>
        </div>

        {/* Content */}
        <div className="max-h-96 overflow-y-auto">
          {activeTab === "activity" && activityQuery.data?.items.map((item) => (
            <button
              key={`${item.source_type}:${item.source_id}`}
              className={cn(
                "w-full text-left px-4 py-3 hover:bg-accent border-b border-border/50",
                item.unread && "bg-primary/5"
              )}
              onClick={() => handleItemClick(item.action_url)}
            >
              <div className="flex items-center gap-3">
                <ActivityIcon type={item.source_type} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{item.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {formatRelativeTime(item.latest_ts)}
                  </p>
                </div>
                {item.unread && <div className="w-2 h-2 rounded-full bg-primary shrink-0" />}
              </div>
              {/* Aggregation badges */}
              <div className="flex gap-2 mt-1 ml-9">
                {item.aggregations.post_liked && (
                  <Badge variant="outline" className="text-[10px]">
                    <Heart className="h-3 w-3 mr-1" /> {item.aggregations.post_liked.count}
                  </Badge>
                )}
                {item.aggregations.post_comment && (
                  <Badge variant="outline" className="text-[10px]">
                    <MessageCircle className="h-3 w-3 mr-1" /> {item.aggregations.post_comment.count}
                  </Badge>
                )}
                {item.aggregations.post_tip && (
                  <Badge variant="outline" className="text-[10px]">
                    <DollarSign className="h-3 w-3 mr-1" />
                    ${(item.aggregations.post_tip.total_cents / 100).toFixed(2)}
                  </Badge>
                )}
              </div>
            </button>
          ))}
        </div>

        {/* Footer */}
        <div className="border-t p-2">
          <Button variant="ghost" size="sm" className="w-full" onClick={() => navigate("/alerts")}>
            View all notifications
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
```

### 3.5 Enhanced AlertsPage

The `AlertsPage` (`frontend/src/pages/alerts/AlertsPage.tsx`) gains new tabs:

```tsx
<Tabs defaultValue="activity">
  <TabsList>
    <TabsTrigger value="activity">Activity</TabsTrigger>
    <TabsTrigger value="mentions">Mentions</TabsTrigger>
    <TabsTrigger value="tips">Tips & Earnings</TabsTrigger>
    <TabsTrigger value="security">Security</TabsTrigger>
    <TabsTrigger value="all">All</TabsTrigger>
  </TabsList>
  <TabsContent value="activity"><ActivityFeed /></TabsContent>
  <TabsContent value="mentions"><MentionsFeed /></TabsContent>
  <TabsContent value="tips"><TipsFeed /></TabsContent>
  <TabsContent value="security"><AlertCenter /></TabsContent>
  <TabsContent value="all"><AlertCenter /></TabsContent>
</Tabs>
```

### 3.6 Updated `write_alert` Function

```python
def write_alert(
    *,
    user_sub: str,
    event: str,
    outcome: str = "success",
    title: str,
    details: Optional[Dict[str, Any]] = None,
    priority: Optional[str] = None,
    action_url: Optional[str] = None,
    source_type: Optional[str] = None,
    source_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Write a new alert record with category, action_url, and source entity."""
    ts = now_ts()
    alert_id = f"{ts:010d}#{uuid.uuid4().hex}"
    safe_details = _sanitize_details(details or {})
    category = get_alert_category(event)

    # Auto-derive action_url if not provided
    if not action_url:
        action_url = _build_action_url(event, safe_details)

    # Auto-derive source entity if not provided
    if not source_type or not source_id:
        source_type, source_id = _determine_source(event, safe_details)

    # Validate action_url is relative (prevent open redirect)
    if action_url and (not action_url.startswith("/") or "://" in action_url):
        logger.warning("Invalid action_url rejected: %s", action_url)
        action_url = None

    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "alert_id": alert_id,
        "ts": ts,
        "event": event,
        "outcome": outcome,
        "title": title[:120],
        "details": safe_details,
        "read": False,
        "read_at": 0,
        "priority": priority or _default_priority(event),
        "category": category,
    }
    if action_url:
        item["action_url"] = action_url
    if source_type:
        item["source_type"] = source_type
    if source_id:
        item["source_id"] = source_id

    T.alerts.put_item(Item=item)
    sse_publish_alert(user_sub, _alert_out(item))
    return item
```

### 3.7 SSE Event Enhancement

Update the SSE event payload to include `action_url` and `category`:

```python
def _alert_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "alert_id": item["alert_id"],
        "ts": int(item.get("ts", 0)),
        "event": item.get("event", ""),
        "outcome": item.get("outcome", ""),
        "title": item.get("title", ""),
        "details": item.get("details", {}),
        "read": bool(item.get("read", False)),
        "priority": item.get("priority", "low"),
        # NEW fields
        "action_url": item.get("action_url"),
        "category": item.get("category", "security"),
        "actors": item.get("actors", []),
        "actor_count": int(item.get("actor_count", 0)),
        "source_type": item.get("source_type"),
        "source_id": item.get("source_id"),
    }
```

### 3.8 SSE Debounce for High-Frequency Events

For viral posts that generate hundreds of reactions per minute, add server-side SSE debouncing:

```python
_SSE_LAST_PUBLISH: Dict[str, float] = {}  # key: f"{user_sub}:{batch_key}" -> timestamp
_SSE_DEBOUNCE_SECONDS = 5.0

def _should_sse_publish(user_sub: str, batch_key: Optional[str]) -> bool:
    """Rate-limit SSE publishes for the same batch key to prevent flooding."""
    if not batch_key:
        return True  # Non-batched alerts always publish
    key = f"{user_sub}:{batch_key}"
    now = time.time()
    last = _SSE_LAST_PUBLISH.get(key, 0)
    if now - last < _SSE_DEBOUNCE_SECONDS:
        return False
    _SSE_LAST_PUBLISH[key] = now
    return True
```

---

## 4. API Endpoints

### 4.1 Activity Feed (Grouped)

```
GET /ui/alerts/activity
  Query params:
    limit: int (1-50, default 20)
    cursor: str (optional, base64-encoded DDB LastEvaluatedKey)
    category: str (optional, filter by category: "activity" | "security" | "updates" | "commerce")
  Auth: require_ui_session
  Response 200: {
    items: [ActivityGroupItem],
    next_cursor: str | null
  }
```

**ActivityGroupItem schema**:

```json
{
  "source_type": "post" | "message" | "follower" | "ticket" | "standalone",
  "source_id": "string (entity ID)",
  "action_url": "string | null (relative URL for navigation)",
  "aggregations": {
    "post_liked": { "count": 5, "latest_actor": "Alice", "total_cents": 0 },
    "post_comment": { "count": 2, "latest_actor": "Bob", "total_cents": 0 }
  },
  "latest_ts": 1771234567,
  "title": "string (formatted human-readable title)",
  "unread": true,
  "alert_ids": ["string (alert_id)..."]
}
```

### 4.2 Tips Summary

```
GET /ui/alerts/tips-summary
  Query params:
    period: str ("7d" | "30d" | "all", default "30d")
  Auth: require_ui_session
  Response 200: {
    total_tips_cents: int,
    tip_count: int,
    top_tippers: [{ user_id: str, display_name: str, total_cents: int }],
    by_type: {
      post_tip: { count: int, total_cents: int },
      message_tip: { count: int, total_cents: int }
    }
  }
```

**Backend implementation**:

```python
@router.get("/tips-summary")
def get_tips_summary(
    period: str = Query(default="30d", regex="^(7d|30d|all)$"),
    session=Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    ts = now_ts()

    # Determine time range
    period_seconds = {"7d": 7 * 86400, "30d": 30 * 86400, "all": 10 * 365 * 86400}
    cutoff_ts = ts - period_seconds.get(period, 30 * 86400)

    # Query alerts filtered to tip types
    tip_types = {"post_tip", "message_tip"}
    resp = T.alerts.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
        ScanIndexForward=False,
        Limit=1000,
    )

    total_tips_cents = 0
    tip_count = 0
    tipper_totals: Dict[str, Dict[str, Any]] = {}  # user_id -> {display_name, total_cents}
    by_type: Dict[str, Dict[str, int]] = {
        "post_tip": {"count": 0, "total_cents": 0},
        "message_tip": {"count": 0, "total_cents": 0},
    }

    for item in resp.get("Items", []):
        event = item.get("event", "")
        if event not in tip_types:
            continue
        item_ts = int(item.get("ts", 0))
        if item_ts < cutoff_ts:
            continue

        details = item.get("details", {})
        amount = int(details.get("amount_cents", 0))
        actor_id = details.get("actor_user_id", "")
        actor_name = details.get("actor_display_name", "Unknown")

        total_tips_cents += amount
        tip_count += 1

        if event in by_type:
            by_type[event]["count"] += 1
            by_type[event]["total_cents"] += amount

        if actor_id:
            if actor_id not in tipper_totals:
                tipper_totals[actor_id] = {"display_name": actor_name, "total_cents": 0}
            tipper_totals[actor_id]["total_cents"] += amount

    # Sort top tippers by total_cents desc
    top_tippers = sorted(
        [{"user_id": uid, **data} for uid, data in tipper_totals.items()],
        key=lambda x: x["total_cents"],
        reverse=True,
    )[:10]

    return {
        "total_tips_cents": total_tips_cents,
        "tip_count": tip_count,
        "top_tippers": top_tippers,
        "by_type": by_type,
    }
```

### 4.3 Enhanced Alert Output

The existing `_alert_out` function in `app/routers/alerts.py` (line 78) <!-- VERIFIED: alerts.py router:78 --> gains new fields:

```python
def _alert_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        # ... existing fields ...
        "action_url": item.get("action_url"),
        "category": item.get("category", "security"),
        "actors": item.get("actors", []),          # for batched alerts
        "actor_count": int(item.get("actor_count", 0)),
        "source_type": item.get("source_type"),    # "post", "message", "ticket"
        "source_id": item.get("source_id"),
    }
```

### 4.4 Mark Activity Group Read

```
POST /ui/alerts/mark-group-read
  Body: {
    alert_ids: List[str]    (up to 50 alert IDs from a single activity group)
  }
  Auth: require_ui_session (CSRF required)
  Response 200: { ok: true, marked_count: int }
```

This endpoint marks all alerts in a group as read in a single request, avoiding N individual `mark_read` calls for grouped activity items.

---

## 5. Frontend Components

### 5.1 ActivityFeed Component

**File**: `frontend/src/pages/alerts/ActivityFeed.tsx`

- Uses `useInfiniteQuery` to fetch grouped activity items
- Renders `ActivityGroupCard` for each grouped item
- Shows aggregated counts (5 likes, 2 comments) with actor avatars
- Click navigates to `action_url`
- "Mark read" button per group

```tsx
export function ActivityFeed() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const activityQuery = useInfiniteQuery({
    queryKey: ["alerts", "activity"],
    queryFn: ({ pageParam }) => getActivityFeed({ limit: 20, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor,
  });

  const markGroupReadMut = useMutation({
    mutationFn: (alertIds: string[]) => markGroupRead(alertIds),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });

  const allItems = activityQuery.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <div className="space-y-3">
      {allItems.map((item) => (
        <ActivityGroupCard
          key={`${item.source_type}:${item.source_id}`}
          item={item}
          onClick={() => item.action_url && navigate(item.action_url)}
          onMarkRead={() => markGroupReadMut.mutate(item.alert_ids)}
        />
      ))}
      {activityQuery.hasNextPage && (
        <Button variant="outline" onClick={() => activityQuery.fetchNextPage()}>
          Load more
        </Button>
      )}
    </div>
  );
}
```

### 5.2 ActivityGroupCard Component

**File**: `frontend/src/pages/alerts/ActivityGroupCard.tsx`

- Renders a card with source entity context (post preview, message snippet)
- Shows aggregation badges (Heart icon + count, MessageCircle icon + count, DollarSign icon + amount)
- Shows actor avatar stack (up to 3 avatars with "+N" overflow)
- Relative timestamp
- Unread indicator

```tsx
interface ActivityGroupCardProps {
  item: ActivityGroupItem;
  onClick: () => void;
  onMarkRead: () => void;
}

export function ActivityGroupCard({ item, onClick, onMarkRead }: ActivityGroupCardProps) {
  const aggs = item.aggregations;

  return (
    <Card
      className={cn(
        "cursor-pointer hover:bg-accent/50 transition-colors",
        item.unread && "border-l-4 border-l-primary"
      )}
      onClick={onClick}
    >
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <ActivityIcon type={item.source_type} className="h-8 w-8 text-muted-foreground mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className={cn("text-sm", item.unread && "font-semibold")}>{item.title}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {formatRelativeTime(item.latest_ts)}
            </p>
            {/* Aggregation badges */}
            <div className="flex flex-wrap gap-2 mt-2">
              {aggs.post_liked && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <Heart className="h-3 w-3" /> {aggs.post_liked.count}
                </Badge>
              )}
              {aggs.post_reaction && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <Smile className="h-3 w-3" /> {aggs.post_reaction.count}
                </Badge>
              )}
              {aggs.post_comment && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <MessageCircle className="h-3 w-3" /> {aggs.post_comment.count}
                </Badge>
              )}
              {aggs.post_tip && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <DollarSign className="h-3 w-3" />
                  ${(aggs.post_tip.total_cents / 100).toFixed(2)}
                </Badge>
              )}
              {aggs.post_shared && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <Share className="h-3 w-3" /> {aggs.post_shared.count}
                </Badge>
              )}
            </div>
          </div>
          {item.unread && (
            <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); onMarkRead(); }}>
              <CheckCheck className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function ActivityIcon({ type, className }: { type: string; className?: string }) {
  switch (type) {
    case "post": return <FileText className={className} />;
    case "message": return <MessageSquare className={className} />;
    case "follower": return <UserPlus className={className} />;
    case "ticket": return <Ticket className={className} />;
    default: return <Bell className={className} />;
  }
}
```

### 5.3 TipsFeed Component

**File**: `frontend/src/pages/alerts/TipsFeed.tsx`

- Fetches tip-type alerts filtered by `category=activity` and `alert_type in (post_tip, message_tip)`
- Shows total earnings summary card at top
- Lists individual tip events with amount, sender, and source

```tsx
export function TipsFeed() {
  const summaryQuery = useQuery({
    queryKey: ["alerts", "tips-summary", "30d"],
    queryFn: () => getTipsSummary("30d"),
  });

  const summary = summaryQuery.data;

  return (
    <div className="space-y-4">
      {/* Summary card */}
      {summary && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Tips & Earnings (30 days)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold">${(summary.total_tips_cents / 100).toFixed(2)}</p>
                <p className="text-xs text-muted-foreground">Total Earned</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.tip_count}</p>
                <p className="text-xs text-muted-foreground">Tips Received</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{summary.top_tippers.length}</p>
                <p className="text-xs text-muted-foreground">Unique Tippers</p>
              </div>
            </div>
            {/* Top tippers */}
            {summary.top_tippers.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-medium mb-2">Top Supporters</h4>
                {summary.top_tippers.slice(0, 5).map((tipper) => (
                  <div key={tipper.user_id} className="flex items-center justify-between py-1">
                    <span className="text-sm">{tipper.display_name}</span>
                    <span className="text-sm font-medium">${(tipper.total_cents / 100).toFixed(2)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
```

### 5.4 MentionsFeed Component

**File**: `frontend/src/pages/alerts/MentionsFeed.tsx`

- Fetches alerts filtered by `alert_type=mention`
- Shows mention context (post/comment text preview)
- Click navigates to the mentioned content

### 5.5 Enhanced Bell Popover

**File**: `frontend/src/components/layout/Header.tsx`

- Add two sub-tabs to the existing popover (Activity / System)
- Render activity items with clickable `action_url` navigation
- Add per-item "mark read" via `markRead` mutation
- Show actor avatars alongside notification text

### 5.6 Frontend API Endpoints

**File**: `frontend/src/api/endpoints/alerts.ts`

```typescript
// New API functions
export const getActivityFeed = (params: { limit?: number; cursor?: string; category?: string }) =>
  api.get<{ items: ActivityGroupItem[]; next_cursor: string | null }>("/ui/alerts/activity", params);

export const getTipsSummary = (period: "7d" | "30d" | "all" = "30d") =>
  api.get<TipsSummary>("/ui/alerts/tips-summary", { period });

export const markGroupRead = (alertIds: string[]) =>
  api.post<{ ok: boolean; marked_count: number }>("/ui/alerts/mark-group-read", {
    alert_ids: alertIds,
  });
```

### 5.7 Frontend Types

**File**: `frontend/src/api/types.ts`

```typescript
export interface ActivityGroupItem {
  source_type: "post" | "message" | "follower" | "ticket" | "standalone";
  source_id: string;
  action_url: string | null;
  aggregations: Record<string, {
    count: number;
    latest_actor: string | null;
    total_cents: number;
  }>;
  latest_ts: number;
  title: string;
  unread: boolean;
  alert_ids: string[];
}

export interface TipsSummary {
  total_tips_cents: number;
  tip_count: number;
  top_tippers: Array<{
    user_id: string;
    display_name: string;
    total_cents: number;
  }>;
  by_type: {
    post_tip: { count: number; total_cents: number };
    message_tip: { count: number; total_cents: number };
  };
}
```

---

## 6. E2E Test Plan

### Section 105: Activity Feed API

```
105.1  Post like generates activity alert with action_url="/feed?post={id}"
105.2  Multiple likes on same post batch into single activity with actor_count > 1
105.3  GET /ui/alerts/activity returns grouped items sorted by latest_ts desc
105.4  Activity items have category="activity"
105.5  Security alerts have category="security"
105.6  Activity and security alerts are separated by category filter
105.7  Standalone alerts (no source entity) appear as individual items in feed
105.8  Post comment + post like on same post are grouped under one source_id
105.9  Activity title includes aggregated counts: "Your post received 3 likes, 1 comment"
105.10 Cursor-based pagination returns distinct non-overlapping pages
105.11 Empty activity feed returns { items: [], next_cursor: null }
105.12 Alert category defaults to "security" for unknown event types
```

### Section 106: Tips Summary API

```
106.1  Tip on post creates tip alert; tips-summary reflects total
106.2  Tips from multiple sources aggregate correctly
106.3  Period filter ("7d", "30d") filters by timestamp
106.4  Top tippers list is sorted by total_cents desc
106.5  by_type breakdown separates post_tip and message_tip
106.6  Tips summary with no tips returns all zeros
106.7  Period "all" includes all historical tips
```

### Section 107: Action URL Navigation

```
107.1  Alert with action_url="/feed?post=X" navigates to the post when clicked
107.2  Alert with action_url="/messages/conv123" navigates to conversation
107.3  Alert without action_url does not navigate (no error)
107.4  Ticket alert with action_url="/tickets/tkt789" navigates to ticket
107.5  Follower alert with action_url="/discover?user=X" navigates to profile
107.6  Security alert with action_url="/security/sessions" navigates to sessions
107.7  action_url with external domain is rejected (not stored)
107.8  action_url with protocol (http://) is rejected
```

### Section 108: Activity Feed UI

```
108.1  Activity tab shows grouped notifications (not flat list)
108.2  Mentions tab shows only mention-type alerts
108.3  Tips tab shows tip-type alerts with amounts
108.4  Security tab shows security/audit alerts only
108.5  Bell popover Activity/System tabs filter correctly
108.6  Clicking a notification in the bell popover navigates and closes popover
108.7  Unread indicator dot appears on items with unread=true
108.8  Mark read button removes unread indicator
108.9  Activity group card shows aggregation badges (heart, comment, dollar)
108.10 Tips summary card shows total earnings and top tippers
108.11 Load more button fetches additional pages
108.12 Bell popover shows activity count badge
```

### Section 109: Mark Group Read

```
109.1  POST /ui/alerts/mark-group-read marks all alerts in a group
109.2  Marking a group read updates the activity feed item to unread=false
109.3  Marking a group with already-read alerts returns correct marked_count
109.4  Empty alert_ids array returns marked_count=0
109.5  Alert IDs from different users are rejected (404 for each)
```

---

## 7. Edge Cases

1. **Batch overflow**: When a post receives > `_BATCH_ACTORS_MAX` (10) reactions, the actors list is trimmed to the 10 most recent. The `actor_count` remains accurate because it uses atomic `ADD` (line 339-343 in `social_alerts.py`) <!-- CORRECTED: was "line 338", actually the update_item call is at line 339, the ADD operation is embedded in the UpdateExpression -->. The activity feed must use `actor_count` for display, not `len(actors)`.

2. **Self-notification**: The `emit_social_alert` function (line 189) <!-- VERIFIED: social_alerts.py:189 --> already suppresses self-notifications. The activity feed should never show "You liked your own post."

3. **Deleted source entity**: If a post is deleted after notifications were created, the `action_url` will lead to a 404. The activity feed should handle this gracefully --- show the notification but display "Content no longer available" if the navigation target returns 404. The frontend should catch navigation errors and show a toast rather than a blank page.

4. **High-frequency events**: A viral post could generate hundreds of alerts per minute. The batching system mitigates this (one batch record per post per alert type), but the SSE stream still fires for each event. The new `_should_sse_publish` debounce function (5-second window per batch key) prevents SSE flooding while still delivering timely notifications.

5. **Multi-device sync**: If the user marks alerts as read on one device, the other device should reflect this. The current SSE system pushes `alert_read` events which the frontend handles (`useAlertStream.ts`, line 79). The activity feed grouping must also respect read state. When any alert in a group is marked unread, the group shows as unread.

6. **Per-type preference disabled**: If the user disables `post_reaction` in type preferences, the activity feed must not show reaction alerts even if they were previously persisted. Filter at query time using the user's current preferences. However, this is expensive (requires fetching prefs on every request). Instead, respect prefs at write time and accept that disabled prefs only take effect for new alerts.

7. **Timezone-aware relative time**: The `formatAlertDate` function in `AlertCenter.tsx` (line 312) uses browser-local time. Activity feed timestamps should use the same approach for consistency.

8. **Activity feed ordering**: Grouped items should be ordered by `latest_ts` (the timestamp of the most recent alert in the group). When a new like comes in for an older post, that post's group should move to the top of the feed. This is achieved by using `ScanIndexForward=False` on the alerts query and taking the max `ts` for each group.

9. **Large activity groups**: A post with 1000 likes would generate 1000 alerts. The grouping query uses `Limit: limit * 5` to over-fetch, but for a single post dominating the feed, this may not be enough. The query should consume up to 5 DDB pages to find enough distinct source entities.

10. **Mixed category groups**: A single source entity (e.g., a ticket) could have both "activity" alerts (someone commented) and "updates" alerts (status changed). The grouping should include all categories for a source entity, not just one. The `category` filter on the activity feed endpoint filters at the alert level, which may split a single entity's events across categories. Consider using the `source_type` filter instead.

---

## 8. Security Considerations

1. **Alert isolation**: Alerts are partitioned by `user_sub` in DynamoDB. The `list_alerts` endpoint (line 98-99 in `alerts.py` router) <!-- CORRECTED: was "line 98", actually decorator at line 98, function def at line 99 --> queries with `Key("user_sub").eq(ctx["user_sub"])`, ensuring users can only see their own alerts. The activity feed endpoint must use the same pattern.

2. **Action URL validation**: The `action_url` field must be a relative URL (no external domains). The backend should validate that `action_url` starts with `/` and does not contain `://` to prevent open redirect attacks. The `write_alert` function now includes this validation:

   ```python
   if action_url and (not action_url.startswith("/") or "://" in action_url):
       logger.warning("Invalid action_url rejected: %s", action_url)
       action_url = None
   ```

3. **Actor identity**: The `actors` list in batched alerts contains `user_id` and `display_name`. Display names are user-controlled input and must be sanitized before rendering. The frontend should use React's default escaping (no `dangerouslySetInnerHTML`). The `display_name` is already sanitized at profile-update time, but defense in depth requires frontend escaping as well.

4. **Tips summary privacy**: The tips summary endpoint must only return tip data for the authenticated user's own content. An attacker should not be able to query another user's tip earnings. The endpoint uses `session["user_sub"]` to scope the query.

5. **SSE connection limits**: Each connected user holds an in-memory `asyncio.Queue` (`_SSE_SUBSCRIBERS` dict at line 61 in `alerts.py`) <!-- VERIFIED: alerts.py:61 -->. The activity feed does not require a separate SSE channel --- it reuses the existing alert stream. Monitor memory usage for users with many concurrent connections. The `maxsize=200` on the queue prevents unbounded memory growth.

6. **Read state manipulation**: The `mark_read` endpoint uses `ConditionExpression="#r = :f"` (line 169 in `alerts.py` router) <!-- VERIFIED: alerts.py router line 169 has ConditionExpression --> to only count items that were previously unread. This prevents a malicious client from inflating the "marked read" count by repeatedly marking the same alert. The new `mark-group-read` endpoint should use the same conditional check.

7. **CSRF on mutation endpoints**: The `POST /ui/alerts/mark-group-read` endpoint requires CSRF validation for cookie-authenticated requests. The frontend `api.post` method automatically attaches the `x-csrf-token` header.

8. **Enumeration via activity feed**: The activity feed reveals that certain posts/messages exist and have received engagement. This is acceptable since the user is the content owner. However, the `actor_user_id` in details reveals who liked/tipped the content. Consider whether this should be privacy-restricted (e.g., "someone" instead of a specific name) based on the actor's privacy settings.
