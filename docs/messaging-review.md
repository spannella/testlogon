# Messaging setup review and recommendations

## Current state (high-level)

The messaging feature is functional and fairly complete (DM/group, reactions, edits, forwarding, presence, typing, search, receipts), but it is carrying technical debt in three main areas:

1. **API contract drift between frontend and backend** (highest risk).
2. **A very large single router module** that mixes transport, business logic, and persistence concerns.
3. **Real-time/event scalability constraints** from per-client polling patterns.

---

## Key findings

### 1) Frontend and backend contracts have drifted

There are several payload/shape mismatches that can cause runtime bugs or silent failures:

- Frontend sends `body` for text messages, but backend expects `text`.  
- Frontend starts a DM with `participant_id`, but backend expects `participant_ids` list.  
- Frontend `markRead` sends `last_read_message_id`, but backend expects `last_read_at` timestamp.  
- Frontend mute sends `{ muted: boolean }`, but backend expects `{ muted_until: int }`.  
- Frontend edit uses `{ body: string }`, but backend expects `{ text: string }`.  
- TypeScript message model uses fields like `body`, `image_url`, `file_url`, while backend response model uses `text`, nested `image`, nested `file`.

**Recommendation:** establish an API-first contract (OpenAPI-generated TS client/types or a shared schema package) and remove handwritten drift-prone endpoint typings.

### 2) Messaging backend is a monolith

`app/routers/messaging.py` is ~2.7k lines and includes auth decisions, validation, DDB/OpenSearch integration, fanout, search ranking, presence/typing, and SSE stream handling.

**Recommendation:** split into bounded modules/services, for example:

- `messaging/auth.py`
- `messaging/conversations_service.py`
- `messaging/messages_service.py`
- `messaging/events_service.py`
- `messaging/search_service.py`
- `messaging/presence_service.py`

Keep router handlers thin (request/response mapping only), move data logic to service layer with unit tests.

### 3) Event delivery will become expensive at scale

Current SSE uses a loop that repeatedly queries DynamoDB on an interval (`poll_ms`, default 1000ms) per connected client. This is simple but can become costly for many idle connections.

**Recommendation:**

- Short-term: add adaptive backoff for idle streams and reduce query frequency when inactive.
- Mid-term: support resume semantics via `Last-Event-ID` and explicit ack cursor management.
- Long-term: move to push-driven fanout (WebSocket manager / managed pubsub / stream consumer) instead of per-client polling.

### 4) Search fallback path can degrade with larger conversations

When OpenSearch/index path is unavailable, fallback search loops over message pages and does substring checks in app code.

**Recommendation:** maintain index health and observability as first-class. Treat fallback as emergency-only and guard it with tighter limits/circuit breakers.

### 5) Auth mode is flexible but easy to misuse

Messaging auth can use session cookie flow or bearer extraction fallback. This is useful for migration, but ambiguous in mixed clients and increases testing surface.

**Recommendation:** standardize auth mode by client type and add explicit telemetry for which auth path is used.

---

## Prioritized improvement plan

1. **Fix contract mismatches immediately** (P0): align frontend request/response shapes to backend models; add integration tests for top message flows.
2. **Introduce generated client/types** (P1): derive TS client + models from backend OpenAPI during CI.
3. **Refactor monolith into services** (P1/P2): split router by domain and preserve behavior with snapshot/integration tests.
4. **Improve event architecture** (P2): add stream cursor resume and reduce idle polling pressure.
5. **Add operational guardrails** (P2): metrics for event lag, DDB query rate, stream reconnect rate, search fallback frequency.

---

## Suggested quick wins (1–2 sprints)

- Add a **contract test** that serializes representative backend responses and validates frontend decoders/types.
- Add **lint rule / CI step** preventing manual edits to generated API types.
- Add **event instrumentation** (`events queried`, `events delivered`, `empty polls`, reconnect counts).
- Add **error budget alert** for search fallback activation rate.

These changes will give immediate reliability gains without needing a full rewrite.


## Detailed remediation plan

See `docs/messaging-contract-fix-plan.md` for an implementation-ready phased plan and acceptance criteria.
