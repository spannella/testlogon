# BOT-004: AI Chat Bot (LLM Integration)

**Ticket**: BOT-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days
**Dependencies**: BOT-001 (Bot Framework & Lifecycle)

---

## 1. Overview & Motivation

### 1.1 Purpose

BOT-004 adds AI-powered conversational capabilities to the bot framework by integrating external LLM providers. Creators configure an AI bot with their own API key for any OpenAI-compatible endpoint (OpenAI, Anthropic via proxy, local models, etc.), a system prompt defining the bot's personality and knowledge boundaries, and optional knowledge base documents that provide context. The bot maintains per-user conversation history for coherent multi-turn conversations. Safety guardrails include forbidden topic detection, per-user rate limiting, human escalation triggers, and content filtering. The backend proxies all LLM API calls so the creator's API key is never exposed to the frontend or end users. Cost tracking monitors API usage per bot per month.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to connect my own LLM API key to power my bot. | API endpoint + key configured; test connection succeeds. |
| Creator | As a creator, I want to write a system prompt defining my bot's personality. | System prompt saved; bot uses it in all conversations. |
| Creator | As a creator, I want to set temperature and max tokens. | LLM parameters saved and applied to API calls. |
| Creator | As a creator, I want to upload knowledge documents for my bot to reference. | Documents uploaded and injected into system prompt context. |
| Creator | As a creator, I want my bot to remember conversation context per user. | Per-user history maintained; configurable context window. |
| Creator | As a creator, I want to set forbidden topics that escalate to me. | Forbidden keyword/topic list; bot sends fallback and flags conversation. |
| Creator | As a creator, I want to rate-limit AI responses per user. | Max N AI responses per user per hour. |
| Creator | As a creator, I want to see how much my AI bot costs per month. | Cost tracking dashboard with per-bot monthly spend estimate. |
| Creator | As a creator, I want a fallback message if the AI API is down. | Fallback template sent when API call fails. |
| User | As a user, I want to have a natural conversation with a creator's AI bot. | Bot responds contextually; conversation flows naturally. |
| User | As a user, I want to know I am talking to an AI, not a human. | "AI Bot" badge visible on all AI bot messages. |

### 1.3 Why This Is Needed

Template bots (BOT-002) handle structured, predictable interactions but cannot hold free-form conversations. Many creators want bots that can engage users in open-ended discussion -- answering questions about their content, providing personalized recommendations, or simply chatting in the creator's voice. LLM integration bridges this gap. By requiring creators to supply their own API keys, the platform avoids bearing LLM costs while enabling powerful AI experiences. The proxy architecture protects API keys and enables platform-level safety enforcement.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Bot framework** (BOT-001): Bot CRUD, assignments, trigger evaluation, `send_bot_message()`, `sender_type=bot` on messages.
- **Templates** (BOT-002): Fallback message templates, scheduled sends. AI bots use templates for the fallback message when the LLM API is unavailable.
- **Messaging** (`app/routers/messaging.py`): `send_text_message()` with `MessageOut` model. Bot messages flow through the same pipeline as human messages.
- **Crypto** (`app/core/crypto.py`): KMS encrypt/decrypt for sensitive data at rest. Used for encrypting creator API keys.
- **S3** (`app/core/dev_s3.py`): File upload infrastructure for knowledge base documents.
- **Billing/cost tracking**: `billing` table with `pk=USER#{user_sub}` pattern. Existing ledger infrastructure for tracking debits/credits.

### 2.2 Gaps

1. No LLM API integration layer -- no HTTP client for OpenAI-compatible APIs.
2. No secure API key storage (encrypted at rest).
3. No conversation history management for AI context.
4. No knowledge base upload and injection system.
5. No safety guardrail engine (forbidden topics, content filtering, escalation).
6. No per-user AI rate limiting.
7. No cost estimation or tracking for LLM API calls.
8. No AI configuration UI (API key, system prompt, model params).
9. No test-conversation interface for creators to preview their AI bot.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 ChatBots Table Extension (AI Config)

Additional fields on the existing `ChatBots` table (BOT-001) for AI-enabled bots:

| Field | Type | Description |
|-------|------|-------------|
| `ai_enabled` | BOOL | Whether this bot uses LLM integration |
| `ai_provider_url` | S | OpenAI-compatible API endpoint URL |
| `ai_api_key_encrypted` | B | KMS-encrypted API key (binary) |
| `ai_model` | S | Model name (e.g., "gpt-4o", "claude-sonnet-4-6") |
| `ai_system_prompt` | S | System prompt text (max 10000 chars) |
| `ai_temperature` | N | Temperature parameter (0.0-2.0, default 0.7) |
| `ai_max_tokens` | N | Max response tokens (default 500, max 4000) |
| `ai_stop_sequences` | L (list of S) | Stop sequences (optional) |
| `ai_context_window_size` | N | Number of recent messages to include as context (default 20, max 100) |
| `ai_forbidden_topics` | SS (string set) | Keywords/phrases that trigger human escalation |
| `ai_fallback_template_id` | S (optional) | Template to send when API fails |
| `ai_max_responses_per_user_per_hour` | N | Rate limit (default 30) |
| `ai_escalation_enabled` | BOOL | Whether escalation to human is enabled (default true) |
| `ai_content_filter_enabled` | BOOL | Whether response content filtering is active (default true) |

No new table needed; these fields extend the existing bot record.

#### 3.1.2 BotKnowledge Table

Stores knowledge base documents uploaded by the creator.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}` |
| `sk` | S | `DOC#{doc_id}` |
| `doc_id` | S | UUID hex |
| `bot_id` | S | Parent bot |
| `creator_id` | S | Bot owner |
| `title` | S | Document title (max 200 chars) |
| `content` | S | Document text content (max 50000 chars) |
| `content_hash` | S | SHA-256 hash for deduplication |
| `source_filename` | S (optional) | Original upload filename |
| `char_count` | N | Character count of content |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |

```python
TableDef(
    "bot_knowledge", "pk", "sk",
    attr_types={"char_count": "N", "created_at": "N", "updated_at": "N"},
),
```

#### 3.1.3 BotConversationHistory Table

Per-user conversation history for AI context. Messages are stored as compact entries (role + content only) to minimize storage and context window assembly cost.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}#USER#{user_id}` |
| `sk` | S | `MSG#{timestamp_ms}#{message_id_suffix}` |
| `role` | S | `user` or `assistant` |
| `content` | S | Message text |
| `timestamp` | N | Unix timestamp (ms precision) |
| `token_estimate` | N | Approximate token count for this message |
| `ttl` | N | DDB TTL; auto-expire after 30 days |

```python
TableDef(
    "bot_conversation_history", "pk", "sk",
    attr_types={"timestamp": "N", "token_estimate": "N", "ttl": "N"},
),
```

#### 3.1.4 BotCostTracking Table

Tracks LLM API usage and estimated cost per bot per month.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}` |
| `sk` | S | `MONTH#{YYYY-MM}` |
| `api_calls` | N | Total API calls this month |
| `prompt_tokens` | N | Total prompt tokens |
| `completion_tokens` | N | Total completion tokens |
| `estimated_cost_cents` | N | Estimated cost in cents |
| `last_updated` | N | Unix timestamp |

```python
TableDef(
    "bot_cost_tracking", "pk", "sk",
    attr_types={"api_calls": "N", "prompt_tokens": "N", "completion_tokens": "N",
                "estimated_cost_cents": "N", "last_updated": "N"},
),
```

#### 3.1.5 BotEscalations Table

Stores conversations flagged for human review by the AI bot.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `CREATOR#{creator_id}` |
| `sk` | S | `ESC#{escalation_id}` |
| `escalation_id` | S | UUID hex |
| `bot_id` | S | Bot that escalated |
| `conversation_id` | S | Conversation being escalated |
| `user_id` | S | User whose message triggered escalation |
| `reason` | S | `forbidden_topic`, `rate_limit`, `api_failure`, `content_filter`, `manual` |
| `trigger_text` | S (optional) | The message text that triggered escalation (truncated to 500 chars) |
| `status` | S | `pending`, `reviewed`, `dismissed` |
| `created_at` | N | Unix timestamp |
| `reviewed_at` | N (optional) | When creator reviewed |
| `GSI1PK` | S | `CREATOR#{creator_id}#STATUS#{status}` |
| `GSI1SK` | N | `created_at` |

```python
TableDef(
    "bot_escalations", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"created_at": "N", "reviewed_at": "N", "GSI1SK": "N"},
),
```

### 3.2 LLM Client (`app/services/bot_llm_client.py`)

Server-side async HTTP client for OpenAI-compatible chat completion APIs using `httpx`.

```python
async def call_llm(*, provider_url: str, api_key: str, model: str,
                    messages: list[dict], temperature: float = 0.7,
                    max_tokens: int = 500,
                    stop: list[str] | None = None,
                    timeout_seconds: int = 30) -> dict:
    """POST to {provider_url}/chat/completions with Bearer auth.
    Returns {"content": str, "prompt_tokens": int, "completion_tokens": int,
             "model": str, "finish_reason": str}."""

def estimate_tokens(text: str) -> int:
    """Rough heuristic: ~4 chars per token."""
    return max(1, len(text) // 4)

def estimate_cost_cents(*, model: str, prompt_tokens: int,
                         completion_tokens: int) -> int:
    """Estimate cost in cents from token usage using a model cost lookup table.
    Default rates used for unknown models."""
```

The cost table maps known model names (gpt-4o, gpt-4o-mini, gpt-3.5-turbo) to per-1K-token prompt/completion costs. Unknown models use conservative default rates.

### 3.3 Backend Service (`app/services/bot_ai.py`)

```python
def configure_ai_bot(*, bot_id: str, creator_id: str,
                      provider_url: str, api_key: str, model: str,
                      system_prompt: str, temperature: float = 0.7,
                      max_tokens: int = 500,
                      stop_sequences: list[str] | None = None,
                      context_window_size: int = 20,
                      forbidden_topics: list[str] | None = None,
                      fallback_template_id: str | None = None,
                      max_responses_per_user_per_hour: int = 30) -> dict:
    """Configure AI capabilities for an existing bot."""
    # 1. Verify bot ownership
    # 2. Validate provider_url is a valid HTTPS URL
    # 3. Encrypt api_key via KMS
    # 4. Update bot record with ai_* fields
    # 5. Set ai_enabled=True

def test_ai_connection(*, bot_id: str, creator_id: str) -> dict:
    """Send a test message to verify API connectivity."""
    # 1. Decrypt API key
    # 2. Send simple test prompt
    # 3. Return {"ok": bool, "model": str, "response_time_ms": int, "error": str | None}

def update_ai_config(*, bot_id: str, creator_id: str, **fields) -> dict:
    """Update AI configuration fields (system prompt, temperature, etc.)."""

def disable_ai(*, bot_id: str, creator_id: str) -> dict:
    """Disable AI for a bot (keeps config but stops LLM calls)."""

# Knowledge base management
def upload_knowledge_doc(*, bot_id: str, creator_id: str, title: str,
                          content: str, source_filename: str | None = None) -> dict:
    """Upload a knowledge base document."""
    # 1. Verify bot ownership
    # 2. Validate content length (max 50000 chars)
    # 3. Compute content_hash for dedup
    # 4. Check total knowledge base size (max 200000 chars across all docs)
    # 5. Write to BotKnowledge table

def list_knowledge_docs(*, bot_id: str) -> list[dict]:
    """List all knowledge documents for a bot."""

def delete_knowledge_doc(*, bot_id: str, doc_id: str, creator_id: str) -> dict:
    """Delete a knowledge document."""

def get_knowledge_context(*, bot_id: str) -> str:
    """Assemble all knowledge docs into a single context string for injection."""
    # Fetch all docs; concatenate with section separators
    # Truncate if total exceeds context budget

# Conversation history management
def append_to_history(*, bot_id: str, user_id: str, role: str,
                       content: str, message_id: str) -> None:
    """Append a message to the conversation history."""
    # Write to BotConversationHistory with TTL (30 days)

def get_conversation_history(*, bot_id: str, user_id: str,
                              max_messages: int = 20) -> list[dict]:
    """Fetch recent conversation history for context window."""
    # Query PK=BOT#{bot_id}#USER#{user_id}, ScanIndexForward=False, Limit=max_messages
    # Reverse to chronological order
    # Return [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]

def clear_conversation_history(*, bot_id: str, user_id: str) -> dict:
    """Clear all history for a user-bot pair (used for escalation reset)."""

# Core AI response flow
async def generate_ai_response(*, bot_id: str, conversation_id: str,
                                 user_id: str, user_message: str) -> dict:
    """Generate an AI response to a user message."""
    # 1. Fetch bot record (including AI config)
    # 2. Check ai_enabled
    # 3. Check per-user rate limit
    # 4. Check forbidden topics in user_message
    #    If match: create escalation, send fallback, return
    # 5. Decrypt API key
    # 6. Build messages array:
    #    a. System prompt (includes knowledge context)
    #    b. Conversation history (last N messages)
    #    c. Current user message
    # 7. Call LLM API
    # 8. Check forbidden topics in response
    #    If match: discard response, send fallback, create escalation
    # 9. If content_filter_enabled: run response through content filter
    #    If rejected: discard response, send fallback
    # 10. Send bot message with response text
    # 11. Append both user message and bot response to history
    # 12. Track cost (update BotCostTracking)
    # 13. Record impression on template if applicable
    # 14. Return message dict

def _check_ai_rate_limit(*, bot_id: str, user_id: str,
                          max_per_hour: int) -> bool:
    """Check if user has exceeded AI response rate limit.
    Uses in-memory counter with hourly window."""

def _check_forbidden_topics(text: str, forbidden: set[str]) -> str | None:
    """Check if text contains any forbidden topic.
    Returns matched topic or None."""
    text_lower = text.lower()
    for topic in forbidden:
        if topic.lower() in text_lower:
            return topic
    return None

def _build_system_prompt(*, base_prompt: str, knowledge_context: str,
                          bot_name: str) -> str:
    """Assemble full system prompt with knowledge context."""
    parts = [base_prompt]
    if knowledge_context:
        parts.append(f"\n\n--- Knowledge Base ---\n{knowledge_context}")
    parts.append(f"\n\nYour name is {bot_name}. You are an AI assistant.")
    return "\n".join(parts)

# Escalation management
def create_escalation(*, creator_id: str, bot_id: str, conversation_id: str,
                       user_id: str, reason: str,
                       trigger_text: str | None = None) -> dict:
    """Create an escalation record for human review."""

def list_escalations(*, creator_id: str, status: str | None = None) -> list[dict]:
    """List escalations for a creator, optionally filtered by status."""

def review_escalation(*, creator_id: str, escalation_id: str,
                       action: str) -> dict:
    """Mark escalation as reviewed or dismissed."""

# Cost tracking
def track_api_cost(*, bot_id: str, prompt_tokens: int,
                    completion_tokens: int, model: str) -> None:
    """Update monthly cost tracking record."""
    # Atomic ADD on api_calls, prompt_tokens, completion_tokens, estimated_cost_cents

def get_cost_summary(*, bot_id: str, months: int = 3) -> list[dict]:
    """Fetch cost summary for recent months."""
```

### 3.4 Backend Router (`app/routers/bot_ai.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/ui/bots/{bot_id}/ai-config` | `require_ui_session` | Configure AI settings (API key, model, system prompt) |
| GET | `/ui/bots/{bot_id}/ai-config` | `require_ui_session` | Get AI configuration (API key masked) |
| POST | `/ui/bots/{bot_id}/ai-test` | `require_ui_session` | Test API connection |
| DELETE | `/ui/bots/{bot_id}/ai-config` | `require_ui_session` | Disable AI integration |
| POST | `/ui/bots/{bot_id}/knowledge` | `require_ui_session` | Upload knowledge document |
| GET | `/ui/bots/{bot_id}/knowledge` | `require_ui_session` | List knowledge documents |
| DELETE | `/ui/bots/{bot_id}/knowledge/{doc_id}` | `require_ui_session` | Delete knowledge document |
| POST | `/ui/bots/{bot_id}/ai-chat` | `require_ui_session` | Test conversation (creator previews AI responses) |
| GET | `/ui/bots/{bot_id}/cost-summary` | `require_ui_session` | Cost tracking summary |
| GET | `/ui/bots/{bot_id}/escalations` | `require_ui_session` | List escalations |
| PATCH | `/ui/bots/{bot_id}/escalations/{escalation_id}` | `require_ui_session` | Review/dismiss escalation |
| DELETE | `/ui/bots/{bot_id}/history/{user_id}` | `require_ui_session` | Clear conversation history for a user |

**Key request models**:

```python
class ConfigureAiIn(BaseModel):
    provider_url: str = Field(..., min_length=8, max_length=500)
    api_key: str = Field(..., min_length=1, max_length=500)
    model: str = Field(..., min_length=1, max_length=100)
    system_prompt: str = Field(..., min_length=1, max_length=10000)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=500, ge=50, le=4000)
    stop_sequences: Optional[List[str]] = Field(default=None, max_length=5)
    context_window_size: int = Field(default=20, ge=1, le=100)
    forbidden_topics: Optional[List[str]] = Field(default=None, max_length=50)
    fallback_template_id: Optional[str] = None
    max_responses_per_user_per_hour: int = Field(default=30, ge=1, le=200)
    escalation_enabled: bool = True
    content_filter_enabled: bool = True

class UploadKnowledgeDocIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, max_length=50000)
    source_filename: Optional[str] = Field(default=None, max_length=255)
```

Additional models: `UpdateAiConfigIn` (all fields optional), `AiTestChatIn` (message text), `ReviewEscalationIn` (action: reviewed/dismissed). Response models: `AiConfigOut` (mirrors config with `api_key_masked`), `KnowledgeDocOut` (doc_id, title, char_count, timestamps), `AiTestChatOut` (response, token counts, response_time_ms), `MonthlyCostOut` (month, api_calls, token counts, estimated_cost_cents), `EscalationOut` (escalation details with status).

Register in `app/main.py`:

```python
from app.routers.bot_ai import router as bot_ai_router
app.include_router(bot_ai_router, prefix="/ui")
```

### 3.5 Message Processing Integration

After `send_text_message()` succeeds in `app/routers/messaging.py`, a `_trigger_bot_responses()` hook runs. It calls `get_bots_for_conversation()` to find assigned bots, then for AI bots dispatches `generate_ai_response()` as an async task; for template bots, it calls `evaluate_triggers()` and renders/sends the matched template (BOT-002).

### 3.6 Content Filtering

`filter_ai_response(response_text)` checks AI output against platform content policy before delivery: PII patterns (SSN, credit card), prohibited content categories, external URL spam, and max length. Returns `(allowed: bool, reason: str | None)`. Rejected responses are replaced by the fallback template message.

### 3.7 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface AiConfig {
  ai_enabled: boolean;
  provider_url: string;
  api_key_masked: string;
  model: string;
  system_prompt: string;
  temperature: number;
  max_tokens: number;
  stop_sequences?: string[];
  context_window_size: number;
  forbidden_topics?: string[];
  fallback_template_id?: string;
  max_responses_per_user_per_hour: number;
  escalation_enabled: boolean;
  content_filter_enabled: boolean;
}

export interface KnowledgeDoc {
  doc_id: string;
  bot_id: string;
  title: string;
  char_count: number;
  source_filename?: string;
  created_at: number;
  updated_at: number;
}

export interface BotEscalation {
  escalation_id: string;
  bot_id: string;
  conversation_id: string;
  user_id: string;
  reason: string;
  trigger_text?: string;
  status: "pending" | "reviewed" | "dismissed";
  created_at: number;
  reviewed_at?: number;
}

export interface MonthlyCost {
  month: string;
  api_calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  estimated_cost_cents: number;
}

export interface AiTestResult {
  response: string;
  prompt_tokens: number;
  completion_tokens: number;
  response_time_ms: number;
}

// Extend MessageOut
export interface MessageOut {
  // ... existing fields ...
  ai_generated?: boolean;  // true for AI bot responses
}
```

### 3.8 Frontend API (`frontend/src/api/endpoints/bots.ts`)

Standard CRUD wrappers for AI config, knowledge, test chat, cost, and escalation endpoints (matching router paths in 3.4). Key functions: `configureAi`, `getAiConfig`, `testAiConnection`, `disableAi`, `uploadKnowledgeDoc`, `listKnowledgeDocs`, `deleteKnowledgeDoc`, `aiTestChat`, `getCostSummary`, `listEscalations`, `reviewEscalation`, `clearUserHistory`.

### 3.9 Frontend Pages

- **AiConfigPage** (`frontend/src/pages/bots/AiConfigPage.tsx`): Route `/bots/:botId/ai`. Tabbed layout: Config | Knowledge | Test Chat | Costs | Escalations. `data-testid="ai-config-page"`.
  - **Config tab**: Provider URL input, API key input (password field), model name, system prompt textarea, temperature slider, max tokens input, context window slider, forbidden topics tag input, fallback template selector, rate limit input, toggle switches for escalation + content filtering. "Test Connection" button. "Save" button.
  - **Knowledge tab**: Upload text documents (paste or file upload). List existing docs as cards with title, char count, delete button. Total knowledge base size indicator. `data-testid="knowledge-tab"`.
  - **Test Chat tab**: Chat interface for creator to preview AI responses. Message input + send button. Conversation history display. Shows token usage + response time. "Clear History" button. `data-testid="test-chat-tab"`.
  - **Costs tab**: Monthly cost breakdown table (month, API calls, tokens, estimated cost). Chart showing cost trend. `data-testid="costs-tab"`.
  - **Escalations tab**: List of escalation cards with reason, trigger text, status badge, conversation link. "Review" and "Dismiss" action buttons. Filter by status. `data-testid="escalations-tab"`.

### 3.10 AI Bot Badge Enhancement

In `MessageBubble.tsx`, when `message.sender_type === "bot"` and `message.ai_generated === true`:

```tsx
<Badge variant="outline" className="text-xs">
  <Sparkles className="h-3 w-3 mr-1" /> AI Bot
</Badge>
```

Distinct from the regular "Bot" badge (BOT-001) to indicate AI-generated content.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/bot_llm_client.py` | OpenAI-compatible HTTP client, token estimation, cost calculation |
| `app/services/bot_ai.py` | AI config, knowledge base, history, response generation, escalations, cost tracking |
| `app/routers/bot_ai.py` | AI configuration + knowledge + escalation endpoints |
| `frontend/src/pages/bots/AiConfigPage.tsx` | AI configuration + knowledge + test chat + costs + escalations UI |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `bot_knowledge`, `bot_conversation_history`, `bot_cost_tracking`, `bot_escalations` TableDefs |
| `app/core/settings.py` | Add table name settings for new tables |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `bot_ai_router` |
| `app/services/chat_bot.py` | Add AI config fields to bot record handling; wire `_trigger_bot_responses()` into message flow |
| `app/routers/messaging.py` | Add `ai_generated` field to `MessageOut`; call `_trigger_bot_responses()` after message send |
| `frontend/src/api/types.ts` | Add `AiConfig`, `KnowledgeDoc`, `BotEscalation`, `MonthlyCost`, `AiTestResult` types |
| `frontend/src/api/endpoints/bots.ts` | Add AI config, knowledge, test chat, cost, escalation API functions |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render "AI Bot" badge with sparkle icon for AI-generated messages |
| `frontend/src/App.tsx` | Add `/bots/:botId/ai` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/bot-ai.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let botId: string;
let docId: string;
let escalationId: string;
// Alice = creator (bot owner), Bob = user chatting with AI bot
// Mock LLM endpoint: tests use a mock HTTP server or intercept via page.route()
```

### 5.3 Section 519: AI Configuration API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 519.1 | Configure AI on a bot | PUT `/ui/bots/{botId}/ai-config` with provider_url, api_key, model, system_prompt; 200; `ai_enabled=true` |
| 519.2 | Get AI config (key masked) | GET `/ui/bots/{botId}/ai-config`; 200; `api_key_masked` shows last 3 chars only |
| 519.3 | Update system prompt | PUT with new `system_prompt`; 200; prompt updated |
| 519.4 | Disable AI | DELETE `/ui/bots/{botId}/ai-config`; 200; GET shows `ai_enabled=false` |

### 5.4 Section 520: Knowledge Base API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 520.1 | Upload knowledge document | POST `/ui/bots/{botId}/knowledge` with title + content; 201; `doc_id`, `char_count` matches |
| 520.2 | List knowledge documents | GET `/ui/bots/{botId}/knowledge`; array includes uploaded doc |
| 520.3 | Upload second document | POST; 201; list length = 2 |
| 520.4 | Delete knowledge document | DELETE; 200; list length decremented |

### 5.5 Section 521: Escalation & Cost Tracking API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 521.1 | Test AI connection | POST `/ui/bots/{botId}/ai-test`; 200; `ok` field present |
| 521.2 | Test chat with bot | POST `/ui/bots/{botId}/ai-chat` with message; 200; `response` non-empty, `prompt_tokens > 0` |
| 521.3 | Get cost summary | GET `/ui/bots/{botId}/cost-summary`; 200; `months` array present |
| 521.4 | List escalations | GET `/ui/bots/{botId}/escalations`; 200; array returned (may be empty) |

### 5.6 Section 522: AI Config UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 522.1 | AI config page loads | Navigate `/bots/{botId}/ai`; `[data-testid="ai-config-page"]` visible |
| 522.2 | Knowledge tab displays docs | Click "Knowledge" tab; `[data-testid="knowledge-tab"]` visible; uploaded doc card shown |
| 522.3 | Test chat tab works | Click "Test Chat" tab; `[data-testid="test-chat-tab"]` visible; send message; response appears |
| 522.4 | AI Bot badge renders on messages | Navigate to conversation with AI bot message; "AI Bot" badge visible |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Bot not found | 404 | "Bot not found" |
| Not bot owner | 403 | "You do not own this bot" |
| Invalid provider URL | 422 | "Provider URL must be a valid HTTPS URL" |
| API key too short | 422 | "API key must be at least 1 character" |
| LLM API connection failed | 502 | "Failed to connect to LLM provider" |
| LLM API timeout | 504 | "LLM provider did not respond within 30 seconds" |
| LLM API rate limited | 429 | "LLM provider returned rate limit error" |
| User AI rate limit exceeded | 429 | "AI response limit reached. Try again later." |
| Knowledge doc too large | 422 | "Document content must be 50000 characters or fewer" |
| Knowledge base capacity exceeded | 409 | "Knowledge base size limit reached (200000 characters)" |
| Forbidden topic detected | 200 | Fallback message sent; escalation created (not an HTTP error) |
| Content filter rejection | 200 | Fallback message sent (not an HTTP error) |
| No AI config on bot | 404 | "AI is not configured for this bot" |
| Escalation not found | 404 | "Escalation not found" |

---

## 7. Security Considerations

- **API key encryption**: Creator API keys are encrypted at rest using KMS (`app/core/crypto.py`). The plaintext key is only decrypted in-memory at the moment of the LLM API call. Never logged, never returned to the frontend.
- **API key masking**: GET endpoints return `api_key_masked` (e.g., `"sk-...xyz"`) showing only the last 3 characters. Full key never exposed via API.
- **Provider URL validation**: Must be HTTPS (reject HTTP). Block private IP ranges (`127.0.0.1`, `10.*`, `192.168.*`, `169.254.*`) to prevent SSRF attacks against internal services.
- **Response content filtering**: AI responses are checked for PII patterns (SSN, credit card numbers), prohibited content, and external URL spam before delivery. Rejected responses are discarded and replaced with the fallback message.
- **System prompt injection prevention**: User messages are placed in the `user` role, never concatenated into the system prompt. System prompt and knowledge context are in the `system` role only.
- **Cost protection**: Per-user rate limits prevent a single user from running up the creator's API costs. Creator can set `max_responses_per_user_per_hour` as low as 1.
- **Escalation audit trail**: All escalations are logged with timestamp, reason, and trigger text. Creator reviews are tracked with `reviewed_at` timestamp.
- **Conversation history TTL**: History records auto-expire after 30 days (DDB TTL) to limit data retention. Creator can manually clear history for a specific user.
- **No client-side LLM calls**: All LLM API calls are proxied through the backend. The frontend never sees the provider URL or API key. This prevents credential theft via browser devtools.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| LLM API latency (1-10s) | Async task; user sees "typing" indicator; 30s timeout with fallback |
| Knowledge context assembly | Cache assembled knowledge text per bot with 5-minute TTL; invalidate on doc add/delete |
| Conversation history query per message | Query last N messages only (configurable, default 20); DDB SK sort is efficient |
| History table growth | 30-day TTL auto-cleanup; no manual purge needed |
| Cost tracking counter contention | Monthly partition key (`MONTH#{YYYY-MM}`) limits write contention; atomic ADD operations |
| Forbidden topic check on every message | Simple substring match in Python; set lookup is O(N) but N <= 50 topics; sub-millisecond |
| LLM API key decryption | KMS decrypt is ~10ms; cached in-memory for 5 minutes per bot to reduce KMS calls |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| BOT-001 (Bot Framework) | BOT-001 | Required (bot CRUD, assignments, send_bot_message, trigger evaluation) |
| BOT-002 (Templates) | BOT-002 | Optional (fallback template when AI fails; not strictly required for AI to function) |
| KMS crypto | Existing | Available (`app/core/crypto.py` for API key encryption) |
| httpx library | New dependency | Add to `requirements.txt` (async HTTP client for LLM API calls) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| ANALYTICS-001 (Creator Analytics) | AI cost data feeds into creator analytics |
| MOD-001 (Content Review) | Escalated AI conversations surface in moderation queue |
