# AGENT-005: Agent Memory & Context Injection — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

AGENT-005 gives each worker a persistent "mind": a structured identity prompt (role description), a project context block (repo conventions, coding standards, CI commands), and an append-only log of accumulated memories from prior ticket sessions. At each ticket start, `assemble_full_context` combines all three layers plus the per-ticket instructions from AGENT-003 into a single text payload injected into the agent's terminal. Memory is stored in a dedicated `agent_memory` DynamoDB table; when total token count approaches a configurable threshold, the service auto-summarizes old low-importance entries so the context window is never exhausted.

- **Type**: Feature (persistence / context management)
- **Priority**: Medium — significantly improves agent quality but not required for basic orchestration
- **Status**: Implemented
- **Owning area**: AI Agents / Context Management
- **User persona**: Developer who wants agents to accumulate project knowledge over time; power user who curates agent memory
- **Cross-references**: [[AGENT-002]] (calls `initialize_memory` at worker creation), [[AGENT-003]] (calls `assemble_full_context` before ticket injection), [[AGENT-004]] (MemoryEditor tab in WorkerDetailDrawer), [[SEC-022]] (memory content must not leak encrypted fields), [[SECOPS-007]] (summarization uses in-process truncation in dev, LLM-based in prod)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service file

`app/services/agent_memory.py` (569 lines) is fully present.

**`IDENTITY_TEMPLATES`** (line 26): dict mapping `agent_type` strings (`"coder"`, `"qa"`, `"reviewer"`, `"devops"`) to multi-paragraph identity prompts that define the agent's role, responsibilities, and coding/testing rules. These are hardcoded strings with `{branch_convention}` and `{test_framework}` placeholders that are replaced at `assemble_full_context` time.

**`initialize_memory`** (line 100): called by the provisioner at worker creation. Writes an `IDENTITY` record (SK literal `"IDENTITY"`) and a `PROJECT` record (SK `"PROJECT"`) to the `agent_memory` table. Pulls the identity text from `IDENTITY_TEMPLATES`, accepts an optional `project_context` dict for immediate project configuration.

**`get_identity`** / **`set_identity`** (lines 145, 153): read/update the identity record. `set_identity` allows updating `identity_text` and/or `custom_instructions` and/or `agent_type`. If `agent_type` changes, it resets `identity_text` to the template for the new type (line 170).

**`get_project_context`** / **`set_project_context`** (lines 210, 218): read/update project fields. `set_project_context` uses a dynamic `UpdateExpression` built from keyword arguments — note the field names are interpolated directly into the expression string at line 234 (`f"{k} = :{k}"`). This is safe as long as `k` values are sanitized, but since they come from a `ProjectContextUpdateIn` Pydantic model with known field names, there is no injection risk from client input.

**`add_memory`** (line 273): creates a new memory entry with `category` (learning/decision/pattern/error/custom), `title`, `content`, `ticket_id`, `importance` (1-5). Estimates token count as `len(content) // 4`. Calls `_maybe_trigger_summarization` after each add.

**`list_memories`** (line 315): queries by `pk=WORKER#{worker_id}` and either `begins_with(sk, "MEM#")` or via the `ByCategory` GSI. Returns at most `limit=50` entries by default.

**`assemble_full_context`** (line 400): the critical function that AGENT-003 calls. It:
1. Reads identity + custom instructions
2. Reads project context and formats the relevant fields
3. Reads up to 100 memories, sorts by descending importance then descending created_at, trims to token budget
4. For each memory, uses `summary` if `summarized=True`, else uses `content`
5. Optionally fetches ticket context from AGENT-003's `inject_ticket_context`
6. Returns the assembled string

**`_maybe_trigger_summarization`** (line 535): sums `token_count` across all memories; if total > `SUMMARIZE_THRESHOLD` (80,000), sorts candidates by ascending importance and ascending created_at, and for each: truncates `content` to 200 chars + `"..."` and sets `summarized=True`. In dev mode this is simple truncation; in prod this would call an LLM to produce a semantic summary (see §3.2 and §4.2).

**`export_memory`** / **`import_memory`** (lines 466, 481): JSON roundtrip for backup/transfer between workers. Import appends to existing memories (does not delete).

**`list_templates`** (line 518): returns identity template metadata for all agent types.

### 2.2 Router

`app/routers/agent_memory.py` (289 lines) provides 12 endpoints under `/ui/agent/memory/{worker_id}`. All use `require_ui_session`. Registered at `app/main.py:752`. The worker ownership check is performed by calling `get_worker(user_id, worker_id)` and returning 404 if the authenticated user does not own the worker.

### 2.3 Data model

`app/models.py:6237` — `MemoryEntryIn` with `category` pattern `^(learning|decision|pattern|error|custom)$`, `title` max 200, `content` max 10000, `importance` ge=1 le=5.

`app/models.py` also has `AgentIdentityOut`, `AgentIdentityUpdateIn`, `ProjectContextOut`, `ProjectContextUpdateIn` (all fields optional for partial update), `MemoryEntryOut`, `MemoryListOut` (with `total_tokens`), `FullContextOut`, `MemoryExportOut`, `MemoryImportIn`, `MemoryImportOut`, `MemoryTemplateOut`.

### 2.4 DynamoDB table

`scripts/local-ddb-init.py:1925` creates `agent_memory`:
- PK `WORKER#{worker_id}`, SK multi-pattern: `IDENTITY`, `PROJECT`, `MEM#{memory_id}`
- GSIs: `ByCreatedAt` (pk + created_at, `attr_types={"created_at":"N"}`), `ByCategory` (pk + category)

`app/core/settings.py:2163` adds `agent_memory_table_name`, `agent_memory_max_entries`, `agent_memory_max_token_count`.

### 2.5 Frontend

`frontend/src/pages/agents/AgentMemoryPage.tsx` — standalone memory management page at `/agents/memory/:workerId`. The memory editor appears to be embedded in the worker detail drawer as a tab (as designed) but also accessible as a standalone page.

### 2.6 E2E tests

`frontend/e2e/agent-memory.spec.ts` covers sections 639-642 (18 tests): identity/project context API, memory CRUD, context assembly/export, and memory UI.

### 2.7 Dev vs prod parity (SECOPS-007)

The memory service has one point where dev and prod diverge: `_maybe_trigger_summarization`. In dev it uses simple 200-char truncation (line 558). In prod it would call an LLM (via an injected LLM client selected by `S.dev_mode`) to produce semantic summaries. Per SECOPS-007, the prod LLM call must use a provider interface + factory, selected by flag, with a mock that returns deterministic results in dev. Currently the dev stub is the only implementation — the prod LLM call is not yet written. This is a known gap (see §3.2).

---

## 3. Gap / Threat Analysis

### 3.1 Memory content security: no sanitization of injected text

`assemble_full_context` (line 400) concatenates memory entry `content` fields directly into the context payload. If a malicious ticket description causes an agent to write `[AGENT_COMPLETE]` into its own memory via `add_memory`, that memory will re-trigger false completion signals on all future tickets. This is the prompt-injection vector from the memory layer.

**Mitigation**: Apply the same signal token sanitization from AGENT-003 §4.3 to memory `content` and `title` before assembly. Also, entries with `category="error"` that contain adversarial content (e.g., injected via a compromised ticket) should be reviewed before re-injection.

### 3.2 Summarization LLM call not implemented for prod

`_maybe_trigger_summarization` truncates to 200 chars in all environments. In prod, this loses semantic information: an entry like "After trying three approaches, the cleanest solution was X because of Y" becomes "After trying three approaches, the cl..." — meaningless. The prod path needs an LLM summarization call. Per SECOPS-007, this should be gated by `S.dev_mode`: a mock that returns the first sentence in dev, a real LLM call in prod using a stored API key from AGENT-001.

### 3.3 Token count estimation is inaccurate

`len(content) // 4` is a rough approximation. For code-heavy content (lots of short tokens like `{`, `}`, `;`), actual token count can be 2x this estimate. For prose, it is about right. If the estimate is systematically low, `assemble_full_context` may inject a context larger than the target LLM's context window, causing truncation or errors. Fix: use a proper tokenizer (e.g., `tiktoken` for OpenAI, or a character-based estimate calibrated per provider) gated by `S.dev_mode`.

### 3.4 `set_project_context` uses dynamic UpdateExpression field names

In `set_project_context` (line 218), the update expression is built from keyword argument names:
```python
for k, v in fields.items():
    updates.append(f"{k} = :{k}")
    values[f":{k}"] = v
```
Since `k` comes from a Pydantic model field, injection is not possible via the API. However, if `set_project_context` is called internally with arbitrary kwargs (e.g., from import_memory), a field name like `pk` or `sk` would overwrite the table key. Add an allowlist check: `k in ProjectContextUpdateIn.model_fields`.

### 3.5 Memory import does not validate content size

`import_memory` (line 481) calls `add_memory` for each entry in the import JSON. A malicious import with 1000 entries of 10KB each would write 10MB to DDB and push the summarization threshold into a tight loop. Add a cap: `max(len(data.get("memories", [])), agent_memory_max_entries)` and validate `len(content) <= 10000` per entry.

### 3.6 Memory not deleted when worker is terminated

When a worker is terminated (AGENT-002's `terminate_worker`), the `agent_memory` records for that worker remain in DDB indefinitely. This is a data retention issue: user data that is conceptually "gone" persists in the system. Add a `delete_all_memory(worker_id)` call at worker termination time, or implement a TTL strategy.

---

## 4. Proposed Design / Fix

### 4.1 Signal token sanitization in assembly

```python
# In assemble_full_context, when appending a memory entry:
safe_content = text.replace("[AGENT_COMPLETE]", "﹝AGENT_COMPLETE﹞")
                   .replace("[AGENT_FEEDBACK_NEEDED]", "﹝AGENT_FEEDBACK_NEEDED﹞")
included.append(f"- [{mem.get('category', 'note')}] {mem.get('title', '')}: {safe_content}")
```

Apply the same to `identity_text` and project context fields.

### 4.2 Prod LLM summarization (SECOPS-007 compliant)

Create a `SummarizationClient` interface:

```python
class SummarizationClient(Protocol):
    def summarize(self, text: str, max_tokens: int) -> str: ...

class MockSummarizationClient:
    def summarize(self, text: str, max_tokens: int) -> str:
        # Return first sentence (deterministic, no LLM call)
        return text.split(".")[0] + "." if "." in text else text[:200]

class AnthropicSummarizationClient:
    def summarize(self, text: str, max_tokens: int) -> str:
        # Real Anthropic API call, key from AGENT-001 vault
        ...

def _get_summarization_client() -> SummarizationClient:
    if S.dev_mode:
        return MockSummarizationClient()
    return AnthropicSummarizationClient(key=get_platform_llm_key())
```

Factory selected once at startup, injected into `_maybe_trigger_summarization`. This satisfies SECOPS-007: no outbound call in dev, real LLM in prod, same code path.

### 4.3 Memory deletion on worker termination

In `agent_worker_provisioner.py`, `terminate_worker` (line 422) should call:
```python
from app.services.agent_memory import delete_all_memory
delete_all_memory(worker_id)
```

Where `delete_all_memory` issues a `batch_write_item` to delete all `WORKER#{worker_id}` items (identity, project, all MEM# entries).

### 4.4 Import validation

```python
def import_memory(worker_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    entries = data.get("memories", [])
    if len(entries) > MAX_MEMORY_ENTRIES:
        raise ValueError(f"Import limited to {MAX_MEMORY_ENTRIES} entries")
    for entry in entries:
        if len(entry.get("content", "")) > 10000:
            raise ValueError("Memory entry content exceeds 10000 characters")
    ...
```

### 4.5 Dev/Prod parity (SECOPS-007)

Beyond summarization (§4.2), the memory service is fully dev/prod agnostic: DDB via `T.agent_memory`, timestamps via `now_ts()`, no external calls. The `export_memory` → S3 path (if added) would use `app/core/dev_s3.py` (moto) in dev and real S3 in prod, following the existing pattern.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_agent_memory.py`)

| Test | What it pins |
|---|---|
| `test_initialize_memory_creates_identity_and_project` | `IDENTITY` and `PROJECT` records exist after `initialize_memory` |
| `test_identity_template_for_each_type` | coder/qa/reviewer/devops identity texts are non-empty and distinct |
| `test_add_memory_increments_token_count` | `token_count = len(content) // 4` for new entries |
| `test_summarization_triggered_above_threshold` | Add entries until `total_tokens > SUMMARIZE_THRESHOLD`, verify some entries have `summarized=True` |
| `test_full_context_contains_all_sections` | `assemble_full_context` output contains "AGENT IDENTITY", "PROJECT CONTEXT", "ACCUMULATED MEMORY" |
| `test_full_context_sanitizes_signal_tokens` | Memory entry with `[AGENT_COMPLETE]` → context contains escaped version |
| `test_import_validates_entry_count` | Import with 201 entries → ValueError |
| `test_set_project_context_rejects_key_fields` | `set_project_context(worker_id, pk="evil")` → ValueError |
| `test_memory_scoped_to_worker` | Alice's memories never appear in Bob's `list_memories` result |

### 5.2 E2E tests (Playwright)

`frontend/e2e/agent-memory.spec.ts` sections 639-642:
- Section 639.1: New worker identity contains "Coder Agent" for `agent_type="coder"`
- Section 641.10: Full context response contains all three section headers
- Section 641.11: Export/import roundtrip preserves all memory entries
- Section 642.15-18: UI tab shows identity textarea and memory list with badges

### 5.3 Manual QA

```bash
# After creating a worker, check identity was initialized
curl http://localhost:8000/ui/agent/memory/$WORKER_ID/identity -b "$COOKIES"
# Should return agent_type, identity_text, custom_instructions

# Add a memory entry
curl -X POST http://localhost:8000/ui/agent/memory/$WORKER_ID/entries \
  -H "x-csrf-token: $CSRF" -b "$COOKIES" \
  -d '{"category":"learning","title":"DynamoDB trick","content":"Always use begins_with for SK prefix queries","importance":4}'

# Preview full context
curl http://localhost:8000/ui/agent/memory/$WORKER_ID/full-context -b "$COOKIES"
```

### 5.4 Observability

Add `logger.info` in `add_memory` (memory_id, worker_id, category, token_count) and `_maybe_trigger_summarization` (worker_id, entries_summarized, tokens_freed). Add a metric `agent_memory_total_tokens{worker_id}` gauge — updated after each add or summarize operation.

### 5.5 Rollout

1. Memory service is already active for new workers. `initialize_memory` is called in `create_worker`.
2. Summarization LLM call: keep dev stub in place; implement prod path behind `AGENT_MEMORY_SUMMARIZATION_ENABLED` flag.
3. Memory deletion on termination: add to AGENT-002 termination flow in a PR.

### 5.6 Rollback

If memory injection causes agent misbehavior, `update_identity(worker_id, identity_text="")` clears the identity prompt for a specific worker. Memories can be deleted individually via the API. No global rollback needed — feature is additive.

### 5.7 Effort estimate: **S** (2-3 days) for gap fixes (signal sanitization, import validation, memory cleanup on termination, prod summarization stub). Core service is already implemented.
