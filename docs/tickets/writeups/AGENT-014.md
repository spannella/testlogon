# AGENT-014: Documentation Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-014 defines the Documentation Agent, a hybrid-triggered agent type that maintains comprehensive and accurate documentation for the platform. It activates on three triggers: tickets labeled `type:documentation`, PR merges (when `DOC_PR_TRIGGER_ENABLED` is set), and a configurable daily/weekly schedule for freshness checks. The core capability is a freshness monitoring system that tracks documentation artifacts against git-hash fingerprints of their source files: when a source file changes, the corresponding docs are flagged as stale and either updated by the agent or escalated as tickets. The agent also manages documentation templates and can create `type:documentation` tickets requesting inline code documentation from coder agents.

**Type**: Feature (new agent type + coverage/freshness tracking system). **Priority**: Medium. **Status**: Implemented (service + router + frontend pages + DDB tables all present). **Persona**: Platform owner / developer.

Cross-references: **SECOPS-007** (dev/prod parity for git hash computation — hashes are computed by the agent terminal, not the backend). Agent terminal execution of git operations is latent-gated, touching **SEC-021** when `DOC_AGENT_ENABLED` execution path is active.

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend Service

`app/services/agent_docs.py` (811 lines). Module docstring (lines 1–19) explicitly identifies this as AGENT-014. Note: there is no `doc_agent_execute_commands` flag in `settings.py` — the docs service treats `S.doc_agent_enabled` (`settings.py:2196`) as its master gate, and notes that "freshness comparison is pure/deterministic so it is fully driveable and testable from E2E without touching the filesystem."

- **Table bootstrap** (`ensure_tables`, line 71): Creates `agent_types` (reused), `agent_doc_coverage`, and `agent_doc_templates` tables in-process. The `agent_doc_coverage` table has two GSIs: GSI1 on `USER#{user_id}#TYPE#{doc_type}` + `last_updated`, GSI2 on `USER#{user_id}#STALE#{is_stale}` + `stale_since`. Table names from `settings.py:2191–2192`. Table handles in `app/core/tables.py:269–270`, `504–505`.

- **Path validation** (`validate_path`, `validate_paths`, lines 174–196): `validate_path` enforces relative paths, rejects absolute paths and traversal sequences (`../`, `..\\`). Called on `source_refs` before any storage. Returns `True`/`False` (non-raising); `validate_paths` collects invalid paths and returns them as a list.

- **Source hash computation** (`_compute_source_hash`, `compute_source_hashes`, lines 198–218): `_compute_source_hash(path)` opens the file at the given relative path using `open(path, "rb")` and returns `hashlib.sha256(data).hexdigest()[:16]`. **This calls the filesystem directly from the backend service.** In the ticket spec §9, "Git hash computation: Source hashes are computed by the agent in its terminal session — the backend stores hashes as opaque strings." The current implementation deviates: it reads files directly during `register_doc` and `check_freshness`. This means the backend must have the repository checked out at the working directory. In production where the backend and the agent terminal are different machines, this will return stale or missing hashes.

- **Doc coverage CRUD** (`get_doc`, `register_doc`, `update_doc_record`, `delete_doc`, `list_docs`, lines 278–419): `register_doc` (line 285) validates path, computes initial source hashes via `compute_source_hashes`, writes to DDB. If a doc with the same path already exists, raises a `DocValidationError("DOC_ALREADY_EXISTS", ...)` (409).

- **Freshness check** (`check_freshness`, line 421): Queries all `DOC#*` records for a user, recomputes current hashes via `compute_source_hashes`, compares against stored `source_hashes`. Marks stale docs with `is_stale=True`, `stale_since=now`. Returns `{"total": N, "stale": M, "fresh": K, "stale_docs": [...]}`.

- **Staleness query** (`list_stale_docs`, line 494): Queries GSI2 with `GSI2PK=USER#{user_id}#STALE#true`, sorted by `stale_since` ascending (oldest-stale first).

- **PR impact assessment** (`assess_pr_impact`, line 566): Given a list of `changed_files`, finds all doc coverage records whose `source_refs` overlap (Python set intersection). Identifies uncovered files. Returns `{"docs_to_update": [...], "uncovered_files": [...], "impact_level": "none|low|medium|high"}` where `_impact_level` (line 590) uses thresholds of 0/1-2/3-5/>5 docs to update.

- **Template CRUD** (`create_doc_template`, `get_doc_template`, `list_doc_templates`, `update_doc_template`, `delete_doc_template`, lines 609–709): Standard CRUD on `agent_doc_templates` table with `pk=USER#{user_id}`, `sk=TMPL#{template_id}`. `list_doc_templates` supports optional `doc_type` filter.

- **Doc Agent config** (`get_doc_config`, `update_doc_config`, lines 711–779): Config stored on `agent_types` table with key `TYPE#{agent_type_id}` → `DOC_CONFIG`. Validated fields: `freshness_check_frequency` (hourly/daily/weekly), `min_coverage_threshold` (0.0–1.0), `freshness_check_hour_utc` (0–23), `ignored_paths` (list of strings).

- **Inline doc ticket creation** (`create_inline_doc_ticket`, line 780): Creates a `type:documentation` ticket via `tickets_svc.STORE.create_ticket`, gated by `S.doc_inline_tickets_enabled` (`settings.py:2198`).

- **Coverage summary** (`get_coverage_summary`, line 534): Queries all docs, groups by `doc_type`, computes average `coverage_score` and `stale_count` per type. Returns `overall_coverage` as weighted mean.

### 2.2 Backend Router

`app/routers/agent_docs.py` (274 lines). Router prefix: `/ui/agents/docs`. Registered in `app/main.py:773`.

All endpoints use `require_ui_session`. No admin-gating — scoped to authenticated user's `user_sub`.

Endpoints match the ticket §3.3 spec:
- `GET /ui/agents/docs/coverage` → coverage summary
- `GET /ui/agents/docs/coverage/details` → list all docs (with `?doc_type=` filter)
- `GET /ui/agents/docs/stale` → stale docs list
- `POST /ui/agents/docs/freshness-check` → trigger freshness check
- `POST /ui/agents/docs/register` → register doc artifact
- `PUT /ui/agents/docs/coverage/{doc_path:path}` → update doc record
- `POST /ui/agents/docs/assess-pr` → PR impact assessment
- `GET /ui/agents/docs/templates` → list templates
- `POST /ui/agents/docs/templates` → create template
- `PUT /ui/agents/docs/templates/{template_id}` → update template
- `DELETE /ui/agents/docs/templates/{template_id}` → delete template
- `PUT /ui/agents/docs/config` → update doc agent config

### 2.3 Frontend

Routes in `frontend/src/App.tsx`:
- `agents/docs` → `DocCoveragePage` (lazy, line 221, 481)
- `agents/docs/templates` → `DocTemplatesPage` (line 222, 482)

Frontend pages at:
- `frontend/src/pages/agents/DocCoveragePage.tsx`
- `frontend/src/pages/agents/DocTemplatesPage.tsx`
- `frontend/src/pages/agents/StaleDocsPanel.tsx`

Note: `StaleDocsPanel` exists as a component but the ticket spec mentions it as a standalone page with route. In practice it is embedded in `DocCoveragePage` as a tab/section.

### 2.4 Dev/Prod Parity

Feature flags in `app/core/settings.py`:

| Flag | Setting key | Default | Purpose |
|------|-------------|---------|---------|
| `DOC_AGENT_ENABLED` | `doc_agent_enabled` (line 2196) | `"1"` (on) | Master kill switch + inline ticket gate |
| `DOC_PR_TRIGGER_ENABLED` | `doc_pr_trigger_enabled` (line 2197) | `"0"` (off) | Auto-trigger on PR merge |
| `DOC_INLINE_TICKETS_ENABLED` | `doc_inline_tickets_enabled` (line 2198) | `"1"` (on) | Create inline doc tickets |

Freshness checks are fully deterministic: `compute_source_hashes` reads local files, compares SHA256 hashes, no LLM calls. All DDB operations use DynamoDB Local in dev via `app/core/aws.py`. No shell execution in the backend service. SECOPS-007 requirements are met for the non-execution path.

---

## 3. Gap / Threat Analysis

### 3.1 What Is Implemented

All core functions from the ticket §3.3 spec are present: `check_freshness`, `get_coverage_summary`, `register_doc`, `update_doc_record`, `list_stale_docs`, `assess_pr_impact`, `create_doc_template`, `list_doc_templates`, `create_inline_doc_ticket`. Router, DDB tables, and frontend pages are all wired up.

### 3.2 Gaps and Risks

1. **Backend hash computation conflicts with ticket spec** (significant architecture deviation): `_compute_source_hash` (line 198) opens files from the filesystem using `open(path, "rb")`. The ticket spec §9 states: "Git hash computation: Source hashes are computed by the agent in its terminal session — the backend stores hashes as opaque strings." In a production deployment where the backend server does not share a filesystem with the agent terminal, `check_freshness` will fail or compute incorrect hashes for any file not present on the backend's disk. For the local dev stack (single machine), this works because the repo is at the working directory. For production, the hash comparison must accept externally-provided hashes — the backend should treat `source_hashes` as opaque and compare, never compute them.

2. **Path traversal in hash computation** (`compute_source_hashes`, line 211): Although `validate_paths` (line 188) checks for `../`, it returns a list of invalid paths without raising — the caller must handle this. `register_doc` calls `validate_paths` at line 307 and raises `DocValidationError("INVALID_PATH", ...)` if any invalid path is returned. However, `check_freshness` calls `compute_source_hashes` directly (line 453) without re-validating stored paths. If a stored `source_ref` somehow contains `../` (e.g., written before validation was added), `open(path)` would access files outside the repo.

3. **PR impact assessment O(N×M) performance**: `assess_pr_impact` (line 566) loads all doc coverage records into memory (`_raw_user_docs`, line 513) and performs Python-level set intersection. For users with 500+ docs and PRs with 100+ changed files, this is 50,000 set membership tests in-memory. Mitigated by the ticket §8 "practical limit ~100 changed files" note, but no enforcement exists.

4. **`doc_path` URL-encoding in router**: The update endpoint uses `{doc_path:path}` in FastAPI to capture slash-containing paths. Ensure that doc paths with `/` are round-tripped correctly through `encode_cursor`/`decode_cursor` (used for pagination) and DDB SK prefixes.

5. **Coverage score is user-supplied float**: `register_doc` accepts `coverage_score` as a `float` in `[0.0, 1.0]` validated by Pydantic. There is no automated computation of coverage — it is entirely self-reported by the agent or the user. This means the `overall_coverage` metric in `get_coverage_summary` reflects whatever the agent chose to report, which may be optimistic.

---

## 4. Proposed Design / Fix

### 4.1 Backend Hash Computation Removal (Production Fix)

Refactor `check_freshness` and `register_doc` to accept externally-provided hashes instead of computing them:

```python
def register_doc(*, user_id: str, doc_path: str, doc_type: str,
                  source_refs: list[str], coverage_score: float,
                  source_hashes: dict[str, str] | None = None,  # NEW: agent-provided hashes
                  agent_id: str | None = None) -> dict:
    """If source_hashes is None and S.dev_mode, compute locally (dev only).
    If source_hashes is None and not S.dev_mode, store empty hashes (no staleness tracking)."""
    hashes = source_hashes or (compute_source_hashes(source_refs) if S.dev_mode else {})
    ...
```

This preserves the current dev behavior (local hash computation) while allowing prod agents to supply hashes from their terminal sessions via the API payload. The `RegisterDocIn` Pydantic model gains an optional `source_hashes: dict[str, str] | None = None` field.

### 4.2 Path Traversal Defense in check_freshness

Add path re-validation in `check_freshness` before calling `compute_source_hashes`:

```python
# In check_freshness, app/services/agent_docs.py line ~453
invalid = validate_paths(source_refs)
if invalid:
    logger.warning("Skipping invalid paths in stored source_refs: %s", invalid)
    source_refs = [p for p in source_refs if p not in set(invalid)]
```

### 4.3 Dev/Prod Parity (SECOPS-007)

Current: `compute_source_hashes` reads local files — dev-only code in a non-dev-gated function. Fix: gate local hash computation on `S.dev_mode`:

```python
def compute_source_hashes(paths: list[str]) -> dict[str, str]:
    if not S.dev_mode:
        return {}  # Prod: hashes are agent-provided, never computed backend-side
    out = {}
    for path in paths:
        out[path] = _compute_source_hash(path)
    return out
```

This is the SECOPS-007 pattern: same code path, behavior selected by flag. No scattered `if dev:` branches — one central gate.

---

## 5. Testing, Verification & Rollout

### 5.1 E2E Tests

Ticket spec: `frontend/e2e/agent-docs.spec.ts`, sections 675–680 (16+ tests).

Key scenarios:
- **675.1**: `POST /ui/agents/docs/register` with `doc_path="docs/api/messaging.md"`, `source_refs=["app/routers/messaging.py"]`; 201; `is_stale=false`, `coverage_score=0.95`.
- **675.3**: `GET /ui/agents/docs/coverage`; `overall_coverage` numeric, `total_docs >= 3`.
- **676.1**: `POST /ui/agents/docs/freshness-check`; returns `total`, `stale`, `fresh`.
- **676.4**: `POST /ui/agents/docs/assess-pr` with `changed_files=["app/routers/messaging.py"]`; `docs_to_update` includes the messaging API doc; `impact_level` in `["none","low","medium","high"]`.
- **677.1**: `POST /ui/agents/docs/templates` with `doc_type="api"`, `template_body="# {{endpoint}}\n..."`, `required_sections=["Overview"]`; 201; `template_id` present.
- **679.1**: `POST /ui/agents/docs/register` same path twice; 409 `DOC_ALREADY_EXISTS`.

### 5.2 Unit Tests

File: `tests/test_documentation_agent.py`. Key cases:
- `test_register_doc_valid`: Register with valid `source_refs`, verify DDB item has `source_hashes` map and `is_stale=False`.
- `test_register_doc_invalid_path`: `source_refs=["../etc/passwd"]`; raises `DocValidationError("INVALID_PATH", ...)`.
- `test_freshness_check_marks_stale`: Register doc with hash `"abc"`, modify the source hash to `"def"` in DDB, run `check_freshness`; doc appears in `stale_docs` result.
- `test_assess_pr_impact_overlap`: Register doc referencing `app/routers/messaging.py`; `assess_pr_impact(changed_files=["app/routers/messaging.py"])` returns `docs_to_update` with that doc.
- `test_template_crud`: Create → list → update → delete lifecycle; list returns empty after delete.
- `test_create_inline_doc_ticket`: With `S.doc_inline_tickets_enabled=True`, `create_inline_doc_ticket` calls `tickets_svc.STORE.create_ticket` with `category="documentation"`.

### 5.3 Observability

Recommended additions following the ticket §7.1 metric spec:
- `doc_freshness_checks_total` Counter
- `doc_stale_count_gauge` Gauge
- `doc_coverage_gauge` Gauge with `doc_type` label

These can be added to `app/metrics.py` following the pattern of existing counters.

### 5.4 Rollout

Incremental flag-driven rollout (from ticket §8.2):
- **Week 1**: `DOC_PR_TRIGGER_ENABLED=0`, `DOC_INLINE_TICKETS_ENABLED=0`. Register docs + freshness checking only. Validate hash comparison accuracy.
- **Week 2**: `DOC_INLINE_TICKETS_ENABLED=1`. Observe ticket creation rate.
- **Week 3**: `DOC_PR_TRIGGER_ENABLED=1`. Full automation on PR merge.

Tables (`agent_doc_coverage`, `agent_doc_templates`) are defined in `scripts/local-ddb-init.py:1988,2016`. Additive — no migration.

**Effort**: M (service fully implemented; backend hash computation architectural deviation needs design fix before production).

**Open question**: The `doc_config` field stored in `agent_types` is per-agent-type (accessed by `agent_type_id`), but `register_doc` and `check_freshness` are scoped by `user_id`. This means one user can have multiple Documentation Agent types, each with different configs, but they all share the same `agent_doc_coverage` table namespace under `USER#{user_id}`. Multi-agent-type coverage tracking under one user may produce conflicting coverage records for the same `doc_path`.

### 5.4 Additional Unit Test Cases

Beyond the basic test set:
- `test_register_doc_duplicate_rejected`: Register `docs/api/messaging.md` twice; second call raises `DocValidationError("DOC_ALREADY_EXISTS", ...)` returning 409.
- `test_check_freshness_skips_invalid_paths`: Manually write a DDB record with `source_refs=["../etc/passwd"]`; `check_freshness` skips that path without crashing, logs warning.
- `test_assess_pr_no_match`: `assess_pr_impact(changed_files=["app/routers/billing.py"])` when only `docs/api/messaging.md` is registered; returns `docs_to_update=[]`, `uncovered_files=["app/routers/billing.py"]`, `impact_level="low"`.
- `test_coverage_summary_by_type`: Register 3 api docs (avg 0.9) + 1 architecture doc (0.5); `get_coverage_summary` returns `by_type["api"]["avg_coverage"] ≈ 0.9` and `by_type["architecture"]["avg_coverage"] = 0.5`.
- `test_update_doc_clears_staleness`: Manually set `is_stale=True` on a doc record; call `update_doc_record`; result has `is_stale=False`, `last_updated` is recent.
- `test_create_inline_doc_ticket`: With `S.doc_inline_tickets_enabled=True`, `create_inline_doc_ticket(source_file="app/services/billing.py", description="Missing module docstring")` calls `tickets_svc.STORE.create_ticket` with `labels=["type:documentation"]`.
- `test_template_required_sections`: Create template with `required_sections=["Overview", "Parameters"]`; list returns entry with `required_sections` matching.
