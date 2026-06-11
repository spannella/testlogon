# CRM Workflow & Process Automation — Implementation Tickets

**Area**: Workflow & Process Automation (AOW)
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T3] Workflow & Process Automation (AOW) — 9 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Advanced OpenWorkflow (AOW) module provides a user-configurable rule engine: admins define workflow rules that target a CRM module (contact, lead, ticket, etc.), choose a trigger (on-save when a record is created or updated; on schedule / cron cadence; N hours/days after a record field date), compose multi-field conditions (equality, contains, greater-than, less-than, is-empty), and attach ordered action steps (modify a field, create a linked record such as a Task or Case, send a template email, or run a multi-stage drip sequence). Rules fire automatically — the platform evaluates every rule whose trigger and conditions match whenever the relevant record changes or the scheduler runs.

testlogon has solid time-based scheduling (`app/services/scheduled_actions.py`, `app/services/unified_scheduler.py`), narrow event-triggered automation (chatbot keyword triggers in `app/services/bot_template.py`, cart-abandonment drip in `app/services/cart_reminders.py`), and outbound webhook dispatch (`app/services/webhook_service.py`) — but no user-configurable rule-engine: no rule definitions persisted in DynamoDB, no multi-field condition evaluator, no modify-field or create-record action steps, and no on-save trigger hook.

## Cross-cutting constraints

- **Additive only, default-off**: All tickets are gated by `S.crm_workflow_enabled` (`CRM_WORKFLOW_ENABLED`, default `"0"`). With the flag off, all routes under `/ui/crm/workflow/*` return 404 and all background workers are no-ops. No existing service files are modified unless a ticket explicitly calls it out.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: New tables follow the `TableDef` pattern at `scripts/local-ddb-init.py:29`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` — omitting causes a DynamoDB `ValidationException` at query time (CLAUDE.md gotcha). All code runs identically in dev (moto, `DDB_ENDPOINT_URL=http://localhost:8001`) and prod. No `if dev_mode` branches in business logic.
- **Reuse existing primitives — never fork**:
  - Auth: `app/auth/policy.require_admin_or_root` / `require_admin_or_root_csrf` (`app/routers/admin_notifications.py:13`) for admin-scoped endpoints; `app/services/sessions.require_ui_session` for user-scoped read endpoints.
  - Background loop pattern: `app/services/audit_export_schedule.py:295` — `asyncio.sleep(poll_interval)` + `start_*_task` startup hook registered in `app/main.py` via `app.add_event_handler("startup", ...)`.
  - Unified scheduler infrastructure: `app/services/unified_scheduler.py` — `_EXECUTORS` dispatch table, `query_due_actions` / `claim_action` / `mark_action_completed` / `mark_action_failed` from `app/services/scheduled_actions.py:355`.
  - Template email: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`), `app/services/notification_templates.get_template` / `preview_template` (`app/services/notification_templates.py:171`), variable substitution via `app/services/bot_template.resolve_variables` (`app/services/bot_template.py:215`).
  - Staged reminder config pattern: `app/services/cart_reminders.py` — `_get_stages()`, `_STAGE_CONFIG_PK`, `_OPTOUT_PK_PREFIX`, `_default_stages()` for config-driven multi-stage sequences with per-stage delay and template.
  - Audit events: `app/services/alerts.audit_event` (`app/services/alerts.py:644`).
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor` (`app/core/cursor.py`).
  - Job registry: `app/services/job_registry.register_task` / `report_poll` / `report_error` (`app/services/job_registry.py:23`).
  - Ticket CRUD: `app/services/tickets.TicketStore` (`app/services/tickets.py:244`) for create-record action targeting tickets.
- **Route ordering**: Declare static sub-paths (`/definitions`, `/runs`, `/actions`, `/templates`) **before** dynamic `/{rule_id}` segments to prevent FastAPI matching literals as path params.
- **Hermetic offline tests**: All pytest use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles (canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`). No real AWS, network, or external service calls.

---

### WFL-001: Feature flag, settings & DynamoDB scaffolding
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Introduce the `CRM_WORKFLOW_ENABLED` feature flag, new table-name settings, and the two new DynamoDB tables required by all subsequent WFL tickets. This ticket is pure scaffolding — no user-visible behaviour.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern used for `unified_scheduler_enabled` at `app/core/settings.py:1933`:

```python
crm_workflow_enabled: bool = _bool_env("CRM_WORKFLOW_ENABLED", False)
crm_workflow_rules_table_name: str = _str_env("CRM_WORKFLOW_RULES_TABLE_NAME", "crm_workflow_rules")
crm_workflow_runs_table_name: str = _str_env("CRM_WORKFLOW_RUNS_TABLE_NAME", "crm_workflow_runs")
crm_workflow_poll_interval_seconds: int = int(os.environ.get("CRM_WORKFLOW_POLL_INTERVAL_SECONDS", "60"))
crm_workflow_max_rules_per_module: int = int(os.environ.get("CRM_WORKFLOW_MAX_RULES_PER_MODULE", "50"))
crm_workflow_max_conditions_per_rule: int = int(os.environ.get("CRM_WORKFLOW_MAX_CONDITIONS_PER_RULE", "10"))
crm_workflow_max_actions_per_rule: int = int(os.environ.get("CRM_WORKFLOW_MAX_ACTIONS_PER_RULE", "10"))
```

**Table additions** (`scripts/local-ddb-init.py`) — two new `TableDef` entries following the pattern at `scripts/local-ddb-init.py:1319`:

1. `crm_workflow_rules` — stores rule definitions and their enabled/disabled state:
   - PK `pk` (S), SK `sk` (S)
   - META row: `sk="META"` — full rule definition (rule_id, name, description, target_module, trigger_type, trigger_config, conditions list, actions list, enabled bool, created_by, created_at, updated_at)
   - GSI `ByModule`: PK `GSI_MODULE_PK` (S) = `MODULE#{target_module}`, SK `GSI_MODULE_SK` (N) = `created_at` — allows listing all active rules for a target module efficiently
   - `attr_types={"GSI_MODULE_SK": "N"}`

2. `crm_workflow_runs` — append-only execution log for rule evaluations:
   - PK `pk` (S) = `RULE#{rule_id}`, SK `sk` (S) = `RUN#{ts:010d}#{run_id}`
   - Fields: run_id, rule_id, target_module, record_id, trigger_type, outcome (`matched` / `skipped` / `error`), actions_fired list, started_at (N), finished_at (N), error_message
   - GSI `ByRecord`: PK `GSI_RECORD_PK` (S) = `{target_module}#{record_id}`, SK `GSI_RECORD_SK` (N) = `started_at` — enables per-record run history queries
   - `attr_types={"GSI_RECORD_SK": "N"}`

**Table handles** (`app/core/tables.py`) — add `crm_workflow_rules` and `crm_workflow_runs` to `T` via `_safe_table(S.crm_workflow_rules_table_name)` and `_safe_table(S.crm_workflow_runs_table_name)`, mirroring the `T.contacts = _safe_table(S.contacts_table_name)` pattern at `app/core/tables.py:354`.

**Acceptance Criteria**
- `CRM_WORKFLOW_ENABLED=0` (default): no routes registered, background worker is a no-op.
- Both DynamoDB tables are created by `scripts/local-ddb-init.py` on `just up` / `just restart`.
- `app/core/tables.py` exposes `T.crm_workflow_rules` and `T.crm_workflow_runs`.
- `just test` remains green with zero modifications to existing service files.

**Dependencies**
- None. Must be merged first.

---

### WFL-002: Workflow rule data model & CRUD service
**Type:** Feature  **Priority:** P0  **Estimate:** 2d

**Description**

Implement the core `WorkflowRuleStore` service (`app/services/workflow_rules.py`) that persists rule definitions to `T.crm_workflow_rules` and exposes typed CRUD helpers. No router or executor in this ticket — only the data layer that all subsequent tickets depend on.

**Data model** (inline Python; also add matching Pydantic models to `app/models.py`):

```python
# Trigger types
TRIGGER_TYPES = ["on_save", "on_schedule", "on_time_elapsed"]

# Target modules — extensible enum; initial set:
TARGET_MODULES = ["ticket", "contact", "order", "subscription", "lead"]

# Condition: one field comparison triple
# operator: eq | neq | contains | gt | lt | is_empty | is_not_empty
ConditionIn = {"field": str, "operator": str, "value": Optional[str]}

# Trigger config varies by trigger_type:
#   on_save:         {"events": ["create", "update"]}           (one or both)
#   on_schedule:     {"cron_expression": str, "timezone": str}  (mirrors bot_scheduler.py:77)
#   on_time_elapsed: {"field": str, "offset_hours": int}        # fire N hours after field value

# Action step (ordered list, executed sequentially on match)
# action_type: modify_field | create_record | send_email | drip_sequence
ActionIn = {"action_type": str, "config": dict}
```

**DDB key scheme** (mirroring `app/services/scheduled_actions.py:34`):
- PK: `RULE#{rule_id}`, SK: `META`
- GSI_MODULE_PK: `MODULE#{target_module}`, GSI_MODULE_SK: `created_at` (N)

**Service functions** in `app/services/workflow_rules.py`:
- `create_rule(*, created_by, name, description, target_module, trigger_type, trigger_config, conditions, actions, enabled=True) -> dict` — validates `target_module` in `TARGET_MODULES`, trigger/conditions/actions count limits from `S`, writes to DDB, emits `audit_event("crm_workflow_rule.created", ...)` via `app/services/alerts.audit_event` (`app/services/alerts.py:644`).
- `get_rule(rule_id) -> dict | None`
- `list_rules(*, target_module=None, enabled_only=False, limit=25, cursor=None) -> dict` — queries `ByModule` GSI when `target_module` supplied; otherwise scans (small table); cursor pagination via `app/core/cursor.encode_cursor`.
- `update_rule(rule_id, *, updated_by, **fields) -> dict | None` — partial patch; emits `crm_workflow_rule.updated`.
- `delete_rule(rule_id, *, deleted_by) -> bool` — hard-delete; emits `crm_workflow_rule.deleted`.
- `enable_rule(rule_id, *, actor) / disable_rule(rule_id, *, actor) -> dict | None` — sets `enabled` flag, emits appropriate audit event.
- `list_rules_for_module(target_module) -> list[dict]` — used internally by the executor; returns all `enabled=True` rules for a module ordered by `created_at`.

**Pydantic models** added to `app/models.py`:
- `WorkflowConditionIn`, `WorkflowActionIn`, `WorkflowRuleCreateIn`, `WorkflowRuleUpdateIn`, `WorkflowRuleOut` — mirrors the pattern of `ScheduledActionCreateIn` at `app/models.py`.

**Acceptance Criteria**
- All seven service functions pass unit tests with moto-backed `T.crm_workflow_rules`.
- Creating a rule with an invalid `target_module` or `trigger_type` raises `ValueError`.
- Exceeding `S.crm_workflow_max_conditions_per_rule` or `S.crm_workflow_max_actions_per_rule` raises `OverflowError`.
- `list_rules_for_module("ticket")` returns only `enabled=True` rules for the ticket module.

**Dependencies**
- WFL-001 (tables and flag).

---

### WFL-003: Condition evaluator engine
**Type:** Feature  **Priority:** P0  **Estimate:** 1d

**Description**

Implement a pure, stateless condition evaluator module (`app/services/workflow_condition_evaluator.py`) that takes a list of `ConditionIn` dicts and a flat record dict, and returns `(matched: bool, details: list[dict])`. This module has zero DynamoDB calls — it is purely in-memory logic, making it fully testable without moto.

**Operators supported** (mirrors SuiteCRM condition operators):

| Operator | Record field type | Logic |
|---|---|---|
| `eq` | any | `str(record[field]) == str(value)` (case-insensitive for strings) |
| `neq` | any | inverse of `eq` |
| `contains` | str | `value.lower() in record[field].lower()` |
| `gt` | numeric or ISO datetime str | `float(record[field]) > float(value)` |
| `lt` | numeric or ISO datetime str | `float(record[field]) < float(value)` |
| `is_empty` | any | field absent, `None`, or `""` |
| `is_not_empty` | any | inverse of `is_empty` |

All conditions are ANDed (all must pass for `matched=True`). A missing field evaluates as empty-string for non-`is_empty` operators (never raises `KeyError`). Unknown operators return `False` with `{"operator": op, "error": "unknown_operator"}` in details.

**Key function signatures** (`app/services/workflow_condition_evaluator.py`):
```python
def evaluate_conditions(conditions: list[dict], record: dict) -> tuple[bool, list[dict]]:
    ...

def _eval_one(condition: dict, record: dict) -> tuple[bool, dict]:
    ...
```

`evaluate_conditions` short-circuits on the first failing condition for performance (AND semantics). `details` list always contains one entry per condition with `{"field", "operator", "value", "record_value", "passed"}`.

**Acceptance Criteria**
- Unit tests (no moto required) cover all seven operators, missing-field edge case, and short-circuit behaviour.
- `evaluate_conditions([], record)` returns `(True, [])` — empty conditions always match (enables "fire on all records" rules).
- Unknown operator returns `(False, [{"error": "unknown_operator"}])`.

**Dependencies**
- WFL-001 (flag only, for guard).

---

### WFL-004: On-save trigger hook
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Wire the on-save workflow trigger into the platform's existing save paths for the initial supported modules (tickets, contacts, orders). When a record is written, the hook looks up all enabled `on_save` rules targeting that module, evaluates their conditions against the newly written record, and enqueues matched rules as `crm_workflow` action items in the `scheduled_actions` table for immediate (or near-immediate) dispatch by the unified scheduler.

**Hook implementation** (`app/services/workflow_hooks.py`):
```python
def fire_on_save_hook(*, module: str, record: dict, event: str) -> int:
    """Called after a successful record write.
    
    module: one of TARGET_MODULES (e.g. "ticket", "contact")
    record: the full record dict as returned by the service layer
    event: "create" or "update"
    Returns the count of rules matched and enqueued.
    """
```

Internal flow:
1. Guard: `if not S.crm_workflow_enabled: return 0`.
2. `rules = workflow_rules.list_rules_for_module(module)` — fetches all enabled rules for the module from `T.crm_workflow_rules` (uses `ByModule` GSI).
3. Filter to `trigger_type == "on_save"` where `event in trigger_config["events"]`.
4. For each rule: `matched, details = evaluate_conditions(rule["conditions"], record)`.
5. If matched: enqueue via `create_action(user_sub="system", action_type="crm_workflow", scheduled_at=now_ts(), payload={"rule_id": rule["rule_id"], "module": module, "record_id": record_id, "event": event})` — reuses `app/services/scheduled_actions.create_action` (`app/services/scheduled_actions.py:91`). Uses `user_sub="system"` so the action appears in the system partition.
6. Returns count of enqueued actions.

**Wiring into existing save paths** — add a fire-and-forget (best-effort `try/except`) call to `fire_on_save_hook` at the end of:
- `app/services/tickets.TicketStore.create_ticket` (`app/services/tickets.py:411`) — `module="ticket"`, `event="create"`.
- `app/services/tickets.TicketStore._conditional_update_meta` (`app/services/tickets.py:723`) — `module="ticket"`, `event="update"` (only when the conditional put succeeds).
- `app/routers/contacts.add_contact` (`app/routers/contacts.py:85`) — `module="contact"`, `event="create"`.
- `app/routers/contacts.update_contact` (`app/routers/contacts.py:121`) — `module="contact"`, `event="update"`.

Wrapping in `try/except Exception: logger.warning(...)` ensures a bug in the workflow hook never breaks the primary write path. The hook itself is synchronous (no `await`) to keep the wiring simple.

**Acceptance Criteria**
- With `CRM_WORKFLOW_ENABLED=0`, `fire_on_save_hook` returns 0 and makes no DDB calls.
- An enabled `on_save` rule with matching conditions produces one `crm_workflow` action row in `T.scheduled_actions`.
- A rule with non-matching conditions produces no action row.
- A rule scoped to `events=["update"]` does not fire on `event="create"`.
- Existing ticket and contact tests remain green (`just test`).

**Dependencies**
- WFL-001, WFL-002, WFL-003.

---

### WFL-005: On-schedule & time-elapsed triggers (background worker)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement the background worker (`app/services/workflow_scheduler.py`) that drives `on_schedule` and `on_time_elapsed` workflow rule triggers. This is the CRM analogue of the existing `app/services/audit_export_schedule.py:295` pattern.

**On-schedule trigger**: For rules with `trigger_type == "on_schedule"`, the worker uses the `cron_expression` field from `trigger_config` to determine if the rule is due (mirrors the cron parser already in `app/services/bot_scheduler.py:77`). When due: query the module's record list, evaluate conditions per-record, enqueue matched records as `crm_workflow` scheduled actions.

**On-time-elapsed trigger**: For rules with `trigger_type == "on_time_elapsed"`, the worker:
1. Reads `trigger_config["field"]` (e.g. `"closed_at"`) and `trigger_config["offset_hours"]`.
2. Queries records in the target module whose `field` value is a timestamp that occurred `offset_hours` hours ago (within a ±`poll_interval` window).
3. Evaluates conditions per-record; enqueues matched records.

**DDB state tracking**: Each `on_schedule` rule stores `next_run_at` (N) on its META row (updated after each run). `on_time_elapsed` rules are stateless — the worker re-queries each poll cycle (idempotent: the action executor logs the run to `crm_workflow_runs` and skips re-execution for the same `rule_id+record_id+window`).

**Background loop** (`app/services/workflow_scheduler.py`):
```python
async def run_workflow_scheduler_loop() -> None:
    register_task("crm_workflow_scheduler", S.crm_workflow_poll_interval_seconds, ...)
    while True:
        try:
            _tick_scheduled_rules(now_ts())
            _tick_time_elapsed_rules(now_ts())
        except Exception:
            logger.exception("crm_workflow_scheduler_error")
        await asyncio.sleep(S.crm_workflow_poll_interval_seconds)

async def start_workflow_scheduler_task() -> None:
    if S.crm_workflow_enabled:
        asyncio.create_task(run_workflow_scheduler_loop())
```

Register in `app/main.py`: `app.add_event_handler("startup", start_workflow_scheduler_task)` alongside existing `start_unified_scheduler_task` at `app/main.py:229`.

**Record querying helpers** (`app/services/workflow_record_fetcher.py`): small adapter module with one function per supported module that returns a list of record dicts; initial implementations:
- `fetch_module_records(module: str, *, field_filter: dict | None = None, limit: int = 100) -> list[dict]` — dispatches to per-module helpers (`_fetch_tickets`, `_fetch_contacts`) using existing service functions (`TicketStore.list_tickets`, contacts list endpoint logic).

**Acceptance Criteria**
- With `CRM_WORKFLOW_ENABLED=0`, the scheduler loop exits immediately without registering the task.
- `on_schedule` rule with `next_run_at <= now` is processed and `next_run_at` is advanced by one cron interval.
- `on_time_elapsed` rule with `offset_hours=24` and a record whose `closed_at` is `now - 24h` (within poll window) produces one enqueued action.
- No duplicate enqueue: running the tick twice within the same window does not produce two action rows (dedup via `crm_workflow_runs` check).
- Background worker registers with `job_registry.register_task` so it appears in the admin jobs dashboard.

**Dependencies**
- WFL-001, WFL-002, WFL-003, WFL-004.

---

### WFL-006: Action executor — modify-field & create-record
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement the action executor (`app/services/workflow_action_executor.py`) and wire it into the unified scheduler's `_EXECUTORS` dispatch table (`app/services/unified_scheduler.py:28`). This ticket covers the two record-mutation action types: `modify_field` and `create_record`.

**Executor wiring**: Add `"crm_workflow": execute_crm_workflow_action` to `_EXECUTORS` in `app/services/unified_scheduler.py:28`. The executor receives `(user_sub, payload)` where `payload = {"rule_id", "module", "record_id", "event"}`.

**Top-level executor function** (`app/services/workflow_action_executor.py`):
```python
async def execute_crm_workflow_action(user_sub: str, payload: dict) -> None:
    rule = workflow_rules.get_rule(payload["rule_id"])
    if not rule or not rule["enabled"]:
        return  # rule deleted/disabled after enqueue — skip silently
    run_id = _new_run_id()
    started_at = now_ts()
    actions_fired = []
    try:
        for action in rule["actions"]:
            result = await _execute_action(action, module=payload["module"],
                                           record_id=payload["record_id"])
            actions_fired.append({"action_type": action["action_type"], "result": result})
    except Exception as exc:
        _write_run(rule_id=rule["rule_id"], run_id=run_id,
                   outcome="error", error_message=str(exc),
                   actions_fired=actions_fired, ...)
        raise
    _write_run(rule_id=rule["rule_id"], run_id=run_id,
               outcome="matched", actions_fired=actions_fired, ...)
```

**`modify_field` action** — `config = {"field": str, "value": str | None}`:
- `ticket` module: calls `TicketStore._conditional_update_meta` (already exists at `app/services/tickets.py:723`), patching the named field. Supported fields for initial release: `status`, `assignee_sub`, `priority`, `title`.
- `contact` module: calls the contact `update_contact` service logic, patching the named field.
- Unknown field or module: logs a warning, marks action result as `skipped`.

**`create_record` action** — `config = {"module": str, "fields": dict}`:
- `ticket`: calls `TicketStore.create_ticket(owner_sub="system", **fields)` — reuses `app/services/tickets.py:411`.
- Emits `audit_event("crm_workflow.create_record", "system", ...)` via `app/services/alerts.audit_event` (`app/services/alerts.py:644`).
- `fields` dict undergoes the same validation as the regular create endpoint (title required, etc.).

**Run log**: `_write_run` writes to `T.crm_workflow_runs` using the PK/SK scheme from WFL-001:
- `pk = RULE#{rule_id}`, `sk = RUN#{started_at:010d}#{run_id}`, all action results, outcome, timestamps, `GSI_RECORD_PK = {module}#{record_id}`, `GSI_RECORD_SK = started_at` (N).

**Acceptance Criteria**
- `modify_field` on a ticket's `status` field updates the ticket row in DDB.
- `create_record` for module `ticket` produces a new ticket row and an audit event.
- A rule with no matching enabled actions still produces a `matched` run log entry with empty `actions_fired`.
- Unknown action type produces a `skipped` entry in `actions_fired` and does not raise.
- Hermetic offline tests use moto-backed `T.crm_workflow_rules`, `T.crm_workflow_runs`, `T.tickets`.

**Dependencies**
- WFL-001, WFL-002, WFL-003, WFL-004, WFL-005.

---

### WFL-007: Action executor — send-email action
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Extend the action executor (`app/services/workflow_action_executor.py`) with the `send_email` action type. This action resolves the target email address from the record, renders a notification template, and dispatches via the existing `send_alert_email` infrastructure.

**`send_email` action** — `config = {"template_id": str, "to_field": str, "extra_vars": dict}`:
1. Resolve `to_address`: look up `config["to_field"]` in the record dict (e.g. `"email"` on a contact record, or `"owner_sub"` to look up the user's email via `app/services/profile.get_profile` at `app/services/profile.py:262`).
2. Load template: `notification_templates.get_template(config["template_id"])` (`app/services/notification_templates.py:171`) — returns subject/body with `{{variable}}` placeholders.
3. Build variable context: `{"record_id": ..., **record fields, **config["extra_vars"]}` — pass to `bot_template.resolve_variables` (`app/services/bot_template.py:215`) for substitution.
4. Dispatch: `alerts.send_alert_email(to_emails=[to_address], subject=rendered_subject, body_text=rendered_body)` (`app/services/alerts.py:459`).
5. Emit `audit_event("crm_workflow.send_email", "system", template_id=..., record_id=..., to=to_address)`.

**Guard**: if `to_address` cannot be resolved (field missing, user profile not found), log a warning and mark action result as `skipped` — never raise so subsequent actions in the same rule still execute.

**Template requirement**: The `template_id` must reference an existing row in `T.admin_messaging_templates` (same table used by `app/services/notification_templates.py` — the `admin_messaging_templates` table). If the template does not exist, the action is `skipped` with `error="template_not_found"`.

**Acceptance Criteria**
- `send_email` action with a valid template and a record containing `email` field calls `send_alert_email` with correct rendered subject/body.
- Missing `to_field` on the record skips the action without raising.
- Non-existent `template_id` skips the action without raising.
- `owner_sub` resolution correctly fetches the user's email from the profile table.
- Hermetic offline tests patch `send_alert_email` and `get_profile`; use moto for `T.admin_messaging_templates`.

**Dependencies**
- WFL-001, WFL-002, WFL-003, WFL-006.

---

### WFL-008: Action executor — drip sequence action
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Extend the action executor with the `drip_sequence` action type that fires a configurable multi-stage sequence of emails/notifications against a record over time. This generalises the cart-abandonment stage-reminder pattern from `app/services/cart_reminders.py` into the workflow rule engine.

**`drip_sequence` action** — `config = {"sequence_id": str}`:
A drip sequence definition is stored separately in `T.crm_workflow_rules` with a dedicated row type:
- PK: `DRIP#{sequence_id}`, SK: `META` — sequence metadata (name, description, stages list, created_by, created_at).
- `stages`: `[{"stage_number": int, "delay_hours": int, "template_id": str, "to_field": str}]` — mirrors the `_default_stages()` structure in `app/services/cart_reminders.py:44`.

**Execution flow** — on first fire for a given `(sequence_id, record_id)`:
1. Record a sequence enrolment row: PK `ENROL#{sequence_id}`, SK `RECORD#{module}#{record_id}` — fields: `current_stage=0`, `enrolled_at`, `completed=False`, `stopped=False`.
2. Schedule stage 1's action as a `crm_workflow_drip_stage` scheduled action at `now + stage.delay_hours * 3600` via `create_action` (`app/services/scheduled_actions.py:91`) — payload: `{"sequence_id", "stage_number", "module", "record_id", "template_id", "to_field"}`.

**Stage executor** (`"crm_workflow_drip_stage"` added to `_EXECUTORS` in `app/services/unified_scheduler.py:28`):
1. Load stage payload; check enrolment row is not `stopped=True`.
2. Send email via the same `send_email` logic from WFL-007 (shared helper).
3. Advance `current_stage`; if more stages remain, schedule the next stage at the next delay offset.
4. If no more stages, mark enrolment `completed=True`.

**Stop drip**: `stop_drip_sequence(sequence_id, module, record_id)` sets `stopped=True` on the enrolment row — the stage executor checks this flag before each send and exits cleanly. Exposed as an internal helper; no separate router endpoint in this ticket.

**Drip sequence CRUD** (`app/services/workflow_drip_sequences.py`): `create_sequence`, `get_sequence`, `list_sequences`, `update_sequence`, `delete_sequence` — same DDB patterns as WFL-002.

**Acceptance Criteria**
- `drip_sequence` action with a 2-stage sequence enrols the record and schedules stage 1.
- Stage 1 executor sends the email, marks stage advanced, schedules stage 2.
- Stage 2 executor sends the email and marks enrolment `completed=True`.
- Setting `stopped=True` before stage 2 fires causes stage 2 to skip its send.
- Second enrolment of the same `(sequence_id, record_id)` within the same run is idempotent (conditional-put guard on enrolment row).
- Hermetic offline tests patch `send_alert_email`; moto-backed `T.crm_workflow_rules` and `T.scheduled_actions`.

**Dependencies**
- WFL-001, WFL-002, WFL-003, WFL-006, WFL-007.

---

### WFL-009: Admin CRUD router & frontend UI
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Expose the workflow rule engine via an admin REST API and a minimal frontend management page so admins can create, edit, enable/disable, and monitor workflow rules without writing code.

**Backend router** (`app/routers/workflow_rules.py`, registered in `app/main.py`):

All endpoints are gated by `S.crm_workflow_enabled` (return 404 when flag is off) and require `Depends(require_admin_or_root_csrf)` for mutating methods (`app/auth/policy.py`, mirroring `app/routers/admin_notifications.py:13`).

```
POST   /ui/admin/crm/workflow/rules                  Create rule
GET    /ui/admin/crm/workflow/rules                  List rules (target_module, enabled_only query params)
GET    /ui/admin/crm/workflow/rules/{rule_id}        Get rule detail
PATCH  /ui/admin/crm/workflow/rules/{rule_id}        Update rule
DELETE /ui/admin/crm/workflow/rules/{rule_id}        Delete rule
POST   /ui/admin/crm/workflow/rules/{rule_id}/enable Enable rule
POST   /ui/admin/crm/workflow/rules/{rule_id}/disable Disable rule
GET    /ui/admin/crm/workflow/rules/{rule_id}/runs   List execution runs (per-rule run history)
GET    /ui/admin/crm/workflow/drip-sequences         List drip sequence definitions
POST   /ui/admin/crm/workflow/drip-sequences         Create drip sequence
PATCH  /ui/admin/crm/workflow/drip-sequences/{id}    Update drip sequence
DELETE /ui/admin/crm/workflow/drip-sequences/{id}    Delete drip sequence
```

Route ordering: static paths (`/rules`, `/drip-sequences`) are declared before dynamic `/{rule_id}` — see cross-cutting constraint on route ordering above.

**Frontend page** (`frontend/src/pages/admin/workflow/`):
- `WorkflowRulesPage.tsx` — lists rules in a `shadcn/ui` `Table` with module, trigger type, enabled toggle, last-run status, and edit/delete actions. Uses `useQuery(["workflow-rules"])` via React Query.
- `WorkflowRuleEditor.tsx` — drawer/dialog with three sections: (1) Trigger (dropdown for trigger type + sub-fields for cron expression or time-elapsed config), (2) Conditions (add/remove rows with field / operator / value inputs), (3) Actions (add/remove rows with action type + JSON config textarea for MVP). Uses React Hook Form + Zod validation.
- API wrappers in `frontend/src/api/endpoints/workflowRules.ts`.
- TypeScript types in `frontend/src/api/types.ts`: `WorkflowRule`, `WorkflowCondition`, `WorkflowAction`, `WorkflowRuleCreateIn`, `WorkflowRunLog`.
- Route added to `frontend/src/App.tsx`: `/admin/workflow/rules` → `WorkflowRulesPage` (lazy-loaded; admin/root role guard).
- Sidebar nav entry under Admin section.

**Acceptance Criteria**
- `POST /ui/admin/crm/workflow/rules` creates a rule and returns the `WorkflowRuleOut` shape.
- `PATCH /{rule_id}` partial-updates only the supplied fields.
- `GET /{rule_id}/runs` returns run history sorted newest-first with `outcome`, `actions_fired`, `started_at`.
- `/enable` and `/disable` toggle the `enabled` flag and return the updated rule.
- With `CRM_WORKFLOW_ENABLED=0` all endpoints return 404.
- Frontend page renders the rule list, opens the editor on "Add Rule", and submits the form to the create endpoint.
- Non-admin users are redirected away from `/admin/workflow/rules`.

**Dependencies**
- WFL-001, WFL-002, WFL-003, WFL-004, WFL-005, WFL-006, WFL-007, WFL-008.
