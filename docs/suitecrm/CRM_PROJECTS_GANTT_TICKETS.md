# CRM Projects, Project Tasks & Gantt — Implementation Tickets

**Area**: Projects, Project Tasks & Gantt
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T4] Projects, Project Tasks & Gantt — 12 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Projects module is a full project management system: a project header (name, description, status, dates, priority, assigned user), project tasks with per-task duration, start/end dates, percent complete, order, dependencies (predecessor/successor links), and resource assignment (assign a task to a user or contact). A Gantt chart view renders tasks as bars with dependency arrows. Projects can be created from reusable templates (a cloneable task structure). Milestone tasks render as diamond markers. A project team member pool (roles: owner, member, viewer) feeds the Gantt resource rows. Projects carry relationships to Contacts, to Account/Organization records, and to Cases/Tickets. Project status follows a defined workflow (planned → in-review → underway → completed → deferred).

The testlogon `projects` table/service is a file-grouping layer (tracks files from cloud providers) that is unrelated to CRM project management. The `ProjectModel` at `app/models.py:1796` carries only `id`, `owner`, `name`, `description`, `tags`, `settings`, `created_at`, `updated_at` — no CRM project management fields.

## Cross-cutting constraints

- **Additive only, default-off**: A single top-level feature flag `CRM_PROJECTS_ENABLED` (env `CRM_PROJECTS_ENABLED`, default `"0"`) gates all PRJ work. Every router method checks `S.crm_projects_enabled` and raises HTTP 404 when off. The existing file-grouping `T.projects` table and its router (`app/routers/projects.py`) are **never modified** — new CRM project management lives in a separate DDB table and router.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: All new tables follow the `TableDef` pattern in `scripts/local-ddb-init.py`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` (CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha — omitting causes `ValidationException`). Same code path dev (moto in-process) and prod (real DDB) — no `dev_mode` branches in service layer.
- **Reuse existing primitives — never fork**:
  - Auth: `app/services/sessions.require_ui_session` (`app/services/sessions.py:330`) returns `{"user_sub": str, "role": Role, ...}`. Admin-only routes use `app/auth/deps.require_admin_session`.
  - Audit: `app/services/alerts.audit_event` (`app/services/alerts.py:644`)
  - Email: `app/services/alerts.send_alert_email` (`app/services/alerts.py:459`)
  - In-app alerts: `app/services/alerts.write_alert` (`app/services/alerts.py:356`)
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor` (`app/core/cursor.py:94,103`)
  - Timestamps: `app/core/time.now_ts()` (integer Unix seconds)
  - Settings singleton: `app/core/settings.S`; table handles: `app/core/tables.T`
- **Planned upstream dependencies**: PTY-001..PTY-015 (`PARTY_CRM_TICKETS.md`) will deliver the Party/Contact/Account model. Tickets that link to contacts or accounts (PRJ-010, PRJ-011) declare PTY as a soft prerequisite and use opaque `linked_entity_type` + `linked_entity_id` string pairs until PTY ships.
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles. Pattern: `tests/test_gap_0220_0221_ssh_stored_key.py`. No real AWS or network calls.

---

### PRJ-001: Feature flag, settings keys, and DynamoDB table scaffold
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Scaffold all downstream PRJ work. Nothing user-visible ships in this ticket.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern from `cart_reminders_enabled` (line 821):

```python
crm_projects_enabled: bool = os.environ.get("CRM_PROJECTS_ENABLED", "0") not in ("0", "false", "False")
crm_pm_projects_table_name: str  = os.environ.get("DDB_CRM_PM_PROJECTS_TABLE", "crm_pm_projects")
crm_pm_tasks_table_name: str     = os.environ.get("DDB_CRM_PM_TASKS_TABLE", "crm_pm_tasks")
crm_pm_members_table_name: str   = os.environ.get("DDB_CRM_PM_MEMBERS_TABLE", "crm_pm_members")
crm_pm_templates_table_name: str = os.environ.get("DDB_CRM_PM_TEMPLATES_TABLE", "crm_pm_templates")
```

**DynamoDB table additions** (`scripts/local-ddb-init.py`) — insert after the existing `projects` table block at line 277:

```python
# CRM Project Management (PRJ-001) — main project records
# PK=OWNER#{user_sub}, SK=PROJECT#{project_id}
# GSI1: PK=PROJECT#{project_id}, SK=OWNER#{user_sub}  (owned-project lookup)
# GSI2: PK=STATUS#{status}, SK=created_at             (status-filtered list)
TableDef(
    _resolve_table_name(S.crm_pm_projects_table_name, "crm_pm_projects"),
    "PK", "SK",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"GSI2SK": "N"},
),

# CRM Project Tasks (PRJ-002) — task rows per project
# PK=PROJECT#{project_id}, SK=TASK#{task_order:06d}#{task_id}
# GSI1: PK=TASK#{task_id}, SK=PROJECT#{project_id}    (single-task lookup)
# GSI2: PK=ASSIGNEE#{user_sub}, SK=due_date           (per-assignee workload)
TableDef(
    _resolve_table_name(S.crm_pm_tasks_table_name, "crm_pm_tasks"),
    "PK", "SK",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"GSI2SK": "N"},
),

# CRM Project Members (PRJ-007) — membership roster per project
# PK=PROJECT#{project_id}, SK=MEMBER#{user_sub}
# GSI1: PK=MEMBER#{user_sub}, SK=PROJECT#{project_id} (per-user project list)
TableDef(
    _resolve_table_name(S.crm_pm_members_table_name, "crm_pm_members"),
    "PK", "SK",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
),

# CRM Project Templates (PRJ-006)
# PK=OWNER#{user_sub}, SK=TEMPLATE#{template_id}
# GSI1: PK=TEMPLATE#{template_id}, SK=OWNER#{user_sub}
TableDef(
    _resolve_table_name(S.crm_pm_templates_table_name, "crm_pm_templates"),
    "PK", "SK",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
),
```

**Table handles** (`app/core/tables.py`) — add four handles following the `projects` entry at line 353:

```python
crm_pm_projects:   Any
crm_pm_tasks:      Any
crm_pm_members:    Any
crm_pm_templates:  Any
```

and wire `_safe_table(S.crm_pm_projects_table_name)` etc. in the `T` singleton block.

**Guard helper** — add `_require_crm_projects()` (raises `HTTPException(404)` when `S.crm_projects_enabled` is False) in the new `app/routers/crm_projects.py`. All route handlers call it first.

**Acceptance Criteria**
- `scripts/local-ddb-init.py` creates all four tables without error on a clean stack start.
- `T.crm_pm_projects`, `T.crm_pm_tasks`, `T.crm_pm_members`, `T.crm_pm_templates` are accessible from any service module.
- `CRM_PROJECTS_ENABLED=0` (default): any call to `_require_crm_projects()` raises 404.
- Hermetic pytest confirms table creation via moto.

**Dependencies**
- None (pure scaffolding).
- Flag: `CRM_PROJECTS_ENABLED` (new, default off).

---

### PRJ-002: Project header CRUD with status, dates, and priority
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the CRM project model to match SuiteCRM's project header. The existing `ProjectModel` at `app/models.py:1796` is for the file-grouping layer; this ticket introduces a **new** `CrmProjectModel` Pydantic model in `app/models.py` and a new service `app/services/crm_projects.py`.

**`CrmProjectModel`** fields (add to `app/models.py` after line 1930):

```python
class CrmProjectStatus(str, Enum):
    draft     = "draft"
    in_review = "in_review"
    underway  = "underway"
    completed = "completed"
    deferred  = "deferred"

class CrmProjectModel(BaseModel):
    id:             str
    owner_sub:      str
    name:           str               # 1–120 chars
    description:    Optional[str]     # ≤2000 chars
    status:         CrmProjectStatus  = CrmProjectStatus.draft
    priority:       int               = 0   # 0=none, 1=low, 2=medium, 3=high, 4=urgent
    start_date:     Optional[int]     = None  # Unix timestamp (seconds)
    end_date:       Optional[int]     = None  # Unix timestamp (seconds)
    assigned_user_sub: Optional[str]  = None
    account_id:     Optional[str]     = None  # PARTY_GROUP party_id (PRJ-011)
    created_at:     int
    updated_at:     int
```

**DDB item shape** (stored in `T.crm_pm_projects`):

```
PK          = "OWNER#{owner_sub}"
SK          = "PROJECT#{project_id}"
GSI1PK      = "PROJECT#{project_id}"
GSI1SK      = "OWNER#{owner_sub}"
GSI2PK      = "STATUS#{status}"
GSI2SK      = created_at          ← integer, attr_types={"GSI2SK": "N"}
entity_type = "crm_project"
```

**Service** (`app/services/crm_projects.py`):
- `create_crm_project(owner_sub, name, *, description, status, priority, start_date, end_date, assigned_user_sub, account_id) -> CrmProjectModel`
- `get_crm_project(owner_sub, project_id) -> CrmProjectModel` — 404 if not found or not owner
- `update_crm_project(owner_sub, project_id, **fields) -> CrmProjectModel` — partial update, emits `audit_event("crm_project.updated", ...)` on status change
- `delete_crm_project(owner_sub, project_id) -> {"ok": True}` — hard delete + cascades to task rows
- `list_crm_projects(owner_sub, *, limit, cursor, status_filter, name_query) -> {items, cursor}` — queries primary on `OWNER#` prefix, supports status GSI2 path when `status_filter` is set

**Router** (`app/routers/crm_projects.py`, prefix `/v1/crm/projects`):

```
POST   /               → create_crm_project_route
GET    /               → list_crm_projects_route  (limit, cursor, status, name_query)
GET    /{project_id}   → get_crm_project_route
PATCH  /{project_id}   → update_crm_project_route
DELETE /{project_id}   → delete_crm_project_route
```

All routes use `Depends(require_ui_session)` (same pattern as `app/routers/projects.py:169`). Register the new router in `app/main.py`.

**Frontend types** (`frontend/src/api/types.ts`): add `CrmProject`, `CrmProjectCreateReq`, `CrmProjectUpdateReq`, `CrmProjectListResp` interfaces.

**Frontend API endpoints** (`frontend/src/api/endpoints/crmProjects.ts`): `listCrmProjects`, `createCrmProject`, `getCrmProject`, `updateCrmProject`, `deleteCrmProject`.

**Acceptance Criteria**
- CRUD round-trip: create with all fields, GET returns all fields, PATCH updates `status` + emits audit event, DELETE removes item.
- `status` validation: transition to `completed` or `deferred` accepted; unknown status returns 422.
- `end_date` < `start_date` returns 400 `end_before_start`.
- `CRM_PROJECTS_ENABLED=0` → all routes return 404.
- Hermetic pytest with moto covers create / get / update / delete / list.

**Dependencies**
- PRJ-001 (tables + flag).

---

### PRJ-003: Project tasks CRUD (duration, dates, percent complete, order)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement the `CrmProjectTask` entity and its CRUD API. Tasks live in `T.crm_pm_tasks`.

**`CrmProjectTaskModel`** (add to `app/models.py` after `CrmProjectModel`):

```python
class CrmProjectTaskModel(BaseModel):
    id:               str
    project_id:       str
    owner_sub:        str
    name:             str               # 1–200 chars
    description:      Optional[str]     # ≤2000 chars
    task_order:       int = 0           # ascending integer, used in SK
    duration_days:    int = 1           # ≥1
    start_date:       Optional[int]     # Unix ts
    end_date:         Optional[int]     # Unix ts; auto-computed start_date + duration_days * 86400 if absent
    percent_complete: int = 0           # 0–100
    is_milestone:     bool = False      # PRJ-005: milestone flag (defaults False)
    assigned_user_sub: Optional[str]    # PRJ-004: resource assignment
    predecessor_task_ids: List[str] = Field(default_factory=list)  # PRJ-004: dependency
    created_at:       int
    updated_at:       int
```

**DDB item shape** (stored in `T.crm_pm_tasks`):

```
PK          = "PROJECT#{project_id}"
SK          = "TASK#{task_order:06d}#{task_id}"
GSI1PK      = "TASK#{task_id}"
GSI1SK      = "PROJECT#{project_id}"
GSI2PK      = "ASSIGNEE#{assigned_user_sub}" (or "ASSIGNEE#unassigned")
GSI2SK      = end_date (int or 0)            ← attr_types={"GSI2SK": "N"}
entity_type = "crm_task"
```

**Service** (`app/services/crm_project_tasks.py`):
- `create_task(owner_sub, project_id, name, *, task_order, duration_days, start_date, description, assigned_user_sub, is_milestone) -> CrmProjectTaskModel` — verifies project ownership via `get_crm_project`; auto-assigns `task_order = max_existing + 1` if 0; computes `end_date = start_date + duration_days * 86400` when `start_date` given.
- `get_task(owner_sub, task_id) -> CrmProjectTaskModel` — uses GSI1 lookup
- `list_tasks(owner_sub, project_id, *, limit, cursor) -> {items, cursor}` — queries `PK=PROJECT#{project_id}` + `SK begins_with("TASK#")`, `ScanIndexForward=True` (ascending order)
- `update_task(owner_sub, task_id, **fields) -> CrmProjectTaskModel` — partial update
- `delete_task(owner_sub, task_id) -> {"ok": True}`
- `reorder_tasks(owner_sub, project_id, task_ids: List[str]) -> List[CrmProjectTaskModel]` — accepts ordered list of task IDs, rewrites SK values to reflect new `task_order`

**Router** (extend `app/routers/crm_projects.py`, same prefix `/v1/crm/projects`):

```
POST   /{project_id}/tasks               → create_task_route
GET    /{project_id}/tasks               → list_tasks_route
GET    /{project_id}/tasks/{task_id}     → get_task_route
PATCH  /{project_id}/tasks/{task_id}     → update_task_route
DELETE /{project_id}/tasks/{task_id}     → delete_task_route
PUT    /{project_id}/tasks/order         → reorder_tasks_route
```

**Acceptance Criteria**
- Create task with explicit `task_order`, GET returns same order.
- List tasks returns ascending `task_order`.
- `end_date` auto-computed from `start_date + duration_days`.
- `percent_complete` out of 0–100 range → 422.
- Reorder: POST with reversed list returns reversed order in subsequent GET.
- Hermetic pytest covers full task lifecycle.

**Dependencies**
- PRJ-001, PRJ-002.

---

### PRJ-004: Task dependencies and resource assignment
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend `CrmProjectTaskModel` and the task service to support predecessor/successor dependencies and per-task resource assignment (user or contact).

**Dependency validation** in `update_task` and `create_task`: when `predecessor_task_ids` is set, verify:
1. All listed task IDs belong to the same project (GSI1 lookup for each).
2. No circular dependency — build the adjacency graph from all project tasks and run DFS; raise `HTTP 400 {"code": "circular_dependency"}` if a cycle is detected.
3. The task's `start_date`, if provided, must be ≥ the maximum `end_date` of all direct predecessors; return a `400 {"code": "predecessor_date_conflict"}` with the blocking task ID if violated.

**Resource assignment** — `assigned_user_sub` (already on the model) is a `user_sub` string. Add a `project_resource_type` field (`"user"` | `"contact"`) and an optional `linked_contact_id` field (opaque string, deferred PTY integration) so the same field can reference a platform user or a CRM contact party once PTY ships.

**`get_project_workload(owner_sub, project_id) -> List[{user_sub, task_count, overdue_count}]`** — queries `GSI2PK=ASSIGNEE#{sub}` across all tasks in the project to return per-user workload summary.

**Router additions** (extend `app/routers/crm_projects.py`):

```
GET /{project_id}/workload   → get_project_workload_route
```

**Acceptance Criteria**
- Create task B with `predecessor_task_ids=[A_id]`; B start_date before A end_date → 400 `predecessor_date_conflict`.
- Create cycle: A depends on B, B depends on A → 400 `circular_dependency`.
- Valid assignment: task assigned to `user_sub`, `GET /workload` returns `task_count: 1`.
- Hermetic pytest covers dependency validation + circular detection.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-003.

---

### PRJ-005: Project milestones
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

`is_milestone: bool` is already present on `CrmProjectTaskModel` (added in PRJ-003 with `default=False`). This ticket wires the milestone use cases:

1. **API filter**: `GET /{project_id}/tasks?milestones_only=true` — adds a `FilterExpression` in `list_tasks` to return only items where `is_milestone=True`.
2. **Milestone summary endpoint** `GET /{project_id}/milestones` — returns the milestone list with `percent_complete` and whether the milestone is `on_track` (milestone `end_date` > now_ts) or `overdue` (`end_date` <= now_ts and `percent_complete` < 100).
3. **Frontend badge**: `CrmTaskRow` component renders a diamond icon (`Milestone` from lucide-react) beside task name when `is_milestone=True`.
4. **Gantt diamond marker** (PRJ-008 prerequisite): the milestone flag is already surfaced in the tasks API response; the Gantt component (PRJ-008) reads `is_milestone` to render diamond markers rather than bars.

No new DDB schema is required — `is_milestone` is stored as an attribute on the existing task item.

**Acceptance Criteria**
- `GET /tasks?milestones_only=true` returns only milestone tasks.
- `GET /milestones` returns `on_track: true` for future-dated milestones, `overdue: true` for past-dated incomplete milestones.
- Hermetic pytest verifies filter and summary.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-003.

---

### PRJ-006: Project templates (clone task structure)
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Allow users to save a project's task structure as a reusable template, and instantiate new projects from a template.

**`CrmProjectTemplateModel`** (add to `app/models.py`):

```python
class CrmProjectTemplateModel(BaseModel):
    id:          str
    owner_sub:   str
    name:        str           # 1–120 chars
    description: Optional[str]
    task_defs:   List[Dict]    # serialized task structures (name, duration_days, task_order, is_milestone, predecessor_task_ids)
    created_at:  int
    updated_at:  int
```

**DDB item shape** (stored in `T.crm_pm_templates`):

```
PK          = "OWNER#{owner_sub}"
SK          = "TEMPLATE#{template_id}"
GSI1PK      = "TEMPLATE#{template_id}"
GSI1SK      = "OWNER#{owner_sub}"
entity_type = "crm_template"
```

**Service** (`app/services/crm_project_templates.py`):
- `create_template_from_project(owner_sub, project_id, name, description) -> CrmProjectTemplateModel` — reads all tasks via `list_tasks`, strips transient fields (`start_date`, `end_date`, `assigned_user_sub`, `percent_complete`), stores the template.
- `create_template(owner_sub, name, description, task_defs) -> CrmProjectTemplateModel`
- `list_templates(owner_sub) -> {items, cursor}`
- `get_template(owner_sub, template_id) -> CrmProjectTemplateModel`
- `delete_template(owner_sub, template_id) -> {"ok": True}`
- `instantiate_from_template(owner_sub, template_id, project_name, *, start_date) -> CrmProjectModel` — creates a new `crm_pm_project` via `create_crm_project`, then creates one task per `task_def` with `start_date` offset = `template.task_defs[i].offset_days * 86400 + start_date`; preserves `predecessor_task_ids` mapping (re-maps old template IDs to new task IDs).

**Router** (extend `app/routers/crm_projects.py`):

```
POST   /templates                           → create_template_route
POST   /templates/from-project/{project_id} → create_template_from_project_route
GET    /templates                           → list_templates_route
GET    /templates/{template_id}             → get_template_route
DELETE /templates/{template_id}             → delete_template_route
POST   /templates/{template_id}/instantiate → instantiate_from_template_route
```

Declare `/templates` routes **before** `/{project_id}` in the router to prevent FastAPI from capturing the literal `templates` as a path param (same ordering rule documented in CLAUDE.md for `/schedules`).

**Acceptance Criteria**
- Save project with 3 tasks as template; instantiate with a `start_date`; new project has 3 tasks with correctly offset dates.
- Predecessor re-mapping: template task B depends on A → instantiated task B depends on new A.
- Hermetic pytest covers save → instantiate round-trip.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-003, PRJ-004.

---

### PRJ-007: Project team members (owner/member/viewer roles)
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a project membership roster to control who can view and edit a CRM project. The existing projects service (`app/services/projects_store.py`) is per-owner only; the CRM project management system needs shared access.

**`CrmProjectMemberRole`** enum: `owner`, `member`, `viewer`.

**`CrmProjectMemberModel`** (add to `app/models.py`):

```python
class CrmProjectMemberModel(BaseModel):
    project_id:  str
    user_sub:    str
    role:        CrmProjectMemberRole = CrmProjectMemberRole.member
    added_by:    str
    added_at:    int
```

**DDB item shape** (stored in `T.crm_pm_members`):

```
PK          = "PROJECT#{project_id}"
SK          = "MEMBER#{user_sub}"
GSI1PK      = "MEMBER#{user_sub}"
GSI1SK      = "PROJECT#{project_id}"
entity_type = "crm_member"
```

**Authorization change**: every CRM project service function that currently checks `owner_sub == project.owner_sub` is extended to also accept any member with `role in {owner, member}` (via `_assert_project_access(caller_sub, project_id, min_role="member")`). Viewers get read-only access. Only the project `owner` can add/remove members or delete the project.

**Service** (`app/services/crm_project_members.py`):
- `add_member(owner_sub, project_id, target_sub, role) -> CrmProjectMemberModel` — owner only; bootstraps owner row on first use
- `remove_member(owner_sub, project_id, target_sub) -> {"ok": True}` — owner only; cannot remove the owner row itself
- `list_members(caller_sub, project_id) -> List[CrmProjectMemberModel]`
- `get_member_role(caller_sub, project_id) -> CrmProjectMemberRole | None`
- `_assert_project_access(caller_sub, project_id, min_role) -> CrmProjectMemberRole` — raises 403 if caller not a member with sufficient role

**Router additions** (extend `app/routers/crm_projects.py`):

```
POST   /{project_id}/members              → add_member_route
GET    /{project_id}/members              → list_members_route
PATCH  /{project_id}/members/{user_sub}   → update_member_role_route
DELETE /{project_id}/members/{user_sub}   → remove_member_route
```

**Acceptance Criteria**
- Owner can add a member; member can GET project tasks; viewer cannot PATCH tasks (403).
- Remove member: subsequent GET by removed user returns 403.
- Owner cannot be removed from their own project.
- Hermetic pytest covers add/list/remove/access-control.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-003.

---

### PRJ-008: Gantt chart frontend component
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Build the Gantt chart view for a CRM project. The Gantt consumes the `GET /v1/crm/projects/{id}/tasks` API response.

**Library choice**: use `react-gantt-task` (npm package `gantt-task-react`, MIT-licensed, no server-side dependency, renders as SVG). Install in `frontend/package.json`.

**`CrmProjectGanttPage`** (`frontend/src/pages/crmProjects/CrmProjectGanttPage.tsx`):

- Fetches project header (`getCrmProject`) + task list (`listCrmProjectTasks`) via React Query.
- Maps `CrmProjectTask` → `gantt-task-react` `Task` shape:
  - `type`: `"milestone"` when `is_milestone=true`, else `"task"`
  - `start`: `new Date(task.start_date * 1000)`
  - `end`: `new Date(task.end_date * 1000)`
  - `progress`: `task.percent_complete`
  - `dependencies`: `task.predecessor_task_ids` (the library uses the same string array)
- Renders `<Gantt>` from `gantt-task-react` with `viewMode={ViewMode.Day}` by default; a `ViewMode` toggle (Day / Week / Month) in the toolbar.
- Milestones render as diamond markers natively via `type: "milestone"`.
- Clicking a task opens a slide-over panel with `CrmTaskEditForm` (inline edit of name, dates, % complete, assigned user).
- Loading state: `<Loader2>` spinner; error state: `<Alert variant="destructive">`.

**Route**: add `/crm/projects/:projectId/gantt` to `frontend/src/App.tsx` (lazy-loaded).

**Sidebar link**: add "Gantt" link in the `CrmProjectDetailPage` header tabs.

**Acceptance Criteria**
- Gantt renders tasks in chronological order with correct bar lengths.
- Milestone tasks display as diamond markers.
- Dependency arrows rendered between tasks that have `predecessor_task_ids`.
- View mode toggle switches bar granularity.
- Clicking a task opens edit panel; saving calls `PATCH /{project_id}/tasks/{task_id}` and invalidates React Query cache.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-003, PRJ-004, PRJ-005.

---

### PRJ-009: Project status workflow with audit trail
**Type:** Feature  **Priority:** P1  **Estimate:** 1d

**Description**

Enforce valid status transitions on CRM projects and emit audit events on each change.

**Allowed transitions** (defined in `app/services/crm_projects.py`):

```
draft       → in_review | underway | deferred
in_review   → underway | draft | deferred
underway    → completed | in_review | deferred
completed   → underway (reopened)
deferred    → draft | underway
```

Any other transition → `HTTP 400 {"code": "invalid_status_transition", "from": "...", "to": "..."}`.

**Audit emission**: on every status change in `update_crm_project`, call `audit_event("crm_project.status_changed", owner_sub, None, project_id=project_id, from_status=old, to_status=new)` using the pattern from `app/services/alerts.py:644`.

**`GET /{project_id}/status-history`** — queries the alerts/audit table filtered by `event="crm_project.status_changed"` and `project_id` field; returns list of `{from_status, to_status, changed_at, changed_by}` in reverse chronological order.

**Email notification on completion**: when status transitions to `completed`, call `send_alert_email` (`app/services/alerts.py:459`) to all project `owner` members with subject `"Project completed: {name}"`. Best-effort (wrapped in try/except; failure does not roll back the status update).

**Acceptance Criteria**
- `draft → completed` → 400 `invalid_status_transition`.
- `draft → underway` → 200; `GET /status-history` returns one entry.
- Completing a project triggers email (mock `send_alert_email` in test via monkeypatch).
- Hermetic pytest covers all allowed + blocked transitions.

**Dependencies**
- PRJ-001, PRJ-002.

---

### PRJ-010: Project-to-Contact relationships
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Allow a CRM project to be linked to one or more CRM contact party records. This uses an opaque `linked_entity_type` / `linked_entity_id` pattern (per the cross-cutting constraint above) until PTY-001..PTY-015 ship.

**`CrmProjectContactLinkModel`** (add to `app/models.py`):

```python
class CrmProjectContactLinkModel(BaseModel):
    project_id:          str
    linked_entity_type:  Literal["contact_party"]
    linked_entity_id:    str   # party_id (PTY model) or opaque contact ID
    display_name:        Optional[str]   # optional denormalized display name
    added_by:            str
    added_at:            int
```

**DDB storage**: re-use `T.crm_pm_members` single-table by using a different SK prefix:

```
PK          = "PROJECT#{project_id}"
SK          = "CONTACT_LINK#{linked_entity_id}"
entity_type = "crm_contact_link"
```

No new table is needed.

**Service** (`app/services/crm_project_links.py`):
- `add_contact_link(caller_sub, project_id, linked_entity_id, display_name) -> CrmProjectContactLinkModel`
- `remove_contact_link(caller_sub, project_id, linked_entity_id) -> {"ok": True}`
- `list_contact_links(caller_sub, project_id) -> List[CrmProjectContactLinkModel]`

Caller must be a project member with `role >= member` (via `_assert_project_access` from PRJ-007).

**Router additions** (extend `app/routers/crm_projects.py`):

```
POST   /{project_id}/contacts              → add_contact_link_route
GET    /{project_id}/contacts              → list_contact_links_route
DELETE /{project_id}/contacts/{entity_id} → remove_contact_link_route
```

**Acceptance Criteria**
- Link contact ID `"party_abc"` to project; `GET /contacts` returns it with `display_name`.
- Remove link; subsequent GET returns empty list.
- Non-member caller → 403.
- Hermetic pytest covers add / list / remove.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-007.
- Soft dependency: PTY-011 (once party model ships, `linked_entity_id` resolves to real party records).

---

### PRJ-011: Project-to-Account and Project-to-Ticket relationships
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Two lightweight relationship features that share implementation patterns.

**Project-to-Account**: Add `account_id: Optional[str]` field to `CrmProjectModel` (already declared in PRJ-002 as a placeholder). In this ticket, implement:
- `update_crm_project` accepts `account_id` — stored on the project item as a plain string (opaque PARTY_GROUP `party_id`, resolved by PTY once built).
- `list_crm_projects_by_account(caller_sub, account_id, *, limit, cursor)` — queries `GSI2` with `GSI2PK="STATUS#{any}"` is insufficient; instead add a new GSI3 on `T.crm_pm_projects`:
  ```
  GSI3PK = "ACCOUNT#{account_id}"   (or "ACCOUNT#NONE" when null)
  GSI3SK = created_at (int)          attr_types={"GSI3SK": "N"}
  ```
  Add GSI3 to the `crm_pm_projects` `TableDef` in `scripts/local-ddb-init.py` (must be declared in PRJ-001 table definition — amend PRJ-001 to include GSI3 in the table definition).
- `GET /v1/crm/projects?account_id={id}` uses the GSI3 path.

**Project-to-Ticket**: Add optional `project_id: Optional[str]` to the existing ticket `META` item in `app/services/tickets.py`. The tickets table already has a `gsi1pk` / `gsi1sk` structure (see `app/services/tickets.py:441–466`). No new GSI is required for the reverse lookup if we accept a filtered scan; add a dedicated `"crm_project_tickets"` GSI only if the tickets table DDB definition can be amended:

```
GSI_PROJECT_PK = "PROJECT#{project_id}"
GSI_PROJECT_SK = updated_at (int)
```

If table amendment is not feasible in this ticket, the reverse lookup (`GET /v1/crm/projects/{id}/tickets`) falls back to a `FilterExpression` scan against `gsi1pk=STATUS#...` with `project_id` filter — acceptable for small ticket volumes.

**Service additions**:
- `get_tickets_for_project(caller_sub, project_id, *, limit, cursor) -> {items, cursor}` in `app/services/crm_project_links.py`
- `set_ticket_project(caller_sub, ticket_id, project_id) -> {"ok": True}` — writes `project_id` onto the ticket META item

**Router additions** (extend `app/routers/crm_projects.py`):

```
GET  /{project_id}/tickets                → get_tickets_for_project_route
POST /{project_id}/tickets/{ticket_id}    → link_ticket_to_project_route
DELETE /{project_id}/tickets/{ticket_id} → unlink_ticket_from_project_route
```

**Acceptance Criteria**
- Set `account_id` on project; `GET /v1/crm/projects?account_id={id}` returns the project.
- Link ticket to project; `GET /v1/crm/projects/{id}/tickets` returns it.
- Unlink; subsequent GET returns empty list.
- Hermetic pytest covers all paths.

**Dependencies**
- PRJ-001, PRJ-002, PRJ-007, PRJ-009.
- Soft dependency: PTY-015 (org accounts) for `account_id` resolution.

---

### PRJ-012: Projects frontend pages (list, detail, tasks, members)
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Build the complete CRM Projects frontend under `frontend/src/pages/crmProjects/`. All pages are flag-gated: skip rendering if the backend returns 404 on feature-flag guard.

**Pages**:

1. **`CrmProjectsPage.tsx`** — project list:
   - `useQuery(["crm-projects"], listCrmProjects)` with status filter dropdown (All / Draft / In Review / Underway / Completed / Deferred).
   - Project cards with name, status badge (`shadcn/ui Badge`), priority icon, start/end dates, and "Open" / "Gantt" links.
   - "New Project" dialog (name, description, status, priority, start_date, end_date) — React Hook Form + Zod validation.

2. **`CrmProjectDetailPage.tsx`** — project detail with tabbed navigation (Overview | Tasks | Members | Gantt):
   - **Overview tab**: project header fields, editable inline via `useMutation(updateCrmProject)`.
   - **Tasks tab**: `CrmTaskList` component — table of tasks with columns: order, name, assignee, start, end, % complete (editable inline), milestone icon. "Add Task" inline form. Drag-to-reorder via `PUT /tasks/order` (uses `@dnd-kit/sortable` already in the dependency tree if available, otherwise simple up/down arrow buttons).
   - **Members tab**: member list with role badge; "Add Member" dialog (email / user_sub lookup); remove button (owner only).
   - **Gantt tab**: `<CrmProjectGanttPage>` component (PRJ-008).

3. **`CrmProjectFormDialog.tsx`** — shared create/edit dialog (reused in list and detail pages).

**Routes** (add to `frontend/src/App.tsx`):

```
/crm/projects              → lazy(CrmProjectsPage)
/crm/projects/:projectId   → lazy(CrmProjectDetailPage)
/crm/projects/:projectId/gantt → lazy(CrmProjectGanttPage)  (already in PRJ-008)
```

**Sidebar**: add a "Projects" item under a new "CRM" section in `frontend/src/components/layout/Sidebar.tsx` (icon: `FolderKanban` from lucide-react — same icon used in `ProjectsPage.tsx:3`).

**TypeScript types** (`frontend/src/api/types.ts`): add `CrmProjectTask`, `CrmProjectTaskCreateReq`, `CrmProjectMember`, `CrmProjectTemplate` interfaces (complete the set started in PRJ-002).

**API endpoints** (`frontend/src/api/endpoints/crmProjects.ts`): add `listCrmProjectTasks`, `createCrmProjectTask`, `updateCrmProjectTask`, `deleteCrmProjectTask`, `reorderCrmProjectTasks`, `listCrmProjectMembers`, `addCrmProjectMember`, `removeCrmProjectMember`.

**Acceptance Criteria**
- `CRM_PROJECTS_ENABLED=0`: `/crm/projects` shows an empty state or "coming soon" notice (API returns 404; page catches error gracefully).
- Create project → appears in list with correct status badge.
- Add task → appears in Tasks tab; drag reorder changes displayed order.
- Add member → appears in Members tab; only owner sees remove button.
- Navigate to Gantt tab → Gantt component renders (PRJ-008).
- No TypeScript compiler errors.

**Dependencies**
- PRJ-001 through PRJ-008 (all backend + Gantt component).
