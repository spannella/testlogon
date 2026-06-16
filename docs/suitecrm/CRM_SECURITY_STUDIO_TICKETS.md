# CRM Security Suite, Studio & Admin — Implementation Tickets

**Area**: Security Suite, Studio & Admin
**Source**: SuiteCRM gap analysis (`docs/suitecrm/SUITECRM_GAP_ANALYSIS.md`, section "[T3] Security Suite, Studio & Admin — 14 tickets")

## What SuiteCRM provides in this area

SuiteCRM's Security Suite, Studio, and Admin area provides: a per-module CRUD/import/export/mass-update ACL role matrix that can be assigned to users and user groups; record-level Security Groups (users/groups can only see records they own or are assigned to); field-level ACL (hide or read-only specific fields per role); Studio (custom fields, custom modules, layout editor per module/view, dropdown editor for picklist fields, relationship builder for custom inter-module relationships); and administrative infrastructure including a system-level field-change audit trail (old/new value per field change), a scheduler/cron-job management UI with enable/disable/trigger-now controls, an outbound email queue manager with retry/cancel, a global search configuration API (per-domain enable/disable and relevance weights), and multi-currency admin (add currencies, set exchange rates, set default). testlogon has strong platform-admin primitives (`app/auth/roles.py`, `app/routers/admin_roles.py`, `app/services/audit_export*.py`, `app/routers/admin_jobs.py`, `app/routers/admin_email.py`, `app/routers/search.py`) but is entirely missing the CRM-specific ACL layer, Studio, field-change audit trail, job toggle/trigger API extensions, email queue manager, search config API, and currency management.

## Cross-cutting constraints

- **Additive only, default-off**: All tickets are gated by `S.crm_studio_enabled` (env `CRM_STUDIO_ENABLED`, default `"0"`). With the flag off, all routes under `/ui/admin/crm/*`, `/ui/admin/studio/*`, `/ui/admin/currencies/*`, and `/ui/admin/search-config/*` return 404. The ACL enforcement layer is similarly gated by `S.crm_acl_enabled` (env `CRM_ACL_ENABLED`, default `"0"`). Background jobs added here are no-ops when their flag is off.
- **Single-table DynamoDB, SECOPS-007 dev/prod parity**: New tables follow the `TableDef` pattern at `scripts/local-ddb-init.py:29`. Numeric GSI sort keys **must** declare `attr_types={"<key>": "N"}` — omitting causes a DynamoDB `ValidationException` at query time (CLAUDE.md gotcha). All code runs identically in dev (moto) and prod. No `if dev_mode` branches in business logic.
- **Reuse existing primitives — never fork**:
  - Auth: `app/auth/policy.require_admin_or_root` for admin-scoped endpoints; `app/auth/roles.Role` + `AdminScope` + `AdminProfile` (`app/auth/roles.py:8`) for role-gating; `app/services/sessions.require_ui_session` for user-scoped endpoints.
  - Audit events: `app/services/alerts.audit_event` (`app/services/alerts.py:644`) for write-path hooks.
  - Billing config pattern: `app/services/billing_config.py:39` — single-partition DDB table (`pk="BILLING_CONFIG"`, `sk="CURRENT"` + `sk="AUDIT#..."`) with in-memory TTL cache and typed allowlist of editable keys — mirror this pattern for currency and search-config tables.
  - Email delivery: `app/services/email_delivery.py` — existing `record_email_sent` / `record_email_failure` / `list_deliveries` / `get_suppression_list` patterns reused by the email queue manager.
  - Job registry: `app/services/job_registry.py:23` — `register_task` / `report_poll` / `report_error` in-memory registry; STU-007 adds a DDB-backed config overlay on top of it.
  - Cursor pagination: `app/core/cursor.encode_cursor` / `decode_cursor` (`app/core/cursor.py`).
  - Rate limiting: `app/services/rate_limit._bucket_limit` — used in `app/routers/search.py:26` for global search.
  - Feature flag bool-env pattern from `app/core/settings.py` (e.g. `messaging_translation_enabled`).
- **Route ordering**: Declare static route segments (`/config`, `/fields`, `/modules`, `/dropdowns`, `/layouts`, `/currencies`, `/search-config`, `/jobs`) **before** dynamic `{id}` segments to prevent FastAPI path-parameter capture of literals.
- **Hermetic offline tests**: All pytest must use moto-backed DDB tables bound via `object.__setattr__` on frozen `T`/`S` handles (canonical form: `tests/test_gap_0220_0221_ssh_stored_key.py`). No real AWS, network, or external service calls.

---

### STU-001: Feature flag, settings & DynamoDB scaffolding
**Type:** Chore  **Priority:** P0  **Estimate:** 1d

**Description**

Introduce the top-level feature flags, settings entries, and new DynamoDB tables required by all subsequent STU tickets. No user-visible behaviour. All tables follow the `TableDef` convention at `scripts/local-ddb-init.py:29`.

**Settings additions** (`app/core/settings.py`) — follow the bool-env pattern used for `messaging_translation_enabled` and `kyc_risk_auto_escalate_enabled`:

```python
crm_acl_enabled: bool = _bool_env("CRM_ACL_ENABLED", False)
crm_studio_enabled: bool = _bool_env("CRM_STUDIO_ENABLED", False)
# table-name settings
crm_acl_roles_table_name: str = os.environ.get("CRM_ACL_ROLES_TABLE", "crm_acl_roles")
crm_security_groups_table_name: str = os.environ.get("CRM_SECURITY_GROUPS_TABLE", "crm_security_groups")
crm_studio_fields_table_name: str = os.environ.get("CRM_STUDIO_FIELDS_TABLE", "crm_studio_fields")
crm_studio_modules_table_name: str = os.environ.get("CRM_STUDIO_MODULES_TABLE", "crm_studio_modules")
crm_studio_layouts_table_name: str = os.environ.get("CRM_STUDIO_LAYOUTS_TABLE", "crm_studio_layouts")
crm_studio_dropdowns_table_name: str = os.environ.get("CRM_STUDIO_DROPDOWNS_TABLE", "crm_studio_dropdowns")
crm_audit_trail_table_name: str = os.environ.get("CRM_AUDIT_TRAIL_TABLE", "crm_audit_trail")
currencies_table_name: str = os.environ.get("CURRENCIES_TABLE", "currencies")
search_config_table_name: str = os.environ.get("SEARCH_CONFIG_TABLE", "search_config")
email_queue_table_name: str = os.environ.get("EMAIL_QUEUE_TABLE", "email_queue")
```

**New DynamoDB tables** (add to `scripts/local-ddb-init.py`):

| Table | PK | SK | GSIs / notes |
|---|---|---|---|
| `crm_acl_roles` | `pk` (S) e.g. `ROLE#{role_id}` | `sk` (S) | GSI `by-assignee`: PK=`assignee_id` (S), SK=`assigned_at` (N); `attr_types={"assigned_at":"N"}` |
| `crm_security_groups` | `pk` (S) e.g. `GROUP#{group_id}` | `sk` (S) e.g. `META`, `MEMBER#{user_sub}`, `RECORD#{entity_type}#{record_id}` | GSI `by-record`: PK=`record_ref` (S), SK=`created_at` (N); `attr_types={"created_at":"N"}` |
| `crm_studio_fields` | `entity_type` (S) | `field_key` (S) | no GSI needed (per-entity scan acceptable at low record count) |
| `crm_studio_modules` | `pk` (S) e.g. `MODULE#{module_key}` | `sk` (S) e.g. `META` | no GSI |
| `crm_studio_layouts` | `pk` (S) e.g. `LAYOUT#{entity_type}#{view_type}` | `sk` (S) `META` | no GSI |
| `crm_studio_dropdowns` | `pk` (S) e.g. `DROPDOWN#{list_name}` | `sk` (S) `META` | no GSI |
| `crm_audit_trail` | `pk` (S) e.g. `ENTITY#{entity_type}#{record_id}` | `sk` (S) e.g. `CHANGE#{ts}#{event_id}` | GSI `by-actor`: PK=`actor_sub` (S), SK=`changed_at` (N); `attr_types={"changed_at":"N"}` |
| `currencies` | `pk` (S) `CURRENCY#{code}` | `sk` (S) `META` | no GSI |
| `search_config` | `pk` (S) `SEARCH_CONFIG` | `sk` (S) e.g. `DOMAIN#{name}` | no GSI |
| `email_queue` | `pk` (S) e.g. `EMAIL#{msg_id}` | `sk` (S) `META` | GSI `by-status`: PK=`status` (S), SK=`queued_at` (N); `attr_types={"queued_at":"N"}` |

**Table handles** — add to `app/core/tables.py` using the same `ddb.Table(S.<table_name>)` pattern:

```python
T.crm_acl_roles = ddb.Table(S.crm_acl_roles_table_name)
T.crm_security_groups = ddb.Table(S.crm_security_groups_table_name)
T.crm_studio_fields = ddb.Table(S.crm_studio_fields_table_name)
T.crm_studio_modules = ddb.Table(S.crm_studio_modules_table_name)
T.crm_studio_layouts = ddb.Table(S.crm_studio_layouts_table_name)
T.crm_studio_dropdowns = ddb.Table(S.crm_studio_dropdowns_table_name)
T.crm_audit_trail = ddb.Table(S.crm_audit_trail_table_name)
T.currencies = ddb.Table(S.currencies_table_name)
T.search_config = ddb.Table(S.search_config_table_name)
T.email_queue = ddb.Table(S.email_queue_table_name)
```

**Acceptance Criteria**
- All 10 table-name settings are present in `app/core/settings.py` with env-var overrides.
- `S.crm_acl_enabled` and `S.crm_studio_enabled` return `False` when the env vars are absent.
- All 10 `TableDef` entries are present in `scripts/local-ddb-init.py`; `just restart` creates the tables without errors.
- All 10 handles are present in `app/core/tables.py`.
- Pytest: `tests/test_stu_001_scaffolding.py` asserts all settings exist with correct defaults, and that `T` has the expected table-name attributes.

**Dependencies**
- None. This is the foundation for all other STU tickets.
- Flag `CRM_ACL_ENABLED=0` (default off), `CRM_STUDIO_ENABLED=0` (default off).

---

### STU-002: ACL Role matrix — per-module CRUD permission store & evaluation
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Implement the CRM ACL Role entity and the evaluation layer that checks per-module CRUD/import/export/mass-update permissions.

**Data model** on `crm_acl_roles` (table introduced in STU-001):

- `pk = ROLE#{role_id}`, `sk = META` — role definition row: `role_id`, `name`, `description`, `created_at` (N), `created_by_sub`, `permissions` (map of `{module: {create, read, update, delete, export, import_, mass_update}}` each a bool).
- `pk = ROLE#{role_id}`, `sk = ASSIGNMENT#{user_sub}` — per-user assignment: `user_sub`, `assigned_by_sub`, `assigned_at` (N), so the GSI `by-assignee` (PK=`assignee_id`, SK=`assigned_at`) can retrieve all roles for a given user.

**Service** (`app/services/crm_acl.py`, new file):
- `create_acl_role(actor_sub, name, description, permissions) -> dict` — writes META row; emits `audit_event("crm_acl_role.created", actor_sub, role_id=role_id)` via `app/services/alerts.audit_event` (`alerts.py:644`).
- `update_acl_role(actor_sub, role_id, **fields) -> dict` — partial update of name/description/permissions.
- `delete_acl_role(actor_sub, role_id) -> None` — deletes META + all ASSIGNMENT rows (query by GSI not needed: scan sk prefix `ASSIGNMENT#`).
- `assign_role_to_user(actor_sub, role_id, user_sub) -> None` — writes ASSIGNMENT row; emits audit.
- `revoke_role_from_user(actor_sub, role_id, user_sub) -> None` — deletes ASSIGNMENT row.
- `get_roles_for_user(user_sub) -> list[dict]` — queries `by-assignee` GSI.
- `check_permission(user_sub, module: str, action: str) -> bool` — loads all roles for user (with 60 s in-process TTL cache, same pattern as `billing_config.py:50`), returns `True` if any role grants the action. When `S.crm_acl_enabled` is `False`, always returns `True` (open access).
- `require_crm_permission(module: str, action: str)` — FastAPI `Depends`-compatible callable that raises `HTTPException(403)` if `check_permission` returns `False`. Wire into CRM routers as they are built.

**Router** (`app/routers/crm_acl.py`, new file, prefix `/ui/admin/crm/acl-roles`):
- `POST /` — create role (ROOT only via `app/auth/policy.require_root`).
- `GET /` — list all roles (ADMIN/ROOT via `require_admin_or_root`).
- `GET /{role_id}` — get single role.
- `PATCH /{role_id}` — update role (ROOT only).
- `DELETE /{role_id}` — delete role (ROOT only).
- `POST /{role_id}/assignments` — assign role to user (ROOT only).
- `DELETE /{role_id}/assignments/{user_sub}` — revoke (ROOT only).
- `GET /my-permissions` — returns caller's effective permissions map across all modules (authenticated user via `require_ui_session`).

Register the new router in `app/main.py` behind `if S.crm_acl_enabled`.

**Pydantic models** (add to `app/models.py`):
- `CrmAclPermissionMatrix` — map `{module_name: {create, read, update, delete, export, import_, mass_update}}` (all bool, default False).
- `CrmAclRoleCreateIn` — `name`, `description`, `permissions: CrmAclPermissionMatrix`.
- `CrmAclRoleOut` — `role_id`, `name`, `description`, `permissions`, `created_at`, `created_by_sub`.

**Acceptance Criteria**
- `check_permission` returns `True` for all modules when `CRM_ACL_ENABLED=0`.
- Role CRUD, assignment, and revocation endpoints return correct shapes; permissions matrix is persisted/retrieved intact.
- `require_crm_permission("contacts", "export")` returns 403 for a user with no assigned role that grants contacts export.
- Audit events are emitted for create/update/delete/assign/revoke.
- Pytest: `tests/test_stu_002_acl_roles.py` — offline/moto, calls service functions and route handlers directly, covers permission evaluation TTL cache invalidation on assignment change.

**Dependencies**
- STU-001 (tables + settings).
- Flag `CRM_ACL_ENABLED`.

---

### STU-003: ACL Role multi-role assignment & user-group propagation
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the role-assignment model (STU-002) to support multi-role per user (a user can hold N ACL roles simultaneously) and allow user groups (`AdminScope` groups defined in `app/auth/roles.py:14`) to carry an ACL role that propagates to all group members.

**Changes to `app/services/crm_acl.py`**:
- `assign_role_to_user` already supports multi-role (each row is a separate ASSIGNMENT SK); verify `get_roles_for_user` correctly merges permissions from all assigned roles (union of `True` values across all roles).
- `assign_role_to_group(actor_sub, role_id, group_key: str) -> None` — writes `pk=ROLE#{role_id}`, `sk=GROUP_ASSIGNMENT#{group_key}` row. `group_key` is one of the `AdminScope` values (`auth_support`, `billing_support`, etc.) or a platform-level named group.
- `revoke_role_from_group(actor_sub, role_id, group_key: str) -> None` — deletes the GROUP_ASSIGNMENT row.
- `get_effective_roles_for_user(user_sub, admin_profile: AdminProfile) -> list[dict]` — union of: (a) direct ASSIGNMENT rows for `user_sub` via `get_roles_for_user`; (b) GROUP_ASSIGNMENT rows for each scope in `admin_profile.scopes` (queries by `sk` prefix `GROUP_ASSIGNMENT#{scope}`). `admin_profile` is available from `require_ui_session` context (`ctx["admin_profile"]`).
- Update `check_permission` to call `get_effective_roles_for_user` instead of `get_roles_for_user`.

**Router additions** to `app/routers/crm_acl.py` (prefix `/ui/admin/crm/acl-roles`):
- `POST /{role_id}/group-assignments` — `{group_key: str}` body, ROOT only.
- `DELETE /{role_id}/group-assignments/{group_key}` — ROOT only.
- `GET /{role_id}/assignments` — list direct user + group assignments for a role (ADMIN/ROOT).

**Pydantic models** (add to `app/models.py`):
- `CrmAclGroupAssignmentIn` — `group_key: str`.

**Acceptance Criteria**
- A user holding two ACL roles has the union of their permissions (if role A grants contacts.read and role B grants contacts.export, the user has both).
- A user with `AdminScope.AUTH_SUPPORT` in their `AdminProfile` inherits the ACL role assigned to that group.
- Group assignment and revocation endpoints work and emit audit events.
- Pytest: `tests/test_stu_003_acl_multi_role.py` — offline/moto, tests union semantics, group propagation.

**Dependencies**
- STU-002 (ACL role model and evaluation layer).

---

### STU-004: CRM Security Groups — record-level access control
**Type:** Feature  **Priority:** P1  **Estimate:** 3d

**Description**

Implement CRM record-level Security Groups: a DynamoDB membership table linking record references to groups, with enforcement in list/get service calls on CRM entities (contacts via the party model planned in PTY tickets, tickets at `app/services/tickets.py`, and future CRM entities).

**Note**: This is distinct from compute Security Groups (`app/routers/security_groups.py`, `app/services/security_groups.py`) which are EC2/K8s firewall rules — this ticket implements a CRM ACL concept with the same name.

**Data model** on `crm_security_groups` (table introduced in STU-001):

- `pk = GROUP#{group_id}`, `sk = META` — group definition: `group_id`, `name`, `description`, `owner_sub`, `created_at` (N), `is_global: bool` (global groups can be seen by any admin).
- `pk = GROUP#{group_id}`, `sk = MEMBER#{user_sub}` — membership row: `user_sub`, `added_by_sub`, `added_at` (N), `can_edit: bool`.
- `pk = GROUP#{group_id}`, `sk = RECORD#{entity_type}#{record_id}` — record assignment row: `entity_type`, `record_id`, `record_ref` (for GSI), `assigned_by_sub`, `created_at` (N).

The `by-record` GSI (PK=`record_ref`, SK=`created_at`) allows fast lookup of all groups a record belongs to.

**Service** (`app/services/crm_security_groups.py`, new file):
- `create_group(actor_sub, name, description, is_global=False) -> dict`.
- `delete_group(actor_sub, group_id) -> None`.
- `add_member(actor_sub, group_id, user_sub, can_edit=False) -> None`.
- `remove_member(actor_sub, group_id, user_sub) -> None`.
- `assign_record(actor_sub, group_id, entity_type, record_id) -> None` — writes RECORD row; `record_ref = f"{entity_type}#{record_id}"`.
- `unassign_record(actor_sub, group_id, entity_type, record_id) -> None`.
- `get_groups_for_record(entity_type, record_id) -> list[str]` — queries `by-record` GSI, returns group_id list.
- `user_can_access_record(user_sub, entity_type, record_id) -> bool` — returns `True` if: (a) `S.crm_acl_enabled` is `False`; (b) user is ROOT/ADMIN; (c) the record has no groups assigned (open access); or (d) user is a member of at least one group that has the record. Cache group membership per user for 30 s.
- `filter_records_by_access(user_sub, entity_type, records: list[dict]) -> list[dict]` — batch filter, used in list endpoints.

**Router** (`app/routers/crm_security_groups.py`, new file, prefix `/ui/admin/crm/security-groups`):
- `POST /` — create group (ADMIN/ROOT).
- `GET /` — list groups (ADMIN/ROOT).
- `GET /{group_id}` — get group + members (ADMIN/ROOT).
- `DELETE /{group_id}` — delete group (ROOT only).
- `POST /{group_id}/members` — add member (ADMIN/ROOT).
- `DELETE /{group_id}/members/{user_sub}` — remove member (ADMIN/ROOT).
- `POST /{group_id}/records` — assign record (ADMIN/ROOT).
- `DELETE /{group_id}/records/{entity_type}/{record_id}` — unassign record (ADMIN/ROOT).

Register in `app/main.py` behind `if S.crm_acl_enabled`.

**Acceptance Criteria**
- `user_can_access_record` returns `True` for all records when `CRM_ACL_ENABLED=0`.
- A user not in any group that has record X assigned receives 403 from the enforcement layer.
- ROOT/ADMIN users bypass enforcement.
- Records with no group assignments are accessible to all authenticated users.
- Pytest: `tests/test_stu_004_crm_security_groups.py` — offline/moto, covers group CRUD, member add/remove, record assignment, and `user_can_access_record` logic branches.

**Dependencies**
- STU-001 (tables).
- STU-002 (`S.crm_acl_enabled` flag checked in enforcement helpers).

---

### STU-005: Field-level ACL — hide/read-only fields per role
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Build a field-level ACL metadata store and a response-model post-processor that nullifies or omits specified fields from API responses based on the caller's ACL role set.

**Data model** on `crm_studio_fields` (table introduced in STU-001, reused here for field ACL metadata):

The field ACL config is stored as a special row: `entity_type = "__acl__"`, `field_key = "{role_id}#{entity_type}#{field_name}"` with attributes `access: "hidden" | "readonly"`.

**Service** (`app/services/crm_field_acl.py`, new file):
- `set_field_acl(actor_sub, role_id, entity_type, field_name, access: Literal["hidden", "readonly"]) -> None` — upserts the row on `crm_studio_fields`.
- `delete_field_acl(actor_sub, role_id, entity_type, field_name) -> None`.
- `get_field_acls_for_role(role_id, entity_type) -> list[dict]` — returns all field ACL rows for a role+entity.
- `apply_field_acl(response_dict: dict, entity_type: str, user_sub: str, admin_profile: AdminProfile) -> dict` — loads the ACL role IDs for the user (via `crm_acl.get_effective_roles_for_user`), collects all field restrictions for the entity, then: for `hidden` fields sets the value to `None` and removes the key; for `readonly` fields wraps the response with a `_readonly_fields: list[str]` annotation. Returns the modified dict. When `S.crm_acl_enabled` is `False`, returns the dict unmodified.

**Router** (`app/routers/crm_field_acl.py`, new file, prefix `/ui/admin/crm/field-acl`):
- `POST /{role_id}/{entity_type}/{field_name}` — `{access: "hidden"|"readonly"}`, ROOT only.
- `DELETE /{role_id}/{entity_type}/{field_name}` — ROOT only.
- `GET /{role_id}/{entity_type}` — list field ACLs for a role+entity (ADMIN/ROOT).

Register in `app/main.py` behind `if S.crm_acl_enabled`.

**Acceptance Criteria**
- `apply_field_acl` removes `hidden` fields from the dict and adds them to `_hidden_fields` in a debug-only annotation.
- `readonly` fields are preserved in the value but listed in `_readonly_fields`.
- When `CRM_ACL_ENABLED=0`, `apply_field_acl` is a no-op.
- CRUD endpoints for field ACL configuration work and emit audit events.
- Pytest: `tests/test_stu_005_field_acl.py` — offline, no DDB required for `apply_field_acl` unit tests; moto-backed for config persistence tests.

**Dependencies**
- STU-002 (role model + `get_effective_roles_for_user`).
- STU-001 (`crm_studio_fields` table).

---

### STU-006: CRM field-change audit trail
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Add a per-record field-change audit trail (old_value/new_value/field_name/record_type/record_id) extending the existing `UnifiedAuditEvent` / `BaseAuditAdapter` infrastructure at `app/services/audit_export.py` and `app/services/audit_adapters.py`.

**Data model** on `crm_audit_trail` (table introduced in STU-001):

- `pk = ENTITY#{entity_type}#{record_id}`, `sk = CHANGE#{ts:010d}#{event_id}` — one row per field-change batch: `event_id`, `entity_type`, `record_id`, `actor_sub`, `changed_at` (N), `field_changes: list[{field_name, old_value, new_value}]`, `source` (e.g. `api`, `workflow`, `import`).

**Service** (`app/services/crm_audit_trail.py`, new file):
- `record_field_changes(actor_sub, entity_type, record_id, changes: list[dict], source="api") -> None` — best-effort write (wraps `put_item` in `try/except`; never blocks the write path). Uses `now_ts()` from `app/core/time.py:5` and `uuid4().hex` for `event_id`.
- `get_record_audit_trail(entity_type, record_id, limit=50, cursor=None) -> (list[dict], str|None)` — queries by PK, sorted SK descending, with cursor pagination via `app/core/cursor.encode_cursor`.
- `get_actor_audit_trail(actor_sub, limit=50, cursor=None) -> (list[dict], str|None)` — queries `by-actor` GSI (PK=`actor_sub`, SK=`changed_at` desc).

**Write-path hook** — add a helper `_emit_field_changes(actor_sub, entity_type, record_id, before: dict, after: dict) -> None` that diffs the two dicts and calls `record_field_changes`. Call this from:
- `app/services/tickets.py` update paths (after the existing `audit_event` calls).
- Future CRM service update paths (contacts/party service when PTY tickets ship).

**Audit adapter** — add `CrmAuditTrailAdapter(BaseAuditAdapter)` in `app/services/audit_adapters.py` so that field-change events appear in the ENTERPRISE-004 bulk audit export (`app/routers/audit_export.py`).

**Router additions** to `app/routers/audit_export.py` (existing file):
- `GET /ui/admin/audit-exports/crm-trail/{entity_type}/{record_id}` — paginated field-change trail for a record (ADMIN/ROOT).
- `GET /ui/admin/audit-exports/crm-trail/actor/{actor_sub}` — paginated actor-scoped trail (ROOT only).

**Acceptance Criteria**
- `record_field_changes` writes rows to `crm_audit_trail`; a subsequent `get_record_audit_trail` returns them newest-first.
- Updating a ticket subject via `app/services/tickets.py` produces a `field_changes` row with `old_value` and `new_value` for `subject`.
- `CrmAuditTrailAdapter` is registered in `audit_adapters.ADAPTER_REGISTRY` so ENTERPRISE-004 exports include CRM field changes.
- New GET endpoints return paginated results with `next_cursor`.
- Pytest: `tests/test_stu_006_crm_audit_trail.py` — offline/moto, tests write, pagination, actor GSI query, and the `_emit_field_changes` diff logic.

**Dependencies**
- STU-001 (`crm_audit_trail` table).
- Existing `app/services/audit_adapters.py` and `app/services/audit_export.py`.

---

### STU-007: Admin scheduler/cron-job management — enable/disable/trigger API
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Extend the existing admin jobs API (`app/routers/admin_jobs.py`) with enable/disable toggle endpoints and a manual-trigger endpoint, backed by a DDB-persisted job config so that changes survive process restarts.

The current `app/services/job_registry.py` is entirely in-memory and loses state on restart. This ticket adds a thin DDB config overlay.

**Service** (`app/services/job_config.py`, new file):

Data stored in `app_single_table` (existing table, following the `BILLING_CONFIG` single-partition pattern at `app/services/billing_config.py:39`) under `pk = "JOB_CONFIG"`, `sk = "JOB#{task_name}"`:
- `task_name`, `enabled: bool`, `updated_by_sub`, `updated_at` (int).

- `get_job_config(task_name) -> dict | None` — reads the item; returns `None` if absent (treat as enabled).
- `set_job_enabled(actor_sub, task_name, enabled: bool) -> None` — upserts the config row; emits `audit_event("admin_job.toggled", actor_sub, task_name=task_name, enabled=enabled)`.
- `get_all_job_configs() -> dict[str, dict]` — scans all `sk` starting with `JOB#`; returns `{task_name: {enabled, updated_by_sub, updated_at}}` map.
- `is_job_enabled(task_name) -> bool` — returns the DDB-persisted flag if present; falls back to `True`. Called at startup from each background task's startup hook to conditionally call `register_task(enabled=...)`.

**Manual trigger** — add a `trigger_task_now(task_name)` callback registry: each background task's module-level startup registers a `Callable[[], None]` under its task name. `POST /ui/admin/jobs/trigger/{task_name}` invokes the registered callable in a `asyncio.get_event_loop().run_in_executor(None, fn)` background thread.

**Router additions** to `app/routers/admin_jobs.py` (existing file):
- `POST /ui/admin/jobs/task/{task_name}/enable` — `{enabled: bool}` body; ADMIN/ROOT; calls `set_job_enabled`.
- `POST /ui/admin/jobs/task/{task_name}/trigger` — ROOT only; invokes registered trigger callable; returns `{"ok": true, "task_name": task_name}` or 404 if not registered.
- `GET /ui/admin/jobs/config` — returns merged view of in-memory registry + DDB config overrides (ADMIN/ROOT).

**Startup integration** — update at least one background task (e.g. `app/services/audit_export_worker.py:start_audit_export_worker_task`) to call `is_job_enabled("audit_export_worker")` and conditionally skip registration, as a reference implementation.

**Acceptance Criteria**
- `POST /ui/admin/jobs/task/audit_export_worker/enable` with `{"enabled": false}` writes to DDB and the row is retrievable via `get_job_config`.
- After restart (simulated by clearing the in-memory registry), `is_job_enabled` returns the correct value from DDB.
- `POST /ui/admin/jobs/task/{task_name}/trigger` returns 404 for an unregistered task; 200 for a registered one.
- Audit events are emitted on toggle.
- Pytest: `tests/test_stu_007_job_config.py` — offline/moto, tests get/set/is_enabled persistence, trigger 404/200.

**Dependencies**
- STU-001 (`app_single_table` already exists; no new table needed — uses `pk=JOB_CONFIG` partition).
- Existing `app/routers/admin_jobs.py` and `app/services/job_registry.py`.

---

### STU-008: Admin email queue manager
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement an outbound email queue table with per-message status tracking and admin retry/cancel endpoints. The existing `app/services/email_delivery.py` records delivered/bounced/failed emails but has no queuing concept — messages are fired synchronously. This ticket adds an optional async queue layer.

**Data model** on `email_queue` (table introduced in STU-001):

- `pk = EMAIL#{msg_id}`, `sk = META` — one row per queued message: `msg_id` (uuid4 hex), `to_emails: list[str]`, `subject`, `body_text`, `body_html` (optional), `status: "queued"|"sending"|"sent"|"failed"|"cancelled"`, `queued_at` (N), `sent_at` (N, optional), `attempt_count: int`, `last_error: str` (optional), `queued_by_sub: str`.

The `by-status` GSI (PK=`status`, SK=`queued_at`) allows the worker to query `status=queued` in FIFO order.

**Service** (`app/services/email_queue_service.py`, new file):
- `enqueue_email(to_emails, subject, body_text, body_html=None, queued_by_sub="system") -> str` — writes `status=queued` row; returns `msg_id`. In dev mode when `S.dev_mode`, writes the item AND logs it (same dev-mode parity as `app/services/email_delivery.py:33`).
- `process_queue_batch(max_items=50) -> dict` — queries `status=queued` via GSI, claims each via conditional update (`status=queued → status=sending`), calls `app/services/alerts.send_alert_email` for each, updates status to `sent` or `failed`. Returns `{processed, sent, failed}`.
- `retry_message(actor_sub, msg_id) -> None` — resets `status=queued`, clears `last_error`, increments `attempt_count`; ROOT only.
- `cancel_message(actor_sub, msg_id) -> None` — sets `status=cancelled`; ADMIN/ROOT.
- `list_queue(status_filter=None, limit=50, cursor=None) -> (list[dict], str|None)` — queries by status GSI or scans with filter; cursor-paginated.

**Router** (`app/routers/admin_email_queue.py`, new file, prefix `/ui/admin/email-queue`):
- `GET /` — list queue items with optional `?status=` filter (ADMIN/ROOT).
- `POST /{msg_id}/retry` — retry a failed message (ROOT only).
- `POST /{msg_id}/cancel` — cancel a queued message (ADMIN/ROOT).
- `GET /{msg_id}` — get single message details (ADMIN/ROOT).
- `POST /process` — manual trigger to process a batch (ROOT only; for dev/testing).

Register in `app/main.py`.

**Acceptance Criteria**
- `enqueue_email` writes a row with `status=queued`; `list_queue(status_filter="queued")` returns it.
- `process_queue_batch` transitions items `queued → sent` on success and `queued → failed` on error.
- `retry_message` resets a failed item back to `queued`; subsequent `process_queue_batch` picks it up.
- `cancel_message` prevents a queued item from being processed.
- Admin endpoints return correct shapes; ROOT-only endpoints return 403 for ADMIN callers.
- Pytest: `tests/test_stu_008_email_queue.py` — offline/moto, mocks `send_alert_email`, tests full enqueue/process/retry/cancel lifecycle.

**Dependencies**
- STU-001 (`email_queue` table).
- Existing `app/services/email_delivery.py` and `app/services/alerts.send_alert_email`.

---

### STU-009: Admin global search configuration API
**Type:** Feature  **Priority:** P2  **Estimate:** 1d

**Description**

Add an admin API to manage per-domain search inclusion and relevance weights, stored in DynamoDB and reloaded at runtime. The current `app/routers/search.py` uses a hard-coded `ALLOWED_TYPES` set and a single `_EXTENDED_SEARCH` env-var flag (line 41) with no per-domain weight or per-domain on/off capability at runtime without a restart.

**Data model** on `search_config` (table introduced in STU-001):

- `pk = "SEARCH_CONFIG"`, `sk = "DOMAIN#{domain_name}"` — per-domain config row: `domain_name` (one of `users`, `posts`, `catalog`, `files`, `messages`, `tickets`, `contacts`, `videos`, `calendar`), `enabled: bool`, `weight: Decimal` (0.0–10.0, default 1.0), `updated_by_sub`, `updated_at` (int).

**Service** (`app/services/search_config_service.py`, new file):
- `get_all_domain_configs() -> dict[str, dict]` — scans `pk = SEARCH_CONFIG`; returns `{domain: {enabled, weight}}`. In-memory cache with 60 s TTL (same pattern as `billing_config.py:50`).
- `set_domain_config(actor_sub, domain_name, enabled: bool | None, weight: float | None) -> dict` — upserts the row; invalidates cache; emits `audit_event("search_config.updated", actor_sub, domain=domain_name)`.
- `get_effective_allowed_types() -> set[str]` — returns the intersection of `ALLOWED_TYPES` (search.py:43) and the DDB-enabled set. When DDB has no config for a domain, the env-var default (`_EXTENDED_SEARCH`) applies.
- `get_domain_weight(domain_name) -> float` — returns weight for use in result scoring. Default 1.0 if not configured.

**Integration** — add a call to `get_effective_allowed_types()` in `_search_aggregator` (`app/routers/search.py:645`) so that admin-disabled domains are excluded from the fan-out. Import lazily to avoid circular dependency.

**Router** (`app/routers/admin_search_config.py`, new file, prefix `/ui/admin/search-config`):
- `GET /` — get current config for all domains (ADMIN/ROOT).
- `PATCH /{domain_name}` — `{enabled: bool, weight: float}` (ADMIN/ROOT).
- `POST /reset` — reset all domains to env-var defaults; clears DDB rows (ROOT only).

Register in `app/main.py`.

**Acceptance Criteria**
- `PATCH /search-config/videos` with `{"enabled": false}` causes `_search_aggregator` to skip the videos module.
- `PATCH /search-config/catalog` with `{"weight": 2.5}` persists the weight; `get_domain_weight("catalog")` returns 2.5.
- Cache invalidation: after `set_domain_config`, the next call to `get_all_domain_configs` reads fresh data.
- `POST /reset` clears DDB rows; `get_effective_allowed_types` falls back to env-var defaults.
- Pytest: `tests/test_stu_009_search_config.py` — offline/moto, tests config persistence, cache TTL invalidation, and `get_effective_allowed_types` logic.

**Dependencies**
- STU-001 (`search_config` table).
- Existing `app/routers/search.py` (integration: `get_effective_allowed_types` called in `_search_aggregator`).

---

### STU-010: Admin currency management
**Type:** Feature  **Priority:** P1  **Estimate:** 2d

**Description**

Implement admin currency management: DynamoDB-backed currency table, manual exchange rate management, default currency setting, and `GET/POST/PATCH/DELETE /ui/admin/currencies` endpoints. The existing `app/core/settings.py:324-325` defines a single `default_currency`/`default_currency_code` but there is no runtime management or multi-currency exchange-rate store.

**Data model** on `currencies` (table introduced in STU-001):

- `pk = "CURRENCY#{code}"`, `sk = "META"` — per-currency row: `code` (3-letter ISO, e.g. `USD`), `name` (e.g. `US Dollar`), `symbol` (e.g. `$`), `exchange_rate_to_usd: Decimal` (e.g. `1.0` for USD, `0.89` for EUR), `is_default: bool`, `is_active: bool`, `updated_by_sub`, `updated_at` (int).
- `pk = "CURRENCY_CONFIG"`, `sk = "CURRENT"` — global config row: `default_currency_code` (3-letter), `updated_by_sub`, `updated_at`.

Mirror the `app/services/billing_config.py:39` pattern: in-memory cache with 60 s TTL, `invalidate_cache()` on write.

**Service** (`app/services/currency_service.py`, new file):
- `list_currencies(active_only=True) -> list[dict]`.
- `get_currency(code: str) -> dict | None`.
- `create_currency(actor_sub, code, name, symbol, exchange_rate_to_usd) -> dict` — validates 3-letter code; emits `audit_event("currency.created", actor_sub, currency_code=code)`.
- `update_currency(actor_sub, code, **fields) -> dict` — allowed fields: `exchange_rate_to_usd`, `name`, `symbol`, `is_active`; emits audit.
- `delete_currency(actor_sub, code) -> None` — blocks deletion of the default currency; emits audit.
- `set_default_currency(actor_sub, code) -> None` — updates `CURRENCY_CONFIG` + sets `is_default=True` on the target row, `False` on all others; emits `audit_event("currency.default_changed", ...)`.
- `get_default_currency() -> str` — reads from DDB config, falls back to `S.default_currency`.
- `convert_amount(amount_cents: int, from_code: str, to_code: str) -> int` — converts via USD as pivot: `amount_cents * (rate_from / rate_to)`; returns int; raises `ValueError` for unknown codes.
- `get_exchange_rate(from_code, to_code) -> Decimal`.

**Router** (`app/routers/admin_currencies.py`, new file, prefix `/ui/admin/currencies`):
- `GET /` — list currencies (ADMIN/ROOT).
- `POST /` — create currency (ROOT only).
- `GET /{code}` — get single currency (ADMIN/ROOT).
- `PATCH /{code}` — update exchange rate / name / symbol / active flag (ROOT only).
- `DELETE /{code}` — delete currency (ROOT only).
- `POST /default` — `{code: str}` — set default currency (ROOT only).

Register in `app/main.py`.

**Pydantic models** (add to `app/models.py`):
- `CurrencyCreateIn` — `code: str`, `name: str`, `symbol: str`, `exchange_rate_to_usd: float`.
- `CurrencyUpdateIn` — all optional: `exchange_rate_to_usd`, `name`, `symbol`, `is_active`.
- `CurrencyOut` — `code`, `name`, `symbol`, `exchange_rate_to_usd`, `is_default`, `is_active`, `updated_at`.

**Acceptance Criteria**
- `POST /currencies` with `{code:"EUR", name:"Euro", symbol:"€", exchange_rate_to_usd:0.92}` creates the row; `GET /currencies/EUR` returns it.
- `convert_amount(1000, "EUR", "USD")` returns correct centvalue.
- `POST /currencies/default` with `{code:"EUR"}` sets `is_default=True` on EUR and `False` on USD.
- Cannot delete the default currency — returns 409.
- Audit events emitted for create/update/delete/default-change.
- Pytest: `tests/test_stu_010_currencies.py` — offline/moto, covers CRUD, `convert_amount`, default-change blocking.

**Dependencies**
- STU-001 (`currencies` table).

---

### STU-011: Studio — custom fields for existing modules
**Type:** Feature  **Priority:** P2  **Estimate:** 3d

**Description**

Build a Studio-like custom field registry: DynamoDB metadata table for field definitions per entity type, a runtime validation layer, and admin CRUD endpoints. Custom fields allow admins to add domain-specific attributes to CRM entities (contacts, tickets, etc.) without code changes.

**Data model** on `crm_studio_fields` (table introduced in STU-001):

- `entity_type` (PK, S) e.g. `contact`, `ticket`, `opportunity` — `field_key` (SK, S) e.g. `custom_region` — attributes: `field_key`, `label` (human-readable), `field_type: "text"|"integer"|"decimal"|"boolean"|"date"|"picklist"|"multi_picklist"`, `required: bool`, `default_value` (optional), `picklist_name` (if field_type is picklist/multi_picklist, references a dropdown list from STU-014), `max_length: int` (for text), `created_by_sub`, `created_at` (int), `is_active: bool`.

**Service** (`app/services/crm_studio_fields.py`, new file):
- `create_field(actor_sub, entity_type, field_key, label, field_type, **opts) -> dict` — validates `field_key` format (`^[a-z][a-z0-9_]{2,49}$`); emits audit.
- `update_field(actor_sub, entity_type, field_key, **fields) -> dict`.
- `delete_field(actor_sub, entity_type, field_key) -> None` — soft-delete (sets `is_active=False`).
- `list_fields(entity_type, include_inactive=False) -> list[dict]`.
- `get_field(entity_type, field_key) -> dict | None`.
- `validate_custom_fields(entity_type, data: dict) -> dict` — validates an incoming payload dict against active field definitions for the entity: checks required fields present, type coercion, picklist membership; raises `ValueError` with a list of per-field errors on failure. Called from CRM entity create/update handlers.

**Router** (`app/routers/crm_studio.py`, new file, prefix `/ui/admin/studio`; route segment declared before any dynamic `{entity_type}` endpoints):
- `GET /fields/{entity_type}` — list fields for entity (ADMIN/ROOT).
- `POST /fields/{entity_type}` — create field (ROOT only).
- `GET /fields/{entity_type}/{field_key}` — get single field (ADMIN/ROOT).
- `PATCH /fields/{entity_type}/{field_key}` — update field (ROOT only).
- `DELETE /fields/{entity_type}/{field_key}` — soft-delete (ROOT only).

Register in `app/main.py` behind `if S.crm_studio_enabled`.

**Frontend** (`frontend/src/pages/admin/studio/FieldEditor.tsx`, new component):
- List custom fields per entity type in a table; form to create/edit fields (field_key, label, field_type, required, default_value, max_length, picklist_name).
- Accessible from `/admin/studio/fields?entity=contact`.

**Acceptance Criteria**
- `create_field("contact", "custom_region", "Region", "text", max_length=100)` writes to DDB; `list_fields("contact")` returns it.
- `validate_custom_fields("contact", {"custom_region": 123})` raises `ValueError` for type mismatch (integer vs text).
- `validate_custom_fields("contact", {})` raises `ValueError` when a required field is missing.
- Admin UI lists fields and allows create/edit/deactivate.
- Pytest: `tests/test_stu_011_studio_fields.py` — offline/moto, covers CRUD, `validate_custom_fields` type and required-field logic, soft-delete.

**Dependencies**
- STU-001 (`crm_studio_fields` table, `CRM_STUDIO_ENABLED` flag).

---

### STU-012: Studio — dropdown editor for picklist fields
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Build a dropdown editor service: DynamoDB table for named option lists (used by picklist custom fields in STU-011), CRUD admin API at `/ui/admin/studio/dropdowns`, and integration with the custom fields validation layer.

**Data model** on `crm_studio_dropdowns` (table introduced in STU-001):

- `pk = "DROPDOWN#{list_name}"`, `sk = "META"` — dropdown definition: `list_name` (unique slug), `label` (human-readable), `options: list[{value: str, label: str, sort_order: int, is_active: bool}]`, `created_by_sub`, `updated_by_sub`, `created_at` (int), `updated_at` (int).

**Service** (`app/services/crm_studio_dropdowns.py`, new file):
- `create_dropdown(actor_sub, list_name, label, options: list[dict]) -> dict` — validates `list_name` slug; emits audit.
- `update_dropdown(actor_sub, list_name, label=None, options=None) -> dict` — full options replacement on update (client sends the complete list); emits audit.
- `delete_dropdown(actor_sub, list_name) -> None` — blocks deletion if any active custom field references this `picklist_name`; emits audit.
- `get_dropdown(list_name) -> dict | None`.
- `list_dropdowns() -> list[dict]`.
- `get_active_values(list_name) -> list[str]` — returns `[opt["value"] for opt in options if opt["is_active"]]`; used by `crm_studio_fields.validate_custom_fields` to validate picklist values.

**Integration** — update `app/services/crm_studio_fields.py:validate_custom_fields` (STU-011) to call `get_active_values(field["picklist_name"])` for `field_type in ("picklist", "multi_picklist")`.

**Router additions** to `app/routers/crm_studio.py` (STU-011 file):
- `GET /dropdowns` — list all dropdowns (ADMIN/ROOT). Declared before `GET /dropdowns/{list_name}`.
- `POST /dropdowns` — create (ROOT only).
- `GET /dropdowns/{list_name}` — get single dropdown (ADMIN/ROOT).
- `PATCH /dropdowns/{list_name}` — update (ROOT only).
- `DELETE /dropdowns/{list_name}` — delete (ROOT only, blocks if in use).

**Frontend** (`frontend/src/pages/admin/studio/DropdownEditor.tsx`, new component):
- Table of dropdowns with inline add/reorder/remove options using `@dnd-kit/sortable` (already used in `frontend/src/pages/subscriptions/SubscriptionPlansPage.tsx`) or a simple manual-reorder form.
- Accessible from `/admin/studio/dropdowns`.

**Acceptance Criteria**
- `create_dropdown("regions", "Regions", [{value:"EMEA", label:"EMEA", sort_order:0, is_active:true}])` writes to DDB.
- A picklist custom field with `picklist_name="regions"` validates that submitted value `"EMEA"` is accepted and `"INVALID"` is rejected via `validate_custom_fields`.
- `delete_dropdown` returns 409 when a live field references it.
- Pytest: `tests/test_stu_012_studio_dropdowns.py` — offline/moto, covers CRUD, in-use deletion block, picklist validation integration.

**Dependencies**
- STU-001 (`crm_studio_dropdowns` table).
- STU-011 (integration with `validate_custom_fields`).

---

### STU-013: Studio — layout editor (view layouts per module)
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Implement a layout metadata store and a frontend layout renderer that reads field order/visibility from stored layout definitions per module/view type (detail, edit, list, search).

**Data model** on `crm_studio_layouts` (table introduced in STU-001):

- `pk = "LAYOUT#{entity_type}#{view_type}"`, `sk = "META"` — layout definition: `entity_type` (e.g. `contact`, `ticket`), `view_type` (`detail|edit|list|search`), `panels: list[{panel_label: str, columns: int, fields: list[{field_key: str, label: str, colspan: int, required: bool, visible: bool}]}]`, `updated_by_sub`, `updated_at` (int).

**Service** (`app/services/crm_studio_layouts.py`, new file):
- `get_layout(entity_type, view_type) -> dict | None` — reads the row; returns `None` if no custom layout (frontend falls back to default field order).
- `save_layout(actor_sub, entity_type, view_type, panels: list[dict]) -> dict` — upserts the layout row; emits `audit_event("studio.layout_saved", actor_sub, entity_type=entity_type, view_type=view_type)`.
- `delete_layout(actor_sub, entity_type, view_type) -> None` — deletes row (resets to default).
- `list_layouts(entity_type) -> list[dict]` — lists all view types with custom layouts for an entity.

**Router additions** to `app/routers/crm_studio.py` (STU-011 file):
- `GET /layouts/{entity_type}` — list available custom layouts for entity (ADMIN/ROOT).
- `GET /layouts/{entity_type}/{view_type}` — get layout definition (ADMIN/ROOT).
- `PUT /layouts/{entity_type}/{view_type}` — save/replace layout (ROOT only).
- `DELETE /layouts/{entity_type}/{view_type}` — reset to default (ROOT only).

**Frontend** (`frontend/src/pages/admin/studio/LayoutEditor.tsx`, new component):
- Drag-and-drop layout editor using `@dnd-kit/core` (already a project dependency via sortable usage pattern). Shows panels with fields, allows reordering fields within a panel and hiding/showing fields.
- On save, calls `PUT /ui/admin/studio/layouts/{entity_type}/{view_type}`.
- Accessible from `/admin/studio/layouts?entity=contact&view=detail`.

**Acceptance Criteria**
- `save_layout("contact", "detail", panels=[...])` writes to DDB; `get_layout("contact", "detail")` returns it.
- `get_layout("contact", "detail")` returns `None` for an entity with no custom layout (client uses default).
- `delete_layout` removes the row; subsequent `get_layout` returns `None`.
- Admin layout editor loads the current layout and saves changes.
- Pytest: `tests/test_stu_013_studio_layouts.py` — offline/moto, covers save/get/delete/list.

**Dependencies**
- STU-001 (`crm_studio_layouts` table, `CRM_STUDIO_ENABLED` flag).
- STU-011 (layout fields reference custom field keys).

---

### STU-014: Studio — relationship builder (custom inter-module relationships)
**Type:** Feature  **Priority:** P2  **Estimate:** 2d

**Description**

Build a relationship metadata registry allowing admins to define custom inter-module relationships (1:1, 1:N, N:M) between any two entity types, stored in DynamoDB and surfaced via generic relate/unrelate endpoints.

**Data model** on `crm_studio_modules` (table introduced in STU-001, reused here for relationship definitions):

- `pk = "MODULE#{from_entity}#{to_entity}"`, `sk = "REL#{rel_name}"` — relationship definition row: `rel_name` (unique slug within the from/to pair), `from_entity`, `to_entity`, `cardinality: "one_to_one"|"one_to_many"|"many_to_many"`, `label` (human-readable), `reverse_label` (label from `to_entity` perspective), `created_by_sub`, `created_at` (int), `is_active: bool`.

Relationship instance data (actual links between records) stored in `app_single_table` under `pk = "REL#{from_entity}#{from_id}#{rel_name}"`, `sk = "TO#{to_entity}#{to_id}"` with attributes `created_by_sub`, `created_at` (N).

**Service** (`app/services/crm_relationships.py`, new file):
- `define_relationship(actor_sub, from_entity, to_entity, rel_name, cardinality, label, reverse_label) -> dict` — writes definition row; emits audit.
- `delete_relationship_def(actor_sub, from_entity, to_entity, rel_name) -> None` — soft-deletes definition; blocks if any instances exist (count check).
- `list_relationship_defs(from_entity=None) -> list[dict]`.
- `relate(actor_sub, from_entity, from_id, to_entity, to_id, rel_name) -> None` — validates definition exists; enforces 1:1 cardinality by checking no existing link for the same `from_id` and `rel_name`; writes instance row to `app_single_table`.
- `unrelate(actor_sub, from_entity, from_id, to_entity, to_id, rel_name) -> None` — deletes instance row.
- `get_related(from_entity, from_id, rel_name) -> list[dict]` — queries `app_single_table` by PK prefix `REL#{from_entity}#{from_id}#{rel_name}`.

**Router** (`app/routers/crm_relationships.py`, new file, prefix `/ui/admin/studio/relationships`):
- `GET /` — list all relationship definitions (ADMIN/ROOT).
- `POST /` — define relationship (ROOT only).
- `DELETE /{from_entity}/{to_entity}/{rel_name}` — delete definition (ROOT only).
- `POST /instances` — `{from_entity, from_id, to_entity, to_id, rel_name}` — relate records (authenticated user, permission checked via STU-002 `require_crm_permission(from_entity, "update")`).
- `DELETE /instances/{from_entity}/{from_id}/{to_entity}/{to_id}/{rel_name}` — unrelate (same permission).
- `GET /instances/{from_entity}/{from_id}/{rel_name}` — get related records (authenticated user).

Register in `app/main.py` behind `if S.crm_studio_enabled`.

**Acceptance Criteria**
- `define_relationship("contact", "opportunity", "opportunities", "one_to_many", "Opportunities", "Contact")` writes to DDB.
- `relate("contact", "c1", "opportunity", "o1", "opportunities")` creates an instance; `get_related("contact", "c1", "opportunities")` returns `[{"to_entity": "opportunity", "to_id": "o1"}]`.
- `relate` for a 1:1 relationship on an already-related `from_id` returns 409.
- `delete_relationship_def` returns 409 when instances exist.
- Pytest: `tests/test_stu_014_studio_relationships.py` — offline/moto, covers define/delete/relate/unrelate/get, cardinality enforcement.

**Dependencies**
- STU-001 (`crm_studio_modules` table, `CRM_STUDIO_ENABLED` flag).
- STU-002 (`require_crm_permission` used on instance mutation endpoints).
- Existing `app_single_table` for instance rows (uses the same table as search history, chat polls, etc.).
