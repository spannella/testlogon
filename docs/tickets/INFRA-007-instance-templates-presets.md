# INFRA-007: Instance Templates & Presets

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 5-7 days  
**Dependencies**: INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher)

---

## 1. Overview & Motivation

### The Gap

INFRA-003 and INFRA-004 allow users to launch EC2 instances and K8s containers, but every launch starts from scratch. Users must select an instance type, AMI/image, configure startup scripts, set environment variables, and choose ports each time. There is no way to:

1. Save a fully configured launch configuration as a reusable template
2. Browse pre-built templates for common use cases (dev workspace, database, web server)
3. Share templates across the platform (system templates)
4. Clone and customize existing templates
5. Launch an instance/pod with a single click by selecting a template

### Why This Matters

1. **Reduce launch friction**: Instead of 5+ form fields, users select a template and click "Launch."
2. **Best practices**: System templates encode best-practice configurations (security groups, startup scripts, monitoring agents) that individual users might not know.
3. **Reproducibility**: Teams can share templates to ensure consistent environments.
4. **Onboarding**: New users browse a template gallery to understand what the platform offers.

### Architecture After This Change

```
Template System

  System Templates                    User Templates
  (PK="SYSTEM")                       (PK=user_sub)
  +-----------------+                 +-----------------+
  | dev-workspace   |                 | my-ml-env       |
  | database-server |                 | client-demo     |
  | web-server      |                 +-----------------+
  | ml-workspace    |                       |
  +-----------------+                       |
       |                                    |
       +---> TemplateBrowserPage (gallery view)
       |     - System templates: read-only, available to all
       |     - User templates: editable, user-private
       |
       +---> "Launch from Template" button
             POST /ui/remote/ec2/launch { template_id }
             or
             POST /ui/remote/k8s/launch { template_id }
             Pre-fills all launch params from template
```

---

## 2. Current State Analysis

### 2.1 EC2 Launch Parameters (INFRA-003)

`LaunchInstanceIn` accepts:
- `label`, `instance_type`, `ami_id`, `ssh_key_id`, `auto_terminate_after`, `startup_script`, `template_id`

The `template_id` field already exists (as an optional reference) but there is no template storage or resolution.

### 2.2 K8s Launch Parameters (INFRA-004)

`LaunchPodIn` accepts:
- `label`, `image`, `preset`, `ssh_key_id`, `ttl_seconds`, `env_vars`, `template_id`

Similarly, `template_id` is accepted but unresolved.

### 2.3 No Template Storage

No DDB table, service, or router exists for templates. The `template_id` field on launch requests is a no-op.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `instance_templates`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.instance_templates_table_name, "instance_templates"),
    "owner_sub",           # PK — "SYSTEM" for platform templates, user_sub for user templates
    "sk",                  # SK — TEMPLATE#{template_id}
    gsis=[
        {"index_name": "ByCategory", "partition_key": "category", "sort_key": "name_lower"},
        {"index_name": "ByCreatedAt", "partition_key": "owner_sub", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `owner_sub` | S (PK) | `"SYSTEM"` for platform templates, user_sub for custom |
| `sk` | S (SK) | `TEMPLATE#{template_id}` |
| `template_id` | S | UUID |
| `name` | S | Template name (e.g., "Dev Workspace") |
| `name_lower` | S | Lowercase name for GSI sort |
| `description` | S | Description of what this template provides |
| `category` | S | `compute`, `database`, `web`, `ml`, `custom` |
| `target` | S | `ec2` or `k8s` — which launcher this template targets |
| `instance_type` | S | EC2 instance type (for EC2 templates) |
| `ami_id` | S | AMI ID (for EC2 templates) |
| `k8s_image` | S | Container image (for K8s templates) |
| `k8s_preset` | S | Resource preset (for K8s templates) |
| `startup_script` | S | Cloud-init script or container entrypoint |
| `ports` | L[N] | Ports to expose/open in security groups |
| `env_vars` | M | Default environment variables |
| `tags` | L[S] | Tags applied to launched resources |
| `auto_terminate_after` | N | Default idle timeout (EC2) or TTL (K8s) |
| `icon` | S | Icon identifier for UI display |
| `is_system` | BOOL | Whether this is a platform-provided template |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `use_count` | N | Number of times template has been used to launch |

### 3.2 System Templates (Seeded)

Pre-configured templates seeded by `scripts/local-ddb-seed.py` or the service's `ensure_system_templates()` function:

```python
SYSTEM_TEMPLATES = [
    {
        "template_id": "sys-dev-workspace",
        "name": "Dev Workspace",
        "description": "Ubuntu 22.04 with VS Code Server, Python 3.12, Node 20, git, docker. SSH-enabled with tmux.",
        "category": "compute",
        "target": "ec2",
        "instance_type": "t3.small",
        "ami_id": "ami-ubuntu-2204",
        "startup_script": """#!/bin/bash
curl -fsSL https://code-server.dev/install.sh | sh
systemctl enable --now code-server@$USER
apt-get install -y python3.12 python3-pip nodejs npm tmux
""",
        "ports": [22, 8080],
        "env_vars": {"EDITOR": "code", "TERM": "xterm-256color"},
        "auto_terminate_after": 14400,
        "icon": "laptop",
    },
    {
        "template_id": "sys-database-server",
        "name": "Database Server",
        "description": "Ubuntu 22.04 with PostgreSQL 16, pgAdmin, automated backups. SSH-enabled.",
        "category": "database",
        "target": "ec2",
        "instance_type": "t3.medium",
        "ami_id": "ami-ubuntu-2204",
        "startup_script": """#!/bin/bash
apt-get install -y postgresql-16 postgresql-contrib
systemctl enable --now postgresql
su - postgres -c "createuser -s admin"
""",
        "ports": [22, 5432],
        "env_vars": {"PGDATA": "/var/lib/postgresql/16/main"},
        "auto_terminate_after": 28800,
        "icon": "database",
    },
    {
        "template_id": "sys-web-server",
        "name": "Web Server",
        "description": "Ubuntu 22.04 with nginx, Node 20, PM2 process manager. SSH-enabled.",
        "category": "web",
        "target": "ec2",
        "instance_type": "t3.small",
        "ami_id": "ami-ubuntu-2204",
        "startup_script": """#!/bin/bash
apt-get install -y nginx nodejs npm
npm install -g pm2
systemctl enable --now nginx
""",
        "ports": [22, 80, 443, 3000],
        "env_vars": {"NODE_ENV": "production"},
        "auto_terminate_after": 14400,
        "icon": "globe",
    },
    {
        "template_id": "sys-ml-workspace",
        "name": "ML Workspace",
        "description": "Ubuntu 22.04 with Python 3.12, PyTorch, Jupyter Lab, CUDA toolkit. SSH-enabled.",
        "category": "ml",
        "target": "ec2",
        "instance_type": "t3.large",
        "ami_id": "ami-ubuntu-2204",
        "startup_script": """#!/bin/bash
pip3 install torch torchvision jupyterlab numpy pandas scikit-learn matplotlib
jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --allow-root &
""",
        "ports": [22, 8888],
        "env_vars": {"JUPYTER_TOKEN": "auto"},
        "auto_terminate_after": 28800,
        "icon": "brain",
    },
    {
        "template_id": "sys-k8s-dev",
        "name": "Container Dev Environment",
        "description": "Lightweight Ubuntu container with Python, Node, git. Perfect for quick experiments.",
        "category": "compute",
        "target": "k8s",
        "k8s_image": "dev-workspace",
        "k8s_preset": "medium",
        "startup_script": "",
        "ports": [22],
        "env_vars": {"TERM": "xterm-256color"},
        "auto_terminate_after": 7200,
        "icon": "container",
    },
    {
        "template_id": "sys-k8s-alpine",
        "name": "Alpine Quick Shell",
        "description": "Minimal Alpine container with SSH. Starts in 2 seconds. 256MB memory.",
        "category": "compute",
        "target": "k8s",
        "k8s_image": "alpine-ssh",
        "k8s_preset": "small",
        "startup_script": "",
        "ports": [22],
        "env_vars": {},
        "auto_terminate_after": 3600,
        "icon": "terminal",
    },
]
```

### 3.3 Service Layer: `app/services/instance_templates.py`

New file (~250 lines):

```python
"""Instance template management — CRUD for launch templates + system template seeding."""

from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event  # see app/services/alerts.py:695


def ensure_system_templates() -> int:
    """Seed system templates if not already present. Called on app startup.
    Returns count of templates created."""

def create_template(
    user_sub: str,
    *,
    name: str,
    description: str,
    category: str,
    target: str,
    instance_type: str = "",
    ami_id: str = "",
    k8s_image: str = "",
    k8s_preset: str = "",
    startup_script: str = "",
    ports: list[int] | None = None,
    env_vars: dict | None = None,
    tags: list[str] | None = None,
    auto_terminate_after: int = 7200,
) -> Dict[str, Any]:
    """Create a user-owned template."""

def get_template(owner_sub: str, template_id: str) -> Dict[str, Any] | None:
    """Get a template by owner + ID. Pass "SYSTEM" for system templates."""

def list_templates(
    user_sub: str | None = None,
    *,
    category: str | None = None,
    target: str | None = None,
    include_system: bool = True,
) -> List[Dict[str, Any]]:
    """List templates. Combines user's templates + system templates."""

def update_template(user_sub: str, template_id: str, **updates) -> Dict[str, Any]:
    """Update a user-owned template. System templates cannot be modified."""

def delete_template(user_sub: str, template_id: str) -> bool:
    """Delete a user-owned template. System templates cannot be deleted."""

def clone_template(user_sub: str, template_id: str, *, new_name: str) -> Dict[str, Any]:
    """Clone a template (system or another user's) into user's own templates."""

def resolve_template(template_id: str, user_sub: str) -> Dict[str, Any] | None:
    """Resolve a template_id to launch params. Checks user templates first, then system."""

def increment_use_count(owner_sub: str, template_id: str) -> None:
    """Increment the use_count when a template is used to launch."""
```

### 3.4 Launch Integration

Modify `app/services/ec2_launcher.py` and `app/services/k8s_launcher.py` to resolve `template_id`:

```python
# In ec2_launcher.py::launch_instance()
if template_id:
    template = resolve_template(template_id, user_sub)
    if not template:
        raise ValueError(f"Template {template_id} not found")
    # Template provides defaults; explicit params override
    instance_type = instance_type or template.get("instance_type")
    ami_id = ami_id or template.get("ami_id")
    startup_script = startup_script or template.get("startup_script", "")
    auto_terminate_after = auto_terminate_after or template.get("auto_terminate_after", 7200)
    increment_use_count(template.get("owner_sub", "SYSTEM"), template_id)
```

### 3.5 API Router: `app/routers/instance_templates.py`

New file (~180 lines). Prefix: `/ui/remote/templates`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `POST` | `/ui/remote/templates` | `CreateTemplateIn` | `TemplateOut` (201) | Create user template |
| `GET` | `/ui/remote/templates` | query params | `TemplateListOut` | List templates |
| `GET` | `/ui/remote/templates/{id}` | — | `TemplateOut` | Get template detail |
| `PATCH` | `/ui/remote/templates/{id}` | `UpdateTemplateIn` | `TemplateOut` | Update user template |
| `DELETE` | `/ui/remote/templates/{id}` | — | `{"ok": true}` | Delete user template |
| `POST` | `/ui/remote/templates/{id}/clone` | `CloneTemplateIn` | `TemplateOut` | Clone template |

#### Pydantic Models

```python
class CreateTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)
    category: Literal["compute", "database", "web", "ml", "custom"] = "custom"
    target: Literal["ec2", "k8s"]
    instance_type: str = Field(default="", max_length=20)
    ami_id: str = Field(default="", max_length=50)
    k8s_image: str = Field(default="", max_length=100)
    k8s_preset: str = Field(default="", max_length=20)
    startup_script: str = Field(default="", max_length=16_384)
    ports: List[int] = Field(default_factory=list)
    env_vars: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    auto_terminate_after: int = Field(default=7200, ge=600, le=86400)

class TemplateOut(BaseModel):
    template_id: str
    name: str
    description: str
    category: str
    target: str
    instance_type: str = ""
    ami_id: str = ""
    k8s_image: str = ""
    k8s_preset: str = ""
    startup_script: str = ""
    ports: List[int] = []
    env_vars: Dict[str, str] = {}
    tags: List[str] = []
    auto_terminate_after: int = 7200
    icon: str = ""
    is_system: bool = False
    owner_sub: str = ""
    created_at: int = 0
    updated_at: int = 0
    use_count: int = 0

class TemplateListOut(BaseModel):
    templates: List[TemplateOut]
    count: int

class CloneTemplateIn(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=100)

class UpdateTemplateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    category: Optional[Literal["compute", "database", "web", "ml", "custom"]] = None
    instance_type: Optional[str] = None
    ami_id: Optional[str] = None
    k8s_image: Optional[str] = None
    k8s_preset: Optional[str] = None
    startup_script: Optional[str] = Field(default=None, max_length=16_384)
    ports: Optional[List[int]] = None
    env_vars: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    auto_terminate_after: Optional[int] = Field(default=None, ge=600, le=86400)
```

### 3.6 Frontend Components

#### TemplateBrowserPage (`frontend/src/pages/remote/TemplateBrowserPage.tsx`)

New page (~350 lines):

- **Header**: "Templates" with "Create Template" button
- **Category tabs**: All, Compute, Database, Web, ML, Custom
- **Template gallery**: Grid of template cards, each showing:
  - Icon (from lucide-react based on `icon` field)
  - Name and description
  - Target badge (EC2 / K8s)
  - Instance type or preset
  - "Launch" button → opens launch dialog with pre-filled params
  - "Clone" button → creates user copy
  - System templates: blue "System" badge, no edit/delete actions
  - User templates: edit/delete actions in dropdown menu

#### TemplateEditorDialog (`frontend/src/pages/remote/TemplateEditorDialog.tsx`)

Dialog (~200 lines):

- Form matching `CreateTemplateIn` fields
- Target toggle (EC2 / K8s) — shows relevant fields for each target
- Startup script with syntax-highlighted textarea
- Environment variables: key-value pair editor with add/remove rows
- Ports: comma-separated number input

#### Route & Navigation

```tsx
<Route path="/remote/templates" element={<TemplateBrowserPage />} />
```

Sidebar: "Templates" with `LayoutTemplate` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend Template Service (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `instance_templates_table_name` |
| `app/core/tables.py` | Add `instance_templates` table handle |
| `scripts/local-ddb-init.py` | Add `instance_templates` TableDef with 2 GSIs |
| `app/services/instance_templates.py` | New file: CRUD + system template seeding + clone + resolve |
| `app/models.py` | Add template Pydantic models |
| `app/routers/instance_templates.py` | New file: 6 endpoints |
| `app/main.py` | Register router + call `ensure_system_templates()` on startup |

### Phase 2: Launch Integration (1 day)

| File | Change |
|------|--------|
| `app/services/ec2_launcher.py` | Resolve `template_id` in `launch_instance()` |
| `app/services/k8s_launcher.py` | Resolve `template_id` in `launch_pod()` |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add template types |
| `frontend/src/api/endpoints/templates.ts` | New file: API wrappers |
| `frontend/src/pages/remote/TemplateBrowserPage.tsx` | New file: gallery page |
| `frontend/src/pages/remote/TemplateEditorDialog.tsx` | New file: create/edit dialog |
| `frontend/src/App.tsx` | Add `/remote/templates` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Templates" nav item |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/instance-templates.spec.ts` | New file: ~15 tests in 3 sections |

---

## 5. E2E Test Plan (`frontend/e2e/instance-templates.spec.ts`)

**Section 264: Template CRUD API (5 tests)**

1. `System templates are seeded on startup` — GET `/templates`. Verify at least 4 system templates with `is_system: true`.
2. `Alice creates a custom EC2 template` — POST with name, target=ec2, instance_type, ami_id, startup_script. Verify 201 with `is_system: false`, `owner_sub` = Alice's sub.
3. `Alice updates her template` — PATCH with new description. Verify updated.
4. `Alice cannot modify system template` — PATCH system template → 403.
5. `Alice deletes her template` — DELETE. Verify 200. GET → 404.

**Section 265: Template Clone & Launch API (5 tests)**

6. `Clone system template` — POST `/templates/sys-dev-workspace/clone` with `new_name`. Verify clone has `is_system: false`, same params as original.
7. `Launch EC2 from template` — POST `/ui/remote/ec2/launch` with `template_id`. Verify instance launched with template's instance_type and ami_id.
8. `Launch K8s from template` — POST `/ui/remote/k8s/launch` with `template_id: "sys-k8s-dev"`. Verify pod with template's image and preset.
9. `Template use_count increments on launch` — Launch from template, GET template. Verify `use_count: 1`.
10. `Explicit params override template defaults` — Launch with `template_id` AND `instance_type: "t3.large"`. Verify instance uses `t3.large` (overrides template's `t3.small`).

**Section 266: Templates UI (5 tests)**

11. `TemplateBrowserPage shows system templates` — Navigate to `/remote/templates`. Verify system template cards visible with names and badges.
12. `Category tabs filter templates` — Click "Database" tab. Verify only database templates shown.
13. `Create template dialog works` — Click "Create Template", fill form, submit. Verify new card in gallery.
14. `Clone button creates user copy` — Click "Clone" on system template. Verify new card with "(Clone)" suffix.
15. `Launch button opens launcher with pre-filled params` — Click "Launch" on template. Verify launch dialog opens with template's instance_type and AMI pre-selected.

---

## 6. Security Considerations

### 6.1 System Template Protection

System templates (PK="SYSTEM") cannot be modified or deleted via the API. Only `ensure_system_templates()` creates them.

### 6.2 User Template Isolation

User templates use `user_sub` as the DDB partition key. Users can only CRUD their own templates. The `list_templates` endpoint combines system + user templates in a single response.

### 6.3 Startup Script Validation

Startup scripts are stored as plaintext strings with a 16KB limit. They are passed to EC2 user-data or container entrypoints. No server-side execution validation is performed — the script runs in the user's own instance/container.

---

## 7. Acceptance Criteria

1. System templates are seeded on startup with at least 4 EC2 and 2 K8s templates.
2. Users can create, update, delete, and clone templates.
3. System templates cannot be modified or deleted.
4. Launching with `template_id` pre-fills all launch parameters from the template.
5. Explicit launch parameters override template defaults.
6. Template use count increments on each launch.
7. Template gallery shows system + user templates with category filtering.
8. Clone creates a user-owned copy of any template.
9. All template mutations produce audit events.
10. User templates are isolated per user; system templates are visible to all.

---

## 8. Architecture & Data Flow

```
  User clicks "Launch from Template"
       │
       ▼
  Frontend: POST /ui/remote/ec2/launch { template_id, overrides? }
       │
       ▼
  Router: launch_instance()
       │
       ├── resolve_template(template_id, user_sub)
       │     │
       │     ├── Check user templates (PK=user_sub, SK=TEMPLATE#{id})
       │     │     └── Found? → return template
       │     └── Check system templates (PK=SYSTEM, SK=TEMPLATE#{id})
       │           └── Found? → return template
       │
       ├── Merge: template defaults ← explicit overrides
       │     instance_type = override or template.instance_type
       │     ami_id        = override or template.ami_id
       │     startup_script = override or template.startup_script
       │
       ├── increment_use_count(owner_sub, template_id)
       │     └── DDB UpdateItem: SET use_count = use_count + 1
       │
       ├── ec2_launcher.launch_instance(merged_params)
       │     └── Creates instance in EC2 / mock store
       │
       └── audit_event("compute.launch_from_template", ...)
             └── Records template_id, user_sub, merged params
```

---

## 9. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get template by owner + ID | Main table | `owner_sub` | `TEMPLATE#{template_id}` | GetItem | Pass `"SYSTEM"` for system templates |
| 2 | List user templates (by creation date) | GSI `ByCreatedAt` | `owner_sub` | `created_at` (N) | Query | ScanIndexForward=False for newest first |
| 3 | List system templates | GSI `ByCreatedAt` | `"SYSTEM"` | `created_at` (N) | Query | Returns all platform templates |
| 4 | Browse by category | GSI `ByCategory` | `category` | `name_lower` | Query | Alphabetical listing within category |
| 5 | Filter by target (ec2/k8s) | Main table | `owner_sub` | begins_with `TEMPLATE#` | Query + FilterExpression `target = :t` | FilterExpression on non-key attr |
| 6 | Increment use count | Main table | `owner_sub` | `TEMPLATE#{template_id}` | UpdateItem `ADD use_count :one` | Atomic counter increment |
| 7 | Delete user template | Main table | `owner_sub` | `TEMPLATE#{template_id}` | DeleteItem with ConditionExpression `is_system = :false` | Prevents deletion of system templates |

---

## 10. API Request/Response Examples

**POST /ui/remote/templates** (Create user template)

```bash
curl -X POST http://localhost:8000/ui/remote/templates \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{
    "name": "My ML Environment",
    "description": "Custom ML workspace with GPU support",
    "category": "ml",
    "target": "ec2",
    "instance_type": "t3.xlarge",
    "ami_id": "ami-ubuntu-2204",
    "startup_script": "#!/bin/bash\npip3 install torch",
    "ports": [22, 8888],
    "env_vars": {"JUPYTER_TOKEN": "mytoken"},
    "auto_terminate_after": 14400
  }'
```

Response (201):
```json
{
  "template_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "My ML Environment",
  "description": "Custom ML workspace with GPU support",
  "category": "ml",
  "target": "ec2",
  "instance_type": "t3.xlarge",
  "ami_id": "ami-ubuntu-2204",
  "startup_script": "#!/bin/bash\npip3 install torch",
  "ports": [22, 8888],
  "env_vars": {"JUPYTER_TOKEN": "mytoken"},
  "tags": [],
  "auto_terminate_after": 14400,
  "icon": "",
  "is_system": false,
  "owner_sub": "alice_sub_123",
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "use_count": 0
}
```

**GET /ui/remote/templates?category=compute&target=ec2** (List templates)

Response (200):
```json
{
  "templates": [
    {
      "template_id": "sys-dev-workspace",
      "name": "Dev Workspace",
      "description": "Ubuntu 22.04 with VS Code Server...",
      "category": "compute",
      "target": "ec2",
      "instance_type": "t3.small",
      "is_system": true,
      "use_count": 42,
      "created_at": 1748000000
    }
  ],
  "count": 1
}
```

**POST /ui/remote/templates/{id}/clone** (Clone template)

```json
// Request
{ "new_name": "My Dev Workspace (Customized)" }

// Response (201)
{
  "template_id": "new-uuid-here",
  "name": "My Dev Workspace (Customized)",
  "is_system": false,
  "owner_sub": "alice_sub_123",
  "instance_type": "t3.small",
  "ami_id": "ami-ubuntu-2204"
}
```

**PATCH /ui/remote/templates/{id}** (Update template)

```json
// Request
{ "description": "Updated description", "instance_type": "t3.medium" }

// Response (200)
{
  "template_id": "a1b2c3d4...",
  "description": "Updated description",
  "instance_type": "t3.medium",
  "updated_at": 1748521000
}
```

**DELETE /ui/remote/templates/{id}**

Response (200): `{ "ok": true }`

Attempting to delete a system template:
Response (403): `{ "detail": "Cannot modify system template" }`

---

## 11. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Template not found | 404 | `template_not_found` | "Template not found" | Verify template ID |
| Modify system template | 403 | `system_template_immutable` | "Cannot modify system template" | Clone instead of editing |
| Delete system template | 403 | `system_template_immutable` | "Cannot delete system template" | N/A |
| Delete other user's template | 403 | `forbidden` | "You do not own this template" | Use your own templates |
| Name exceeds 100 chars | 422 | `validation_error` | "Name must be 100 characters or fewer" | Shorten name |
| Startup script exceeds 16KB | 422 | `validation_error` | "Startup script exceeds 16KB limit" | Reduce script size |
| auto_terminate < 600s | 422 | `validation_error` | "Auto-terminate must be at least 10 minutes" | Increase value |
| auto_terminate > 86400s | 422 | `validation_error` | "Auto-terminate must be at most 24 hours" | Decrease value |
| Clone non-existent template | 404 | `template_not_found` | "Source template not found" | Verify source template ID |
| Launch with invalid template_id | 404 | `template_not_found` | "Template not found" | Use a valid template |
| Unauthenticated request | 401 | `unauthorized` | "Authentication required" | Log in first |

---

## 12. Frontend Component Tree

```
TemplateBrowserPage
├── PageHeader
│   ├── Title ("Templates")
│   └── CreateTemplateButton
│       └── onClick → opens TemplateEditorDialog
├── CategoryTabs
│   ├── Tab("All")
│   ├── Tab("Compute")
│   ├── Tab("Database")
│   ├── Tab("Web")
│   ├── Tab("ML")
│   └── Tab("Custom")
├── TemplateGallery (grid layout)
│   └── TemplateCard[] (filtered by active tab + target)
│       ├── IconBadge (lucide icon based on template.icon)
│       ├── CardTitle (template.name)
│       ├── CardDescription (template.description)
│       ├── TargetBadge ("EC2" | "K8s")
│       ├── SystemBadge (blue "System" if is_system)
│       ├── InstanceTypeLabel (e.g. "t3.small")
│       ├── UseCountLabel ("Used 42 times")
│       ├── LaunchButton → opens launch dialog with pre-filled params
│       ├── CloneButton → POST /clone, add new card
│       └── DropdownMenu (user templates only)
│           ├── EditItem → opens TemplateEditorDialog(edit mode)
│           └── DeleteItem → confirm dialog → DELETE
└── TemplateEditorDialog (create/edit mode)
    ├── NameInput
    ├── DescriptionTextarea
    ├── CategorySelect
    ├── TargetToggle (EC2 / K8s)
    ├── EC2Fields (shown when target=ec2)
    │   ├── InstanceTypeSelect
    │   └── AmiIdInput
    ├── K8sFields (shown when target=k8s)
    │   ├── ImageInput
    │   └── PresetSelect
    ├── StartupScriptEditor (syntax-highlighted textarea)
    ├── EnvVarsEditor (key-value pair rows)
    ├── PortsInput (comma-separated)
    ├── AutoTerminateSlider (10min - 24h)
    └── SubmitButton
```

**Props interfaces:**

```typescript
interface TemplateCardProps {
  template: TemplateOut;
  onLaunch: (templateId: string) => void;
  onClone: (templateId: string) => void;
  onEdit?: (templateId: string) => void;
  onDelete?: (templateId: string) => void;
}

interface TemplateEditorDialogProps {
  open: boolean;
  onClose: () => void;
  template?: TemplateOut;  // undefined = create mode, present = edit mode
  onSaved: (template: TemplateOut) => void;
}

interface CategoryTabsProps {
  activeCategory: string;
  onChange: (category: string) => void;
  counts: Record<string, number>;
}

interface TemplateGalleryProps {
  templates: TemplateOut[];
  onLaunch: (templateId: string) => void;
  onClone: (templateId: string) => void;
}
```

---

## 13. Observability

### 13.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `template_created_total` | Counter | `target` (ec2/k8s), `category` | Templates created by users |
| `template_cloned_total` | Counter | `source` (system/user) | Templates cloned |
| `template_launch_total` | Counter | `template_id`, `target` | Launches via template |
| `template_seeded_total` | Counter | | System templates seeded on startup |
| `template_deleted_total` | Counter | | User templates deleted |

### 13.2 Structured Logging

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `template.created` | INFO | `template_id`, `user_sub`, `target`, `category` | User creates template |
| `template.updated` | INFO | `template_id`, `user_sub`, `updated_fields` | User updates template |
| `template.deleted` | INFO | `template_id`, `user_sub` | User deletes template |
| `template.cloned` | INFO | `source_id`, `new_id`, `user_sub` | User clones template |
| `template.launched` | INFO | `template_id`, `user_sub`, `resource_id`, `overrides` | Instance launched from template |
| `template.system_seed` | INFO | `count`, `already_existed` | System templates seeded on startup |

### 13.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| System template seeding failed | `ensure_system_templates()` raises exception | Critical | Check DDB connectivity and table existence |
| High template launch failure rate | > 10% of template launches fail in 1 hour | Warning | Check EC2/K8s launcher health |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Operation | Target P95 | Notes |
|-----------|-----------|-------|
| List templates | < 200ms | Two parallel DDB queries (user + system), merge in memory |
| Get template | < 50ms | Single DDB GetItem |
| Create template | < 100ms | Single DDB PutItem |
| Clone template | < 150ms | GetItem + PutItem |
| Resolve template for launch | < 100ms | GetItem (user), fallback GetItem (system) |

### 14.2 Caching Strategy

- System templates change only on deployment. Cache in-memory after first load with TTL of 1 hour.
- User templates are mutable. No client-side caching beyond React Query's stale-while-revalidate (30s staleTime).
- Template gallery page uses `useQuery` with `staleTime: 30_000` and `refetchOnWindowFocus: true`.

### 14.3 Pagination

- `list_templates` returns all user + system templates in a single response. Expected volume: < 100 templates per user (6 system + ~10-50 user).
- No cursor-based pagination needed at current scale. If template count exceeds 200, add `Limit` parameter with cursor support.

---

## 15. Rollout Plan

### 15.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `instance_templates_enabled` | `INSTANCE_TEMPLATES_ENABLED` | `true` | Master switch for template system |
| `template_launch_enabled` | `TEMPLATE_LAUNCH_ENABLED` | `true` | Allow launching from templates |
| `system_templates_seeded` | `SYSTEM_TEMPLATES_SEEDED` | `false` | Set to `true` after initial seed |

### 15.2 Phased Rollout

**Phase 1 (Day 1-2)**: Backend service + DDB table + system template seeding. Feature flag off in production.

**Phase 2 (Day 3)**: API router with all 6 endpoints. Internal testing with dev accounts.

**Phase 3 (Day 4-5)**: Frontend gallery page, editor dialog, route and sidebar. Enable for 10% of users.

**Phase 4 (Day 6-7)**: E2E tests, launch integration, ramp to 100%.

### 15.3 Rollback

1. Set `INSTANCE_TEMPLATES_ENABLED=false` -- API returns 400, frontend hides template nav.
2. System templates remain in DDB but are inert.
3. Launch flow falls back to manual param entry (existing behavior).

---

## 16. Expanded E2E Tests

### Section 264: Template CRUD API (5 tests) -- existing

1-5. (As defined above in Section 5)

### Section 265: Template Clone & Launch API (5 tests) -- existing

6-10. (As defined above in Section 5)

### Section 266: Templates UI (5 tests) -- existing

11-15. (As defined above in Section 5)

### Section 267: Template Validation & Edge Cases (8 tests)

16. `Name at max length (100 chars) succeeds` -- POST with 100-char name. Verify 201.
17. `Name exceeding 100 chars rejected` -- POST with 101-char name. Verify 422.
18. `Startup script at 16KB limit succeeds` -- POST with 16384-byte script. Verify 201.
19. `Startup script exceeding 16KB rejected` -- POST with 16385-byte script. Verify 422.
20. `auto_terminate_after below 600 rejected` -- POST with 500. Verify 422.
21. `auto_terminate_after above 86400 rejected` -- POST with 90000. Verify 422.
22. `Empty env_vars accepted` -- POST with `env_vars: {}`. Verify 201.
23. `Clone preserves all template fields` -- Clone system template. Verify clone has same `instance_type`, `ami_id`, `ports`, `env_vars`, `startup_script`.

### Section 268: System Template Protection & Multi-User Isolation (7 tests)

24. `System templates seeded count >= 6` -- GET templates. Verify at least 6 system templates.
25. `User cannot see other user's templates` -- Alice creates template. Bob lists templates. Verify Bob sees only system templates (not Alice's).
26. `System template cannot be updated (PATCH returns 403)` -- PATCH system template name. Verify 403.
27. `System template cannot be deleted (DELETE returns 403)` -- DELETE system template. Verify 403.
28. `User template is returned with owner_sub set` -- Create and GET. Verify `owner_sub` equals Alice's sub.
29. `Clone of user template by same user succeeds` -- Alice creates + clones own template. Verify clone `is_system: false`.
30. `Launch from system template increments use_count` -- Launch from sys-dev-workspace. GET template. Verify `use_count >= 1`.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `browser_ssh_terminal_enabled` setting | `app/core/settings.py` | 114 | VERIFIED |
| SSH terminal router registration | `app/main.py` | 404 | VERIFIED: `app.include_router(browser_ssh_terminal_router)` |
| `ParamikoSshBridge` class | `app/routers/browser_ssh_terminal.py` | 60 | VERIFIED (1125 lines total) |
| VNC session timeout policy | `app/services/vnc_sessions.py` | 143 | VERIFIED |
| DDB table init script | `scripts/local-ddb-init.py` | exists | VERIFIED (1360 lines) |

### Not Yet Implemented (requires new code)

<!-- NOTE: INFRA-003 (EC2 Launcher) and INFRA-004 (K8s Launcher) are listed as dependencies but their implementation files do not exist yet. The following are all new: -->

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `LaunchInstanceIn` model (INFRA-003) | `app/models.py` or router | NOT FOUND -- new implementation required |
| `LaunchPodIn` model (INFRA-004) | `app/models.py` or router | NOT FOUND -- new implementation required |
| `app/services/ec2_launcher.py` | `app/services/` | NOT FOUND -- new implementation required |
| `app/services/k8s_launcher.py` | `app/services/` | NOT FOUND -- new implementation required |
| `app/services/remote_hosts.py` | `app/services/` | NOT FOUND -- new implementation required |
| `instance_templates` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| `app/routers/instance_templates.py` | `app/routers/` | NOT FOUND -- new router required |
| `app/services/instance_templates.py` | `app/services/` | NOT FOUND -- new service required |
| Instance templates router registration | `app/main.py` | NOT FOUND -- needs `app.include_router()` |
| Template settings (feature flags) | `app/core/settings.py` | NOT FOUND -- new settings required |
| `frontend/src/pages/remote/TemplateBrowserPage.tsx` | `frontend/src/pages/remote/` | NOT FOUND -- new page required |
| `frontend/src/api/endpoints/instance-templates.ts` | `frontend/src/api/endpoints/` | NOT FOUND -- new endpoint file required |
| `/remote/templates` route | `frontend/src/App.tsx` | NOT FOUND -- new route required |

---

## Testing Strategy

### Unit Tests (`tests/test_instance_templates.py`)

**Mock setup**: Use `moto` to mock DynamoDB. Create the `instance_templates` table in a pytest fixture with the same schema and GSIs defined in `scripts/local-ddb-init.py`. Patch `app.core.tables.T.instance_templates` to point at the moto table.

**Test functions**:

| Function | What it validates |
|----------|-------------------|
| `test_ensure_system_templates_seeds_all` | `ensure_system_templates()` creates all 6 system templates (4 EC2 + 2 K8s). Calling twice is idempotent (no duplicates). |
| `test_create_template_stores_item` | `create_template(user_sub, name=..., target="ec2", ...)` writes item with correct PK=user_sub, SK=`TEMPLATE#{id}`, `is_system=False`, `use_count=0`. |
| `test_create_template_sets_name_lower` | Verify `name_lower` is set to `name.lower()` for GSI sort. |
| `test_get_template_returns_none_for_missing` | `get_template("user", "nonexistent")` returns `None`. |
| `test_list_templates_combines_system_and_user` | After seeding system + creating 2 user templates, `list_templates(user_sub, include_system=True)` returns 8 items. |
| `test_list_templates_filters_by_category` | `list_templates(user_sub, category="database")` returns only database templates. |
| `test_list_templates_filters_by_target` | `list_templates(user_sub, target="k8s")` returns only K8s templates. |
| `test_update_template_modifies_fields` | Update `description` and `instance_type`. Verify `updated_at` changes. |
| `test_update_system_template_raises` | Attempting to update a system template raises `ValueError` or returns 403-equivalent. |
| `test_delete_template_removes_item` | Delete user template, verify `get_template` returns `None`. |
| `test_delete_system_template_raises` | Attempting to delete system template raises error / is blocked by ConditionExpression. |
| `test_clone_template_copies_all_fields` | Clone system template. Verify new `template_id`, `owner_sub=user_sub`, `is_system=False`, all config fields match source. |
| `test_clone_preserves_startup_script_and_env` | Clone template with multi-line startup_script and env_vars dict. Verify exact match. |
| `test_resolve_template_checks_user_first` | Create user template with same name as system. `resolve_template(id, user_sub)` returns user's version. |
| `test_resolve_template_falls_back_to_system` | `resolve_template("sys-dev-workspace", user_sub)` returns system template when user has none with that ID. |
| `test_increment_use_count_atomic` | Call `increment_use_count` 3 times. Verify `use_count == 3`. |
| `test_auto_terminate_after_bounds` | Verify service rejects values < 600 or > 86400 at the model validation layer. |

### Integration Tests (`tests/test_instance_templates_integration.py`)

**Setup**: Full FastAPI test client with moto-backed DynamoDB. Seed system templates on startup.

| Test | What it validates |
|------|-------------------|
| `test_create_and_list_round_trip` | POST create template via API, GET list, verify template appears with correct fields. |
| `test_clone_via_api_and_launch` | POST clone system template, POST launch EC2 with cloned template_id. Verify launch params match template. |
| `test_category_filter_via_api` | GET `/ui/remote/templates?category=ml`. Verify only ML templates returned. |
| `test_csrf_required_for_mutations` | POST/PATCH/DELETE without `x-csrf-token` header returns 403. |
| `test_unauthenticated_returns_401` | Requests without session cookie return 401. |
| `test_system_template_protection_via_api` | PATCH and DELETE system templates return 403. |
| `test_user_isolation` | Alice creates template. Bob's GET list does not include it. |
| `test_launch_with_template_overrides` | Launch with `template_id` + explicit `instance_type`. Verify explicit value wins. |
| `test_use_count_increments_on_launch` | Launch from template, GET template, verify `use_count` incremented. |

### E2E Tests (`frontend/e2e/instance-templates.spec.ts`)

**Auth pattern**: `injectAuth(page, "alice")` for user operations, `injectAuth(page, "root")` for admin verification. CSRF via `sessions["alice"].csrf_token` on all POST/PATCH/DELETE.

**Section 264: Template CRUD API (5 tests)**
- Setup: `injectAuth(page, "alice")`.
- Test 1: `GET /ui/remote/templates` — assert `resp.ok`, `body.templates.length >= 4`, every system template has `is_system: true`.
- Test 2: `POST /ui/remote/templates` with `{ name: "E2E Custom", target: "ec2", ... }` — assert status 201, `body.is_system === false`, `body.owner_sub` is Alice's sub.
- Test 3: `PATCH /ui/remote/templates/${id}` with `{ description: "updated" }` — assert 200, `body.description === "updated"`.
- Test 4: `PATCH /ui/remote/templates/sys-dev-workspace` — assert 403 with `detail` containing "system template".
- Test 5: `DELETE /ui/remote/templates/${id}` — assert 200. `GET /ui/remote/templates/${id}` — assert 404.

**Section 265: Template Clone & Launch API (5 tests)**
- Test 6: `POST /ui/remote/templates/sys-dev-workspace/clone` — assert 201, `body.is_system === false`, `body.instance_type === "t3.small"`.
- Test 7: `POST /ui/remote/ec2/launch` with `template_id` — assert 200/201, instance launched.
- Test 8: `POST /ui/remote/k8s/launch` with `template_id: "sys-k8s-dev"` — assert 200/201, pod launched.
- Test 9: After launch, `GET /ui/remote/templates/sys-dev-workspace` — assert `use_count >= 1`.
- Test 10: `POST /ui/remote/ec2/launch` with `template_id` AND `instance_type: "t3.large"` — assert instance uses `t3.large`.

**Section 266: Templates UI (5 tests)**
- Setup: navigate to `/remote/templates`.
- Test 11: `page.getByRole("heading", { name: "Templates" })` visible. System template cards: `page.getByText("Dev Workspace")`, `page.getByText("Database Server")`.
- Test 12: Click `page.getByRole("tab", { name: "Database" })`. Verify `page.getByText("Database Server").toBeVisible()`, `page.getByText("Dev Workspace").not.toBeVisible()`.
- Test 13: Click `page.getByRole("button", { name: /create template/i })`. Fill form. Submit. Verify new card: `page.getByText("Test Template")`.
- Test 14: Click Clone button on system template card. Verify new card with cloned name.
- Test 15: Click Launch on template. Verify launch dialog opens with `page.getByDisplayValue("t3.small")` or equivalent pre-filled value.

**Section 267: Validation & Edge Cases (8 tests)**
- Tests 16-23: Boundary tests for name length (100/101), script size (16384/16385 bytes), auto_terminate bounds (600/500, 86400/90000), empty env_vars, clone field preservation.

**Section 268: System Template Protection & Multi-User Isolation (7 tests)**
- Tests 24-30: System count >= 6, Bob cannot see Alice's templates, PATCH/DELETE system returns 403, owner_sub correct, self-clone works, launch increments use_count.

**Negative tests** (embedded in sections above):
- 401: unauthenticated request (no cookies).
- 403: modify/delete system template; access other user's template.
- 404: GET/DELETE non-existent template; launch with invalid template_id.
- 422: validation failures (name too long, script too large, invalid auto_terminate).

**Teardown**: Delete user-created templates in `afterAll` to avoid polluting subsequent runs.

**Retry safety**: Each test run uses unique template names with `Date.now()` suffix. Clone tests use unique `new_name`. System templates are idempotent (seeded once, never deleted by tests).

### Test Data Requirements

| Requirement | Details |
|-------------|---------|
| DynamoDB table | `instance_templates` with PK `owner_sub` (S), SK `sk` (S), GSIs `ByCategory` and `ByCreatedAt` (sort key `created_at` type N) |
| System templates | Seeded by `ensure_system_templates()` on backend startup (6 templates) |
| Test users | Alice (USER) for CRUD, Bob (USER) for isolation tests, Root (ROOT) for admin verification |
| Session seeding | `e2e_session_setup.py` + `e2e_admin_session_setup.py` |
| INFRA-003/004 tables | EC2 instances and K8s pods tables must exist for launch integration tests |

### CI / Pipeline

| Concern | Approach |
|---------|----------|
| Feature flag | Set `INSTANCE_TEMPLATES_ENABLED=true` in CI `.env.local` |
| Serial execution | Tests must run single-worker (`workers: 1`) — shared DDB state |
| Retry safety | Unique names per run; `afterAll` cleanup of user templates |
| Dependencies | INFRA-003 and INFRA-004 tables/services must be deployed first |
| Startup | Backend `ensure_system_templates()` runs on startup — no separate seed script needed |

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|--------|---------------|--------|--------------|
| INFRA-003 (EC2 Launcher) | `LaunchInstanceIn` model, `ec2_launcher.py` service, EC2 DDB table, launch endpoint | **Not yet implemented** | Yes — template CRUD can be built independently; launch integration wired after INFRA-003 lands |
| INFRA-004 (K8s Launcher) | `LaunchPodIn` model, `k8s_launcher.py` service, K8s pods DDB table, launch endpoint | **Not yet implemented** | Yes — same as above; K8s launch integration wired after INFRA-004 lands |

### Depended On By

| Ticket | What It Needs From INFRA-007 |
|--------|------------------------------|
| INFRA-003 (EC2 Launcher) | References `template_id` field in `LaunchInstanceIn` — expects template resolution |
| INFRA-004 (K8s Launcher) | References `template_id` field in `LaunchPodIn` — expects template resolution |

> No other tickets in the current backlog explicitly depend on INFRA-007.

### Merge Strategy

**Feature-flag-gated + parallel-safe**

- The `instance_templates` DDB table and service are entirely new — no conflicts with existing code.
- Template CRUD endpoints live under a new router (`/ui/remote/templates`) with no overlap to existing routes.
- Launch integration (wiring `resolve_template` into `ec2_launcher.py` / `k8s_launcher.py`) is the only merge-order-sensitive piece — these files must exist first (INFRA-003/004).
- Feature flag `INSTANCE_TEMPLATES_ENABLED` gates the router, so the feature can be merged to main even before INFRA-003/004 if needed.

### Merge Checklist

- [ ] `scripts/local-ddb-init.py` — `instance_templates` table definition added with correct `attr_types={"created_at": "N"}`
- [ ] `app/core/settings.py` — `instance_templates_table_name` setting added
- [ ] `app/core/tables.py` — `instance_templates` table handle added
- [ ] `app/services/instance_templates.py` — all 8 service functions implemented
- [ ] `app/routers/instance_templates.py` — 6 endpoints registered
- [ ] `app/main.py` — router registered + `ensure_system_templates()` called in startup event
- [ ] `app/models.py` — `CreateTemplateIn`, `TemplateOut`, `TemplateListOut`, `CloneTemplateIn`, `UpdateTemplateIn` added
- [ ] `app/services/ec2_launcher.py` — `resolve_template` + `increment_use_count` wired (after INFRA-003)
- [ ] `app/services/k8s_launcher.py` — `resolve_template` + `increment_use_count` wired (after INFRA-004)
- [ ] `frontend/src/api/types.ts` — template TypeScript types added
- [ ] `frontend/src/api/endpoints/instance-templates.ts` — API wrappers
- [ ] `frontend/src/pages/remote/TemplateBrowserPage.tsx` — gallery page
- [ ] `frontend/src/pages/remote/TemplateEditorDialog.tsx` — editor dialog
- [ ] `frontend/src/App.tsx` — `/remote/templates` route
- [ ] `frontend/src/components/layout/Sidebar.tsx` — Templates nav item
- [ ] Feature flag `INSTANCE_TEMPLATES_ENABLED` in `.env.local.example`
- [ ] E2E tests pass: `npx playwright test e2e/instance-templates.spec.ts`
- [ ] Unit tests pass: `pytest tests/test_instance_templates.py`
- [ ] System templates seed correctly on fresh startup (`just restart && just status`)
