# INFRA-007: Instance Templates & Presets

**Status**: Proposed  
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
from app.services.alerts import audit_event


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
