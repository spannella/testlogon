"""Instance template management (INFRA-007).

CRUD for reusable launch templates + system template seeding, clone, and
"materialize template into a launch payload" for one-click launch.

Table: instance_templates
  PK owner_sub  — "SYSTEM" for platform templates, user_sub for user templates
  SK sk         — TEMPLATE#{template_id}
  GSIs: ByCategory (category / name_lower), ByCreatedAt (owner_sub / created_at)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

SYSTEM_OWNER = "SYSTEM"

# Config fields copied verbatim on clone / materialize.
_CONFIG_FIELDS = (
    "instance_type",
    "ami_id",
    "k8s_image",
    "k8s_preset",
    "startup_script",
    "ports",
    "env_vars",
    "tags",
    "auto_terminate_after",
)

# Fields a user may update via PATCH.
_UPDATABLE_FIELDS = (
    "name",
    "description",
    "category",
    "instance_type",
    "ami_id",
    "k8s_image",
    "k8s_preset",
    "startup_script",
    "ports",
    "env_vars",
    "tags",
    "auto_terminate_after",
)


class TemplateNotFound(Exception):
    pass


class SystemTemplateImmutable(Exception):
    pass


# ---------------------------------------------------------------------------
# System templates
# ---------------------------------------------------------------------------

SYSTEM_TEMPLATES: List[Dict[str, Any]] = [
    {
        "template_id": "sys-dev-workspace",
        "name": "Dev Workspace",
        "description": "Ubuntu 22.04 with VS Code Server, Python 3.12, Node 20, git, docker. SSH-enabled with tmux.",
        "category": "compute",
        "target": "ec2",
        "instance_type": "t3.small",
        "ami_id": "ami-ubuntu-2204",
        "startup_script": (
            "#!/bin/bash\n"
            "curl -fsSL https://code-server.dev/install.sh | sh\n"
            "systemctl enable --now code-server@$USER\n"
            "apt-get install -y python3.12 python3-pip nodejs npm tmux\n"
        ),
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
        "startup_script": (
            "#!/bin/bash\n"
            "apt-get install -y postgresql-16 postgresql-contrib\n"
            "systemctl enable --now postgresql\n"
            'su - postgres -c "createuser -s admin"\n'
        ),
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
        "startup_script": (
            "#!/bin/bash\n"
            "apt-get install -y nginx nodejs npm\n"
            "npm install -g pm2\n"
            "systemctl enable --now nginx\n"
        ),
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
        "startup_script": (
            "#!/bin/bash\n"
            "pip3 install torch torchvision jupyterlab numpy pandas scikit-learn matplotlib\n"
            "jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --allow-root &\n"
        ),
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


# ---------------------------------------------------------------------------
# Item helpers
# ---------------------------------------------------------------------------

def _sk(template_id: str) -> str:
    return f"TEMPLATE#{template_id}"


def _item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw DDB item into an API-friendly dict (coerces Decimals)."""
    return {
        "template_id": item.get("template_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "category": item.get("category", "custom"),
        "target": item.get("target", "ec2"),
        "instance_type": item.get("instance_type", ""),
        "ami_id": item.get("ami_id", ""),
        "k8s_image": item.get("k8s_image", ""),
        "k8s_preset": item.get("k8s_preset", ""),
        "startup_script": item.get("startup_script", ""),
        "ports": [int(p) for p in (item.get("ports") or [])],
        "env_vars": {str(k): str(v) for k, v in (item.get("env_vars") or {}).items()},
        "tags": [str(t) for t in (item.get("tags") or [])],
        "auto_terminate_after": int(item.get("auto_terminate_after", 7200)),
        "icon": item.get("icon", ""),
        "is_system": bool(item.get("is_system", False)),
        "owner_sub": item.get("owner_sub", ""),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "use_count": int(item.get("use_count", 0)),
    }


def _build_item(
    *,
    owner_sub: str,
    template_id: str,
    name: str,
    description: str,
    category: str,
    target: str,
    instance_type: str = "",
    ami_id: str = "",
    k8s_image: str = "",
    k8s_preset: str = "",
    startup_script: str = "",
    ports: Optional[List[int]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    tags: Optional[List[str]] = None,
    auto_terminate_after: int = 7200,
    icon: str = "",
    is_system: bool = False,
    created_at: Optional[int] = None,
    use_count: int = 0,
) -> Dict[str, Any]:
    ts = created_at if created_at is not None else now_ts()
    return {
        "owner_sub": owner_sub,
        "sk": _sk(template_id),
        "template_id": template_id,
        "name": name,
        "name_lower": name.lower(),
        "description": description,
        "category": category,
        "target": target,
        "instance_type": instance_type,
        "ami_id": ami_id,
        "k8s_image": k8s_image,
        "k8s_preset": k8s_preset,
        "startup_script": startup_script,
        "ports": [int(p) for p in (ports or [])],
        "env_vars": dict(env_vars or {}),
        "tags": list(tags or []),
        "auto_terminate_after": int(auto_terminate_after),
        "icon": icon,
        "is_system": bool(is_system),
        "created_at": ts,
        "updated_at": ts,
        "use_count": int(use_count),
    }


# ---------------------------------------------------------------------------
# System template seeding
# ---------------------------------------------------------------------------

def ensure_system_templates() -> int:
    """Seed system templates if not already present. Idempotent.

    Returns the number of templates newly created."""
    created = 0
    for tpl in SYSTEM_TEMPLATES:
        tid = tpl["template_id"]
        existing = T.instance_templates.get_item(
            Key={"owner_sub": SYSTEM_OWNER, "sk": _sk(tid)}
        ).get("Item")
        if existing:
            continue
        item = _build_item(
            owner_sub=SYSTEM_OWNER,
            template_id=tid,
            name=tpl["name"],
            description=tpl.get("description", ""),
            category=tpl.get("category", "compute"),
            target=tpl.get("target", "ec2"),
            instance_type=tpl.get("instance_type", ""),
            ami_id=tpl.get("ami_id", ""),
            k8s_image=tpl.get("k8s_image", ""),
            k8s_preset=tpl.get("k8s_preset", ""),
            startup_script=tpl.get("startup_script", ""),
            ports=tpl.get("ports", []),
            env_vars=tpl.get("env_vars", {}),
            tags=tpl.get("tags", []),
            auto_terminate_after=tpl.get("auto_terminate_after", 7200),
            icon=tpl.get("icon", ""),
            is_system=True,
        )
        T.instance_templates.put_item(Item=item)
        created += 1
    if created:
        logger.info("template_system_seed count=%d already_existed=%d", created, len(SYSTEM_TEMPLATES) - created)
    return created


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_template(
    user_sub: str,
    *,
    name: str,
    description: str = "",
    category: str = "custom",
    target: str,
    instance_type: str = "",
    ami_id: str = "",
    k8s_image: str = "",
    k8s_preset: str = "",
    startup_script: str = "",
    ports: Optional[List[int]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    tags: Optional[List[str]] = None,
    auto_terminate_after: int = 7200,
    request=None,
) -> Dict[str, Any]:
    """Create a user-owned template."""
    template_id = uuid.uuid4().hex
    item = _build_item(
        owner_sub=user_sub,
        template_id=template_id,
        name=name,
        description=description,
        category=category,
        target=target,
        instance_type=instance_type,
        ami_id=ami_id,
        k8s_image=k8s_image,
        k8s_preset=k8s_preset,
        startup_script=startup_script,
        ports=ports,
        env_vars=env_vars,
        tags=tags,
        auto_terminate_after=auto_terminate_after,
        is_system=False,
    )
    T.instance_templates.put_item(Item=item)
    audit_event(
        "template.created", user_sub, request,
        outcome="success", template_id=template_id, target=target, category=category,
    )
    logger.info("template_created user_sub=%s template_id=%s target=%s", user_sub, template_id, target)
    return _item_to_out(item)


def get_template(owner_sub: str, template_id: str) -> Optional[Dict[str, Any]]:
    """Get a template by owner + ID. Pass "SYSTEM" for system templates."""
    item = T.instance_templates.get_item(
        Key={"owner_sub": owner_sub, "sk": _sk(template_id)}
    ).get("Item")
    if not item:
        return None
    return _item_to_out(item)


def _query_owner(owner_sub: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("owner_sub").eq(owner_sub)
        & Key("sk").begins_with("TEMPLATE#"),
    }
    resp = T.instance_templates.query(**kwargs)
    items.extend(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        resp = T.instance_templates.query(**kwargs)
        items.extend(resp.get("Items", []))
    return items


def list_templates(
    user_sub: Optional[str] = None,
    *,
    category: Optional[str] = None,
    target: Optional[str] = None,
    include_system: bool = True,
) -> List[Dict[str, Any]]:
    """List templates: user's own templates + (optionally) system templates."""
    raw: List[Dict[str, Any]] = []
    if include_system:
        raw.extend(_query_owner(SYSTEM_OWNER))
    if user_sub:
        raw.extend(_query_owner(user_sub))

    out = [_item_to_out(i) for i in raw]
    if category:
        out = [t for t in out if t["category"] == category]
    if target:
        out = [t for t in out if t["target"] == target]
    # System first, then newest user templates first.
    out.sort(key=lambda t: (0 if t["is_system"] else 1, -t["created_at"]))
    return out


def update_template(user_sub: str, template_id: str, *, request=None, **updates) -> Dict[str, Any]:
    """Update a user-owned template. System templates cannot be modified."""
    # System templates are immutable.
    if get_template(SYSTEM_OWNER, template_id):
        raise SystemTemplateImmutable("Cannot modify system template")

    item = T.instance_templates.get_item(
        Key={"owner_sub": user_sub, "sk": _sk(template_id)}
    ).get("Item")
    if not item:
        raise TemplateNotFound("Template not found")

    changed: Dict[str, Any] = {}
    for field_name in _UPDATABLE_FIELDS:
        if field_name in updates and updates[field_name] is not None:
            val = updates[field_name]
            if field_name == "ports":
                val = [int(p) for p in val]
            elif field_name == "auto_terminate_after":
                val = int(val)
            changed[field_name] = val

    item.update(changed)
    if "name" in changed:
        item["name_lower"] = str(changed["name"]).lower()
    item["updated_at"] = now_ts()
    T.instance_templates.put_item(Item=item)

    audit_event(
        "template.updated", user_sub, request,
        outcome="success", template_id=template_id, updated_fields=list(changed.keys()),
    )
    logger.info("template_updated user_sub=%s template_id=%s fields=%s", user_sub, template_id, list(changed.keys()))
    return _item_to_out(item)


def delete_template(user_sub: str, template_id: str, *, request=None) -> bool:
    """Delete a user-owned template. System templates cannot be deleted."""
    if get_template(SYSTEM_OWNER, template_id):
        raise SystemTemplateImmutable("Cannot delete system template")

    item = T.instance_templates.get_item(
        Key={"owner_sub": user_sub, "sk": _sk(template_id)}
    ).get("Item")
    if not item:
        raise TemplateNotFound("Template not found")

    T.instance_templates.delete_item(
        Key={"owner_sub": user_sub, "sk": _sk(template_id)}
    )
    audit_event(
        "template.deleted", user_sub, request,
        outcome="success", template_id=template_id,
    )
    logger.info("template_deleted user_sub=%s template_id=%s", user_sub, template_id)
    return True


def clone_template(user_sub: str, template_id: str, *, new_name: str, request=None) -> Dict[str, Any]:
    """Clone a template (system or the caller's own) into the user's templates."""
    source = get_template(SYSTEM_OWNER, template_id) or get_template(user_sub, template_id)
    if not source:
        raise TemplateNotFound("Source template not found")

    new_id = uuid.uuid4().hex
    item = _build_item(
        owner_sub=user_sub,
        template_id=new_id,
        name=new_name,
        description=source.get("description", ""),
        category=source.get("category", "custom"),
        target=source.get("target", "ec2"),
        instance_type=source.get("instance_type", ""),
        ami_id=source.get("ami_id", ""),
        k8s_image=source.get("k8s_image", ""),
        k8s_preset=source.get("k8s_preset", ""),
        startup_script=source.get("startup_script", ""),
        ports=source.get("ports", []),
        env_vars=source.get("env_vars", {}),
        tags=source.get("tags", []),
        auto_terminate_after=source.get("auto_terminate_after", 7200),
        icon=source.get("icon", ""),
        is_system=False,
    )
    T.instance_templates.put_item(Item=item)
    audit_event(
        "template.cloned", user_sub, request,
        outcome="success", source_id=template_id, new_id=new_id,
    )
    logger.info("template_cloned user_sub=%s source_id=%s new_id=%s", user_sub, template_id, new_id)
    return _item_to_out(item)


def resolve_template(template_id: str, user_sub: str) -> Optional[Dict[str, Any]]:
    """Resolve a template_id to its config. Checks user templates first, then system."""
    return get_template(user_sub, template_id) or get_template(SYSTEM_OWNER, template_id)


def increment_use_count(owner_sub: str, template_id: str) -> None:
    """Atomically increment a template's use_count when launched."""
    try:
        T.instance_templates.update_item(
            Key={"owner_sub": owner_sub, "sk": _sk(template_id)},
            UpdateExpression="ADD use_count :one",
            ExpressionAttributeValues={":one": 1},
        )
    except Exception:
        logger.exception("increment_use_count failed owner_sub=%s template_id=%s", owner_sub, template_id)


# ---------------------------------------------------------------------------
# Materialize into a launch payload
# ---------------------------------------------------------------------------

def materialize_launch_payload(
    template: Dict[str, Any],
    *,
    label: str = "",
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Turn a resolved template into a launch request payload.

    Template values supply defaults; explicit ``overrides`` win. The returned
    payload matches what ``ec2_launcher.launch_instance`` /
    ``k8s_launcher.launch_pod`` consume."""
    overrides = {k: v for k, v in (overrides or {}).items() if v is not None and v != ""}
    target = template.get("target", "ec2")

    def pick(key: str, default: Any = "") -> Any:
        return overrides.get(key, template.get(key, default))

    if target == "k8s":
        payload: Dict[str, Any] = {
            "target": "k8s",
            "label": label or template.get("name", "from-template"),
            "image": pick("k8s_image", "") or pick("image", ""),
            "preset": pick("k8s_preset", "small") or pick("preset", "small"),
            "ttl_seconds": int(pick("auto_terminate_after", 7200)),
            "env_vars": template.get("env_vars", {}) | {
                k: str(v) for k, v in (overrides.get("env_vars") or {}).items()
            },
            "template_id": template.get("template_id", ""),
        }
    else:
        payload = {
            "target": "ec2",
            "label": label or template.get("name", "from-template"),
            "instance_type": pick("instance_type", ""),
            "ami_id": pick("ami_id", ""),
            "startup_script": pick("startup_script", ""),
            "auto_terminate_after": int(pick("auto_terminate_after", 7200)),
            "template_id": template.get("template_id", ""),
        }
    return payload
