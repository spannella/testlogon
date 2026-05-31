"""Security group management — CRUD for firewall rules applied to compute resources.

INFRA-009 implementation. Security groups are user-owned: PK=user_sub, SK=SG#{sg_id}.
In dev mode there is no real AWS security group — rules are stored and validated in DDB
(mock enforcement). In production these would translate to VPC security group rules.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.normalize import normalize_cidr
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SecurityGroupNotFound(Exception):
    pass


class CannotDeleteDefault(Exception):
    pass


class SecurityGroupInUse(Exception):
    pass


class RuleValidationError(Exception):
    """Raised for invalid rule fields (CIDR / port-range)."""


class DangerousRule(Exception):
    """Raised when a rule opens SSH (22) to 0.0.0.0/0."""


class MaxRulesExceeded(Exception):
    pass


class RuleNotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

VALID_PROTOCOLS = ("tcp", "udp", "icmp", "all")
VALID_DIRECTIONS = ("inbound", "outbound")

DEFAULT_SG_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "default-ssh",
        "protocol": "tcp",
        "port_from": 22,
        "port_to": 22,
        "source": "platform_only",
        "direction": "inbound",
        "description": "SSH from platform only",
    },
    {
        "rule_id": "default-vnc",
        "protocol": "tcp",
        "port_from": 5900,
        "port_to": 5999,
        "source": "platform_only",
        "direction": "inbound",
        "description": "VNC from platform only",
    },
    {
        "rule_id": "default-outbound",
        "protocol": "all",
        "port_from": 0,
        "port_to": 65535,
        "source": "0.0.0.0/0",
        "direction": "outbound",
        "description": "Allow all outbound traffic",
    },
]


# ---------------------------------------------------------------------------
# Platform egress CIDRs
# ---------------------------------------------------------------------------

def resolve_platform_cidrs() -> List[str]:
    """Return the platform's egress CIDR ranges for 'platform_only' source resolution."""
    raw = S.security_groups_platform_egress_cidrs or ""
    cidrs = [c.strip() for c in raw.split(",") if c.strip()]
    return cidrs or ["127.0.0.1/32", "10.0.0.0/8"]


# ---------------------------------------------------------------------------
# Rule validation + normalization
# ---------------------------------------------------------------------------

def validate_rule(rule: Dict[str, Any]) -> List[str]:
    """Validate a security rule. Returns list of error messages (empty = valid)."""
    errors: List[str] = []

    protocol = rule.get("protocol")
    if protocol not in VALID_PROTOCOLS:
        errors.append(f"Invalid protocol: {protocol}")

    direction = rule.get("direction", "inbound")
    if direction not in VALID_DIRECTIONS:
        errors.append(f"Invalid direction: {direction}")

    port_from = int(rule.get("port_from", 0) or 0)
    port_to = int(rule.get("port_to", 0) or 0)
    if protocol in ("tcp", "udp"):
        if not (0 <= port_from <= 65535):
            errors.append("port_from must be 0-65535")
        if not (0 <= port_to <= 65535):
            errors.append("port_to must be 0-65535")
        if port_from > port_to:
            errors.append("port_from must be <= port_to")

    source = rule.get("source", "")
    if source == "platform_only":
        pass  # Valid special value
    elif isinstance(source, str) and source.startswith("sg:"):
        pass  # Security group reference — validated separately by caller if needed
    else:
        try:
            normalize_cidr(source)
        except Exception:
            errors.append(f"Invalid CIDR: {source}")

    return errors


def is_dangerous_rule(rule: Dict[str, Any]) -> bool:
    """True if the rule opens SSH (port 22) to 0.0.0.0/0 inbound over TCP."""
    source = rule.get("source", "")
    protocol = rule.get("protocol")
    direction = rule.get("direction", "inbound")
    port_from = int(rule.get("port_from", 0) or 0)
    port_to = int(rule.get("port_to", 0) or 0)
    return (
        source == "0.0.0.0/0"
        and direction == "inbound"
        and protocol == "tcp"
        and port_from <= 22 <= port_to
    )


def _prepare_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Validate + normalize a single rule, assigning a rule_id if absent.

    Raises RuleValidationError / DangerousRule on invalid input.
    """
    errors = validate_rule(rule)
    if errors:
        raise RuleValidationError("; ".join(errors))

    if S.security_groups_block_dangerous_rules and is_dangerous_rule(rule):
        raise DangerousRule(
            "SSH (port 22) open to 0.0.0.0/0 is not recommended. "
            "Use 'platform_only' or a specific CIDR."
        )

    protocol = rule["protocol"]
    source = rule.get("source", "")
    # Normalize CIDR sources to canonical form (special values pass through)
    if source != "platform_only" and not source.startswith("sg:"):
        source = normalize_cidr(source)

    if protocol in ("icmp", "all"):
        port_from = int(rule.get("port_from", 0) or 0)
        port_to = int(rule.get("port_to", 0) or 0)
    else:
        port_from = int(rule.get("port_from", 0) or 0)
        port_to = int(rule.get("port_to", 0) or 0)

    return {
        "rule_id": rule.get("rule_id") or f"r-{uuid.uuid4().hex[:12]}",
        "protocol": protocol,
        "port_from": port_from,
        "port_to": port_to,
        "source": source,
        "direction": rule.get("direction", "inbound"),
        "description": rule.get("description", "") or "",
    }


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _item_to_sg(item: Dict[str, Any]) -> Dict[str, Any]:
    rules = []
    for r in item.get("rules", []) or []:
        rules.append({
            "rule_id": r.get("rule_id", ""),
            "protocol": r.get("protocol", ""),
            "port_from": int(r.get("port_from", 0) or 0),
            "port_to": int(r.get("port_to", 0) or 0),
            "source": r.get("source", ""),
            "direction": r.get("direction", "inbound"),
            "description": r.get("description", "") or "",
        })
    return {
        "sg_id": item.get("sg_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description", "") or "",
        "rules": rules,
        "is_default": bool(item.get("is_default", False)),
        "created_at": int(item.get("created_at", 0) or 0),
        "updated_at": int(item.get("updated_at", 0) or 0),
        "associated_instances": list(item.get("associated_instances", []) or []),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def ensure_default_sg(user_sub: str) -> Dict[str, Any]:
    """Create default security group if not exists. Idempotent."""
    existing = _find_default_item(user_sub)
    if existing:
        return _item_to_sg(existing)

    now = now_ts()
    sg_id = f"sg-{uuid.uuid4().hex[:12]}"
    item = {
        "user_sub": user_sub,
        "sk": f"SG#{sg_id}",
        "sg_id": sg_id,
        "name": "Default Security Group",
        "description": "Auto-created default: SSH/VNC from platform, all outbound.",
        "rules": [dict(r) for r in DEFAULT_SG_RULES],
        "is_default": True,
        "created_at": now,
        "updated_at": now,
        "associated_instances": [],
    }
    T.security_groups.put_item(Item=item)
    logger.info("sg.default_created sg_id=%s user_sub=%s", sg_id, user_sub)
    return _item_to_sg(item)


def _find_default_item(user_sub: str) -> Optional[Dict[str, Any]]:
    resp = T.security_groups.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("SG#"),
    )
    for it in resp.get("Items", []):
        if it.get("is_default"):
            return it
    return None


def _get_item(user_sub: str, sg_id: str) -> Optional[Dict[str, Any]]:
    resp = T.security_groups.get_item(Key={"user_sub": user_sub, "sk": f"SG#{sg_id}"})
    return resp.get("Item")


def create_security_group(
    user_sub: str,
    *,
    name: str,
    description: str = "",
    rules: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Create a custom security group. Validates all rules."""
    prepared: List[Dict[str, Any]] = []
    for r in (rules or []):
        prepared.append(_prepare_rule(r))

    if len(prepared) > S.security_groups_max_rules:
        raise MaxRulesExceeded(
            f"Security group cannot have more than {S.security_groups_max_rules} rules"
        )

    now = now_ts()
    sg_id = f"sg-{uuid.uuid4().hex[:12]}"
    item = {
        "user_sub": user_sub,
        "sk": f"SG#{sg_id}",
        "sg_id": sg_id,
        "name": name,
        "description": description or "",
        "rules": prepared,
        "is_default": False,
        "created_at": now,
        "updated_at": now,
        "associated_instances": [],
    }
    T.security_groups.put_item(Item=item)
    logger.info("sg.created sg_id=%s user_sub=%s rule_count=%d", sg_id, user_sub, len(prepared))
    return _item_to_sg(item)


def get_security_group(user_sub: str, sg_id: str) -> Optional[Dict[str, Any]]:
    """Get a security group by ID."""
    item = _get_item(user_sub, sg_id)
    return _item_to_sg(item) if item else None


def list_security_groups(user_sub: str) -> List[Dict[str, Any]]:
    """List all security groups for a user, ensuring the default exists. Newest-first."""
    ensure_default_sg(user_sub)
    resp = T.security_groups.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("SG#"),
    )
    items = resp.get("Items", [])
    sgs = [_item_to_sg(i) for i in items]
    # Default first, then newest-first
    sgs.sort(key=lambda s: (0 if s["is_default"] else 1, -s["created_at"]))
    return sgs


def update_security_group(
    user_sub: str,
    sg_id: str,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Update SG name/description."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")

    sets = ["updated_at = :ts"]
    values: Dict[str, Any] = {":ts": now_ts()}
    names: Dict[str, str] = {}
    if name is not None:
        sets.append("#nm = :nm")
        names["#nm"] = "name"
        values[":nm"] = name
    if description is not None:
        sets.append("description = :desc")
        values[":desc"] = description

    kwargs: Dict[str, Any] = {
        "Key": {"user_sub": user_sub, "sk": f"SG#{sg_id}"},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    resp = T.security_groups.update_item(**kwargs)
    return _item_to_sg(resp["Attributes"])


def delete_security_group(user_sub: str, sg_id: str) -> bool:
    """Delete a custom SG. Default SG cannot be deleted. Fails if SG has associated instances."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")
    if item.get("is_default"):
        raise CannotDeleteDefault("Cannot delete default security group")
    if item.get("associated_instances"):
        raise SecurityGroupInUse("Cannot delete SG with associated instances")

    T.security_groups.delete_item(Key={"user_sub": user_sub, "sk": f"SG#{sg_id}"})
    logger.info("sg.deleted sg_id=%s user_sub=%s", sg_id, user_sub)
    return True


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------

def _save_rules(user_sub: str, sg_id: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    resp = T.security_groups.update_item(
        Key={"user_sub": user_sub, "sk": f"SG#{sg_id}"},
        UpdateExpression="SET rules = :rules, updated_at = :ts",
        ExpressionAttributeValues={":rules": rules, ":ts": now_ts()},
        ReturnValues="ALL_NEW",
    )
    return _item_to_sg(resp["Attributes"])


def add_rule(user_sub: str, sg_id: str, rule: Dict[str, Any]) -> Dict[str, Any]:
    """Add a rule to a security group. Validates the rule. Max N rules per SG."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")

    rules = list(item.get("rules", []) or [])
    if len(rules) + 1 > S.security_groups_max_rules:
        raise MaxRulesExceeded(
            f"Security group cannot have more than {S.security_groups_max_rules} rules"
        )

    prepared = _prepare_rule(rule)
    rules.append(prepared)
    logger.info(
        "sg.rule_added sg_id=%s rule_id=%s protocol=%s port=%s-%s source=%s",
        sg_id, prepared["rule_id"], prepared["protocol"],
        prepared["port_from"], prepared["port_to"], prepared["source"],
    )
    return _save_rules(user_sub, sg_id, rules)


def remove_rule(user_sub: str, sg_id: str, rule_id: str) -> Dict[str, Any]:
    """Remove a rule from a security group."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")

    rules = list(item.get("rules", []) or [])
    new_rules = [r for r in rules if r.get("rule_id") != rule_id]
    if len(new_rules) == len(rules):
        raise RuleNotFound(f"Rule {rule_id} not found")
    logger.info("sg.rule_removed sg_id=%s rule_id=%s", sg_id, rule_id)
    return _save_rules(user_sub, sg_id, new_rules)


def update_rule(user_sub: str, sg_id: str, rule_id: str, **updates: Any) -> Dict[str, Any]:
    """Update fields on an existing rule."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")

    rules = list(item.get("rules", []) or [])
    found = None
    for r in rules:
        if r.get("rule_id") == rule_id:
            found = r
            break
    if found is None:
        raise RuleNotFound(f"Rule {rule_id} not found")

    merged = dict(found)
    for k, v in updates.items():
        if v is not None:
            merged[k] = v
    prepared = _prepare_rule(merged)
    prepared["rule_id"] = rule_id  # preserve id

    new_rules = [prepared if r.get("rule_id") == rule_id else r for r in rules]
    return _save_rules(user_sub, sg_id, new_rules)


# ---------------------------------------------------------------------------
# Effective rules (resolve platform_only + sg: references)
# ---------------------------------------------------------------------------

def get_effective_rules(user_sub: str, sg_id: str) -> List[Dict[str, Any]]:
    """Resolve all rules, expanding 'platform_only' to actual CIDRs and sg: references."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")

    platform_cidrs = resolve_platform_cidrs()
    effective: List[Dict[str, Any]] = []
    for r in item.get("rules", []) or []:
        source = r.get("source", "")
        resolved_sources: List[str]
        if source == "platform_only":
            resolved_sources = list(platform_cidrs)
        elif isinstance(source, str) and source.startswith("sg:"):
            ref_id = source[3:]
            ref = _get_item(user_sub, ref_id)
            resolved_sources = []
            if ref:
                for rr in ref.get("rules", []) or []:
                    s = rr.get("source", "")
                    if s == "platform_only":
                        resolved_sources.extend(platform_cidrs)
                    elif not s.startswith("sg:"):
                        resolved_sources.append(s)
        else:
            resolved_sources = [source]

        effective.append({
            "rule_id": r.get("rule_id", ""),
            "protocol": r.get("protocol", ""),
            "port_from": int(r.get("port_from", 0) or 0),
            "port_to": int(r.get("port_to", 0) or 0),
            "source": source,
            "resolved_sources": resolved_sources,
            "direction": r.get("direction", "inbound"),
            "description": r.get("description", "") or "",
        })
    return effective


# ---------------------------------------------------------------------------
# Instance association (used by launch integration)
# ---------------------------------------------------------------------------

def associate_instance(user_sub: str, sg_id: str, instance_id: str) -> None:
    """Record that an instance uses this SG (idempotent)."""
    item = _get_item(user_sub, sg_id)
    if not item:
        raise SecurityGroupNotFound(f"Security group {sg_id} not found")
    assoc = list(item.get("associated_instances", []) or [])
    if instance_id in assoc:
        return
    assoc.append(instance_id)
    T.security_groups.update_item(
        Key={"user_sub": user_sub, "sk": f"SG#{sg_id}"},
        UpdateExpression="SET associated_instances = :a, updated_at = :ts",
        ExpressionAttributeValues={":a": assoc, ":ts": now_ts()},
    )


def disassociate_instance(user_sub: str, sg_id: str, instance_id: str) -> None:
    """Remove an instance association (idempotent)."""
    item = _get_item(user_sub, sg_id)
    if not item:
        return
    assoc = list(item.get("associated_instances", []) or [])
    if instance_id not in assoc:
        return
    assoc = [i for i in assoc if i != instance_id]
    T.security_groups.update_item(
        Key={"user_sub": user_sub, "sk": f"SG#{sg_id}"},
        UpdateExpression="SET associated_instances = :a, updated_at = :ts",
        ExpressionAttributeValues={":a": assoc, ":ts": now_ts()},
    )


def resolve_for_launch(user_sub: str, security_group_id: Optional[str]) -> Dict[str, Any]:
    """Resolve the SG to use at launch time.

    If security_group_id is provided, validate it belongs to the user.
    If not, ensure + return the user's default SG.
    """
    if security_group_id:
        sg = get_security_group(user_sub, security_group_id)
        if not sg:
            raise SecurityGroupNotFound(f"Security group {security_group_id} not found")
        return sg
    return ensure_default_sg(user_sub)
