"""Multi-Hop SSH Bastion path management (INFRA-011).

A *bastion path* models a multi-hop SSH connection that routes through one or
more bastion / jump hosts to reach a final target host. Each path is owned by
a single user. Hops are an ordered list of jump hosts (outermost bastion
first); the target is the final destination.

In the local mock there is no real SSH proxying — this module models, validates
and persists the hop chain and can produce the resolved ProxyJump / ssh_config
representation for the chain.

DynamoDB layout (table ``ssh_bastion_paths``):
    PK ``user_sub``
    SK ``PATH#{path_id}``
    GSI ``ByCreatedAt`` (user_sub, created_at:N)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class BastionPathNotFound(Exception):
    """Raised when a bastion path does not exist for the user."""


class BastionPathLimitExceeded(Exception):
    """Raised when a user exceeds the maximum number of bastion paths."""


class InvalidHop(Exception):
    """Raised when a hop has an invalid host / port / ordering."""


class ChainValidationError(Exception):
    """Raised when the resolved chain fails validation (too long, duplicate, etc.)."""


# ---------------------------------------------------------------------------
# Host / IP validation (reuses ipaddress; falls back to hostname regex)
# ---------------------------------------------------------------------------

# RFC 1123 hostname (labels 1-63 chars, alnum + hyphen, dot-separated)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_host(host: str) -> str:
    """Validate and normalize a hop hostname or IP address.

    Accepts IPv4 / IPv6 literals (normalized via ``ipaddress``) and RFC-1123
    hostnames. Raises :class:`InvalidHop` for anything else.
    """
    host = (host or "").strip()
    if not host:
        raise InvalidHop("hostname is required")
    if len(host) > 253:
        raise InvalidHop("hostname too long")
    # Try IP literal first.
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(host):
        return host.lower()
    raise InvalidHop(f"invalid hostname or IP: {host}")


def validate_port(port: Any) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise InvalidHop("port must be an integer")
    if p < 1 or p > 65535:
        raise InvalidHop("port must be between 1 and 65535")
    return p


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise InvalidHop("username is required")
    if len(username) > 64:
        raise InvalidHop("username too long")
    if not re.match(r"^[A-Za-z0-9._@-]+$", username):
        raise InvalidHop(f"invalid username: {username}")
    return username


def _normalize_hop(hop: Dict[str, Any], *, index: int, is_target: bool) -> Dict[str, Any]:
    """Validate & normalize a single hop dict. Raises InvalidHop on bad input."""
    if not isinstance(hop, dict):
        raise InvalidHop(f"hop {index} must be an object")
    hostname = validate_host(hop.get("hostname", ""))
    port = validate_port(hop.get("port", 22))
    username = validate_username(hop.get("username", ""))
    ssh_key_id = (hop.get("ssh_key_id") or "").strip()
    label = (hop.get("label") or "").strip() or hostname
    return {
        "hostname": hostname,
        "port": port,
        "username": username,
        "ssh_key_id": ssh_key_id,
        "label": label,
        "is_bastion": not is_target,
    }


def _validate_chain(jump_hops: List[Dict[str, Any]], target: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate the full ordered chain (jump hops + target).

    Returns the normalized chain (jump hops first, target last) with
    ``hop_number`` assigned. Raises InvalidHop / ChainValidationError.
    """
    if not isinstance(jump_hops, list):
        raise InvalidHop("jump_hops must be a list")

    norm_jumps = [
        _normalize_hop(h, index=i, is_target=False) for i, h in enumerate(jump_hops)
    ]
    norm_target = _normalize_hop(target, index=len(norm_jumps), is_target=True)

    chain = norm_jumps + [norm_target]

    max_hops = S.ssh_bastion_max_hops
    if len(chain) > max_hops:
        raise ChainValidationError(
            f"Connection chain exceeds maximum {max_hops} hops"
        )

    # Reachability / ordering check: no two consecutive hops may be identical
    # (would be a self-loop), and the full chain must not contain a duplicated
    # (hostname, port) which would indicate a circular route.
    seen: set[tuple[str, int]] = set()
    for i, hop in enumerate(chain):
        hop["hop_number"] = i + 1
        key = (hop["hostname"], hop["port"])
        if key in seen:
            raise ChainValidationError(
                f"Circular bastion chain detected at hop {i + 1} ({hop['hostname']}:{hop['port']})"
            )
        seen.add(key)
    return chain


# ---------------------------------------------------------------------------
# DDB item <-> dict
# ---------------------------------------------------------------------------

def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _hop_out(hop: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hostname": hop.get("hostname", ""),
        "port": _coerce_int(hop.get("port"), 22),
        "username": hop.get("username", ""),
        "ssh_key_id": hop.get("ssh_key_id", "") or "",
        "label": hop.get("label", "") or hop.get("hostname", ""),
        "is_bastion": bool(hop.get("is_bastion", False)),
        "hop_number": _coerce_int(hop.get("hop_number"), 0),
    }


def _item_to_path(item: Dict[str, Any]) -> Dict[str, Any]:
    hops = [_hop_out(h) for h in item.get("hops", [])]
    return {
        "path_id": item["path_id"],
        "label": item.get("label", ""),
        "description": item.get("description", "") or "",
        "hops": hops,
        "total_hops": len(hops),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def _get_item(user_sub: str, path_id: str) -> Optional[Dict[str, Any]]:
    resp = T.ssh_bastion_paths.get_item(
        Key={"user_sub": user_sub, "sk": f"PATH#{path_id}"}
    )
    return resp.get("Item")


def create_path(
    user_sub: str,
    *,
    label: str,
    jump_hops: List[Dict[str, Any]],
    target: Dict[str, Any],
    description: str = "",
) -> Dict[str, Any]:
    """Create a multi-hop bastion path. Validates the full chain first."""
    label = (label or "").strip()
    if not label:
        raise InvalidHop("label is required")
    if len(label) > 200:
        raise InvalidHop("label too long")

    chain = _validate_chain(jump_hops, target)

    # Enforce per-user limit.
    existing = list_paths(user_sub)
    if len(existing) >= S.ssh_bastion_max_paths_per_user:
        raise BastionPathLimitExceeded(
            f"Maximum {S.ssh_bastion_max_paths_per_user} bastion paths per user"
        )

    path_id = "bp_" + uuid.uuid4().hex[:16]
    ts = now_ts()
    item = {
        "user_sub": user_sub,
        "sk": f"PATH#{path_id}",
        "path_id": path_id,
        "label": label,
        "description": (description or "").strip(),
        "hops": chain,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ssh_bastion_paths.put_item(Item=item)
    logger.info(
        "ssh_bastion.path_created path_id=%s user_sub=%s hops=%d",
        path_id, user_sub, len(chain),
    )
    return _item_to_path(item)


def get_path(user_sub: str, path_id: str) -> Optional[Dict[str, Any]]:
    item = _get_item(user_sub, path_id)
    return _item_to_path(item) if item else None


def list_paths(user_sub: str) -> List[Dict[str, Any]]:
    """List all bastion paths for a user, newest-first."""
    resp = T.ssh_bastion_paths.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("PATH#"),
    )
    paths = [_item_to_path(i) for i in resp.get("Items", [])]
    paths.sort(key=lambda p: -p["created_at"])
    return paths


def update_path(
    user_sub: str,
    path_id: str,
    *,
    label: Optional[str] = None,
    description: Optional[str] = None,
    jump_hops: Optional[List[Dict[str, Any]]] = None,
    target: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Update a bastion path. If hops/target supplied, the chain is re-validated.

    Updating hops requires supplying BOTH ``jump_hops`` and ``target`` together
    (the whole chain is replaced atomically).
    """
    item = _get_item(user_sub, path_id)
    if not item:
        raise BastionPathNotFound(f"Bastion path {path_id} not found")

    sets = ["updated_at = :ts"]
    values: Dict[str, Any] = {":ts": now_ts()}
    names: Dict[str, str] = {}

    if label is not None:
        label = label.strip()
        if not label:
            raise InvalidHop("label cannot be empty")
        if len(label) > 200:
            raise InvalidHop("label too long")
        sets.append("#lbl = :lbl")
        names["#lbl"] = "label"
        values[":lbl"] = label

    if description is not None:
        sets.append("description = :desc")
        values[":desc"] = description.strip()

    if jump_hops is not None or target is not None:
        if jump_hops is None or target is None:
            raise InvalidHop("updating hops requires both jump_hops and target")
        chain = _validate_chain(jump_hops, target)
        sets.append("hops = :hops")
        values[":hops"] = chain

    kwargs: Dict[str, Any] = {
        "Key": {"user_sub": user_sub, "sk": f"PATH#{path_id}"},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ExpressionAttributeValues": values,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    resp = T.ssh_bastion_paths.update_item(**kwargs)
    logger.info("ssh_bastion.path_updated path_id=%s user_sub=%s", path_id, user_sub)
    return _item_to_path(resp["Attributes"])


def delete_path(user_sub: str, path_id: str) -> bool:
    item = _get_item(user_sub, path_id)
    if not item:
        raise BastionPathNotFound(f"Bastion path {path_id} not found")
    T.ssh_bastion_paths.delete_item(Key={"user_sub": user_sub, "sk": f"PATH#{path_id}"})
    logger.info("ssh_bastion.path_deleted path_id=%s user_sub=%s", path_id, user_sub)
    return True


# ---------------------------------------------------------------------------
# Resolution: ProxyJump / ssh_config
# ---------------------------------------------------------------------------

def _proxyjump_token(hop: Dict[str, Any]) -> str:
    """Render a single hop as an OpenSSH ProxyJump token: ``user@host:port``."""
    user = hop.get("username", "")
    host = hop.get("hostname", "")
    port = _coerce_int(hop.get("port"), 22)
    token = f"{user}@{host}" if user else host
    if port != 22:
        token = f"{token}:{port}"
    return token


def resolve_path(user_sub: str, path_id: str) -> Dict[str, Any]:
    """Resolve a stored bastion path into ProxyJump / ssh_config representation.

    Re-validates the chain on read so a path that was stored before a config
    change (e.g. a lowered ``max_hops``) is reported as invalid rather than
    silently returned. Returns a dict with the resolved chain, the OpenSSH
    ``ProxyJump`` directive, an ``ssh -J`` command, and a generated
    ``ssh_config`` block.

    Raises :class:`BastionPathNotFound` if the path does not exist.
    """
    item = _get_item(user_sub, path_id)
    if not item:
        raise BastionPathNotFound(f"Bastion path {path_id} not found")

    chain = [_hop_out(h) for h in item.get("hops", [])]
    if not chain:
        raise ChainValidationError("Bastion path has no hops")

    # Re-validate length / circular against current settings.
    max_hops = S.ssh_bastion_max_hops
    if len(chain) > max_hops:
        raise ChainValidationError(f"Connection chain exceeds maximum {max_hops} hops")
    seen: set[tuple[str, int]] = set()
    for hop in chain:
        key = (hop["hostname"], hop["port"])
        if key in seen:
            raise ChainValidationError(
                f"Circular bastion chain detected ({hop['hostname']}:{hop['port']})"
            )
        seen.add(key)

    target = chain[-1]
    jump_hops = chain[:-1]

    # ProxyJump directive: comma-separated jump hosts (outermost first).
    proxy_jump = ",".join(_proxyjump_token(h) for h in jump_hops)

    # ssh -J command.
    if proxy_jump:
        ssh_command = f"ssh -J {proxy_jump} {_proxyjump_token(target)}"
    else:
        ssh_command = f"ssh {_proxyjump_token(target)}"

    # Generated ssh_config block.
    config_lines: List[str] = []
    alias = re.sub(r"[^A-Za-z0-9_.-]", "-", item.get("label", "") or target["hostname"])
    config_lines.append(f"Host {alias}")
    config_lines.append(f"    HostName {target['hostname']}")
    if target.get("username"):
        config_lines.append(f"    User {target['username']}")
    config_lines.append(f"    Port {target['port']}")
    if proxy_jump:
        config_lines.append(f"    ProxyJump {proxy_jump}")
    ssh_config = "\n".join(config_lines)

    return {
        "path_id": item["path_id"],
        "label": item.get("label", ""),
        "chain": chain,
        "jump_hops": jump_hops,
        "target": target,
        "total_hops": len(chain),
        "proxy_jump": proxy_jump,
        "ssh_command": ssh_command,
        "ssh_config": ssh_config,
    }
