"""Host inventory management (INFRA-001).

A persistent, owner-scoped inventory of remote hosts a user connects to via the
existing VNC + SSH terminal systems. Today connection targets are hardcoded in
Python (``vnc_sessions._default_targets``) and the SSH terminal requires the
user to re-enter hostname/port/credentials every session. This module adds a
durable layer where a user can:

  - save hosts (connection *metadata* only — see the security note below)
  - organize them into groups/folders and tag them
  - track connection history (last_connected_at + connection_count + recent
    connection events)
  - bulk-import hosts from CSV
  - resolve a saved host into quick-connect params for an SSH/VNC session

SECURITY: a host record holds connection metadata ONLY — hostname, port,
username, protocol, group, tags. It NEVER stores plaintext passwords, private
keys, or any secret. SSH credentials are still supplied per-session via the
WebSocket; for VNC the record carries a ``ws_url``/``target_id`` reference, not
a secret. Owner isolation is enforced by ``user_sub`` being the partition key —
every function takes ``user_sub`` and includes it in every DDB operation, so a
user can never read/modify another user's hosts.

DynamoDB layout (table ``host_inventory``):
    PK ``user_sub``
    SK ``HOST#{host_id}``
    GSI ``ByLabel``          (user_sub, label_lower)
    GSI ``ByProtocol``       (user_sub, protocol)
    GSI ``ByLastConnected``  (user_sub, last_connected_at:N)
"""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("host_inventory")

# ---------------------------------------------------------------------------
# Constants / validation
# ---------------------------------------------------------------------------

VALID_PROTOCOLS = {"ssh", "vnc", "rdp"}
VALID_OS_TYPES = {"linux", "windows", "macos", "unknown"}
DEFAULT_PORTS = {"ssh": 22, "vnc": 5900, "rdp": 3389}

CSV_MAX_ROWS = 200
MAX_TAGS = 20
MAX_TAG_LEN = 30
MAX_HISTORY_EVENTS = 50

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class HostNotFound(Exception):
    """Raised when a host does not exist for the user."""


class HostValidationError(Exception):
    """Raised when host input fails validation."""


class HostLimitExceeded(Exception):
    """Raised when the user exceeds the maximum number of saved hosts."""


def validate_hostname(hostname: str) -> str:
    """Validate & normalize an IP literal or DNS hostname. No scheme allowed."""
    hostname = (hostname or "").strip()
    if not hostname:
        raise HostValidationError("hostname is required")
    if len(hostname) > 255:
        raise HostValidationError("hostname too long")
    if "://" in hostname:
        raise HostValidationError("hostname must not include a scheme")
    # IP literal first.
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(hostname):
        return hostname.lower()
    raise HostValidationError(f"invalid hostname or IP: {hostname}")


def _validate_protocol(protocol: str) -> str:
    protocol = (protocol or "ssh").strip().lower()
    if protocol not in VALID_PROTOCOLS:
        raise HostValidationError(f"invalid protocol: {protocol}")
    return protocol


def _validate_os_type(os_type: str) -> str:
    os_type = (os_type or "unknown").strip().lower()
    if os_type not in VALID_OS_TYPES:
        raise HostValidationError(f"invalid os_type: {os_type}")
    return os_type


def _validate_port(port: Any, protocol: str) -> int:
    if port is None or port == "":
        return DEFAULT_PORTS.get(protocol, 22)
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise HostValidationError("port must be an integer")
    if p < 1 or p > 65535:
        raise HostValidationError("port must be between 1 and 65535")
    return p


def _clean_tags(tags: Optional[List[str]]) -> List[str]:
    if not tags:
        return []
    out: List[str] = []
    for t in tags:
        t = str(t).strip()
        if not t:
            continue
        if len(t) > MAX_TAG_LEN:
            t = t[:MAX_TAG_LEN]
        if t not in out:
            out.append(t)
        if len(out) >= MAX_TAGS:
            break
    return out


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _sk(host_id: str) -> str:
    return f"HOST#{host_id}"


def _item_to_host(item: Dict[str, Any]) -> Dict[str, Any]:
    """Project a DDB item to the public HostOut-shaped dict (no internal keys,
    no secrets — there are none stored)."""
    def _i(v: Any) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    return {
        "host_id": item.get("host_id", ""),
        "label": item.get("label", ""),
        "hostname": item.get("hostname", ""),
        "port": _i(item.get("port", 0)),
        "protocol": item.get("protocol", "ssh"),
        "username": item.get("username", ""),
        "description": item.get("description", ""),
        "tags": list(item.get("tags", []) or []),
        "group": item.get("group", ""),
        "os_type": item.get("os_type", "unknown"),
        "created_at": _i(item.get("created_at", 0)),
        "updated_at": _i(item.get("updated_at", 0)),
        "last_connected_at": _i(item.get("last_connected_at", 0)),
        "connection_count": _i(item.get("connection_count", 0)),
        "status": item.get("status", "unknown"),
        "is_pinned": bool(item.get("is_pinned", False)),
        "source": item.get("source", "manual"),
        # INFRA-010 / GAP-0234: per-host automatic SSH session recording flag.
        # Defaults False so pre-existing host records (which lack the attribute)
        # do not auto-record until explicitly opted in.
        "record_sessions": bool(item.get("record_sessions", False)),
        # ADR-003 / AQA-009: per-host opt-in for agent-driven QA over SSH.
        # Defaults False so pre-existing hosts are never auto-targetable by an
        # agent action until explicitly opted in (mirrors record_sessions).
        "agent_qa_allowed": bool(item.get("agent_qa_allowed", False)),
    }


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_host(
    user_sub: str,
    *,
    label: str,
    hostname: str,
    port: Optional[int] = None,
    protocol: str = "ssh",
    username: str = "",
    description: str = "",
    tags: Optional[List[str]] = None,
    group: str = "",
    os_type: str = "unknown",
    source: str = "manual",
    record_sessions: bool = False,
    agent_qa_allowed: bool = False,
) -> Dict[str, Any]:
    """Create a new host entry in the user's inventory."""
    label = (label or "").strip()
    if not label:
        raise HostValidationError("label is required")
    if len(label) > 100:
        raise HostValidationError("label too long")

    protocol = _validate_protocol(protocol)
    hostname = validate_hostname(hostname)
    port = _validate_port(port, protocol)
    os_type = _validate_os_type(os_type)
    tags = _clean_tags(tags)
    group = (group or "").strip()[:50]
    username = (username or "").strip()[:64]
    description = (description or "")[:500]

    host_id = "h_" + uuid.uuid4().hex
    ts = now_ts()
    item = {
        "user_sub": user_sub,
        "sk": _sk(host_id),
        "host_id": host_id,
        "label": label,
        "label_lower": label.lower(),
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "username": username,
        "description": description,
        "tags": tags,
        "group": group,
        "os_type": os_type,
        "created_at": ts,
        "updated_at": ts,
        "last_connected_at": 0,
        "connection_count": 0,
        "status": "unknown",
        "is_pinned": False,
        "source": source,
        "record_sessions": bool(record_sessions),
        "agent_qa_allowed": bool(agent_qa_allowed),
        "history": [],
    }
    T.host_inventory.put_item(Item=item)
    _audit("remote_host.created", user_sub, host_id=host_id, protocol=protocol, source=source)
    logger.info(
        "host_created user_sub=%s host_id=%s protocol=%s source=%s",
        user_sub, host_id, protocol, source,
    )
    return _item_to_host(item)


def get_host(user_sub: str, host_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single host by ID, or None if not found / not owned."""
    resp = T.host_inventory.get_item(Key={"user_sub": user_sub, "sk": _sk(host_id)})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_host(item)


def _get_raw(user_sub: str, host_id: str) -> Optional[Dict[str, Any]]:
    resp = T.host_inventory.get_item(Key={"user_sub": user_sub, "sk": _sk(host_id)})
    return resp.get("Item")


def _should_record(user_sub: str, host_id: Optional[str]) -> bool:
    """Return True if the host requires automatic SSH session recording.

    INFRA-010 / GAP-0234. Called from the hot Browser SSH WebSocket connect
    path. Falls back to False when ``host_id`` is absent, the global recording
    feature flag is off, the host is not found, or any lookup error occurs —
    this function must NEVER raise.
    """
    if not host_id:
        return False
    if not S.ssh_session_recording_enabled:
        return False
    try:
        raw = _get_raw(user_sub, host_id)
        return bool((raw or {}).get("record_sessions", False))
    except Exception:
        logger.exception("_should_record lookup failed host_id=%s", host_id)
        return False


def update_host(user_sub: str, host_id: str, **updates: Any) -> Dict[str, Any]:
    """Update mutable fields on a host entry. Raises HostNotFound if missing."""
    raw = _get_raw(user_sub, host_id)
    if not raw:
        raise HostNotFound(host_id)

    set_parts: List[str] = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}

    # Determine effective protocol (may change) for port normalization.
    protocol = raw.get("protocol", "ssh")
    if updates.get("protocol") is not None:
        protocol = _validate_protocol(updates["protocol"])

    def _set(field: str, value: Any) -> None:
        ph = f"#{field}"
        vp = f":{field}"
        names[ph] = field
        values[vp] = value
        set_parts.append(f"{ph} = {vp}")

    if updates.get("label") is not None:
        label = str(updates["label"]).strip()
        if not label:
            raise HostValidationError("label is required")
        if len(label) > 100:
            raise HostValidationError("label too long")
        _set("label", label)
        _set("label_lower", label.lower())
    if updates.get("hostname") is not None:
        _set("hostname", validate_hostname(updates["hostname"]))
    if updates.get("protocol") is not None:
        _set("protocol", protocol)
    if updates.get("port") is not None:
        _set("port", _validate_port(updates["port"], protocol))
    if updates.get("username") is not None:
        _set("username", str(updates["username"]).strip()[:64])
    if updates.get("description") is not None:
        _set("description", str(updates["description"])[:500])
    if updates.get("tags") is not None:
        _set("tags", _clean_tags(updates["tags"]))
    if updates.get("group") is not None:
        _set("group", str(updates["group"]).strip()[:50])
    if updates.get("os_type") is not None:
        _set("os_type", _validate_os_type(updates["os_type"]))
    if updates.get("is_pinned") is not None:
        _set("is_pinned", bool(updates["is_pinned"]))
    if updates.get("record_sessions") is not None:
        _set("record_sessions", bool(updates["record_sessions"]))
    if updates.get("agent_qa_allowed") is not None:
        _set("agent_qa_allowed", bool(updates["agent_qa_allowed"]))

    _set("updated_at", now_ts())

    resp = T.host_inventory.update_item(
        Key={"user_sub": user_sub, "sk": _sk(host_id)},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    _audit("remote_host.updated", user_sub, host_id=host_id)
    return _item_to_host(resp.get("Attributes", {}))


def delete_host(user_sub: str, host_id: str) -> bool:
    """Hard-delete a host entry. Returns True if it existed."""
    raw = _get_raw(user_sub, host_id)
    if not raw:
        return False
    T.host_inventory.delete_item(Key={"user_sub": user_sub, "sk": _sk(host_id)})
    _audit("remote_host.deleted", user_sub, host_id=host_id, protocol=raw.get("protocol", ""))
    return True


# ---------------------------------------------------------------------------
# Listing (loops LastEvaluatedKey — FilterExpression does NOT reduce page size)
# ---------------------------------------------------------------------------

def _scan_all_hosts(user_sub: str) -> List[Dict[str, Any]]:
    """Fetch all of a user's host items, looping LastEvaluatedKey."""
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_sub").eq(user_sub)
        & Key("sk").begins_with("HOST#"),
    }
    while True:
        resp = T.host_inventory.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def list_hosts(
    user_sub: str,
    *,
    protocol: Optional[str] = None,
    group: Optional[str] = None,
    sort_by: str = "label",  # label | last_connected | created_at
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List hosts with filtering, sorting, and simple offset pagination.

    Pagination is done in-application after a full owner-scoped query (each user
    is a small partition). ``cursor`` is the integer offset into the sorted,
    filtered result set, encoded as a string.
    """
    items = [_item_to_host(it) for it in _scan_all_hosts(user_sub)]

    if protocol:
        protocol = protocol.strip().lower()
        items = [h for h in items if h["protocol"] == protocol]
    if group is not None and group != "":
        items = [h for h in items if h["group"] == group]

    if sort_by == "last_connected":
        items.sort(key=lambda h: h["last_connected_at"], reverse=True)
    elif sort_by == "created_at":
        items.sort(key=lambda h: h["created_at"], reverse=True)
    else:  # label (default), case-insensitive alphabetical
        items.sort(key=lambda h: h["label"].lower())

    # Pinned hosts float to the top within the chosen ordering.
    items.sort(key=lambda h: 0 if h["is_pinned"] else 1)

    total = len(items)
    try:
        offset = int(cursor) if cursor else 0
    except (TypeError, ValueError):
        offset = 0
    if offset < 0:
        offset = 0
    limit = max(1, min(int(limit or 100), 500))

    page = items[offset : offset + limit]
    next_cursor: Optional[str] = None
    if offset + limit < total:
        next_cursor = str(offset + limit)

    return {"hosts": page, "count": total, "cursor": next_cursor}


def list_groups(user_sub: str) -> List[str]:
    """Return distinct, sorted group names from the user's hosts."""
    groups = set()
    for it in _scan_all_hosts(user_sub):
        g = it.get("group")
        if g:
            groups.add(str(g))
    return sorted(groups)


# ---------------------------------------------------------------------------
# Connection tracking + history
# ---------------------------------------------------------------------------

def record_connection(user_sub: str, host_id: str) -> Optional[Dict[str, Any]]:
    """Update last_connected_at, increment connection_count, append a history
    event. Returns the updated host, or None if the host does not exist."""
    raw = _get_raw(user_sub, host_id)
    if not raw:
        return None
    ts = now_ts()
    protocol = raw.get("protocol", "ssh")
    history = list(raw.get("history", []) or [])
    history.insert(0, {"connected_at": ts, "protocol": protocol})
    history = history[:MAX_HISTORY_EVENTS]

    resp = T.host_inventory.update_item(
        Key={"user_sub": user_sub, "sk": _sk(host_id)},
        UpdateExpression=(
            "SET last_connected_at = :ts, updated_at = :ts, #history = :h, "
            "connection_count = if_not_exists(connection_count, :zero) + :one, "
            "#status = :online"
        ),
        ExpressionAttributeNames={"#history": "history", "#status": "status"},
        ExpressionAttributeValues={
            ":ts": ts,
            ":zero": 0,
            ":one": 1,
            ":h": history,
            ":online": "online",
        },
        ReturnValues="ALL_NEW",
    )
    attrs = resp.get("Attributes", {})
    logger.info(
        "connection_recorded user_sub=%s host_id=%s protocol=%s connection_count=%s",
        user_sub, host_id, protocol, attrs.get("connection_count"),
    )
    return _item_to_host(attrs)


def get_history(user_sub: str, host_id: str) -> Optional[Dict[str, Any]]:
    """Return connection history for a host, or None if not found."""
    raw = _get_raw(user_sub, host_id)
    if not raw:
        return None
    events = []
    for ev in (raw.get("history", []) or []):
        try:
            events.append(
                {"connected_at": int(ev.get("connected_at", 0)), "protocol": ev.get("protocol", "ssh")}
            )
        except (TypeError, ValueError):
            continue
    return {
        "host_id": host_id,
        "connection_count": int(raw.get("connection_count", 0) or 0),
        "last_connected_at": int(raw.get("last_connected_at", 0) or 0),
        "events": events,
    }


# ---------------------------------------------------------------------------
# Quick-connect
# ---------------------------------------------------------------------------

def quick_connect(user_sub: str, host_id: str) -> Optional[Dict[str, Any]]:
    """Resolve a saved host into the params needed to launch an SSH/VNC session.

    Returns connection METADATA only (no secrets). Records the connection as a
    side effect (bumps last_connected_at + connection_count + history).
    """
    raw = _get_raw(user_sub, host_id)
    if not raw:
        return None
    host = _item_to_host(raw)
    protocol = host["protocol"]

    out: Dict[str, Any] = {
        "host_id": host_id,
        "protocol": protocol,
        "hostname": host["hostname"],
        "port": host["port"],
        "username": host["username"],
        "label": host["label"],
        "target_id": "",
        "ws_url": "",
        "connect_path": "",
    }
    if protocol == "vnc":
        # The VNC session system resolves "user:{host_id}" via the inventory.
        out["target_id"] = f"user:{host_id}"
        out["ws_url"] = f"ws://{host['hostname']}:{host['port']}/websockify"
        out["connect_path"] = f"/remote?target_id=user:{host_id}"
    else:
        # SSH/RDP: frontend pre-fills the terminal connect form.
        params = f"host={host['hostname']}&port={host['port']}"
        if host["username"]:
            params += f"&username={host['username']}"
        out["connect_path"] = f"/remote/ssh?{params}"

    # Record the connection (best-effort; connection still proceeds on failure).
    try:
        record_connection(user_sub, host_id)
    except Exception:  # pragma: no cover - tracking is fire-and-forget
        logger.warning("record_connection failed for host_id=%s", host_id)
    return out


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------

def import_hosts_csv(user_sub: str, csv_content: str) -> Dict[str, Any]:
    """Parse a CSV payload and bulk-create host entries.

    Expected header columns (case-insensitive):
        label,hostname,port,protocol,group,os_type,description,tags
    Returns {"imported": int, "skipped": int, "errors": [str, ...]}.
    """
    errors: List[str] = []
    imported = 0
    skipped = 0

    if not csv_content or not csv_content.strip():
        return {"imported": 0, "skipped": 0, "errors": ["CSV is empty"]}

    reader = csv.DictReader(io.StringIO(csv_content))
    if not reader.fieldnames:
        return {"imported": 0, "skipped": 0, "errors": ["CSV has no header row"]}

    # Normalize header names.
    field_map = {(name or "").strip().lower(): name for name in reader.fieldnames}
    if "hostname" not in field_map or "label" not in field_map:
        return {
            "imported": 0,
            "skipped": 0,
            "errors": ["CSV must include 'label' and 'hostname' columns"],
        }

    rows = list(reader)
    if len(rows) > CSV_MAX_ROWS:
        logger.warning(
            "csv_import_too_large user_sub=%s row_count=%s max_allowed=%s",
            user_sub, len(rows), CSV_MAX_ROWS,
        )
        raise HostValidationError(
            f"CSV exceeds maximum of {CSV_MAX_ROWS} hosts ({len(rows)} rows)"
        )

    seen_labels: set = set()
    for idx, row in enumerate(rows, start=2):  # line 1 is the header
        def g(key: str, default: str = "") -> str:
            src = field_map.get(key)
            if src is None:
                return default
            return (row.get(src) or "").strip()

        label = g("label")
        if not label:
            errors.append(f"row {idx}: missing label")
            skipped += 1
            continue
        if label.lower() in seen_labels:
            errors.append(f"row {idx}: duplicate label '{label}' within import")
            skipped += 1
            continue

        raw_tags = g("tags")
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

        try:
            create_host(
                user_sub,
                label=label,
                hostname=g("hostname"),
                port=g("port") or None,
                protocol=g("protocol", "ssh") or "ssh",
                description=g("description"),
                tags=tags,
                group=g("group"),
                os_type=g("os_type", "unknown") or "unknown",
                source="csv_import",
            )
        except HostValidationError as exc:
            errors.append(f"row {idx}: {exc}")
            skipped += 1
            continue

        seen_labels.add(label.lower())
        imported += 1

    _audit(
        "remote_host.csv_import",
        user_sub,
        imported=imported,
        skipped=skipped,
        errors=len(errors),
    )
    logger.info(
        "csv_import_complete user_sub=%s imported=%s skipped=%s errors=%s total_rows=%s",
        user_sub, imported, skipped, len(errors), len(rows),
    )
    return {"imported": imported, "skipped": skipped, "errors": errors}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, **fields)
    except Exception:  # pragma: no cover - audit must never break the request
        logger.debug("audit_event failed for %s", event, exc_info=True)
