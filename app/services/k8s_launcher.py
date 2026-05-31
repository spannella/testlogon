"""Kubernetes pod launcher — launch, monitor, terminate containers.

Uses in-memory mock in dev mode; real K8s client in production.
INFRA-004 implementation.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import uuid
from typing import Any, Dict, List

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource presets
# ---------------------------------------------------------------------------

RESOURCE_PRESETS: Dict[str, Dict[str, Any]] = {
    "small":  {"cpu_millicores": 250,  "memory_mb": 256,  "cost_cents_per_min": 0.1},
    "medium": {"cpu_millicores": 500,  "memory_mb": 512,  "cost_cents_per_min": 0.3},
    "large":  {"cpu_millicores": 1000, "memory_mb": 1024, "cost_cents_per_min": 0.6},
    "xlarge": {"cpu_millicores": 2000, "memory_mb": 4096, "cost_cents_per_min": 1.2},
}

# Curated image allowlist
IMAGE_ALLOWLIST: Dict[str, Dict[str, str]] = {
    "ubuntu-ssh":    {"display_name": "Ubuntu SSH",    "os_type": "linux", "username": "ubuntu"},
    "alpine-ssh":    {"display_name": "Alpine SSH",    "os_type": "linux", "username": "alpine"},
    "dev-workspace": {"display_name": "Dev Workspace", "os_type": "linux", "username": "dev"},
}

MAX_PODS_PER_USER = 5
DEFAULT_TTL_SECONDS = 14400  # 4 hours


# ---------------------------------------------------------------------------
# Mock K8s store (in-memory, dev mode only)
# ---------------------------------------------------------------------------

class _MockK8sStore:
    """In-memory K8s pod store for dev mode."""

    def __init__(self) -> None:
        self._pods: Dict[str, Dict[str, Any]] = {}
        self._logs: Dict[str, List[str]] = {}

    def create_pod(
        self,
        *,
        pod_name: str,
        namespace: str,
        image: str,
        cpu: int,
        memory_mb: int,
        env_vars: dict,
        ssh_pub_key: str | None,
    ) -> Dict[str, Any]:
        ip_a, ip_b = random.randint(1, 254), random.randint(1, 254)
        pod = {
            "pod_name": pod_name,
            "namespace": namespace,
            "status": "running",  # mock goes straight to running
            "pod_ip": f"10.pod.{ip_a}.{ip_b}",
            "service_hostname": f"{pod_name}.{namespace}.svc.cluster.local",
        }
        self._pods[pod_name] = pod
        self._logs[pod_name] = [
            "Starting SSH server on port 22...",
            "SSH server ready. Accepting connections.",
            f"Container {image} started successfully.",
        ]
        return pod

    def delete_pod(self, pod_name: str, namespace: str) -> bool:
        pod = self._pods.get(pod_name)
        if pod:
            pod["status"] = "terminated"
            return True
        return False

    def get_logs(self, pod_name: str, namespace: str, tail: int = 100) -> List[str]:
        return self._logs.get(pod_name, [])[-tail:]


_mock_store = _MockK8sStore()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_namespace(user_sub: str) -> str:
    """Generate a K8s-valid namespace from user_sub (first 12 chars, lowercase alnum + hyphen)."""
    clean = re.sub(r"[^a-z0-9-]", "-", user_sub[:12].lower()).strip("-")
    return f"user-{clean}" if clean else "user-default"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def launch_pod(
    user_sub: str,
    *,
    label: str,
    image: str,
    preset: str = "small",
    ssh_key_id: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    env_vars: dict | None = None,
    template_id: str | None = None,
) -> Dict[str, Any]:
    """Launch a new container pod."""

    # 1. Validate image
    if image not in IMAGE_ALLOWLIST:
        raise InvalidImage(f"Image '{image}' not in allowed image list")

    # 2. Validate preset
    if preset not in RESOURCE_PRESETS:
        raise InvalidPreset(f"Unknown preset '{preset}'")

    # 3. Check pod limit (running or pending only)
    active = [
        p for p in list_pods(user_sub)
        if p.get("status") in ("running", "pending")
    ]
    max_pods = S.k8s_max_pods_per_user
    if len(active) >= max_pods:
        raise PodLimitReached(
            f"Maximum {max_pods} running pods. Terminate one first."
        )

    # 3b. Enforce per-user admin quota (INFRA-012)
    if S.admin_compute_dashboard_enabled:
        from app.services.admin_compute import (
            enforce_k8s_quota,
            QuotaExceeded,
            SpendingLimitReached,
        )
        try:
            enforce_k8s_quota(user_sub, preset)
        except (QuotaExceeded, SpendingLimitReached) as e:
            raise PodLimitReached(str(e))

    # 4. Build pod metadata
    pod_id = f"p_{uuid.uuid4().hex[:8]}"
    namespace = _sanitize_namespace(user_sub)
    short_sub = re.sub(r"[^a-z0-9]", "", user_sub[:12].lower())
    k8s_pod_name = f"ws-{short_sub}-{pod_id[2:]}"
    preset_info = RESOURCE_PRESETS[preset]
    image_info = IMAGE_ALLOWLIST[image]

    # 5. Launch (mock or real)
    if S.k8s_mock_enabled:
        result = _mock_store.create_pod(
            pod_name=k8s_pod_name,
            namespace=namespace,
            image=image,
            cpu=preset_info["cpu_millicores"],
            memory_mb=preset_info["memory_mb"],
            env_vars=env_vars or {},
            ssh_pub_key=None,  # mock ignores SSH key
        )
    else:
        raise NotImplementedError("Real K8s launch not implemented yet")

    # 6. Store in DDB
    now = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": f"POD#{pod_id}",
        "pod_id": pod_id,
        "k8s_pod_name": k8s_pod_name,
        "namespace": namespace,
        "label": label,
        "image": image,
        "image_display_name": image_info["display_name"],
        "preset": preset,
        "cpu_millicores": preset_info["cpu_millicores"],
        "memory_mb": preset_info["memory_mb"],
        "status": "running",
        "pod_ip": result["pod_ip"],
        "service_hostname": result["service_hostname"],
        "ssh_port": 22,
        "ssh_key_id": ssh_key_id or "",
        "host_id": "",
        "created_at": now,
        "started_at": now,
        "terminated_at": 0,
        "ttl_seconds": ttl_seconds,
        "expires_at": now + ttl_seconds,
        "last_activity_at": 0,
        "template_id": template_id or "",
    }
    T.k8s_pods.put_item(Item=item)

    logger.info(
        "k8s_pod_launched user_sub=%s pod_id=%s image=%s preset=%s ttl=%d",
        user_sub, pod_id, image, preset, ttl_seconds,
    )

    return item


def list_pods(
    user_sub: str,
    *,
    status: str | None = None,
) -> List[Dict[str, Any]]:
    """List user's pods with optional status filter."""
    resp = T.k8s_pods.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub)
        & Key("sk").begins_with("POD#"),
    )
    items = resp.get("Items", [])

    if status:
        items = [i for i in items if i.get("status") == status]

    # Sort by created_at descending (newest first)
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)

    return items


def get_pod(user_sub: str, pod_id: str) -> Dict[str, Any] | None:
    """Get a single pod by ID."""
    resp = T.k8s_pods.get_item(
        Key={"user_sub": user_sub, "sk": f"POD#{pod_id}"}
    )
    return resp.get("Item")


def get_pod_logs(user_sub: str, pod_id: str, *, tail: int = 100) -> List[str]:
    """Get recent container logs."""
    item = get_pod(user_sub, pod_id)
    if not item:
        raise PodNotFound("Pod not found")

    k8s_pod_name = item.get("k8s_pod_name", "")
    namespace = item.get("namespace", "")

    if S.k8s_mock_enabled:
        return _mock_store.get_logs(k8s_pod_name, namespace, tail=tail)

    raise NotImplementedError("Real K8s logs not implemented yet")


def terminate_pod(user_sub: str, pod_id: str) -> Dict[str, Any]:
    """Delete a pod (immediate termination)."""
    item = get_pod(user_sub, pod_id)
    if not item:
        raise PodNotFound("Pod not found")

    if item["status"] in ("terminated",):
        raise PodAlreadyTerminated("Pod already terminated")

    k8s_pod_name = item.get("k8s_pod_name", "")
    namespace = item.get("namespace", "")

    if S.k8s_mock_enabled:
        _mock_store.delete_pod(k8s_pod_name, namespace)

    now = now_ts()
    T.k8s_pods.update_item(
        Key={"user_sub": user_sub, "sk": f"POD#{pod_id}"},
        UpdateExpression="SET #st = :st, terminated_at = :ta",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "terminated", ":ta": now},
    )

    item["status"] = "terminated"
    item["terminated_at"] = now
    logger.info("k8s_pod_terminated user_sub=%s pod_id=%s", user_sub, pod_id)
    return item


def check_expired_pods() -> int:
    """Background task: find pods past their TTL and terminate them.

    Returns count of pods auto-terminated.
    """
    now = now_ts()
    terminated = 0

    # Scan for running pods with expired TTL
    resp = T.k8s_pods.scan(
        FilterExpression="attribute_exists(pod_id) AND #st = :running",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":running": "running"},
    )
    items = resp.get("Items", [])

    for item in items:
        expires_at = int(item.get("expires_at", 0))
        if expires_at > 0 and now > expires_at:
            try:
                terminate_pod(item["user_sub"], item["pod_id"])
                terminated += 1
                logger.info(
                    "k8s_pod_ttl_expired user_sub=%s pod_id=%s",
                    item["user_sub"], item["pod_id"],
                )
            except Exception:
                logger.exception(
                    "k8s_pod_ttl_terminate_failed pod_id=%s",
                    item.get("pod_id"),
                )

    return terminated


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------

async def run_pod_ttl_checker(*, poll_interval: int = 300) -> None:
    """Background task: every 5 minutes scan and terminate expired pods."""
    while True:
        try:
            count = check_expired_pods()
            if count:
                logger.info("auto_terminated %d expired K8s pods", count)
        except Exception:
            logger.exception("pod_ttl_checker error")
        await asyncio.sleep(poll_interval)


def start_k8s_ttl_checker_task() -> None:
    """Register the TTL checker background task at app startup."""
    if S.k8s_ttl_checker_enabled:
        asyncio.ensure_future(run_pod_ttl_checker())
        logger.info("K8s pod TTL checker started")


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------

class InvalidImage(Exception):
    pass


class InvalidPreset(Exception):
    pass


class PodLimitReached(Exception):
    pass


class PodNotFound(Exception):
    pass


class PodAlreadyTerminated(Exception):
    pass
