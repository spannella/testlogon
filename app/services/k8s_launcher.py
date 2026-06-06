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

# Host inventory integration (INFRA-001) — imported at module level so the
# auto-register (GAP-0226) and auto-cleanup (GAP-0227) paths are easily
# monkeypatched in tests as ``app.services.k8s_launcher.create_host`` /
# ``delete_host``. These are pure DynamoDB operations with no dev/prod fork,
# so they run identically under the mock and real K8s paths (SECOPS-007).
from app.services.host_inventory import (  # noqa: E402
    create_host,
    delete_host,
    HostValidationError,
    HostLimitExceeded,
)

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
# Real Kubernetes client helpers (production path only — gated on
# `not S.k8s_mock_enabled`). The `kubernetes` package is an OPTIONAL/prod-only
# dependency: it is imported lazily inside these helpers so the module always
# imports cleanly in dev/CI where the package is not installed (SECOPS-007:
# dev/mock path must remain reachable without the prod dependency).
# ---------------------------------------------------------------------------

# Cached CoreV1Api client (lazy-initialised). Patch this to None to force a
# re-load, or monkeypatch `_get_k8s_core_v1` directly in tests.
_k8s_core_v1_cache: Any = None


def _get_k8s_core_v1():
    """Return a ``kubernetes.client.CoreV1Api`` instance.

    Loads in-cluster config when running inside a pod (``KUBERNETES_SERVICE_HOST``
    is set), otherwise falls back to a kubeconfig file (``KUBECONFIG`` env var,
    or the default location). The result is cached for the process lifetime.

    Raises ``RuntimeError`` (not ``ImportError``) when the optional ``kubernetes``
    package is not installed so callers get an actionable message instead of a
    raw import failure.
    """
    global _k8s_core_v1_cache
    if _k8s_core_v1_cache is not None:
        return _k8s_core_v1_cache

    try:
        from kubernetes import client as k8s_client  # type: ignore
        from kubernetes import config as k8s_config  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only in prod
        raise RuntimeError(
            "kubernetes package not installed. "
            "Run: pip install 'kubernetes>=28.1.0'"
        ) from exc

    import os

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        k8s_config.load_incluster_config()
    else:
        kubeconfig = os.environ.get("KUBECONFIG", "")
        k8s_config.load_kube_config(config_file=kubeconfig or None)

    _k8s_core_v1_cache = k8s_client.CoreV1Api()
    return _k8s_core_v1_cache


def _real_k8s_launch(
    *,
    pod_name: str,
    namespace: str,
    image: str,
    cpu_millicores: int,
    memory_mb: int,
    env_vars: dict,
    ssh_pub_key: str | None,
) -> Dict[str, Any]:
    """Launch a real Kubernetes pod via ``create_namespaced_pod``.

    Mirrors the shape returned by ``_MockK8sStore.create_pod`` so the caller can
    treat mock and real results identically.
    """
    from kubernetes import client as k8s_client  # type: ignore

    core_v1 = _get_k8s_core_v1()

    env_list = [
        k8s_client.V1EnvVar(name=str(k), value=str(v))
        for k, v in (env_vars or {}).items()
    ]
    if ssh_pub_key:
        env_list.append(
            k8s_client.V1EnvVar(name="SSH_PUBLIC_KEY", value=ssh_pub_key)
        )

    container = k8s_client.V1Container(
        name="workspace",
        image=image,
        env=env_list,
        resources=k8s_client.V1ResourceRequirements(
            requests={
                "cpu": f"{cpu_millicores}m",
                "memory": f"{memory_mb}Mi",
            },
            limits={
                "cpu": f"{cpu_millicores * 2}m",
                "memory": f"{memory_mb * 2}Mi",
            },
        ),
        ports=[k8s_client.V1ContainerPort(container_port=22)],
    )
    pod_spec = k8s_client.V1Pod(
        metadata=k8s_client.V1ObjectMeta(
            name=pod_name,
            namespace=namespace,
            labels={
                "app": "platform-workspace",
                "managed-by": "k8s-launcher",
            },
        ),
        spec=k8s_client.V1PodSpec(
            containers=[container],
            restart_policy="Never",
        ),
    )

    # Ensure the per-user namespace exists (idempotent — already-exists is fine).
    try:
        core_v1.create_namespace(
            k8s_client.V1Namespace(
                metadata=k8s_client.V1ObjectMeta(name=namespace)
            )
        )
    except Exception:  # already exists or insufficient perms (namespace pre-created)
        pass

    pod = core_v1.create_namespaced_pod(namespace=namespace, body=pod_spec)

    status = getattr(pod, "status", None)
    metadata = getattr(pod, "metadata", None)
    return {
        "pod_name": getattr(metadata, "name", pod_name) or pod_name,
        "namespace": getattr(metadata, "namespace", namespace) or namespace,
        "status": getattr(status, "phase", None) or "pending",
        "pod_ip": getattr(status, "pod_ip", None) or "",
        "service_hostname": f"{pod_name}.{namespace}.svc.cluster.local",
    }


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
        result = _real_k8s_launch(
            pod_name=k8s_pod_name,
            namespace=namespace,
            image=image,
            cpu_millicores=preset_info["cpu_millicores"],
            memory_mb=preset_info["memory_mb"],
            env_vars=env_vars or {},
            ssh_pub_key=None,  # inject via env_vars if needed
        )

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

    # 7. Auto-register in the Host Inventory (GAP-0226) so the pod is reachable
    #    via Quick Connect / connection profiles, and write the resulting
    #    host_id back into the pod record so termination can clean it up
    #    (GAP-0227). Failure to register must NOT fail the launch — the pod is
    #    already created — so create_host errors are logged and swallowed.
    try:
        host = create_host(
            user_sub,
            label=f"{label} (K8s)",
            hostname=result["service_hostname"],
            port=22,
            protocol="ssh",
            username=image_info.get("username", "ubuntu"),
            description=f"Auto-registered K8s pod {pod_id} (preset={preset})",
            group="K8s Containers",
            os_type=image_info.get("os_type", "linux"),
            source="k8s_auto",
        )
        host_id = host.get("host_id", "")
        if host_id:
            T.k8s_pods.update_item(
                Key={"user_sub": user_sub, "sk": f"POD#{pod_id}"},
                UpdateExpression="SET host_id = :hid",
                ExpressionAttributeValues={":hid": host_id},
            )
            item["host_id"] = host_id
            logger.info(
                "k8s_pod_host_registered user_sub=%s pod_id=%s host_id=%s",
                user_sub, pod_id, host_id,
            )
    except (HostValidationError, HostLimitExceeded):
        logger.warning(
            "k8s_pod_host_register_failed user_sub=%s pod_id=%s hostname=%s",
            user_sub, pod_id, result.get("service_hostname"),
        )
    except Exception:
        logger.exception(
            "k8s_pod_host_register_error user_sub=%s pod_id=%s",
            user_sub, pod_id,
        )

    logger.info(
        "k8s_pod_launched user_sub=%s pod_id=%s image=%s preset=%s ttl=%d host_id=%s",
        user_sub, pod_id, image, preset, ttl_seconds, item.get("host_id", ""),
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

    # Real K8s logs
    core_v1 = _get_k8s_core_v1()
    try:
        log_str = core_v1.read_namespaced_pod_log(
            name=k8s_pod_name,
            namespace=namespace,
            tail_lines=tail,
        )
    except Exception as exc:
        logger.exception(
            "k8s_log_fetch_failed pod=%s namespace=%s", k8s_pod_name, namespace
        )
        raise PodNotFound(
            f"Could not fetch logs for pod {k8s_pod_name}: {exc}"
        ) from exc
    return log_str.splitlines() if log_str else []


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
    else:
        from kubernetes import client as k8s_client  # type: ignore

        core_v1 = _get_k8s_core_v1()
        try:
            core_v1.delete_namespaced_pod(
                name=k8s_pod_name,
                namespace=namespace,
                body=k8s_client.V1DeleteOptions(grace_period_seconds=0),
            )
        except Exception:
            # Log but do not block the DDB status update — a missing pod (already
            # gone) must still flip the record to "terminated".
            logger.exception(
                "k8s_pod_delete_failed pod=%s namespace=%s",
                k8s_pod_name, namespace,
            )

    now = now_ts()
    T.k8s_pods.update_item(
        Key={"user_sub": user_sub, "sk": f"POD#{pod_id}"},
        UpdateExpression="SET #st = :st, terminated_at = :ta",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "terminated", ":ta": now},
    )

    item["status"] = "terminated"
    item["terminated_at"] = now

    # Clean up the auto-registered Host Inventory entry (GAP-0227). The
    # `if host_id:` guard makes this a no-op for pods created before GAP-0226
    # (host_id == ""). delete_host returns False for an unknown host (it never
    # raises HostNotFound), so a broad except is sufficient; cleanup failures
    # must not roll back the already-completed termination.
    host_id = item.get("host_id", "")
    if host_id:
        try:
            delete_host(user_sub, host_id)
            logger.info(
                "k8s_pod_host_deregistered user_sub=%s pod_id=%s host_id=%s",
                user_sub, pod_id, host_id,
            )
        except Exception:
            logger.exception(
                "k8s_pod_host_deregister_failed user_sub=%s pod_id=%s host_id=%s",
                user_sub, pod_id, host_id,
            )

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
