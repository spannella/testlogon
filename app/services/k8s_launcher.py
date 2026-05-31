"""Kubernetes pod launcher — launch, monitor, terminate containers.

Uses in-memory mock in dev mode; real K8s client in production.
INFRA-004 implementation (stub for AGENT-002).
"""

from __future__ import annotations

import logging
import random
import uuid
from typing import Any, Dict

from app.core.settings import S

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mock K8s store (in-memory, dev mode only)
# ---------------------------------------------------------------------------

class _MockK8sStore:
    """In-memory K8s pod store for dev mode."""

    def __init__(self) -> None:
        self._pods: Dict[str, Dict[str, Any]] = {}

    def create_pod(
        self,
        *,
        pod_name: str | None = None,
        namespace: str = "default",
        image: str = "ubuntu-ssh",
        env_vars: dict | None = None,
    ) -> Dict[str, Any]:
        name = pod_name or f"pod-agent-{uuid.uuid4().hex[:8]}"
        ip_a, ip_b = random.randint(1, 254), random.randint(1, 254)
        pod = {
            "pod_name": name,
            "namespace": namespace,
            "status": "running",
            "pod_ip": f"10.pod.{ip_a}.{ip_b}",
        }
        self._pods[name] = pod
        return pod

    def delete_pod(self, pod_name: str) -> bool:
        pod = self._pods.get(pod_name)
        if pod:
            pod["status"] = "terminated"
            return True
        return False


_mock_store = _MockK8sStore()


def launch_pod(
    user_id: str,
    *,
    namespace: str = "default",
    image: str = "ubuntu-ssh",
    env_vars: dict | None = None,
) -> Dict[str, Any]:
    """Launch a K8s pod (mock in dev mode)."""
    return _mock_store.create_pod(namespace=namespace, image=image, env_vars=env_vars)


def delete_pod(user_id: str, pod_name: str) -> bool:
    """Delete a K8s pod."""
    return _mock_store.delete_pod(pod_name)
