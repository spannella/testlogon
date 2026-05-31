"""K8s Launcher -- stub for AGENT-004 dependency.

Provides mock implementations for dev mode.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from uuid import uuid4

logger = logging.getLogger(__name__)


def launch_pod(user_id: str, **kwargs: Any) -> Dict[str, Any]:
    """Launch a K8s pod (mock in dev mode)."""
    pod_name = f"pod-{uuid4().hex[:12]}"
    logger.info("k8s.launch user_id=%s pod=%s", user_id, pod_name)
    return {
        "pod_name": pod_name,
        "pod_ip": f"172.16.{hash(pod_name) % 256}.{hash(pod_name + 'x') % 256}",
    }


def terminate_pod(user_id: str, pod_name: str) -> Dict[str, Any]:
    """Terminate a K8s pod (mock)."""
    logger.info("k8s.terminate user_id=%s pod=%s", user_id, pod_name)
    return {"status": "terminated", "pod_name": pod_name}


def start_k8s_ttl_checker_task():
    """Background task placeholder."""
    pass
