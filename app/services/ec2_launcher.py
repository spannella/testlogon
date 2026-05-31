"""EC2 instance launcher — launch, stop, start, terminate instances.

Uses in-memory mock in dev mode; real boto3 EC2 client in production.
INFRA-003 implementation (stub for AGENT-002).
"""

from __future__ import annotations

import logging
import random
import uuid
from typing import Any, Dict

from app.core.settings import S

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mock EC2 store (in-memory, dev mode only)
# ---------------------------------------------------------------------------

class _MockEc2Store:
    """In-memory EC2 instance store for dev mode."""

    def __init__(self) -> None:
        self._instances: Dict[str, Dict[str, Any]] = {}

    def launch(
        self,
        *,
        instance_type: str = "t3.medium",
        user_data: str | None = None,
    ) -> Dict[str, Any]:
        mock_ec2_id = f"i-mock{uuid.uuid4().hex[:12]}"
        ip_a, ip_b = random.randint(1, 254), random.randint(1, 254)
        instance = {
            "ec2_instance_id": mock_ec2_id,
            "instance_type": instance_type,
            "status": "running",
            "public_ip": f"10.mock.{ip_a}.{ip_b}",
            "private_ip": f"172.16.{ip_a}.{ip_b}",
        }
        self._instances[mock_ec2_id] = instance
        return instance

    def stop(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst:
            inst["status"] = "stopped"
            return True
        return False

    def start(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst:
            inst["status"] = "running"
            return True
        return False

    def terminate(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst:
            inst["status"] = "terminated"
            return True
        return False


_mock_store = _MockEc2Store()


def launch_instance(
    user_id: str,
    *,
    instance_type: str = "t3.medium",
    user_data: str | None = None,
) -> Dict[str, Any]:
    """Launch an EC2 instance (mock in dev mode)."""
    return _mock_store.launch(instance_type=instance_type, user_data=user_data)


def stop_instance(user_id: str, ec2_instance_id: str) -> bool:
    """Stop an EC2 instance."""
    return _mock_store.stop(ec2_instance_id)


def start_instance(user_id: str, ec2_instance_id: str) -> bool:
    """Start a stopped EC2 instance."""
    return _mock_store.start(ec2_instance_id)


def terminate_instance(user_id: str, ec2_instance_id: str) -> bool:
    """Terminate an EC2 instance."""
    return _mock_store.terminate(ec2_instance_id)
