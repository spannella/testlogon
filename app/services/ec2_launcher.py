"""EC2 Launcher -- stub for AGENT-004 dependency.

Provides mock implementations for dev mode.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from uuid import uuid4

logger = logging.getLogger(__name__)


def launch_instance(user_id: str, instance_type: str = "t3.medium", **kwargs: Any) -> Dict[str, Any]:
    """Launch an EC2 instance (mock in dev mode)."""
    ec2_id = f"i-{uuid4().hex[:16]}"
    logger.info("ec2.launch user_id=%s instance_type=%s ec2_id=%s", user_id, instance_type, ec2_id)
    return {
        "ec2_instance_id": ec2_id,
        "public_ip": f"10.0.{hash(ec2_id) % 256}.{hash(ec2_id + 'x') % 256}",
        "instance_type": instance_type,
    }


def stop_instance(user_id: str, instance_id: str) -> Dict[str, Any]:
    """Stop an EC2 instance (mock)."""
    logger.info("ec2.stop user_id=%s instance_id=%s", user_id, instance_id)
    return {"status": "stopped", "instance_id": instance_id}


def start_instance(user_id: str, instance_id: str) -> Dict[str, Any]:
    """Start a stopped EC2 instance (mock)."""
    logger.info("ec2.start user_id=%s instance_id=%s", user_id, instance_id)
    return {"status": "running", "instance_id": instance_id}


def terminate_instance(user_id: str, instance_id: str) -> Dict[str, Any]:
    """Terminate an EC2 instance (mock)."""
    logger.info("ec2.terminate user_id=%s instance_id=%s", user_id, instance_id)
    return {"status": "terminated", "instance_id": instance_id}


def start_ec2_idle_checker_task():
    """Background task placeholder."""
    pass
