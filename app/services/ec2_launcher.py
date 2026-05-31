"""EC2 instance launcher — launch, stop, start, terminate, reboot instances.

Uses in-memory mock in dev mode; real boto3 EC2 client in production.
INFRA-003 implementation.
"""

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Instance type allowlist with cost metadata (cents per minute)
# ---------------------------------------------------------------------------

INSTANCE_TYPES: Dict[str, Dict[str, Any]] = {
    "t3.micro":  {"vcpu": 2, "memory_gb": 1,   "cost_cents_per_min": 0.2},
    "t3.small":  {"vcpu": 2, "memory_gb": 2,   "cost_cents_per_min": 0.4},
    "t3.medium": {"vcpu": 2, "memory_gb": 4,   "cost_cents_per_min": 0.8},
    "t3.large":  {"vcpu": 2, "memory_gb": 8,   "cost_cents_per_min": 1.5},
}

# Curated AMI list
AMIS: Dict[str, Dict[str, str]] = {
    "ami-ubuntu-2204":  {"name": "Ubuntu 22.04 LTS",      "os_type": "linux",   "username": "ubuntu"},
    "ami-ubuntu-2404":  {"name": "Ubuntu 24.04 LTS",      "os_type": "linux",   "username": "ubuntu"},
    "ami-amzn2":        {"name": "Amazon Linux 2023",      "os_type": "linux",   "username": "ec2-user"},
    "ami-windows-2022": {"name": "Windows Server 2022",    "os_type": "windows", "username": "Administrator"},
}

DEFAULT_AUTO_TERMINATE_SECONDS = 7200  # 2 hours


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
        instance_id: str,
        instance_type: str,
        ami_id: str,
        key_name: str | None = None,
        user_data: str | None = None,
    ) -> Dict[str, Any]:
        mock_ec2_id = f"i-mock{uuid.uuid4().hex[:12]}"
        ip_a, ip_b = random.randint(1, 254), random.randint(1, 254)
        instance = {
            "ec2_instance_id": mock_ec2_id,
            "instance_type": instance_type,
            "ami_id": ami_id,
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
        if inst and inst["status"] == "stopped":
            inst["status"] = "running"
            return True
        return False

    def terminate(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst:
            inst["status"] = "terminated"
            return True
        return False

    def reboot(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst and inst["status"] == "running":
            # In mock mode reboot is instant — instance stays running
            return True
        return False

    def describe(self, ec2_instance_id: str) -> Dict[str, Any] | None:
        return self._instances.get(ec2_instance_id)


_mock_store = _MockEc2Store()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def launch_instance(
    user_sub: str,
    *,
    label: str,
    instance_type: str,
    ami_id: str,
    ssh_key_id: str | None = None,
    auto_terminate_after: int = DEFAULT_AUTO_TERMINATE_SECONDS,
    startup_script: str = "",
    template_id: str | None = None,
    security_group_id: str | None = None,
) -> Dict[str, Any]:
    """Launch a new EC2 instance (mock in dev mode)."""

    # 1. Validate instance type
    if instance_type not in INSTANCE_TYPES:
        raise ValueError(f"Instance type {instance_type} not allowed")

    # 2. Validate AMI
    if ami_id not in AMIS:
        raise ValueError(f"AMI {ami_id} not available")

    # 2b. Resolve security group (INFRA-009). If none provided, auto-create/use
    #     the user's default SG. A provided SG must belong to the user.
    resolved_sg_id = ""
    if S.security_groups_enabled:
        from app.services.security_groups import (
            resolve_for_launch,
            SecurityGroupNotFound,
        )
        try:
            sg = resolve_for_launch(user_sub, security_group_id)
        except SecurityGroupNotFound as exc:
            raise ValueError(str(exc))
        resolved_sg_id = sg["sg_id"]

    # 3. Check instance limit (active = running + stopped + launching)
    active = [
        i for i in list_instances(user_sub)
        if i.get("status") in ("running", "stopped", "launching", "stopping")
    ]
    if len(active) >= S.ec2_max_instances_per_user:
        raise InstanceLimitExceeded(
            f"Maximum {S.ec2_max_instances_per_user} active instances allowed"
        )

    # 3b. Enforce per-user admin quota (INFRA-012)
    if S.admin_compute_dashboard_enabled:
        from app.services.admin_compute import (
            enforce_ec2_quota,
            QuotaExceeded,
            SpendingLimitReached,
        )
        try:
            enforce_ec2_quota(user_sub, instance_type)
        except (QuotaExceeded, SpendingLimitReached) as e:
            raise InstanceLimitExceeded(str(e))

    # 4. Launch (mock or real)
    instance_id = uuid.uuid4().hex
    if S.ec2_mock_enabled:
        result = _mock_store.launch(
            instance_id=instance_id,
            instance_type=instance_type,
            ami_id=ami_id,
            user_data=startup_script,
        )
    else:
        # Real EC2 launch would go here
        raise NotImplementedError("Real EC2 launch not implemented yet")

    # 5. Store in DDB
    now = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": f"INSTANCE#{instance_id}",
        "instance_id": instance_id,
        "ec2_instance_id": result["ec2_instance_id"],
        "label": label,
        "instance_type": instance_type,
        "ami_id": ami_id,
        "ami_name": AMIS[ami_id]["name"],
        "status": "running",
        "public_ip": result["public_ip"],
        "private_ip": result["private_ip"],
        "ssh_key_id": ssh_key_id or "",
        "host_id": "",
        "created_at": now,
        "started_at": now,
        "stopped_at": 0,
        "terminated_at": 0,
        "last_activity_at": now,
        "auto_terminate_after": auto_terminate_after,
        "startup_script": startup_script,
        "template_id": template_id or "",
        "source": "template" if template_id else "manual",
        "security_group_id": resolved_sg_id,
    }
    T.ec2_instances.put_item(Item=item)

    # Record the SG association (INFRA-009)
    if resolved_sg_id:
        try:
            from app.services.security_groups import associate_instance
            associate_instance(user_sub, resolved_sg_id, instance_id)
        except Exception:
            logger.exception("sg_associate_failed instance_id=%s sg_id=%s", instance_id, resolved_sg_id)

    logger.info(
        "ec2_launched user_sub=%s instance_id=%s type=%s ami=%s",
        user_sub, instance_id, instance_type, ami_id,
    )

    return item


def list_instances(
    user_sub: str,
    *,
    status: str | None = None,
) -> List[Dict[str, Any]]:
    """List user's instances with optional status filter."""
    resp = T.ec2_instances.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub)
        & Key("sk").begins_with("INSTANCE#"),
    )
    items = resp.get("Items", [])

    if status:
        items = [i for i in items if i.get("status") == status]

    # Sort by created_at descending (newest first)
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)

    return items


def get_instance(user_sub: str, instance_id: str) -> Dict[str, Any] | None:
    """Get a single instance by ID."""
    resp = T.ec2_instances.get_item(
        Key={"user_sub": user_sub, "sk": f"INSTANCE#{instance_id}"}
    )
    return resp.get("Item")


def stop_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Stop a running instance."""
    item = get_instance(user_sub, instance_id)
    if not item:
        raise InstanceNotFound(f"Instance {instance_id} not found")

    if item["status"] != "running":
        raise InvalidInstanceState(
            f"Cannot stop instance in '{item['status']}' state (must be 'running')"
        )

    ec2_id = item["ec2_instance_id"]
    if S.ec2_mock_enabled:
        _mock_store.stop(ec2_id)

    now = now_ts()
    T.ec2_instances.update_item(
        Key={"user_sub": user_sub, "sk": f"INSTANCE#{instance_id}"},
        UpdateExpression="SET #st = :st, stopped_at = :sa",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "stopped", ":sa": now},
    )

    item["status"] = "stopped"
    item["stopped_at"] = now
    logger.info("ec2_stopped user_sub=%s instance_id=%s", user_sub, instance_id)
    return item


def start_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Start a stopped instance."""
    item = get_instance(user_sub, instance_id)
    if not item:
        raise InstanceNotFound(f"Instance {instance_id} not found")

    if item["status"] != "stopped":
        raise InvalidInstanceState(
            f"Cannot start instance in '{item['status']}' state (must be 'stopped')"
        )

    ec2_id = item["ec2_instance_id"]
    if S.ec2_mock_enabled:
        _mock_store.start(ec2_id)

    now = now_ts()
    T.ec2_instances.update_item(
        Key={"user_sub": user_sub, "sk": f"INSTANCE#{instance_id}"},
        UpdateExpression="SET #st = :st, started_at = :sa, last_activity_at = :la",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "running", ":sa": now, ":la": now},
    )

    item["status"] = "running"
    item["started_at"] = now
    item["last_activity_at"] = now
    logger.info("ec2_started user_sub=%s instance_id=%s", user_sub, instance_id)
    return item


def terminate_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Terminate an instance (irreversible)."""
    item = get_instance(user_sub, instance_id)
    if not item:
        raise InstanceNotFound(f"Instance {instance_id} not found")

    if item["status"] in ("terminated", "terminating"):
        raise InvalidInstanceState(
            f"Instance is already '{item['status']}'"
        )

    ec2_id = item["ec2_instance_id"]
    if S.ec2_mock_enabled:
        _mock_store.terminate(ec2_id)

    now = now_ts()
    T.ec2_instances.update_item(
        Key={"user_sub": user_sub, "sk": f"INSTANCE#{instance_id}"},
        UpdateExpression="SET #st = :st, terminated_at = :ta",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "terminated", ":ta": now},
    )

    # Disassociate from its security group so the SG can be deleted (INFRA-009)
    sg_id = item.get("security_group_id")
    if sg_id:
        try:
            from app.services.security_groups import disassociate_instance
            disassociate_instance(user_sub, sg_id, instance_id)
        except Exception:
            logger.exception("sg_disassociate_failed instance_id=%s sg_id=%s", instance_id, sg_id)

    item["status"] = "terminated"
    item["terminated_at"] = now
    logger.info("ec2_terminated user_sub=%s instance_id=%s", user_sub, instance_id)
    return item


def reboot_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Reboot a running instance."""
    item = get_instance(user_sub, instance_id)
    if not item:
        raise InstanceNotFound(f"Instance {instance_id} not found")

    if item["status"] != "running":
        raise InvalidInstanceState(
            f"Cannot reboot instance in '{item['status']}' state (must be 'running')"
        )

    ec2_id = item["ec2_instance_id"]
    if S.ec2_mock_enabled:
        _mock_store.reboot(ec2_id)

    now = now_ts()
    T.ec2_instances.update_item(
        Key={"user_sub": user_sub, "sk": f"INSTANCE#{instance_id}"},
        UpdateExpression="SET last_activity_at = :la",
        ExpressionAttributeValues={":la": now},
    )

    item["last_activity_at"] = now
    logger.info("ec2_rebooted user_sub=%s instance_id=%s", user_sub, instance_id)
    return item


def check_idle_instances() -> int:
    """Scan for instances idle beyond their auto_terminate_after threshold.

    Returns count of instances auto-terminated.
    """
    now = now_ts()
    terminated = 0

    # Scan all records — in production this would use a GSI on status=running
    resp = T.ec2_instances.scan(
        FilterExpression="attribute_exists(instance_id) AND #st = :running",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":running": "running"},
    )
    items = resp.get("Items", [])

    for item in items:
        last_activity = int(item.get("last_activity_at", 0))
        threshold = int(item.get("auto_terminate_after", DEFAULT_AUTO_TERMINATE_SECONDS))
        if last_activity > 0 and (now - last_activity) > threshold:
            try:
                terminate_instance(item["user_sub"], item["instance_id"])
                terminated += 1
                logger.info(
                    "ec2_auto_terminated user_sub=%s instance_id=%s idle_seconds=%d",
                    item["user_sub"], item["instance_id"], now - last_activity,
                )
            except Exception:
                logger.exception(
                    "ec2_auto_terminate_failed instance_id=%s",
                    item.get("instance_id"),
                )

    return terminated


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------

async def run_idle_instance_checker(*, poll_interval: int = 300) -> None:
    """Background task: every 5 minutes scan and terminate idle instances."""
    while True:
        try:
            count = check_idle_instances()
            if count:
                logger.info("auto_terminated %d idle EC2 instances", count)
        except Exception:
            logger.exception("idle_instance_checker error")
        await asyncio.sleep(poll_interval)


def start_ec2_idle_checker_task() -> None:
    """Register the idle checker background task at app startup."""
    if S.ec2_auto_terminate_enabled:
        asyncio.ensure_future(run_idle_instance_checker())
        logger.info("EC2 idle instance checker started")


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------

class InstanceLimitExceeded(Exception):
    pass


class InstanceNotFound(Exception):
    pass


class InvalidInstanceState(Exception):
    pass
