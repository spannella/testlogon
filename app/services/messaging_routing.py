from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Mapping, Optional

RoutingMode = Literal["standard", "helpdesk_bridge"]
RoutingState = Literal["none", "awaiting_agent", "assigned", "paused_no_agents_online", "closed"]
RoutingAction = Literal["assign_agent", "release_agent", "pause_no_agents", "resume_awaiting", "alert_awaiting", "close", "transfer_agent"]


@dataclass(frozen=True)
class RoutingTransitionError(Exception):
    code: str
    message: str


@dataclass(frozen=True)
class RoutingTransitionResult:
    from_state: RoutingState
    to_state: RoutingState
    changed: bool
    event_type: str
    patch: Dict[str, Any]


@dataclass(frozen=True)
class RoutingTransitionInput:
    action: RoutingAction
    now_ts: int
    agent_user_id: Optional[str] = None
    expected_assignment_version: Optional[int] = None


def _state(item: Mapping[str, Any]) -> RoutingState:
    return str(item.get("routing_state") or "none")  # type: ignore[return-value]


def _mode(item: Mapping[str, Any]) -> RoutingMode:
    return str(item.get("routing_mode") or "standard")  # type: ignore[return-value]


def _assignment_version(item: Mapping[str, Any]) -> int:
    try:
        return int(item.get("assignment_version") or 0)
    except (TypeError, ValueError):
        return 0


def _state_group_pk(next_state: RoutingState, group_id: str) -> str:
    return f"{next_state}#{group_id}"


def build_routing_event_item(
    *,
    conversation: Mapping[str, Any],
    transition: RoutingTransitionResult,
    actor_user_id: str,
    created_at: int,
    event_id: str,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "conversation_id": str(conversation.get("conversation_id") or ""),
        "event_id": event_id,
        "event_type": transition.event_type,
        "actor_user_id": actor_user_id,
        "from_state": transition.from_state,
        "to_state": transition.to_state,
        "created_at": int(created_at),
        "assignment_version": int(transition.patch.get("assignment_version") or conversation.get("assignment_version") or 0),
        "routing_group_id": str(conversation.get("routing_group_id") or ""),
        "active_agent_user_id": str(transition.patch.get("active_agent_user_id") or ""),
        "metadata": dict(metadata or {}),
    }


def transition_helpdesk_routing(
    conversation: Mapping[str, Any],
    cmd: RoutingTransitionInput,
) -> RoutingTransitionResult:
    mode = _mode(conversation)
    if mode != "helpdesk_bridge":
        raise RoutingTransitionError(
            code="routing_mode_not_helpdesk_bridge",
            message="routing transitions are only valid for helpdesk bridge conversations",
        )

    from_state = _state(conversation)
    if from_state == "closed" and cmd.action != "close":
        raise RoutingTransitionError(
            code="routing_conversation_closed",
            message="conversation routing is closed",
        )

    current_version = _assignment_version(conversation)
    if cmd.expected_assignment_version is not None and cmd.expected_assignment_version != current_version:
        raise RoutingTransitionError(
            code="routing_assignment_version_conflict",
            message="assignment version mismatch",
        )

    group_id = str(conversation.get("routing_group_id") or "")
    base_patch: Dict[str, Any] = {
        "routing_mode": "helpdesk_bridge",
        "routing_group_id": group_id,
    }

    if cmd.action == "assign_agent":
        if from_state != "awaiting_agent":
            raise RoutingTransitionError(
                code="routing_assign_invalid_state",
                message="agent can only be assigned from awaiting_agent state",
            )
        if not cmd.agent_user_id:
            raise RoutingTransitionError(code="routing_assign_agent_required", message="agent_user_id is required")
        to_state: RoutingState = "assigned"
        return RoutingTransitionResult(
            from_state=from_state,
            to_state=to_state,
            changed=True,
            event_type="helpdesk.conversation.assigned",
            patch={
                **base_patch,
                "routing_state": to_state,
                "active_agent_user_id": cmd.agent_user_id,
                "active_agent_claimed_at": int(cmd.now_ts),
                "assignment_version": current_version + 1,
                "routing_state_group_pk": _state_group_pk(to_state, group_id),
                "routing_state_group_sk": str(conversation.get("conversation_id") or ""),
            },
        )

    if cmd.action == "release_agent":
        if from_state != "assigned":
            raise RoutingTransitionError(
                code="routing_release_invalid_state",
                message="agent can only be released from assigned state",
            )
        current_agent = str(conversation.get("active_agent_user_id") or "")
        if cmd.agent_user_id and current_agent and cmd.agent_user_id != current_agent:
            raise RoutingTransitionError(
                code="routing_release_agent_mismatch",
                message="agent_user_id does not match active agent",
            )
        to_state = "awaiting_agent"
        return RoutingTransitionResult(
            from_state=from_state,
            to_state=to_state,
            changed=True,
            event_type="helpdesk.conversation.released",
            patch={
                **base_patch,
                "routing_state": to_state,
                "active_agent_user_id": "",
                "last_failover_at": int(cmd.now_ts),
                "assignment_version": current_version + 1,
                "routing_state_group_pk": _state_group_pk(to_state, group_id),
                "routing_state_group_sk": str(conversation.get("conversation_id") or ""),
            },
        )

    if cmd.action == "pause_no_agents":
        if from_state not in {"awaiting_agent", "assigned"}:
            raise RoutingTransitionError(
                code="routing_pause_invalid_state",
                message="conversation can only be paused from awaiting_agent or assigned state",
            )
        to_state = "paused_no_agents_online"
        return RoutingTransitionResult(
            from_state=from_state,
            to_state=to_state,
            changed=True,
            event_type="helpdesk.conversation.no_agents_online",
            patch={
                **base_patch,
                "routing_state": to_state,
                "active_agent_user_id": "",
                "no_agents_notice_sent_at": int(cmd.now_ts),
                "assignment_version": current_version + 1,
                "routing_state_group_pk": _state_group_pk(to_state, group_id),
                "routing_state_group_sk": str(conversation.get("conversation_id") or ""),
            },
        )

    if cmd.action == "resume_awaiting":
        if from_state != "paused_no_agents_online":
            raise RoutingTransitionError(
                code="routing_resume_invalid_state",
                message="conversation can only resume from paused_no_agents_online state",
            )
        to_state = "awaiting_agent"
        return RoutingTransitionResult(
            from_state=from_state,
            to_state=to_state,
            changed=True,
            event_type="helpdesk.conversation.alerted",
            patch={
                **base_patch,
                "routing_state": to_state,
                "routing_state_group_pk": _state_group_pk(to_state, group_id),
                "routing_state_group_sk": str(conversation.get("conversation_id") or ""),
            },
        )


    if cmd.action == "alert_awaiting":
        if from_state != "awaiting_agent":
            raise RoutingTransitionError(
                code="routing_alert_invalid_state",
                message="conversation can only be alerted from awaiting_agent state",
            )
        return RoutingTransitionResult(
            from_state=from_state,
            to_state="awaiting_agent",
            changed=False,
            event_type="helpdesk.conversation.alerted",
            patch={},
        )

    if cmd.action == "close":
        if from_state == "closed":
            return RoutingTransitionResult(
                from_state=from_state,
                to_state="closed",
                changed=False,
                event_type="helpdesk.conversation.closed",
                patch={},
            )
        to_state = "closed"
        return RoutingTransitionResult(
            from_state=from_state,
            to_state=to_state,
            changed=True,
            event_type="helpdesk.conversation.closed",
            patch={
                **base_patch,
                "routing_state": to_state,
                "active_agent_user_id": "",
                "assignment_version": current_version + 1,
                "routing_state_group_pk": _state_group_pk(to_state, group_id),
                "routing_state_group_sk": str(conversation.get("conversation_id") or ""),
            },
        )

    if cmd.action == "transfer_agent":
        if from_state != "assigned":
            raise RoutingTransitionError(
                code="routing_transfer_invalid_state",
                message="agent can only be transferred from assigned state",
            )
        if not cmd.agent_user_id:
            raise RoutingTransitionError(code="routing_transfer_agent_required", message="agent_user_id is required")
        to_state = "assigned"
        return RoutingTransitionResult(
            from_state=from_state,
            to_state=to_state,
            changed=True,
            event_type="helpdesk.conversation.transferred",
            patch={
                **base_patch,
                "routing_state": to_state,
                "active_agent_user_id": cmd.agent_user_id,
                "active_agent_claimed_at": int(cmd.now_ts),
                "assignment_version": current_version + 1,
                "routing_state_group_pk": _state_group_pk(to_state, group_id),
                "routing_state_group_sk": str(conversation.get("conversation_id") or ""),
            },
        )

    raise RoutingTransitionError(code="routing_action_not_supported", message=f"unsupported action: {cmd.action}")
