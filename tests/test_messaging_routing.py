from app.services.messaging_routing import (
    RoutingTransitionError,
    RoutingTransitionInput,
    transition_helpdesk_routing,
    build_routing_event_item,
)


def _base_conversation(**overrides):
    base = {
        "conversation_id": "c1",
        "routing_mode": "helpdesk_bridge",
        "routing_group_id": "helpdesk-l1",
        "routing_state": "awaiting_agent",
        "assignment_version": 0,
        "active_agent_user_id": "",
    }
    base.update(overrides)
    return base


def test_assign_agent_success():
    out = transition_helpdesk_routing(
        _base_conversation(),
        RoutingTransitionInput(action="assign_agent", now_ts=101, agent_user_id="agent-1", expected_assignment_version=0),
    )
    assert out.from_state == "awaiting_agent"
    assert out.to_state == "assigned"
    assert out.event_type == "helpdesk.conversation.assigned"
    assert out.patch["active_agent_user_id"] == "agent-1"
    assert out.patch["assignment_version"] == 1


def test_assign_agent_requires_agent_id():
    try:
        transition_helpdesk_routing(
            _base_conversation(),
            RoutingTransitionInput(action="assign_agent", now_ts=101),
        )
        assert False, "expected RoutingTransitionError"
    except RoutingTransitionError as exc:
        assert exc.code == "routing_assign_agent_required"


def test_assign_agent_invalid_state_fails():
    try:
        transition_helpdesk_routing(
            _base_conversation(routing_state="paused_no_agents_online"),
            RoutingTransitionInput(action="assign_agent", now_ts=101, agent_user_id="agent-1"),
        )
        assert False, "expected RoutingTransitionError"
    except RoutingTransitionError as exc:
        assert exc.code == "routing_assign_invalid_state"


def test_release_agent_success():
    out = transition_helpdesk_routing(
        _base_conversation(routing_state="assigned", active_agent_user_id="agent-1", assignment_version=3),
        RoutingTransitionInput(action="release_agent", now_ts=202, agent_user_id="agent-1", expected_assignment_version=3),
    )
    assert out.to_state == "awaiting_agent"
    assert out.event_type == "helpdesk.conversation.released"
    assert out.patch["active_agent_user_id"] == ""
    assert out.patch["last_failover_at"] == 202
    assert out.patch["assignment_version"] == 4


def test_release_agent_mismatch_fails():
    try:
        transition_helpdesk_routing(
            _base_conversation(routing_state="assigned", active_agent_user_id="agent-1"),
            RoutingTransitionInput(action="release_agent", now_ts=202, agent_user_id="agent-2"),
        )
        assert False, "expected RoutingTransitionError"
    except RoutingTransitionError as exc:
        assert exc.code == "routing_release_agent_mismatch"


def test_pause_resume_success_path():
    paused = transition_helpdesk_routing(
        _base_conversation(routing_state="awaiting_agent", assignment_version=1),
        RoutingTransitionInput(action="pause_no_agents", now_ts=333, expected_assignment_version=1),
    )
    assert paused.to_state == "paused_no_agents_online"
    assert paused.event_type == "helpdesk.conversation.no_agents_online"
    assert paused.patch["no_agents_notice_sent_at"] == 333

    resumed = transition_helpdesk_routing(
        _base_conversation(routing_state="paused_no_agents_online", assignment_version=2),
        RoutingTransitionInput(action="resume_awaiting", now_ts=444),
    )
    assert resumed.to_state == "awaiting_agent"
    assert resumed.event_type == "helpdesk.conversation.alerted"


def test_version_conflict_fails():
    try:
        transition_helpdesk_routing(
            _base_conversation(assignment_version=5),
            RoutingTransitionInput(action="assign_agent", now_ts=1, agent_user_id="a1", expected_assignment_version=4),
        )
        assert False, "expected RoutingTransitionError"
    except RoutingTransitionError as exc:
        assert exc.code == "routing_assignment_version_conflict"


def test_non_helpdesk_conversation_fails():
    try:
        transition_helpdesk_routing(
            _base_conversation(routing_mode="standard", routing_state="none"),
            RoutingTransitionInput(action="assign_agent", now_ts=1, agent_user_id="a1"),
        )
        assert False, "expected RoutingTransitionError"
    except RoutingTransitionError as exc:
        assert exc.code == "routing_mode_not_helpdesk_bridge"


def test_closed_is_terminal():
    try:
        transition_helpdesk_routing(
            _base_conversation(routing_state="closed"),
            RoutingTransitionInput(action="assign_agent", now_ts=1, agent_user_id="a1"),
        )
        assert False, "expected RoutingTransitionError"
    except RoutingTransitionError as exc:
        assert exc.code == "routing_conversation_closed"


def test_close_idempotent_when_already_closed():
    out = transition_helpdesk_routing(
        _base_conversation(routing_state="closed"),
        RoutingTransitionInput(action="close", now_ts=10),
    )
    assert out.changed is False
    assert out.to_state == "closed"


def test_build_routing_event_item_contains_timeline_fields():
    transition = transition_helpdesk_routing(
        _base_conversation(),
        RoutingTransitionInput(action="assign_agent", now_ts=101, agent_user_id="agent-1"),
    )
    event = build_routing_event_item(
        conversation=_base_conversation(),
        transition=transition,
        actor_user_id="agent-1",
        created_at=101,
        event_id="0000000101#evt",
        metadata={"source": "claim"},
    )
    assert event["conversation_id"] == "c1"
    assert event["from_state"] == "awaiting_agent"
    assert event["to_state"] == "assigned"
    assert event["assignment_version"] == 1
    assert event["metadata"]["source"] == "claim"
