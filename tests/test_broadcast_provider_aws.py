"""Unit tests for AwsBroadcastProvider start/stop/status/teardown operations.

These tests mock the boto3 MediaLive and MediaPackage clients to verify
that the provider correctly:
- Polls channel state transitions
- Handles timeout scenarios
- Maps MediaLive states to broadcast states
- Performs teardown in correct order
- Handles already-deleted resources gracefully
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, call

import pytest

from app.models_broadcast import BroadcastSessionModel, BroadcastOutputModel
from app.services.broadcast_provider import (
    AwsBroadcastProvider,
    ProviderResult,
    _MEDIALIVE_STATE_MAP,
    _poll_channel_state,
    _poll_input_state,
)


def _make_session(session_id: str = "test-session-1", status: str = "ready") -> BroadcastSessionModel:
    return BroadcastSessionModel(
        id=session_id,
        profile_id="profile-1",
        status=status,
        created_by="user-1",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )


def _make_output(session_id: str = "test-session-1", channel_id: str = "ch-12345") -> BroadcastOutputModel:
    return BroadcastOutputModel(
        session_id=session_id,
        aws_channel_arn=f"arn:aws:medialive:us-east-1:123456789012:channel:{channel_id}",
        provider_state_snapshot={
            "provider": "aws",
            "operation": "provision",
            "state": "ready",
            "details": {
                "channel_id": channel_id,
                "input_arn": f"arn:aws:medialive:us-east-1:123456789012:input:inp-{session_id}",
            },
        },
        updated_at="2026-01-01T00:00:00+00:00",
    )


def _client_error(code: str, message: str = "error") -> Exception:
    """Create a mock ClientError with the given error code."""
    from botocore.exceptions import ClientError
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


class TestPollChannelState:
    """Tests for the _poll_channel_state helper."""

    def test_returns_immediately_on_target_state(self):
        client = MagicMock()
        client.describe_channel.return_value = {"State": "RUNNING"}

        result = _poll_channel_state(
            client, "ch-1",
            target_states={"RUNNING"},
            error_states={"CREATE_FAILED"},
            timeout_seconds=10,
            poll_interval_seconds=0.01,
        )
        assert result == "RUNNING"
        assert client.describe_channel.call_count == 1

    def test_returns_on_error_state(self):
        client = MagicMock()
        client.describe_channel.return_value = {"State": "CREATE_FAILED"}

        result = _poll_channel_state(
            client, "ch-1",
            target_states={"RUNNING"},
            error_states={"CREATE_FAILED"},
            timeout_seconds=10,
            poll_interval_seconds=0.01,
        )
        assert result == "CREATE_FAILED"

    def test_polls_until_target_reached(self):
        client = MagicMock()
        client.describe_channel.side_effect = [
            {"State": "STARTING"},
            {"State": "STARTING"},
            {"State": "RUNNING"},
        ]

        result = _poll_channel_state(
            client, "ch-1",
            target_states={"RUNNING"},
            error_states={"CREATE_FAILED"},
            timeout_seconds=10,
            poll_interval_seconds=0.01,
        )
        assert result == "RUNNING"
        assert client.describe_channel.call_count == 3

    def test_returns_last_state_on_timeout(self):
        client = MagicMock()
        client.describe_channel.return_value = {"State": "STARTING"}

        result = _poll_channel_state(
            client, "ch-1",
            target_states={"RUNNING"},
            error_states={"CREATE_FAILED"},
            timeout_seconds=0.05,
            poll_interval_seconds=0.02,
        )
        assert result == "STARTING"


class TestPollInputState:
    """Tests for the _poll_input_state helper."""

    def test_returns_immediately_on_target_state(self):
        client = MagicMock()
        client.describe_input.return_value = {"State": "DETACHED"}

        result = _poll_input_state(
            client, "inp-1",
            target_states={"DETACHED", "IDLE"},
            timeout_seconds=10,
            poll_interval_seconds=0.01,
        )
        assert result == "DETACHED"

    def test_returns_deleted_on_not_found(self):
        client = MagicMock()
        client.describe_input.side_effect = _client_error("NotFoundException")

        result = _poll_input_state(
            client, "inp-1",
            target_states={"DETACHED"},
            timeout_seconds=10,
            poll_interval_seconds=0.01,
        )
        assert result == "DELETED"


@patch("app.services.broadcast_provider._resolve_channel_id")
@patch("app.services.broadcast_provider._medialive_client")
class TestAwsStart:
    """Tests for AwsBroadcastProvider.start()."""

    def test_start_polls_until_running(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.side_effect = [
            {"State": "IDLE"},       # initial describe
            {"State": "STARTING"},   # poll 1
            {"State": "RUNNING"},    # poll 2
        ]
        client.start_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.start(session, correlation_id="corr-1")

        assert result.state == "live"
        assert result.details["channel_state"] == "RUNNING"
        assert result.details["channel_id"] == "ch-12345"
        assert "started_at" in result.details
        client.start_channel.assert_called_once_with(ChannelId="ch-12345")

    def test_start_already_running(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "RUNNING"}

        provider = AwsBroadcastProvider()
        result = provider.start(session, correlation_id="corr-1")

        assert result.state == "live"
        assert result.details["already_running"] is True
        client.start_channel.assert_not_called()

    def test_start_non_startable_state(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "STOPPING"}

        provider = AwsBroadcastProvider()
        result = provider.start(session, correlation_id="corr-1")

        assert result.state == "error"
        assert "non-startable" in result.details["error"]
        client.start_channel.assert_not_called()

    def test_start_timeout_returns_error(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        # First call is initial describe (IDLE), then all polls return STARTING
        client.describe_channel.side_effect = [
            {"State": "IDLE"},
        ] + [{"State": "STARTING"}] * 100
        client.start_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with (
            patch.object(time, "sleep"),
            patch("app.services.broadcast_provider.S") as mock_settings,
        ):
            mock_settings.broadcast_aws_start_timeout_seconds = 0.05
            mock_settings.broadcast_aws_poll_interval_seconds = 0.01
            result = provider.start(session)

        assert result.state == "error"
        assert "did not reach RUNNING" in result.details["error"]

    def test_start_error_state_during_poll(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.side_effect = [
            {"State": "IDLE"},          # initial
            {"State": "STARTING"},      # poll 1
            {"State": "CREATE_FAILED"}, # poll 2 - error
        ]
        client.start_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.start(session)

        assert result.state == "error"
        assert result.details["channel_state"] == "CREATE_FAILED"


@patch("app.services.broadcast_provider._resolve_channel_id")
@patch("app.services.broadcast_provider._medialive_client")
class TestAwsStop:
    """Tests for AwsBroadcastProvider.stop()."""

    def test_stop_polls_until_idle(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.side_effect = [
            {"State": "RUNNING"},   # initial describe
            {"State": "STOPPING"},  # poll 1
            {"State": "IDLE"},      # poll 2
        ]
        client.stop_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.stop(session, correlation_id="corr-stop")

        assert result.state == "stopped"
        assert result.details["channel_state"] == "IDLE"
        assert "stopped_at" in result.details
        client.stop_channel.assert_called_once_with(ChannelId="ch-12345")

    def test_stop_already_idle(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "IDLE"}

        provider = AwsBroadcastProvider()
        result = provider.stop(session)

        assert result.state == "stopped"
        assert result.details["already_stopped"] is True
        client.stop_channel.assert_not_called()

    def test_stop_non_stoppable_state(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "STARTING"}

        provider = AwsBroadcastProvider()
        result = provider.stop(session)

        assert result.state == "error"
        assert "non-stoppable" in result.details["error"]

    def test_stop_timeout_returns_error(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.side_effect = [
            {"State": "RUNNING"},
        ] + [{"State": "STOPPING"}] * 100
        client.stop_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with (
            patch.object(time, "sleep"),
            patch("app.services.broadcast_provider.S") as mock_settings,
        ):
            mock_settings.broadcast_aws_stop_timeout_seconds = 0.05
            mock_settings.broadcast_aws_poll_interval_seconds = 0.01
            result = provider.stop(session)

        assert result.state == "error"
        assert "did not reach IDLE" in result.details["error"]


@patch("app.services.broadcast_provider._resolve_channel_id")
@patch("app.services.broadcast_provider._medialive_client")
class TestAwsStatus:
    """Tests for AwsBroadcastProvider.status()."""

    def test_status_maps_running_to_live(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "RUNNING", "PipelinesRunningCount": 2}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "live"
        assert result.details["channel_state"] == "RUNNING"
        assert result.details["pipelines_running"] == 2

    def test_status_maps_idle_to_ready(self, mock_client_fn, mock_resolve):
        session = _make_session(status="ready")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "IDLE", "PipelinesRunningCount": 0}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "ready"
        assert result.details["channel_state"] == "IDLE"

    def test_status_maps_stopping_to_stopping(self, mock_client_fn, mock_resolve):
        session = _make_session(status="stopping")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "STOPPING"}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "stopping"

    def test_status_maps_create_failed_to_error(self, mock_client_fn, mock_resolve):
        session = _make_session(status="provisioning")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "CREATE_FAILED"}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "error"

    def test_status_maps_recovering_to_live(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "RECOVERING"}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "live"

    def test_status_not_found_returns_error(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.side_effect = _client_error("NotFoundException")

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "error"
        assert result.details["error"] == "channel_not_found"

    def test_status_unknown_state_maps_to_error(self, mock_client_fn, mock_resolve):
        session = _make_session(status="live")
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "SOME_UNKNOWN_STATE"}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == "error"

    @pytest.mark.parametrize("ml_state,expected_state", list(_MEDIALIVE_STATE_MAP.items()))
    def test_status_maps_all_known_states(self, mock_client_fn, mock_resolve, ml_state, expected_state):
        session = _make_session()
        mock_resolve.return_value = "ch-12345"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": ml_state}

        provider = AwsBroadcastProvider()
        result = provider.status(session)

        assert result.state == expected_state


@patch("app.services.broadcast_provider._find_input_by_name")
@patch("app.services.broadcast_provider._resolve_channel_id")
@patch("app.services.broadcast_provider._mediapackage_client")
@patch("app.services.broadcast_provider._medialive_client")
class TestAwsTeardown:
    """Tests for AwsBroadcastProvider.teardown()."""

    def test_teardown_deletes_channel_and_input(
        self, mock_ml_client_fn, mock_mp_client_fn, mock_resolve, mock_find_input
    ):
        session = _make_session(session_id="sess-td-1")
        mock_resolve.return_value = "ch-12345"
        ml_client = MagicMock()
        mp_client = MagicMock()
        mock_ml_client_fn.return_value = ml_client
        mock_mp_client_fn.return_value = mp_client

        # Channel is already IDLE
        ml_client.describe_channel.return_value = {"State": "IDLE"}
        ml_client.delete_channel.return_value = {}
        ml_client.delete_input.return_value = {}
        mock_find_input.return_value = {"Id": "inp-123", "Name": "broadcast-sess-td-1-input"}
        ml_client.describe_input.return_value = {"State": "DETACHED"}
        mp_client.delete_origin_endpoint.return_value = {}
        mp_client.delete_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.teardown(session)

        assert result.state == "deleted"
        assert result.details["resources_cleaned"] is True
        assert "deleted_at" in result.details
        ml_client.delete_channel.assert_called_once_with(ChannelId="ch-12345")
        ml_client.delete_input.assert_called_once_with(InputId="inp-123")
        mp_client.delete_origin_endpoint.assert_called_once_with(Id="broadcast-sess-td-1-hls")
        mp_client.delete_channel.assert_called_once_with(Id="broadcast-sess-td-1-pkg")

    def test_teardown_stops_running_channel_first(
        self, mock_ml_client_fn, mock_mp_client_fn, mock_resolve, mock_find_input
    ):
        session = _make_session(session_id="sess-td-2")
        mock_resolve.return_value = "ch-99"
        ml_client = MagicMock()
        mp_client = MagicMock()
        mock_ml_client_fn.return_value = ml_client
        mock_mp_client_fn.return_value = mp_client

        # Channel is RUNNING -- must be stopped first
        ml_client.describe_channel.side_effect = [
            {"State": "RUNNING"},   # initial check
            {"State": "STOPPING"},  # poll 1
            {"State": "IDLE"},      # poll 2 -> stopped
        ]
        ml_client.stop_channel.return_value = {}
        ml_client.delete_channel.return_value = {}
        ml_client.delete_input.return_value = {}
        mock_find_input.return_value = {"Id": "inp-99", "Name": "broadcast-sess-td-2-input"}
        ml_client.describe_input.return_value = {"State": "DETACHED"}
        mp_client.delete_origin_endpoint.return_value = {}
        mp_client.delete_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.teardown(session)

        assert result.state == "deleted"
        ml_client.stop_channel.assert_called_once_with(ChannelId="ch-99")

    def test_teardown_handles_already_deleted_resources(
        self, mock_ml_client_fn, mock_mp_client_fn, mock_resolve, mock_find_input
    ):
        session = _make_session(session_id="sess-td-3")
        mock_resolve.return_value = "ch-gone"
        ml_client = MagicMock()
        mp_client = MagicMock()
        mock_ml_client_fn.return_value = ml_client
        mock_mp_client_fn.return_value = mp_client

        # All resources already deleted (NotFoundException)
        ml_client.describe_channel.side_effect = _client_error("NotFoundException")
        ml_client.delete_channel.side_effect = _client_error("NotFoundException")
        mock_find_input.return_value = None  # input not found
        mp_client.delete_origin_endpoint.side_effect = _client_error("NotFoundException")
        mp_client.delete_channel.side_effect = _client_error("NotFoundException")

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.teardown(session)

        assert result.state == "deleted"
        assert result.details["resources_cleaned"] is True

    def test_teardown_partial_failure(
        self, mock_ml_client_fn, mock_mp_client_fn, mock_resolve, mock_find_input
    ):
        session = _make_session(session_id="sess-td-4")
        mock_resolve.return_value = "ch-fail"
        ml_client = MagicMock()
        mp_client = MagicMock()
        mock_ml_client_fn.return_value = ml_client
        mock_mp_client_fn.return_value = mp_client

        # Channel is IDLE; deletion succeeds
        ml_client.describe_channel.return_value = {"State": "IDLE"}
        ml_client.delete_channel.return_value = {}
        mock_find_input.return_value = {"Id": "inp-fail", "Name": "broadcast-sess-td-4-input"}
        ml_client.describe_input.return_value = {"State": "DETACHED"}
        ml_client.delete_input.return_value = {}
        # MediaPackage endpoint delete fails with a non-NotFoundException
        mp_client.delete_origin_endpoint.side_effect = _client_error("InternalError", "Something went wrong")
        mp_client.delete_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.teardown(session)

        assert result.state == "error"
        assert result.details["resources_may_remain"] is True
        assert len(result.details["partial_errors"]) == 1
        assert "delete_origin_endpoint" in result.details["partial_errors"][0]

    def test_teardown_no_input_found_still_succeeds(
        self, mock_ml_client_fn, mock_mp_client_fn, mock_resolve, mock_find_input
    ):
        session = _make_session(session_id="sess-td-5")
        mock_resolve.return_value = "ch-noinp"
        ml_client = MagicMock()
        mp_client = MagicMock()
        mock_ml_client_fn.return_value = ml_client
        mock_mp_client_fn.return_value = mp_client

        ml_client.describe_channel.return_value = {"State": "IDLE"}
        ml_client.delete_channel.return_value = {}
        mock_find_input.return_value = None  # No input found by name
        mp_client.delete_origin_endpoint.return_value = {}
        mp_client.delete_channel.return_value = {}

        provider = AwsBroadcastProvider()
        with patch.object(time, "sleep"):
            result = provider.teardown(session)

        assert result.state == "deleted"
        ml_client.delete_input.assert_not_called()


class TestResolveChannelId:
    """Tests for the _resolve_channel_id helper."""

    @patch("app.services.broadcast_store.get_output")
    def test_resolves_from_provider_state_snapshot(self, mock_get_output):
        from app.services.broadcast_provider import _resolve_channel_id

        mock_get_output.return_value = _make_output(channel_id="ch-from-snapshot")
        session = _make_session()

        result = _resolve_channel_id(session)
        assert result == "ch-from-snapshot"

    @patch("app.services.broadcast_store.get_output")
    def test_fallback_to_arn_parsing(self, mock_get_output):
        from app.services.broadcast_provider import _resolve_channel_id

        output = BroadcastOutputModel(
            session_id="test-session-1",
            aws_channel_arn="arn:aws:medialive:us-east-1:123456789012:channel:ch-from-arn",
            provider_state_snapshot={"details": {}},
            updated_at="2026-01-01T00:00:00+00:00",
        )
        mock_get_output.return_value = output
        session = _make_session()

        result = _resolve_channel_id(session)
        assert result == "ch-from-arn"

    @patch("app.services.broadcast_store.get_output")
    def test_raises_409_when_no_output(self, mock_get_output):
        from app.services.broadcast_provider import _resolve_channel_id

        mock_get_output.return_value = None
        session = _make_session()

        with pytest.raises(HTTPException) as exc_info:
            _resolve_channel_id(session)
        assert exc_info.value.status_code == 409

    @patch("app.services.broadcast_store.get_output")
    def test_raises_409_when_channel_id_not_resolvable(self, mock_get_output):
        from app.services.broadcast_provider import _resolve_channel_id

        output = BroadcastOutputModel(
            session_id="test-session-1",
            aws_channel_arn="",
            provider_state_snapshot={"details": {}},
            updated_at="2026-01-01T00:00:00+00:00",
        )
        mock_get_output.return_value = output
        session = _make_session()

        with pytest.raises(HTTPException) as exc_info:
            _resolve_channel_id(session)
        assert exc_info.value.status_code == 409


class TestStateMap:
    """Verify all expected MediaLive states have mappings."""

    def test_all_known_states_mapped(self):
        expected_states = {
            "CREATING", "CREATE_FAILED", "IDLE", "STARTING", "RUNNING",
            "STOPPING", "DELETING", "DELETED", "RECOVERING", "UPDATE_FAILED",
        }
        assert set(_MEDIALIVE_STATE_MAP.keys()) == expected_states

    def test_map_returns_error_for_unknown_state(self):
        assert _MEDIALIVE_STATE_MAP.get("BOGUS_STATE", "error") == "error"


class TestProviderResultContract:
    """Ensure the modified provider still satisfies the protocol contract."""

    @patch("app.services.broadcast_provider._resolve_channel_id")
    @patch("app.services.broadcast_provider._medialive_client")
    def test_start_returns_provider_result(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-1"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "RUNNING"}

        result = AwsBroadcastProvider().start(session)
        assert isinstance(result, ProviderResult)
        assert result.operation == "start"
        assert result.provider == "aws"

    @patch("app.services.broadcast_provider._resolve_channel_id")
    @patch("app.services.broadcast_provider._medialive_client")
    def test_stop_returns_provider_result(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-1"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "IDLE"}

        result = AwsBroadcastProvider().stop(session)
        assert isinstance(result, ProviderResult)
        assert result.operation == "stop"
        assert result.provider == "aws"

    @patch("app.services.broadcast_provider._resolve_channel_id")
    @patch("app.services.broadcast_provider._medialive_client")
    def test_status_returns_provider_result(self, mock_client_fn, mock_resolve):
        session = _make_session()
        mock_resolve.return_value = "ch-1"
        client = MagicMock()
        mock_client_fn.return_value = client
        client.describe_channel.return_value = {"State": "IDLE"}

        result = AwsBroadcastProvider().status(session)
        assert isinstance(result, ProviderResult)
        assert result.operation == "status"
        assert result.provider == "aws"

    @patch("app.services.broadcast_provider._find_input_by_name")
    @patch("app.services.broadcast_provider._resolve_channel_id")
    @patch("app.services.broadcast_provider._mediapackage_client")
    @patch("app.services.broadcast_provider._medialive_client")
    def test_teardown_returns_provider_result(
        self, mock_ml_fn, mock_mp_fn, mock_resolve, mock_find_input
    ):
        session = _make_session()
        mock_resolve.return_value = "ch-1"
        ml = MagicMock()
        mp = MagicMock()
        mock_ml_fn.return_value = ml
        mock_mp_fn.return_value = mp
        ml.describe_channel.return_value = {"State": "IDLE"}
        ml.delete_channel.return_value = {}
        mock_find_input.return_value = None
        mp.delete_origin_endpoint.side_effect = _client_error("NotFoundException")
        mp.delete_channel.side_effect = _client_error("NotFoundException")

        with patch.object(time, "sleep"):
            result = AwsBroadcastProvider().teardown(session)
        assert isinstance(result, ProviderResult)
        assert result.operation == "teardown"
        assert result.provider == "aws"


# Import here to avoid issues with fixture ordering
from fastapi import HTTPException
