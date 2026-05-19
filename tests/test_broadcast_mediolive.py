from __future__ import annotations

from unittest.mock import patch

from app.services import broadcast_mediolive


class _FakeMediaLiveClient:
    def __init__(self) -> None:
        self.inputs = []
        self.channels = []
        self.create_input_calls = 0
        self.create_channel_calls = 0
        self.fail_once = True

    def list_inputs(self, MaxResults=1000):  # noqa: N803
        return {"Inputs": self.inputs}

    def list_channels(self, MaxResults=1000):  # noqa: N803
        return {"Channels": self.channels}

    def create_input(self, **kwargs):
        self.create_input_calls += 1
        if self.fail_once:
            self.fail_once = False
            raise broadcast_mediolive.ClientError({"Error": {"Code": "ThrottlingException", "Message": "slow down"}}, "CreateInput")
        item = {"Id": "in-1", "Arn": "arn:aws:medialive:input:in-1", "Name": kwargs["Name"]}
        self.inputs.append(item)
        return {"Input": item}

    def create_channel(self, **kwargs):
        self.create_channel_calls += 1
        item = {"Id": "ch-1", "Arn": "arn:aws:medialive:channel:ch-1", "Name": kwargs["Name"], "State": "CREATING"}
        self.channels.append(item)
        return {"Channel": item}


def test_provision_is_idempotent_and_retries_transient_errors() -> None:
    fake = _FakeMediaLiveClient()
    with (
        patch.object(broadcast_mediolive, "_client", return_value=fake),
        patch.object(broadcast_mediolive.time, "sleep"),
    ):
        first = broadcast_mediolive.provision_mediolive_input_and_channel(
            session_id="sess-1",
            correlation_id="cid-1",
            idempotency_key="idem-1",
        )
        second = broadcast_mediolive.provision_mediolive_input_and_channel(
            session_id="sess-1",
            correlation_id="cid-1",
            idempotency_key="idem-1",
        )

    assert first.input_arn == second.input_arn
    assert first.channel_arn == second.channel_arn
    assert first.archive_prefix.startswith("s3://")
    assert fake.create_input_calls == 2  # first throttled once + one successful creation
    assert fake.create_channel_calls == 1  # second call reuses existing channel by deterministic name
