from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from app.models import DeployEvent, DeployStatus


class MockScenario(str, Enum):
    SUCCESS = 'success'
    PLAN_FAILURE = 'plan_failure'
    APPLY_FAILURE = 'apply_failure'
    POST_DEPLOY_FAILURE = 'post_deploy_failure'


SCENARIO_FIXTURES: dict[MockScenario, dict[str, object]] = {
    MockScenario.SUCCESS: {
        'fail_stage': None,
        'outputs': {
            'change_set_id': 'mock-cs-0001',
            'planned_resources': '5',
            'stack_name': 'mock-stack-abc123',
            'api_url': 'https://mock-api.internal.example.com',
            'artifact_bucket': 'mock-artifacts-bucket-001',
            'health_check': 'ok',
            'latency_p95_ms': '42',
        },
    },
    MockScenario.PLAN_FAILURE: {
        'fail_stage': 'plan_change_set',
        'error': 'SIMULATED: unable to produce change set due to policy validation failure.',
    },
    MockScenario.APPLY_FAILURE: {
        'fail_stage': 'apply_changes',
        'error': 'SIMULATED: apply failed while provisioning network resources.',
    },
    MockScenario.POST_DEPLOY_FAILURE: {
        'fail_stage': 'post_deploy_checks',
        'error': 'SIMULATED: post-deploy health checks reported elevated error rate.',
    },
}


class DeployExecutionClient(Protocol):
    def execute(self, scenario: MockScenario) -> tuple[DeployStatus, list[DeployEvent], dict[str, str]]:
        raise NotImplementedError


class MockDeployExecutionClient:
    def execute(self, scenario: MockScenario) -> tuple[DeployStatus, list[DeployEvent], dict[str, str]]:
        fixture = SCENARIO_FIXTURES[scenario]
        fail_stage = fixture.get('fail_stage')
        outputs = fixture.get('outputs', {})

        events: list[DeployEvent] = []
        stages = [
            'preflight_checks',
            'plan_change_set',
            'apply_changes',
            'post_deploy_checks',
        ]

        for stage in stages:
            if fail_stage == stage:
                events.append(
                    DeployEvent(
                        stage=stage,
                        status=DeployStatus.FAILED.value,
                        message=str(fixture['error']),
                        created_at=datetime.now(tz=timezone.utc),
                    )
                )
                return DeployStatus.FAILED, events, _outputs_for_completed_stages(outputs, events)

            events.append(
                DeployEvent(
                    stage=stage,
                    status=DeployStatus.SUCCESS.value,
                    message=f'SIMULATED: {stage} completed using mock cloud/provider clients.',
                    details={'synthetic': 'true', 'scenario': scenario.value},
                    created_at=datetime.now(tz=timezone.utc),
                )
            )

        return DeployStatus.SUCCESS, events, dict(outputs)


def _outputs_for_completed_stages(all_outputs: dict[str, str], events: list[DeployEvent]) -> dict[str, str]:
    stage_names = {event.stage for event in events}
    outputs: dict[str, str] = {}
    if 'plan_change_set' in stage_names:
        outputs['change_set_id'] = all_outputs.get('change_set_id', 'mock-cs')
        outputs['planned_resources'] = all_outputs.get('planned_resources', '0')
    if 'apply_changes' in stage_names:
        outputs['stack_name'] = all_outputs.get('stack_name', 'mock-stack')
        outputs['api_url'] = all_outputs.get('api_url', 'https://mock.invalid')
        outputs['artifact_bucket'] = all_outputs.get('artifact_bucket', 'mock-bucket')
    if 'post_deploy_checks' in stage_names:
        outputs['health_check'] = all_outputs.get('health_check', 'unknown')
        outputs['latency_p95_ms'] = all_outputs.get('latency_p95_ms', '0')
    return outputs


def resolve_scenario(value: str | None) -> MockScenario:
    if value is None:
        return MockScenario.SUCCESS
    normalized = value.strip().lower()
    for scenario in MockScenario:
        if scenario.value == normalized:
            return scenario
    return MockScenario.SUCCESS


def default_mock_deploy_execution_client() -> MockDeployExecutionClient:
    return MockDeployExecutionClient()
