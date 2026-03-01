from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from app.models import DeployEvent, DeployResponse, DeployStatus


class DeployStage(str, Enum):
    PREFLIGHT = 'preflight_checks'
    PLAN = 'plan_change_set'
    APPLY = 'apply_changes'
    POST_DEPLOY = 'post_deploy_checks'


def next_deploy_run_id() -> str:
    return str(uuid4())


def execute_live_deploy(session_config: dict) -> tuple[DeployStatus, list[DeployEvent], dict[str, str]]:
    events: list[DeployEvent] = []
    outputs: dict[str, str] = {}

    stage_runners = [
        (DeployStage.PREFLIGHT, _run_preflight),
        (DeployStage.PLAN, _run_plan),
        (DeployStage.APPLY, _run_apply),
        (DeployStage.POST_DEPLOY, _run_post_deploy),
    ]

    for stage, runner in stage_runners:
        try:
            result = runner(session_config)
            if result:
                outputs.update(result)
            events.append(
                DeployEvent(
                    stage=stage.value,
                    status=DeployStatus.SUCCESS.value,
                    message=_success_message(stage),
                    details=result,
                    created_at=datetime.now(tz=timezone.utc),
                )
            )
        except ValueError as exc:
            events.append(
                DeployEvent(
                    stage=stage.value,
                    status=DeployStatus.FAILED.value,
                    message=str(exc),
                    created_at=datetime.now(tz=timezone.utc),
                )
            )
            return DeployStatus.FAILED, events, outputs

    return DeployStatus.SUCCESS, events, outputs


def _success_message(stage: DeployStage) -> str:
    return {
        DeployStage.PREFLIGHT: 'Preflight checks passed.',
        DeployStage.PLAN: 'Plan/change-set stage completed.',
        DeployStage.APPLY: 'Apply stage completed.',
        DeployStage.POST_DEPLOY: 'Post-deploy checks passed.',
    }[stage]


def _run_preflight(cfg: dict) -> dict[str, str] | None:
    account_id = cfg['deployment_context']['aws_account_id']
    owner_email = cfg['deployment_context']['owner_email']
    if not account_id.isdigit() or len(account_id) != 12:
        raise ValueError('Invalid AWS account ID format in deployment context.')
    if account_id.startswith('000'):
        raise ValueError('Preflight failed: account not enabled for production deploys.')
    if owner_email.endswith('@invalid.local'):
        raise ValueError('Preflight failed: owner email domain is not allowed.')
    return None


def _run_plan(cfg: dict) -> dict[str, str]:
    app_name = cfg['deployment_context']['app_name']
    if 'fail-plan' in app_name:
        raise ValueError('Plan stage failed: unable to create change set for application.')
    return {'change_set_id': f'cs-{app_name[:10]}', 'planned_resources': '6'}


def _run_apply(cfg: dict) -> dict[str, str]:
    vpc_id = cfg['deployment_options']['vpc_id']
    app_name = cfg['deployment_context']['app_name']
    if 'fail-apply' in vpc_id:
        raise ValueError('Apply stage failed: provisioning error while creating network resources.')
    return {
        'stack_name': f'{app_name}-prod',
        'api_url': f'https://{app_name}.internal.example.com',
        'artifact_bucket': f'{app_name}-artifacts',
    }


def _run_post_deploy(cfg: dict) -> dict[str, str]:
    if cfg['deployment_options']['instance_count'] < 1:
        raise ValueError('Post-deploy checks failed: invalid instance count after apply.')
    return {'health_check': 'ok', 'latency_p95_ms': '120'}


def build_deploy_response(
    session_id: str,
    run_id: str,
    status: DeployStatus,
    events: list[DeployEvent],
    outputs: dict[str, str],
) -> DeployResponse:
    return DeployResponse(
        session_id=session_id,
        run_id=run_id,
        status=status.value,
        events=events,
        outputs=outputs,
    )
