from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from app.models import ArtifactDiffEntry, GeneratedArtifact


def _canonical_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _stable_hash(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def build_artifacts(session_config: dict, schema_version: str) -> list[GeneratedArtifact]:
    generated_at = datetime.now(tz=timezone.utc)

    env_lines = [
        f"SCHEMA_VERSION={schema_version}",
        f"APP_NAME={session_config['deployment_context']['app_name']}",
        f"AWS_REGION={session_config['deployment_context']['region']}",
        f"VPC_ID={session_config['deployment_options']['vpc_id']}",
        f"ENABLE_HELPDESK={str(session_config['optional_features']['enable_helpdesk']).lower()}",
        f"ENABLE_MESSAGING={str(session_config['optional_features']['enable_messaging']).lower()}",
    ]
    env_content = '\n'.join(env_lines) + '\n'

    service_cfg = {
        'schema_version': schema_version,
        'deployment_context': session_config['deployment_context'],
        'optional_features': session_config['optional_features'],
        'feature_config': session_config['feature_config'],
    }
    service_cfg_content = _canonical_json(service_cfg)

    iac_params = {
        'version': schema_version,
        'account_id': session_config['deployment_context']['aws_account_id'],
        'region': session_config['deployment_context']['region'],
        'app_name': session_config['deployment_context']['app_name'],
        'vpc_id': session_config['deployment_options']['vpc_id'],
        'subnets': session_config['deployment_options']['subnet_ids'],
    }
    iac_params_content = _canonical_json(iac_params)

    artifacts = [
        GeneratedArtifact(
            name='.env.template',
            version=schema_version,
            hash=_stable_hash(env_content),
            generated_at=generated_at,
            content=env_content,
        ),
        GeneratedArtifact(
            name='service.config.json',
            version=schema_version,
            hash=_stable_hash(service_cfg_content),
            generated_at=generated_at,
            content=service_cfg_content,
        ),
        GeneratedArtifact(
            name='iac.params.json',
            version=schema_version,
            hash=_stable_hash(iac_params_content),
            generated_at=generated_at,
            content=iac_params_content,
        ),
    ]

    return artifacts


def next_run_id() -> str:
    return str(uuid4())


def build_diff(current_artifacts: list[GeneratedArtifact], previous_artifacts: list[GeneratedArtifact]) -> list[ArtifactDiffEntry]:
    prev = {a.name: a.content for a in previous_artifacts}
    curr = {a.name: a.content for a in current_artifacts}

    diff: list[ArtifactDiffEntry] = []
    for name in sorted(set(prev.keys()) | set(curr.keys())):
        before = prev.get(name, '(not generated)')
        after = curr.get(name, '(removed)')
        if before != after:
            diff.append(ArtifactDiffEntry(path=name, before=before, after=after))

    return diff
