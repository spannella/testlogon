from __future__ import annotations

from app.models import DeploymentSession

REDACTED = 'REDACTED_SECRET_VALUE'


def redact_secret(value: str) -> str:
    _ = value
    return REDACTED


def redact_config_payload(config: dict) -> dict:
    redacted = dict(config)
    required = dict(redacted.get('required_secrets', {}))
    for key in required:
        required[key] = redact_secret(str(required[key]))
    redacted['required_secrets'] = required
    return redacted


def redact_session(session: DeploymentSession) -> DeploymentSession:
    payload = session.model_dump(mode='json')
    payload['config'] = redact_config_payload(payload['config'])
    return DeploymentSession.model_validate(payload)
