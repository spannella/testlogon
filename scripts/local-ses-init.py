#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError

ENV_FILE = Path('.env.local')
ENV_EXAMPLE_FILE = Path('.env.local.example')


def _read_env_value(path: Path, key: str) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        candidate_key, candidate_value = stripped.split('=', 1)
        if candidate_key.strip() == key:
            value = candidate_value.strip()
            return value or None
    return None


def _setting(key: str, default: str = '') -> str:
    return (
        os.environ.get(key)
        or _read_env_value(ENV_FILE, key)
        or _read_env_value(ENV_EXAMPLE_FILE, key)
        or default
    ).strip()


def main() -> None:
    from_email = _setting('SES_FROM_EMAIL')
    if not from_email:
        print('Skipping local SES bootstrap: SES_FROM_EMAIL is not configured.')
        return

    endpoint = _setting('AWS_ENDPOINT_URL', 'http://localhost:4566')
    region = _setting('AWS_REGION', 'us-east-1')

    os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
    os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')

    client = boto3.client('ses', region_name=region, endpoint_url=endpoint)
    client.verify_email_identity(EmailAddress=from_email)
    print(f'Ensured SES identity exists for {from_email} at {endpoint}')


if __name__ == '__main__':
    try:
        main()
    except (ClientError, BotoCoreError) as exc:
        raise SystemExit(f'Failed to initialize local SES: {exc}')
