#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Any, NamedTuple

class ValidationFailure(NamedTuple):
    check: str
    reason: str


def _table_name(env_key: str, default: str) -> str:
    return str(os.getenv(env_key, default)).strip() or default


def _ddb_client() -> Any:
    import boto3

    kwargs: dict[str, Any] = {}
    endpoint = os.getenv("DDB_ENDPOINT_URL") or os.getenv("AWS_DDB_ENDPOINT") or ""
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    region = os.getenv("AWS_REGION") or "us-east-1"
    return boto3.client("dynamodb", region_name=region, **kwargs)


def _validate_table(
    *,
    client: Any,
    table_name: str,
    required_pk: list[tuple[str, str]],
    required_gsis: list[str],
) -> ValidationFailure | None:
    try:
        meta = client.describe_table(TableName=table_name)["Table"]
    except Exception as exc:  # pragma: no cover - external API
        return ValidationFailure(check=f"table:{table_name}", reason=f"describe failed: {exc}")

    key_schema = {(row["AttributeName"], row["KeyType"]) for row in meta.get("KeySchema", [])}
    for attr, key_type in required_pk:
        if (attr, key_type) not in key_schema:
            return ValidationFailure(
                check=f"table:{table_name}",
                reason=f"missing key schema entry ({attr}, {key_type})",
            )

    gsi_names = {row.get("IndexName") for row in meta.get("GlobalSecondaryIndexes", [])}
    missing = [g for g in required_gsis if g not in gsi_names]
    if missing:
        return ValidationFailure(
            check=f"table:{table_name}",
            reason=f"missing GSIs: {', '.join(missing)}",
        )
    return None


def validate_schema() -> list[ValidationFailure]:
    client = _ddb_client()
    campaigns_table = _table_name("MASS_MESSAGE_CAMPAIGNS_TABLE_NAME", "MassMessageCampaigns")
    destinations_table = _table_name("MASS_MESSAGE_CAMPAIGN_DESTINATIONS_TABLE_NAME", "MassMessageCampaignDestinations")

    failures: list[ValidationFailure] = []
    c = _validate_table(
        client=client,
        table_name=campaigns_table,
        required_pk=[("campaign_id", "HASH")],
        required_gsis=["BySenderCreatedAt", "ByStatusSendAt"],
    )
    if c:
        failures.append(c)

    d = _validate_table(
        client=client,
        table_name=destinations_table,
        required_pk=[("campaign_id", "HASH"), ("conversation_id", "RANGE")],
        required_gsis=["ByCampaignStateUpdatedAt"],
    )
    if d:
        failures.append(d)
    return failures


def validate_existing_messaging_endpoints(*, api_base: str, token: str) -> list[ValidationFailure]:
    import requests

    headers = {"Authorization": f"Bearer {token}"}
    checks = [
        ("healthz", f"{api_base.rstrip('/')}/messaging/healthz"),
        ("config", f"{api_base.rstrip('/')}/messaging/config"),
        ("conversations", f"{api_base.rstrip('/')}/messaging/conversations"),
    ]
    failures: list[ValidationFailure] = []
    for name, url in checks:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
        except Exception as exc:  # pragma: no cover - network dependent
            failures.append(ValidationFailure(check=f"endpoint:{name}", reason=f"request failed: {exc}"))
            continue
        if resp.status_code >= 400:
            failures.append(
                ValidationFailure(
                    check=f"endpoint:{name}",
                    reason=f"unexpected status {resp.status_code}: {resp.text[:240]}",
                )
            )
    return failures


def run_regression_suite() -> list[ValidationFailure]:
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_messaging_routes.py",
        "tests/test_mass_message_create_endpoint.py",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        reason = (proc.stdout + "\n" + proc.stderr).strip()[-4000:]
        return [ValidationFailure(check="regression:messaging", reason=reason)]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate mass messaging migration compatibility and messaging regressions.")
    parser.add_argument("--api-base", default=os.getenv("API_BASE", "http://localhost:8000"), help="Base URL for API smoke checks.")
    parser.add_argument("--token", default=os.getenv("MASS_MESSAGE_VALIDATION_TOKEN", ""), help="Bearer token for endpoint checks.")
    parser.add_argument("--skip-endpoint-checks", action="store_true", help="Skip existing messaging endpoint smoke checks.")
    parser.add_argument("--run-regression-suite", action="store_true", help="Run unchanged messaging regression pytest suite.")
    args = parser.parse_args()

    failures = validate_schema()
    if not args.skip_endpoint_checks:
        if not args.token:
            failures.append(
                ValidationFailure(
                    check="endpoint:auth",
                    reason="token required (set --token or MASS_MESSAGE_VALIDATION_TOKEN)",
                )
            )
        else:
            failures.extend(validate_existing_messaging_endpoints(api_base=args.api_base, token=args.token))

    if args.run_regression_suite:
        failures.extend(run_regression_suite())

    if failures:
        print("mass_message_rollout_validation=FAIL")
        for f in failures:
            print(f"- [{f.check}] {f.reason}")
        return 1

    print("mass_message_rollout_validation=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
