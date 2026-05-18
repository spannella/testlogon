#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Dict, List, Tuple

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    boto3 = None
    BotoCoreError = ClientError = Exception


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    details: str


QUOTA_TARGETS: Dict[str, Dict[str, float]] = {
    "medialive": {
        "Inputs": 25,
        "Channels": 20,
    },
    "mediapackage": {
        "Channel": 30,
        "Endpoint": 30,
    },
    "cloudfront": {
        "Distributions": 10,
    },
}

REQUIRED_KMS_ALIASES = ["alias/broadcast-stream-keys", "alias/broadcast-drm-keys"]


def _check_quotas(region: str) -> List[CheckResult]:
    results: List[CheckResult] = []
    if boto3 is None:
        return [CheckResult("quota:all", False, "boto3 is not installed in this environment")]
    sq = boto3.client("service-quotas", region_name=region)

    for service_code, targets in QUOTA_TARGETS.items():
        try:
            paginator = sq.get_paginator("list_service_quotas")
            quotas = []
            for page in paginator.paginate(ServiceCode=service_code):
                quotas.extend(page.get("Quotas", []))
        except (BotoCoreError, ClientError) as exc:
            results.append(CheckResult(f"quota:{service_code}", False, f"unable to query quotas: {exc}"))
            continue

        for quota_hint, min_value in targets.items():
            match = None
            for q in quotas:
                name = str(q.get("QuotaName", ""))
                if quota_hint.lower() in name.lower():
                    match = q
                    break
            if not match:
                results.append(
                    CheckResult(
                        f"quota:{service_code}:{quota_hint}",
                        False,
                        "quota not found; explicit fallback required in launch tracker",
                    )
                )
                continue
            actual = float(match.get("Value") or 0.0)
            ok = actual >= min_value
            details = f"{match.get('QuotaName')}={actual} target>={min_value}"
            if not ok:
                details += " (fallback required: temporary concurrency cap + approval ticket)"
            results.append(CheckResult(f"quota:{service_code}:{quota_hint}", ok, details))

    return results


def _check_iam_role(role_name: str) -> CheckResult:
    if boto3 is None:
        return CheckResult("iam:role", False, "boto3 is not installed in this environment")
    iam = boto3.client("iam")
    try:
        iam.get_role(RoleName=role_name)
        return CheckResult("iam:role", True, f"role exists: {role_name}")
    except (BotoCoreError, ClientError) as exc:
        return CheckResult("iam:role", False, f"missing role {role_name}: {exc}")


def _check_kms_aliases(region: str) -> List[CheckResult]:
    if boto3 is None:
        return [CheckResult("kms:aliases", False, "boto3 is not installed in this environment")]
    kms = boto3.client("kms", region_name=region)
    try:
        aliases = []
        paginator = kms.get_paginator("list_aliases")
        for page in paginator.paginate():
            aliases.extend([a.get("AliasName") for a in page.get("Aliases", [])])
    except (BotoCoreError, ClientError) as exc:
        return [CheckResult("kms:aliases", False, f"unable to query aliases: {exc}")]

    out: List[CheckResult] = []
    for alias in REQUIRED_KMS_ALIASES:
        out.append(CheckResult(f"kms:{alias}", alias in aliases, f"alias {'found' if alias in aliases else 'missing'}: {alias}"))
    return out


def _check_s3_bucket(region: str, bucket: str) -> CheckResult:
    if boto3 is None:
        return CheckResult("s3:bucket", False, "boto3 is not installed in this environment")
    s3 = boto3.client("s3", region_name=region)
    try:
        s3.head_bucket(Bucket=bucket)
        return CheckResult("s3:bucket", True, f"bucket exists: {bucket}")
    except (BotoCoreError, ClientError) as exc:
        return CheckResult("s3:bucket", False, f"bucket not ready: {bucket} ({exc})")


def run(region: str, env: str, account_id: str, role_name: str) -> Tuple[bool, List[CheckResult]]:
    bucket = f"broadcast-archive-{env}-{account_id}-{region}"
    checks: List[CheckResult] = []
    checks.extend(_check_quotas(region))
    checks.append(_check_iam_role(role_name))
    checks.extend(_check_kms_aliases(region))
    checks.append(_check_s3_bucket(region, bucket))

    ok = all(c.ok for c in checks)
    return ok, checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Broadcast account readiness check for BRD-002")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--env", choices=["dev", "staging", "prod"], default="dev")
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--role-name", default="BroadcastOrchestratorRole")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    ok, checks = run(args.region, args.env, args.account_id, args.role_name)

    if args.as_json:
        print(json.dumps({"ok": ok, "checks": [c.__dict__ for c in checks]}, indent=2))
    else:
        for c in checks:
            status = "PASS" if c.ok else "FAIL"
            print(f"[{status}] {c.name}: {c.details}")
        print(f"Overall: {'READY' if ok else 'NOT_READY'}")

    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
