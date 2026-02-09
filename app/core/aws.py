from __future__ import annotations

from app.core.aws_clients import ddb_resource, kms_client, sqs_client as aws_sqs_client
from .settings import S

ddb = ddb_resource()
kms = kms_client()

# Optional clients - import lazily / guarded so the server can run without extras installed.
ses = None
if S.ses_from_email:
    from boto3 import client as _boto3_client  # lazy import

    ses = _boto3_client(
        "ses",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )

try:
    from twilio.rest import Client as TwilioClient  # type: ignore
except Exception:  # pragma: no cover
    TwilioClient = None  # type: ignore

twilio = None
if TwilioClient and S.twilio_account_sid and S.twilio_auth_token:
    twilio = TwilioClient(S.twilio_account_sid, S.twilio_auth_token)

def sns_client():
    from boto3 import client as _boto3_client  # lazy import

    return _boto3_client(
        "sns",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )


def sqs_client():
    return aws_sqs_client()
