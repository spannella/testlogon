from __future__ import annotations

import boto3

from .settings import S

_session = boto3.session.Session(region_name=S.aws_region or "us-east-1")

ddb = _session.resource("dynamodb")
kms = _session.client("kms")

# Optional clients - import lazily / guarded so the server can run without extras installed.
ses = _session.client("ses") if S.ses_from_email else None

try:
    from twilio.rest import Client as TwilioClient  # type: ignore
except Exception:  # pragma: no cover
    TwilioClient = None  # type: ignore

twilio = None
if TwilioClient and S.twilio_account_sid and S.twilio_auth_token:
    twilio = TwilioClient(S.twilio_account_sid, S.twilio_auth_token)

def sns_client():
    return _session.client("sns")
