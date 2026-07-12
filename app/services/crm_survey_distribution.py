"""CRM Survey Distribution service — EVT-008.

Adds survey email invitation dispatch to existing questionnaires.
Uses the existing questionnaires table (no new table).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _q_pk(questionnaire_id: str) -> str:
    """Mirror of questionnaires_repository._q_pk — not imported to avoid coupling."""
    return f"QNR#{questionnaire_id}"


def send_survey_invitations(
    *,
    questionnaire_id: str,
    owner_sub: str,
    recipients: list[str],
    subject: str,
    survey_url: str,
    message: Optional[str] = None,
    contact_list_id: Optional[str] = None,
) -> dict[str, int]:
    """Dispatch survey invitation emails.

    Each unique normalised email gets an idempotent SURVEY_INVITE#{email} row.
    Duplicate addresses are skipped (not re-sent).
    Returns {sent, skipped, failed}.
    """
    from app.core.normalize import normalize_email  # lazy import (RULE-1)
    from app.services.alerts import send_alert_email, audit_event  # lazy import (RULE-1)

    sent = skipped = failed = 0

    for raw_email in recipients:
        try:
            email = normalize_email(raw_email)
        except Exception:
            logger.warning("crm_survey_dist invalid email: %r", raw_email)
            failed += 1
            continue

        invite_ref = uuid.uuid4().hex[:16]
        url_with_ref = f"{survey_url}?ref={invite_ref}"

        body_parts = []
        if message:
            body_parts.append(message)
        body_parts.append(f"\nPlease complete the survey at:\n{url_with_ref}")
        body_text = "\n".join(body_parts)

        sk = f"SURVEY_INVITE#{email}"
        pk = _q_pk(questionnaire_id)
        row: dict[str, Any] = {
            "pk": pk,
            "sk": sk,
            "entity_type": "survey_invite",
            "questionnaire_id": questionnaire_id,
            "recipient_email": email,
            "owner_sub": owner_sub,
            "status": "sent",
            "sent_at": now_ts(),
            "invite_ref": invite_ref,
        }
        if message:
            row["message"] = message
        if contact_list_id:
            row["contact_list_id"] = contact_list_id

        try:
            T.questionnaires.put_item(
                Item=row,
                ConditionExpression="attribute_not_exists(sk)",
            )
        except Exception as exc:
            _code = ""
            try:
                _code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
            except Exception:
                _code = str(exc)
            if "ConditionalCheckFailed" in _code:
                skipped += 1
                continue
            logger.warning("crm_survey_dist ddb write failed: %s", exc)
            failed += 1
            continue

        try:
            send_alert_email([email], subject, body_text)
            sent += 1
        except Exception:
            logger.warning("crm_survey_dist email failed to %s", email, exc_info=True)
            failed += 1
            # Row is already written — marks intent even if email failed

    try:
        audit_event(
            "survey_distribution_sent",
            owner_sub,
            questionnaire_id=questionnaire_id,
            sent=sent,
            skipped=skipped,
            failed=failed,
        )
    except Exception:
        pass

    return {"sent": sent, "skipped": skipped, "failed": failed}


def get_distribution_summary(
    *,
    questionnaire_id: str,
    owner_sub: str,
) -> dict[str, Any]:
    """Return distribution summary: total_sent, total_responses, response_rate."""
    pk = _q_pk(questionnaire_id)

    # Count invite rows
    invite_rows: list[dict] = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": (
            __import__("boto3").dynamodb.conditions.Key("pk").eq(pk)
            & __import__("boto3").dynamodb.conditions.Key("sk").begins_with("SURVEY_INVITE#")
        ),
    }
    while True:
        resp = T.questionnaires.query(**kwargs)
        invite_rows.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    total_sent = len(invite_rows)

    # Count submitted response sessions
    resp_rows: list[dict] = []
    resp_kwargs: dict[str, Any] = {
        "KeyConditionExpression": (
            __import__("boto3").dynamodb.conditions.Key("pk").eq(pk)
            & __import__("boto3").dynamodb.conditions.Key("sk").begins_with("RESP#")
        ),
    }
    while True:
        resp = T.questionnaires.query(**resp_kwargs)
        resp_rows.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        resp_kwargs["ExclusiveStartKey"] = lek

    submitted_respondents: set[str] = set()
    for row in resp_rows:
        if row.get("status") == "submitted":
            rid = row.get("respondent_id")
            if rid:
                submitted_respondents.add(str(rid))

    total_responses = len(submitted_respondents)
    response_rate = round(total_responses / total_sent * 100, 1) if total_sent > 0 else 0.0

    return {
        "total_sent": total_sent,
        "total_responses": total_responses,
        "response_rate": response_rate,
    }
