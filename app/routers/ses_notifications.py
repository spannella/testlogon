"""SES delivery notification receiver (bounces, complaints, deliveries).

This endpoint receives SNS HTTPS push notifications for SES events.
Path: /internal/ses/notifications (not exposed via Vite proxy).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, Request, Response

from app.services.email_delivery import (
    record_email_bounce,
    record_email_complaint,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ses-notifications"])


@router.post("/internal/ses/notifications")
async def ses_notification(request: Request) -> Response:
    """Receive SES delivery notifications via SNS HTTPS subscription."""
    try:
        body = await request.json()
    except Exception:
        logger.warning("SES notification: invalid JSON body")
        return Response(status_code=400)

    msg_type = body.get("Type", "")

    if msg_type == "SubscriptionConfirmation":
        subscribe_url = body.get("SubscribeURL", "")
        topic_arn = body.get("TopicArn", "")
        logger.info(
            "SNS subscription confirmation: topic=%s, url=%s",
            topic_arn, subscribe_url[:100] if subscribe_url else "",
        )
        # In production, auto-confirm by fetching SubscribeURL
        return Response(status_code=200)

    if msg_type == "UnsubscribeConfirmation":
        logger.info("SNS unsubscribe confirmation: %s", body.get("TopicArn", ""))
        return Response(status_code=200)

    if msg_type == "Notification":
        try:
            message = json.loads(body.get("Message", "{}"))
            _process_ses_notification(message)
        except Exception:
            logger.exception("Error processing SES notification")
        return Response(status_code=200)

    logger.warning("SES notification: unknown type=%s", msg_type)
    return Response(status_code=200)


def _process_ses_notification(message: Dict[str, Any]) -> None:
    """Route SES notification to the appropriate handler."""
    notification_type = message.get("notificationType", "")
    mail = message.get("mail", {})
    message_id = mail.get("messageId", "")
    source = mail.get("source", "")
    destination = mail.get("destination", [])

    if notification_type == "Bounce":
        bounce = message.get("bounce", {})
        bounce_type = bounce.get("bounceType", "Unknown")
        bounce_sub_type = bounce.get("bounceSubType", "Unknown")
        bounced_recipients = [
            r["emailAddress"] for r in bounce.get("bouncedRecipients", [])
        ]
        record_email_bounce(
            message_id=message_id,
            bounce_type=bounce_type,
            bounce_sub_type=bounce_sub_type,
            bounced_recipients=bounced_recipients,
            raw=message,
        )
        logger.warning(
            "SES bounce: type=%s, sub_type=%s, recipients=%s, source=%s",
            bounce_type, bounce_sub_type, bounced_recipients, source,
        )

    elif notification_type == "Complaint":
        complaint = message.get("complaint", {})
        complaint_feedback_type = complaint.get("complaintFeedbackType", "")
        complained_recipients = [
            r["emailAddress"] for r in complaint.get("complainedRecipients", [])
        ]
        record_email_complaint(
            message_id=message_id,
            complaint_feedback_type=complaint_feedback_type,
            complained_recipients=complained_recipients,
            raw=message,
        )
        logger.warning(
            "SES complaint: type=%s, recipients=%s, source=%s",
            complaint_feedback_type, complained_recipients, source,
        )

    elif notification_type == "Delivery":
        delivery = message.get("delivery", {})
        recipients = delivery.get("recipients", destination)
        processing_time_ms = delivery.get("processingTimeMillis", 0)
        logger.info(
            "SES delivery confirmed: message_id=%s, recipients=%s, time=%dms",
            message_id, recipients, processing_time_ms,
        )

    else:
        logger.warning(
            "SES notification: unknown type=%s, message_id=%s",
            notification_type, message_id,
        )
