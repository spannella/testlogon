from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from app.models import DeploymentSession, SessionStatus


class ValidationSeverity(str, Enum):
    ERROR = 'error'
    WARNING = 'warning'


class ValidationLayer(str, Enum):
    SCHEMA = 'schema'
    BUSINESS = 'business'
    READINESS = 'readiness'


class ValidationIssue(BaseModel):
    code: str
    severity: ValidationSeverity
    layer: ValidationLayer
    message: str
    path: str | None = None


class SessionValidationResponse(BaseModel):
    session_id: str
    ready_to_deploy: bool
    blocking_issue_count: int
    warning_count: int
    issues: list[ValidationIssue] = Field(default_factory=list)


def validate_session(session: DeploymentSession) -> SessionValidationResponse:
    issues: list[ValidationIssue] = []

    # Layer 1: schema-level checks enforced by pydantic are augmented here with operational signals.
    if session.config.schema_version != '1.0.0':
        issues.append(
            ValidationIssue(
                code='schema.unsupported_version',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.SCHEMA,
                message='Unsupported config schema version for validator.',
                path='config.schema_version',
            )
        )

    # Layer 2: cross-field/business rules.
    features = session.config.optional_features
    feature_config = session.config.feature_config
    required_secrets = session.config.required_secrets
    deployment_options = session.config.deployment_options

    if features.enable_helpdesk and feature_config.helpdesk.routing_queue.strip() == '':
        issues.append(
            ValidationIssue(
                code='business.helpdesk.routing_queue_required',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.BUSINESS,
                message='Helpdesk routing queue is required when helpdesk is enabled.',
                path='config.feature_config.helpdesk.routing_queue',
            )
        )

    if features.enable_messaging and feature_config.messaging.retention_days < 7:
        issues.append(
            ValidationIssue(
                code='business.messaging.retention_too_low',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.BUSINESS,
                message='Messaging retention must be at least 7 days when messaging is enabled.',
                path='config.feature_config.messaging.retention_days',
            )
        )

    if features.enable_alerting and not feature_config.alerting.slack_webhook_url:
        issues.append(
            ValidationIssue(
                code='business.alerting.slack_webhook_missing',
                severity=ValidationSeverity.WARNING,
                layer=ValidationLayer.BUSINESS,
                message='Alerting is enabled without a Slack webhook URL; only email notifications will be used.',
                path='config.feature_config.alerting.slack_webhook_url',
            )
        )

    if features.enable_signature_packets and feature_config.signature_packets.reminder_interval_hours > 72:
        issues.append(
            ValidationIssue(
                code='business.signature.reminder_interval_high',
                severity=ValidationSeverity.WARNING,
                layer=ValidationLayer.BUSINESS,
                message='Signature reminder interval above 72h may reduce completion rates.',
                path='config.feature_config.signature_packets.reminder_interval_hours',
            )
        )

    if deployment_options.instance_count >= 10 and deployment_options.instance_type.startswith('t3.'):
        issues.append(
            ValidationIssue(
                code='business.compute.instance_type_warning',
                severity=ValidationSeverity.WARNING,
                layer=ValidationLayer.BUSINESS,
                message='High instance count on burstable t3 class may cause CPU credit throttling.',
                path='config.deployment_options.instance_type',
            )
        )

    if session.metadata.env.startswith('prod') and 'test' in required_secrets.stripe_api_key.lower():
        issues.append(
            ValidationIssue(
                code='business.secrets.stripe_key_not_live',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.BUSINESS,
                message='Production environments require a live Stripe key.',
                path='config.required_secrets.stripe_api_key',
            )
        )

    if session.metadata.env.startswith('prod') and 'test' in required_secrets.openai_api_key.lower():
        issues.append(
            ValidationIssue(
                code='business.secrets.openai_key_not_live',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.BUSINESS,
                message='Production environments require a live OpenAI key.',
                path='config.required_secrets.openai_api_key',
            )
        )

    # Layer 3: readiness gate aggregation.
    if session.status not in {SessionStatus.DRAFT, SessionStatus.VALIDATED, SessionStatus.READY}:
        issues.append(
            ValidationIssue(
                code='readiness.invalid_session_status',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.READINESS,
                message='Session status must be draft, validated, or ready for validation/deploy readiness.',
                path='status',
            )
        )

    if session.metadata.env.startswith('prod') and not deployment_options.enable_multi_az:
        issues.append(
            ValidationIssue(
                code='readiness.prod_multi_az_disabled',
                severity=ValidationSeverity.ERROR,
                layer=ValidationLayer.READINESS,
                message='Production deployments require multi-AZ to be enabled.',
                path='config.deployment_options.enable_multi_az',
            )
        )

    blocking_issue_count = len([i for i in issues if i.severity == ValidationSeverity.ERROR])
    warning_count = len([i for i in issues if i.severity == ValidationSeverity.WARNING])

    return SessionValidationResponse(
        session_id=session.session_id,
        ready_to_deploy=blocking_issue_count == 0,
        blocking_issue_count=blocking_issue_count,
        warning_count=warning_count,
        issues=issues,
    )
