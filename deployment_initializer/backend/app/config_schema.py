from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

CONFIG_SCHEMA_VERSION = '1.0.0'


class LogLevel(str, Enum):
    DEBUG = 'debug'
    INFO = 'info'
    WARN = 'warn'
    ERROR = 'error'


class DeploymentContext(BaseModel):
    environment: str = Field(min_length=1, examples=['prod-us-east-1'])
    region: str = Field(min_length=1, examples=['us-east-1'])
    aws_account_id: str = Field(min_length=12, max_length=12, pattern=r'^\d{12}$')
    app_name: str = Field(min_length=1)
    owner_email: str = Field(min_length=3)


class RequiredSecrets(BaseModel):
    database_password: str = Field(min_length=8)
    jwt_signing_key: str = Field(min_length=16)
    internal_api_token: str = Field(min_length=16)
    stripe_api_key: str = Field(min_length=8)
    openai_api_key: str = Field(min_length=8)


class OptionalFeatures(BaseModel):
    enable_helpdesk: bool = False
    enable_messaging: bool = False
    enable_filemanager: bool = False
    enable_alerting: bool = True
    enable_signature_packets: bool = False


class HelpdeskFeatureConfig(BaseModel):
    routing_queue: str = 'general'
    auto_assign: bool = True


class MessagingFeatureConfig(BaseModel):
    retention_days: int = Field(default=30, ge=1, le=365)
    allow_external_sharing: bool = False


class FilemanagerFeatureConfig(BaseModel):
    max_upload_mb: int = Field(default=100, ge=1, le=10_000)
    enable_virus_scan: bool = True


class AlertingFeatureConfig(BaseModel):
    slack_webhook_url: str | None = None
    email_notifications_enabled: bool = True


class SignaturePacketsFeatureConfig(BaseModel):
    reminder_interval_hours: int = Field(default=24, ge=1, le=168)


class FeatureConfig(BaseModel):
    helpdesk: HelpdeskFeatureConfig = Field(default_factory=HelpdeskFeatureConfig)
    messaging: MessagingFeatureConfig = Field(default_factory=MessagingFeatureConfig)
    filemanager: FilemanagerFeatureConfig = Field(default_factory=FilemanagerFeatureConfig)
    alerting: AlertingFeatureConfig = Field(default_factory=AlertingFeatureConfig)
    signature_packets: SignaturePacketsFeatureConfig = Field(default_factory=SignaturePacketsFeatureConfig)


class DeploymentOptions(BaseModel):
    instance_count: int = Field(default=2, ge=1, le=50)
    instance_type: str = 't3.medium'
    vpc_id: str = Field(min_length=2)
    subnet_ids: list[str] = Field(default_factory=list)
    enable_multi_az: bool = True
    log_level: LogLevel = LogLevel.INFO


class DeploymentConfigV1(BaseModel):
    schema_version: Literal[CONFIG_SCHEMA_VERSION] = CONFIG_SCHEMA_VERSION
    deployment_context: DeploymentContext
    required_secrets: RequiredSecrets
    optional_features: OptionalFeatures = Field(default_factory=OptionalFeatures)
    feature_config: FeatureConfig = Field(default_factory=FeatureConfig)
    deployment_options: DeploymentOptions


class ConfigSchemaEnvelope(BaseModel):
    schema_version: str
    compatibility: str
    json_schema: dict[str, Any]


def export_machine_schema() -> ConfigSchemaEnvelope:
    return ConfigSchemaEnvelope(
        schema_version=CONFIG_SCHEMA_VERSION,
        compatibility='backward-compatible additive changes within major version',
        json_schema=DeploymentConfigV1.model_json_schema(),
    )
