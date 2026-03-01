from __future__ import annotations

AUTH_HEADERS = {'X-SSO-Email': 'e2e-admin@example.com', 'X-SSO-Role': 'admin'}

E2E_CONFIG = {
    'schema_version': '1.0.0',
    'deployment_context': {
        'environment': 'prod-us-east-1',
        'region': 'us-east-1',
        'aws_account_id': '123456789012',
        'app_name': 'deployment-initializer-e2e',
        'owner_email': 'ops@example.com',
    },
    'required_secrets': {
        'database_password': 'supersecret-password',
        'jwt_signing_key': 'jwt-signing-key-12345',
        'internal_api_token': 'internal-api-token-12345',
        'stripe_api_key': 'sk_live_1234567890',
        'openai_api_key': 'sk-live-1234567890',
    },
    'optional_features': {
        'enable_helpdesk': True,
        'enable_messaging': True,
        'enable_filemanager': True,
        'enable_alerting': True,
        'enable_signature_packets': False,
    },
    'feature_config': {
        'helpdesk': {'routing_queue': 'tier1', 'auto_assign': True},
        'messaging': {'retention_days': 30, 'allow_external_sharing': False},
        'filemanager': {'max_upload_mb': 250, 'enable_virus_scan': True},
        'alerting': {'slack_webhook_url': 'https://hooks.slack.test/e2e', 'email_notifications_enabled': True},
        'signature_packets': {'reminder_interval_hours': 24},
    },
    'deployment_options': {
        'instance_count': 2,
        'instance_type': 't3.medium',
        'vpc_id': 'vpc-e2e-1234',
        'subnet_ids': ['subnet-1', 'subnet-2'],
        'enable_multi_az': True,
        'log_level': 'info',
    },
}
