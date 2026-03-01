from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def test_config_schema_endpoint() -> None:
    response = client.get('/config/schema')
    assert response.status_code == 200
    body = response.json()
    assert body['schema_version'] == '1.0.0'
    assert body['compatibility'] == 'backward-compatible additive changes within major version'
    assert 'properties' in body['json_schema']
    assert 'deployment_context' in body['json_schema']['properties']
    assert 'required_secrets' in body['json_schema']['properties']
    assert 'optional_features' in body['json_schema']['properties']
    assert 'feature_config' in body['json_schema']['properties']
    assert 'deployment_options' in body['json_schema']['properties']
