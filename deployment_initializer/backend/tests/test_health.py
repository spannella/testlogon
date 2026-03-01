from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.main import app


AUTH_HEADERS = {'X-SSO-Email': 'ops@example.com', 'X-SSO-Role': 'admin'}

client = TestClient(app, headers=AUTH_HEADERS)


def test_health() -> None:
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}
