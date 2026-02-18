from app.core.aws_clients import _local_credentials_kwargs


def test_local_credentials_added_for_localhost_endpoint(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    creds = _local_credentials_kwargs("http://localhost:8001")

    assert creds["aws_access_key_id"] == "test"
    assert creds["aws_secret_access_key"] == "test"


def test_local_credentials_added_for_private_ip_endpoint(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    creds = _local_credentials_kwargs("http://192.168.1.10:8001")

    assert creds["aws_access_key_id"] == "test"
    assert creds["aws_secret_access_key"] == "test"


def test_local_credentials_added_for_host_internal_endpoint(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    creds = _local_credentials_kwargs("http://host.docker.internal:8001")

    assert creds["aws_access_key_id"] == "test"
    assert creds["aws_secret_access_key"] == "test"


def test_no_local_credentials_for_aws_endpoint(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    creds = _local_credentials_kwargs("https://dynamodb.us-east-1.amazonaws.com")

    assert creds == {}


def test_local_credentials_for_public_non_aws_endpoint_in_dev_mode(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    creds = _local_credentials_kwargs("http://18.222.237.167:8001")

    assert creds["aws_access_key_id"] == "test"
    assert creds["aws_secret_access_key"] == "test"
