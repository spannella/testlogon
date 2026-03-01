from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import quote


class ArtifactStorage(ABC):
    @abstractmethod
    def put_text(self, storage_key: str, content: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_text(self, storage_key: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def create_signed_token(self, storage_key: str, expires_epoch_s: int) -> str:
        raise NotImplementedError

    @abstractmethod
    def verify_signed_token(self, token: str) -> tuple[str, int]:
        raise NotImplementedError


class LocalArtifactStorage(ArtifactStorage):
    def __init__(self, base_dir: str, signing_secret: str) -> None:
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret.encode('utf-8')

    def put_text(self, storage_key: str, content: str) -> str:
        path = self._base_dir / storage_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return str(path)

    def get_text(self, storage_key: str) -> str:
        path = self._base_dir / storage_key
        return path.read_text()

    def create_signed_token(self, storage_key: str, expires_epoch_s: int) -> str:
        payload = {'k': storage_key, 'exp': expires_epoch_s}
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8')).decode('utf-8')
        signature = hmac.new(self._secret, encoded.encode('utf-8'), hashlib.sha256).hexdigest()
        return f'{encoded}.{signature}'

    def verify_signed_token(self, token: str) -> tuple[str, int]:
        encoded, signature = token.rsplit('.', 1)
        expected = hmac.new(self._secret, encoded.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError('invalid_signature')
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode('utf-8')).decode('utf-8'))
        return str(payload['k']), int(payload['exp'])


def default_artifact_storage() -> LocalArtifactStorage:
    base_dir = os.getenv('ARTIFACT_STORAGE_DIR', 'deployment_initializer/backend/artifact_store')
    signing_secret = os.getenv('ARTIFACT_SIGNING_SECRET', 'local-dev-artifact-signing-secret')
    return LocalArtifactStorage(base_dir=base_dir, signing_secret=signing_secret)


def build_storage_key(session_id: str, run_id: str, artifact_name: str) -> str:
    safe_name = quote(artifact_name, safe='.-_')
    return f'{session_id}/{run_id}/{safe_name}'
