from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class CredentialTestStatus(str, Enum):
    PASS = 'pass'
    FAIL = 'fail'
    WARNING = 'warning'
    UNKNOWN = 'unknown'


@dataclass
class ProviderCredentialInput:
    provider: str
    secret: str


@dataclass
class CredentialTestResult:
    provider: str
    status: CredentialTestStatus
    message: str
    attempts: int


class TransientCredentialError(Exception):
    """Retryable transient credential check failure."""


class CredentialAdapter(Protocol):
    provider_name: str

    def test(self, credential: ProviderCredentialInput, timeout_seconds: float) -> CredentialTestResult:
        ...


class OpenAIAdapter:
    provider_name = 'openai'

    def test(self, credential: ProviderCredentialInput, timeout_seconds: float) -> CredentialTestResult:
        # Baseline adapter behavior for initial rollout:
        # - Recognize obvious prefixes
        # - Support retry simulation for tests via env/secret marker without leaking secret contents.
        _ = timeout_seconds
        if credential.secret.startswith('transient:'):
            raise TransientCredentialError('transient_network_error')

        if credential.secret.startswith('sk-live-') or credential.secret.startswith('sk_live_'):
            return CredentialTestResult(
                provider=self.provider_name,
                status=CredentialTestStatus.PASS,
                message='Credential format accepted for OpenAI adapter.',
                attempts=1,
            )

        if credential.secret.startswith('sk-test-') or credential.secret.startswith('sk_test_'):
            return CredentialTestResult(
                provider=self.provider_name,
                status=CredentialTestStatus.WARNING,
                message='Test-style OpenAI key detected; production may require live key.',
                attempts=1,
            )

        return CredentialTestResult(
            provider=self.provider_name,
            status=CredentialTestStatus.FAIL,
            message='Unsupported OpenAI credential format.',
            attempts=1,
        )


class StripeAdapter:
    provider_name = 'stripe'

    def test(self, credential: ProviderCredentialInput, timeout_seconds: float) -> CredentialTestResult:
        _ = timeout_seconds
        if credential.secret.startswith('transient:'):
            raise TransientCredentialError('transient_network_error')

        if credential.secret.startswith('sk_live_'):
            return CredentialTestResult(
                provider=self.provider_name,
                status=CredentialTestStatus.PASS,
                message='Credential format accepted for Stripe adapter.',
                attempts=1,
            )

        if credential.secret.startswith('sk_test_'):
            return CredentialTestResult(
                provider=self.provider_name,
                status=CredentialTestStatus.WARNING,
                message='Test Stripe key detected; production may require live key.',
                attempts=1,
            )

        return CredentialTestResult(
            provider=self.provider_name,
            status=CredentialTestStatus.FAIL,
            message='Unsupported Stripe credential format.',
            attempts=1,
        )


class CredentialAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, CredentialAdapter] = {}

    def register(self, adapter: CredentialAdapter) -> None:
        self._adapters[adapter.provider_name] = adapter

    def get(self, provider: str) -> CredentialAdapter | None:
        return self._adapters.get(provider)

    def providers(self) -> list[str]:
        return sorted(self._adapters.keys())


def _timeout_seconds() -> float:
    return float(os.getenv('CREDENTIAL_TEST_TIMEOUT_SECONDS', '2.0'))


def _max_retries() -> int:
    return int(os.getenv('CREDENTIAL_TEST_MAX_RETRIES', '2'))


def _retry_backoff_seconds() -> float:
    return float(os.getenv('CREDENTIAL_TEST_RETRY_BACKOFF_SECONDS', '0.05'))


def default_registry() -> CredentialAdapterRegistry:
    reg = CredentialAdapterRegistry()
    reg.register(OpenAIAdapter())
    reg.register(StripeAdapter())
    return reg


def sanitize_secret(secret: str) -> str:
    if len(secret) <= 6:
        return '***'
    return f'{secret[:3]}***{secret[-2:]}'


def run_provider_test(registry: CredentialAdapterRegistry, credential: ProviderCredentialInput) -> CredentialTestResult:
    adapter = registry.get(credential.provider)
    if adapter is None:
        return CredentialTestResult(
            provider=credential.provider,
            status=CredentialTestStatus.UNKNOWN,
            message=f'No credential adapter registered for provider: {credential.provider}',
            attempts=0,
        )

    max_retries = max(0, _max_retries())
    timeout = _timeout_seconds()
    backoff = _retry_backoff_seconds()

    attempt = 0
    while True:
        attempt += 1
        try:
            result = adapter.test(credential, timeout)
            result.attempts = attempt
            return result
        except TransientCredentialError:
            if attempt > max_retries:
                return CredentialTestResult(
                    provider=credential.provider,
                    status=CredentialTestStatus.WARNING,
                    message='Transient credential test failures after retries; provider status unknown.',
                    attempts=attempt,
                )
            time.sleep(backoff)
        except Exception:
            return CredentialTestResult(
                provider=credential.provider,
                status=CredentialTestStatus.UNKNOWN,
                message='Credential test failed with unexpected provider error.',
                attempts=attempt,
            )
