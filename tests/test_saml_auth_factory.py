"""Offline regression test for GAP-0174 (ENTERPRISE-002).

The SAML login redirect and ACS processing previously used ``MockSamlAuth``
unconditionally in every environment, so assertions were never cryptographically
verified and forged ACS POSTs were accepted.

The fix introduces ``get_saml_auth`` which:
  - returns ``MockSamlAuth`` only when ``S.dev_mode`` is True (dev/CI/E2E), and
  - returns the real ``OneLogin_Saml2_Auth`` from ``python3-saml`` in production,
    raising a clear ``RuntimeError`` (fail closed) if the library is missing —
    never silently downgrading to the insecure mock.

These tests exercise the selector directly (no TestClient / network / DDB). ``S``
is a frozen dataclass, so ``dev_mode`` is toggled via ``object.__setattr__`` and
always restored in a ``finally`` block.
"""
from __future__ import annotations

import sys
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

from app.core.settings import S
from app.services import sso_saml_sp
from app.services.sso_saml_sp import MockSamlAuth, get_saml_auth


@contextmanager
def _dev_mode(value: bool):
    """Temporarily override the frozen Settings.dev_mode flag."""
    original = S.dev_mode
    object.__setattr__(S, "dev_mode", value)
    try:
        yield
    finally:
        object.__setattr__(S, "dev_mode", original)


def test_get_saml_auth_returns_mock_in_dev_mode():
    with _dev_mode(True):
        auth = get_saml_auth({"post_data": {}}, {})
    assert isinstance(auth, MockSamlAuth)


def test_get_saml_auth_uses_real_lib_in_prod(monkeypatch):
    """In prod mode the factory must select OneLogin_Saml2_Auth, not the mock."""
    sentinel = object()

    def _fake_real_auth(request_data, settings):
        return sentinel

    fake_module = MagicMock()
    fake_module.OneLogin_Saml2_Auth = _fake_real_auth
    # The factory imports ``onelogin.saml2.auth``; inject a fake so the test does
    # not require the native xmlsec1-backed python3-saml package to be installed.
    monkeypatch.setitem(sys.modules, "onelogin", MagicMock())
    monkeypatch.setitem(sys.modules, "onelogin.saml2", MagicMock())
    monkeypatch.setitem(sys.modules, "onelogin.saml2.auth", fake_module)

    with _dev_mode(False):
        auth = get_saml_auth({"post_data": {}}, {})

    assert auth is sentinel
    assert not isinstance(auth, MockSamlAuth)


def test_get_saml_auth_raises_in_prod_when_lib_missing(monkeypatch):
    """Prod mode must fail closed (RuntimeError), never fall back to MockSamlAuth."""
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _blocking_import(name, *args, **kwargs):
        if name == "onelogin.saml2.auth" or name.startswith("onelogin"):
            raise ImportError("python3-saml not installed (simulated)")
        return real_import(name, *args, **kwargs)

    # Drop any cached onelogin modules so the import inside the factory re-runs.
    for mod in list(sys.modules):
        if mod == "onelogin" or mod.startswith("onelogin."):
            monkeypatch.delitem(sys.modules, mod, raising=False)
    monkeypatch.setattr("builtins.__import__", _blocking_import)

    with _dev_mode(False):
        with pytest.raises(RuntimeError) as excinfo:
            get_saml_auth({"post_data": {}}, {})

    assert "python3-saml" in str(excinfo.value)


def test_router_call_sites_use_factory():
    """The login + ACS auth paths must route through get_saml_auth, not MockSamlAuth.

    Guards against a regression where someone re-introduces a direct MockSamlAuth
    call in the production authentication path.
    """
    import inspect

    from app.routers import sso_saml as router

    login_src = inspect.getsource(router.saml_login)
    acs_src = inspect.getsource(router.saml_acs)

    assert "get_saml_auth(" in login_src
    assert "MockSamlAuth(" not in login_src
    assert "get_saml_auth(" in acs_src
    assert "MockSamlAuth(" not in acs_src
