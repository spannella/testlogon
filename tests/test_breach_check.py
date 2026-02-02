from types import SimpleNamespace

from app.services import breach_check


def test_breach_check_disabled():
    original_settings = breach_check.S
    try:
        breach_check.S = SimpleNamespace(hibp_enabled=False, hibp_api_key="")
        assert breach_check.check_password_breach("password123") is None
    finally:
        breach_check.S = original_settings
