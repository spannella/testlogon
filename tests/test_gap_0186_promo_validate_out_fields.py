"""Regression test for GAP-0186 (FIN-002).

``PromoValidateOut`` was missing six FIN-002 spec fields — ``error_code``,
``discount_pct``, ``original_price_cents``, ``buy_x``, ``get_y``, and
``free_item_description`` — and ``validate_promo_code`` never produced them, so
the checkout UI could not render type-specific discount badges or surface
structured error states.

Fails-before: the success/fail dicts returned by ``validate_promo_code`` omit
``error_code``/``discount_pct``/``original_price_cents`` (KeyError below), and
``PromoValidateOut`` would silently drop them even if produced.

Passes-after: the model declares the six optional fields and the service
populates ``discount_pct`` (percentage), ``original_price_cents`` (all paths),
and ``error_code`` (each failure reason).

Fully offline: the DynamoDB lookups inside ``validate_promo_code`` are
monkeypatched with in-memory fakes, so no real AWS / DDB access occurs.
``Settings`` is frozen, so any override uses ``object.__setattr__``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.models import PromoValidateOut
from app.services import promo_codes as svc

_CLOCK = 1_700_000_000


def _install_promo(monkeypatch, promo: Optional[Dict[str, Any]], *, redeems: Optional[List[Dict]] = None):
    """Patch the service's DDB-backed helpers with offline fakes."""
    monkeypatch.setattr(svc, "now_ts", lambda: _CLOCK)
    monkeypatch.setattr(svc, "get_promo_code_by_string", lambda code: promo)
    monkeypatch.setattr(
        svc,
        "_query_promo_user_redeems",
        lambda code_id, user_id: list(redeems or []),
    )


def _base_promo(**overrides: Any) -> Dict[str, Any]:
    promo = {
        "code_id": "pc_abc123",
        "code": "SAVE20",
        "creator_user_id": "alice@test.local",
        "discount_type": "percentage",
        "discount_value": 20,
        "free_trial_days": 0,
        "applies_to": ["shop", "subscription"],
        "min_purchase_cents": 0,
        "max_uses": 0,
        "max_uses_per_user": 0,
        "current_uses": 0,
        "expires_at": 0,
        "active": True,
    }
    promo.update(overrides)
    return promo


def _validate(**kwargs: Any) -> Dict[str, Any]:
    defaults = dict(
        code="SAVE20",
        user_id="bob@test.local",
        checkout_type="shop",
        item_price_cents=2500,
        creator_user_id="alice@test.local",
    )
    defaults.update(kwargs)
    return svc.validate_promo_code(**defaults)


# ─── Success paths: type-specific fields populated ────────────────────


def test_percentage_populates_discount_pct_and_original_price(monkeypatch):
    _install_promo(monkeypatch, _base_promo(discount_type="percentage", discount_value=20))
    result = _validate(item_price_cents=2500)

    assert result["valid"] is True
    # FAILS-BEFORE: KeyError — field absent from success dict.
    assert result["discount_pct"] == 20
    assert result["original_price_cents"] == 2500
    assert result["discount_cents"] == 500
    assert result["final_price_cents"] == 2000
    assert result["error_code"] is None

    # The PromoValidateOut model must serialise the new fields (not drop them).
    out = PromoValidateOut(**result)
    assert out.discount_pct == 20
    assert out.original_price_cents == 2500
    assert "discount_pct" in out.model_dump()
    assert "error_code" in out.model_dump()
    assert "buy_x" in out.model_dump()


def test_fixed_amount_has_null_discount_pct_but_original_price(monkeypatch):
    _install_promo(
        monkeypatch,
        _base_promo(discount_type="fixed_amount", discount_value=500),
    )
    result = _validate(item_price_cents=2500)

    assert result["valid"] is True
    assert result["discount_pct"] is None  # not a percentage promo
    assert result["original_price_cents"] == 2500
    assert result["discount_cents"] == 500
    assert result["final_price_cents"] == 2000


def test_free_trial_populates_original_price(monkeypatch):
    _install_promo(
        monkeypatch,
        _base_promo(
            discount_type="free_trial",
            discount_value=0,
            free_trial_days=7,
            applies_to=["subscription"],
        ),
    )
    result = _validate(checkout_type="subscription", item_price_cents=1000)

    assert result["valid"] is True
    assert result["free_trial_days"] == 7
    assert result["original_price_cents"] == 1000
    assert result["discount_pct"] is None


# ─── Failure paths: error_code populated + original_price preserved ───


def test_not_found_sets_error_code(monkeypatch):
    _install_promo(monkeypatch, None)
    result = _validate(item_price_cents=500)

    assert result["valid"] is False
    # FAILS-BEFORE: KeyError — error_code absent from fail dict.
    assert result["error_code"] == "not_found"
    assert result["original_price_cents"] == 500
    assert result["final_price_cents"] == 500


def test_deactivated_sets_error_code(monkeypatch):
    _install_promo(monkeypatch, _base_promo(active=False))
    result = _validate()
    assert result["valid"] is False
    assert result["error_code"] == "deactivated"


def test_expired_sets_error_code(monkeypatch):
    _install_promo(monkeypatch, _base_promo(expires_at=_CLOCK - 10))
    result = _validate()
    assert result["valid"] is False
    assert result["error_code"] == "expired"


def test_usage_limit_sets_error_code(monkeypatch):
    _install_promo(monkeypatch, _base_promo(max_uses=1, current_uses=1))
    result = _validate()
    assert result["valid"] is False
    assert result["error_code"] == "usage_limit"


def test_already_used_sets_error_code(monkeypatch):
    _install_promo(
        monkeypatch,
        _base_promo(max_uses_per_user=1),
        redeems=[{"sk": "REDEEM#bob@test.local#1"}],
    )
    result = _validate()
    assert result["valid"] is False
    assert result["error_code"] == "already_used"


def test_checkout_type_mismatch_sets_error_code(monkeypatch):
    _install_promo(monkeypatch, _base_promo(applies_to=["shop"]))
    result = _validate(checkout_type="subscription")
    assert result["valid"] is False
    assert result["error_code"] == "checkout_type_mismatch"


def test_creator_mismatch_sets_error_code(monkeypatch):
    _install_promo(monkeypatch, _base_promo(creator_user_id="alice@test.local"))
    result = _validate(creator_user_id="charlie@test.local")
    assert result["valid"] is False
    assert result["error_code"] == "product_mismatch"


def test_min_order_sets_error_code_and_preserves_original_price(monkeypatch):
    _install_promo(monkeypatch, _base_promo(min_purchase_cents=5000))
    result = _validate(item_price_cents=2000)
    assert result["valid"] is False
    assert result["error_code"] == "min_order"
    assert result["original_price_cents"] == 2000
    assert result["final_price_cents"] == 2000
