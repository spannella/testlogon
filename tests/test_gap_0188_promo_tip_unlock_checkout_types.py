"""Regression test for GAP-0188 (FIN-002).

``VALID_CHECKOUT_TYPES`` in ``app/services/promo_codes.py`` was
``{"subscription", "vod", "shop"}`` — the ``"tip"`` and ``"unlock"`` surfaces
were absent. Two consequences:

1. ``create_promo_code`` validates ``applies_to`` against ``VALID_CHECKOUT_TYPES``,
   so a creator could not even create a promo targeting tip/unlock checkouts
   (returned ``"Invalid applies_to value: tip"``).
2. Such a code could therefore never list ``"tip"``/``"unlock"`` in ``applies_to``,
   so ``validate_promo_code(checkout_type="tip")`` always failed with
   ``error_code="checkout_type_mismatch"``.

Fails-before: ``create_promo_code(applies_to=["tip"])`` returns an error, so a
tip-scoped code can never validate.
Passes-after: the code is created and ``validate_promo_code`` returns
``valid=True`` for ``checkout_type="tip"`` / ``"unlock"``.

Fully offline: the PromoCodes DynamoDB table is replaced with an in-memory fake
(supporting ``put_item`` and the two GSIs the service queries). No real AWS /
DynamoDB access occurs. Settings ``S`` is frozen, so any setting override uses
``object.__setattr__``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.services import promo_codes as pc


def _collect_constraints(cond) -> list[tuple[str, str, object]]:
    """Walk a boto3 condition tree, returning (op, key_name, value) tuples.

    Supports the equality and begins_with constraints the promo service uses
    (the latter matters so per-user REDEEM lookups don't match the META row).
    """
    expr = cond.get_expression()
    op = expr["operator"]
    values = expr["values"]
    if op == "AND":
        out: list[tuple[str, str, object]] = []
        for sub in values:
            out.extend(_collect_constraints(sub))
        return out
    if op == "=":
        return [("=", values[0].name, values[1])]
    if op == "begins_with":
        return [("begins_with", values[0].name, values[1])]
    return []


def _matches(item: dict, constraints: list[tuple[str, str, object]]) -> bool:
    for op, name, val in constraints:
        actual = item.get(name)
        if op == "=":
            if actual != val:
                return False
        elif op == "begins_with":
            if not (isinstance(actual, str) and actual.startswith(val)):
                return False
    return True


@dataclass
class _FakePromoTable:
    """Minimal in-memory stand-in for the PromoCodes DynamoDB table.

    Supports ``put_item``, ``get_item`` and the two GSI queries the service
    issues (``ByCodeString`` on ``code_lookup_pk`` and ``ByCreatorCreatedAt``
    on ``creator_scope``).
    """

    items: dict[tuple[str, str], dict] = field(default_factory=dict)

    def put_item(self, *, Item):
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def query(self, **kwargs):
        # The service builds KeyConditionExpression as either a single
        # Key(name).eq(val) equality or an And of (eq partition key,
        # begins_with sort key). Walk the expression tree and collect every
        # equality constraint, then match items against all of them.
        constraints = _collect_constraints(kwargs["KeyConditionExpression"])
        matched = [dict(v) for v in self.items.values() if _matches(v, constraints)]
        return {"Items": matched}


def _install_fake_table(monkeypatch) -> _FakePromoTable:
    table = _FakePromoTable()
    monkeypatch.setattr(pc, "_tbl", lambda: table)
    return table


def test_create_and_validate_tip_promo(monkeypatch):
    """Tip-scoped promo creates and validates (was rejected before the fix)."""
    _install_fake_table(monkeypatch)

    creator = "creator_alice"
    item, err = pc.create_promo_code(
        creator_id=creator,
        code="TIP20OFF",
        discount_type="percentage",
        discount_value=20,
        applies_to=["tip"],
    )
    # FAILS-BEFORE: err == "Invalid applies_to value: tip"
    assert err is None, f"create_promo_code rejected tip surface: {err}"
    assert item is not None
    assert item["applies_to"] == ["tip"]

    result = pc.validate_promo_code(
        code="TIP20OFF",
        user_id="buyer_bob",
        checkout_type="tip",
        item_price_cents=1000,
        creator_user_id=creator,
    )
    # FAILS-BEFORE: error_code == "checkout_type_mismatch" (code never existed)
    assert result["valid"] is True, result.get("error_code")
    assert result["discount_cents"] == 200  # 20% of 1000
    assert result["error_code"] is None


def test_create_and_validate_unlock_promo(monkeypatch):
    """Unlock-scoped promo creates and validates (was rejected before the fix)."""
    _install_fake_table(monkeypatch)

    creator = "creator_alice"
    item, err = pc.create_promo_code(
        creator_id=creator,
        code="UNLOCK100",
        discount_type="fixed_amount",
        discount_value=100,
        applies_to=["unlock"],
    )
    # FAILS-BEFORE: err == "Invalid applies_to value: unlock"
    assert err is None, f"create_promo_code rejected unlock surface: {err}"
    assert item is not None
    assert item["applies_to"] == ["unlock"]

    result = pc.validate_promo_code(
        code="UNLOCK100",
        user_id="buyer_bob",
        checkout_type="unlock",
        item_price_cents=500,
        creator_user_id=creator,
    )
    # FAILS-BEFORE: error_code == "checkout_type_mismatch" (code never existed)
    assert result["valid"] is True, result.get("error_code")
    assert result["discount_cents"] == 100  # fixed $1.00 off
    assert result["error_code"] is None


def test_valid_checkout_types_constant_includes_tip_and_unlock():
    """The constant the gate reads from must include both new surfaces."""
    assert "tip" in pc.VALID_CHECKOUT_TYPES
    assert "unlock" in pc.VALID_CHECKOUT_TYPES
