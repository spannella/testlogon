"""ADV3-9 (D6) prod hotfix: stamp surface/slot_type/geo_country on the impression
and click charge meta so the analytics rollup can attribute real per-surface /
per-geo spend. Targeted patch (prod ad_billing.py diverges from the dev clone)."""
import sys


def patch(path, subs):
    s = open(path, encoding="utf-8").read()
    orig = s
    for old, new, n in subs:
        c = s.count(old)
        assert c == n, f"{path}: expected {n} of <<{old[:50]}>> got {c}"
        s = s.replace(old, new)
    assert s != orig
    open(path, "w", encoding="utf-8").write(s)
    print("patched", path)


bp = sys.argv[1] if len(sys.argv) > 1 else "app/services/ad_billing.py"
patch(bp, [
(
'''def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
    idempotency_key: str = "",
) -> dict:
    """Charge advertiser for one impression (CPM model)."""
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm"},
        idempotency_key=idempotency_key,
    )''',
'''def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
    idempotency_key: str = "",
    surface: str = "", slot_type: str = "", geo_country: str = "",
) -> dict:
    """Charge advertiser for one impression (CPM model).

    ADV3-9 (D6): surface / slot_type / geo_country are stamped on the ledger meta
    so the analytics rollup can attribute REAL spend into the per-surface and
    per-geo breakdowns (previously spend=0 on every non-creative dimension).
    """
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm",
              "surface": surface, "slot_type": slot_type, "geo_country": geo_country},
        idempotency_key=idempotency_key,
    )''', 1),
(
'''def charge_click(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpc_cents: int,
    idempotency_key: str = "",
) -> dict:
    """Charge advertiser for one click (CPC model)."""
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="click_charge", charge_cents=bid_cpc_cents,
        creator_id=creator_id, reason="Ad click",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc"},
        idempotency_key=idempotency_key,
    )''',
'''def charge_click(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpc_cents: int,
    idempotency_key: str = "",
    surface: str = "", slot_type: str = "", geo_country: str = "",
) -> dict:
    """Charge advertiser for one click (CPC model).

    ADV3-9 (D6): surface / slot_type / geo_country stamped on ledger meta for the
    per-surface / per-geo spend breakdown.
    """
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="click_charge", charge_cents=bid_cpc_cents,
        creator_id=creator_id, reason="Ad click",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc",
              "surface": surface, "slot_type": slot_type, "geo_country": geo_country},
        idempotency_key=idempotency_key,
    )''', 1),
])
