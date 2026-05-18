from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def _load_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "payment_incident_backfill_reconcile.py"
    spec = importlib.util.spec_from_file_location("payment_incident_backfill_reconcile", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def test_build_backfill_report_is_deterministic() -> None:
    mod = _load_module()
    candidates = mod.collect_failed_payment_candidates(
        [
            {"pk": "USER#u2", "sk": "PAY#pi_2", "status": "payment_failed", "provider": "stripe"},
            {"pk": "USER#u1", "sk": "PAY#pi_1", "status": "requires_payment_method", "provider": "paypal"},
        ]
    )
    report_1 = mod.build_backfill_report(candidates=candidates, incidents=[])
    report_2 = mod.build_backfill_report(candidates=candidates, incidents=[])
    assert report_1 == report_2
    assert report_1["missing_count"] == 2
    assert report_1["missing"][0]["payment_reference"] == "pi_1"
    assert report_1["missing"][1]["payment_reference"] == "pi_2"


def test_build_backfill_report_omits_existing_payment_failure_incidents() -> None:
    mod = _load_module()
    candidates = mod.collect_failed_payment_candidates(
        [
            {"pk": "USER#u1", "sk": "PAY#pi_1", "status": "payment_failed", "provider": "stripe"},
            {"pk": "USER#u2", "sk": "PAY#pi_2", "status": "payment_failed", "provider": "stripe"},
        ]
    )
    report = mod.build_backfill_report(
        candidates=candidates,
        incidents=[
            {
                "incident_type": "payment_failure",
                "provider": "stripe",
                "payment_reference": "pi_2",
            }
        ],
    )
    assert report["missing_count"] == 1
    assert report["missing"][0]["payment_reference"] == "pi_1"
