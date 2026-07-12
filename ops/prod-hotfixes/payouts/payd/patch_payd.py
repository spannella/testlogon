#!/usr/bin/env python3
"""PAY-D idempotent anchor-based patcher (LIVE PROD HOTFIX + dev mirror).

Applies the scheduled payout runner + lifecycle + manual holds + retries +
notifications across 5 files. Idempotent: re-running is a no-op (each edit is
guarded by a marker). Asserts each anchor is present so a drifted file fails
loudly instead of silently mis-patching.

Usage: python3 patch_payd.py <repo_root> <blocks_dir>
"""
import io
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
BLOCKS = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(__file__))


def read(rel):
    with io.open(os.path.join(ROOT, rel), "r", encoding="utf-8") as fh:
        return fh.read()


def write(rel, data):
    with io.open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(data)


def block(name):
    with io.open(os.path.join(BLOCKS, name), "r", encoding="utf-8") as fh:
        return fh.read()


def replace_once(src, old, new, *, rel):
    n = src.count(old)
    assert n == 1, "anchor not unique (%d) in %s: %r" % (n, rel, old[:80])
    return src.replace(old, new, 1)


def insert_after_line(src, contains, block_text, *, rel):
    lines = src.split("\n")
    hits = [i for i, ln in enumerate(lines) if contains in ln]
    assert len(hits) >= 1, "line anchor missing in %s: %r" % (rel, contains)
    i = hits[0]
    # block_text lines inserted right after line i
    new_lines = lines[: i + 1] + block_text.rstrip("\n").split("\n") + lines[i + 1 :]
    return "\n".join(new_lines)


changed = []


# ── 1) creator_payouts.py: append the PAY-D service block + emit hooks ──────
rel = "app/services/creator_payouts.py"
src = read(rel)
if "def run_payout_sweep(" not in src:
    src = src.rstrip("\n") + "\n" + block("service_block.py")
    changed.append(rel + ":service_block")

# payout_paid emit inside _finalize_paid
fin_anchor = (
    '    item["transfer_provider"] = transfer["transfer_provider"]\n'
    '    item["transfer_ref"] = transfer["transfer_ref"]\n'
    '    return _payout_to_dict(item)'
)
if 'title="Your withdrawal was paid"' not in src:
    fin_new = (
        '    item["transfer_provider"] = transfer["transfer_provider"]\n'
        '    item["transfer_ref"] = transfer["transfer_ref"]\n'
        '    # PAY-34: default-on transactional "your withdrawal was paid" alert.\n'
        '    try:\n'
        '        _emit_payout_alert(\n'
        '            "payout_paid",\n'
        '            recipient=user_id,\n'
        '            title="Your withdrawal was paid",\n'
        '            details={"payout_id": payout_id, "amount_cents": _to_int(item.get("amount_cents", 0)), "transfer_provider": transfer["transfer_provider"]},\n'
        '        )\n'
        '    except Exception:\n'
        '        pass\n'
        '    return _payout_to_dict(item)'
    )
    src = replace_once(src, fin_anchor, fin_new, rel=rel)
    changed.append(rel + ":finalize_paid_alert")

# payout_failed / payout_returned emit inside fail_payout
fail_anchor = (
    '    item["status"] = new_status\n'
    '    item["updated_at"] = now\n'
    '    return _payout_to_dict(item)'
)
if '"payout_returned" if returned else "payout_failed"' not in src:
    fail_new = (
        '    item["status"] = new_status\n'
        '    item["updated_at"] = now\n'
        '    # PAY-34: default-on transactional failure/return alert.\n'
        '    try:\n'
        '        _emit_payout_alert(\n'
        '            "payout_returned" if returned else "payout_failed",\n'
        '            recipient=user_id,\n'
        '            title=("Your withdrawal was returned" if returned else "Your withdrawal failed"),\n'
        '            details={"payout_id": payout_id, "amount_cents": _to_int(item.get("amount_cents", 0)), "returned": bool(returned), "reason": reason},\n'
        '        )\n'
        '    except Exception:\n'
        '        pass\n'
        '    return _payout_to_dict(item)'
    )
    src = replace_once(src, fail_anchor, fail_new, rel=rel)
    changed.append(rel + ":fail_payout_alert")
write(rel, src)


# ── 2) admin_payouts.py: append PAY-D router block ──────────────────────────
rel = "app/routers/admin_payouts.py"
src = read(rel)
if "payd_admin_router" not in src:
    src = src.rstrip("\n") + "\n" + block("router_block.py")
    changed.append(rel + ":router_block")
write(rel, src)


# ── 3) alerts.py: register payout event types + default-on + category + url ─
rel = "app/services/alerts.py"
src = read(rel)
if '"payout_initiated"' not in src.split("ALERT_EVENT_TYPES", 1)[-1][:2000]:
    src = insert_after_line(
        src,
        "ALERT_EVENT_TYPES: List[str] = [",
        '    # Payouts (PAY-D / PAY-34): creator payout lifecycle (default-on transactional)\n'
        '    "payout_initiated","payout_paid","payout_failed","payout_returned",',
        rel=rel,
    )
    changed.append(rel + ":ALERT_EVENT_TYPES")
if "DEFAULT_PUSH_EVENT_TYPES" in src and '"payout_paid",       # PAY-D' not in src:
    src = insert_after_line(
        src,
        "DEFAULT_PUSH_EVENT_TYPES: List[str] = [",
        '    "payout_initiated",  # PAY-D: your withdrawal is processing\n'
        '    "payout_paid",       # PAY-D: your withdrawal was paid\n'
        '    "payout_failed",     # PAY-D: your withdrawal failed\n'
        '    "payout_returned",   # PAY-D: your withdrawal was returned',
        rel=rel,
    )
    changed.append(rel + ":DEFAULT_PUSH")
if '"payouts": {"payout_initiated"' not in src:
    src = insert_after_line(
        src,
        "ALERT_CATEGORIES: Dict[str, set] = {",
        '    "payouts": {"payout_initiated", "payout_paid", "payout_failed", "payout_returned"},',
        rel=rel,
    )
    changed.append(rel + ":ALERT_CATEGORIES")
if '"payout_paid": "/wallet/payouts",' not in src:
    src = insert_after_line(
        src,
        '"subscription_gifted": "/subscriptions/manage",',
        '        "payout_initiated": "/wallet/payouts",\n'
        '        "payout_paid": "/wallet/payouts",\n'
        '        "payout_failed": "/wallet/payouts",\n'
        '        "payout_returned": "/wallet/payouts",',
        rel=rel,
    )
    changed.append(rel + ":url_map")
write(rel, src)


# ── 4) settings.py: add runner + retry config ───────────────────────────────
rel = "app/core/settings.py"
src = read(rel)
if "payout_runner_enabled" not in src:
    src = insert_after_line(
        src,
        "payout_verification_gate_enabled",
        '\n'
        '    # PAY-D (PAY-30..33): scheduled payout runner + bounded retry config.\n'
        '    payout_runner_enabled: bool = os.environ.get("PAYOUT_RUNNER_ENABLED", "true").lower() in ("1", "true", "yes", "on")\n'
        '    payout_runner_interval_seconds: int = int(os.environ.get("PAYOUT_RUNNER_INTERVAL_SECONDS", "300"))\n'
        '    payout_runner_min_age_seconds: int = int(os.environ.get("PAYOUT_RUNNER_MIN_AGE_SECONDS", "0"))\n'
        '    payout_max_transfer_attempts: int = int(os.environ.get("PAYOUT_MAX_TRANSFER_ATTEMPTS", "4"))\n'
        '    payout_retry_backoff_seconds: str = os.environ.get("PAYOUT_RETRY_BACKOFF_SECONDS", "60,300,900")',
        rel=rel,
    )
    changed.append(rel + ":runner_config")
write(rel, src)


# ── 5) main.py: import + include the PAY-D routers + register the runner task ─
rel = "app/main.py"
src = read(rel)
if "from app.services.creator_payouts import start_payout_runner_task" not in src:
    src = replace_once(
        src,
        "from app.services.subscription_renewal import start_subscription_renewal_task",
        "from app.services.subscription_renewal import start_subscription_renewal_task\n"
        "from app.services.creator_payouts import start_payout_runner_task  # PAY-D\n"
        "from app.routers.admin_payouts import payd_admin_router, payd_webhook_router  # PAY-D",
        rel=rel,
    )
    changed.append(rel + ":imports")
if "app.add_event_handler(\"startup\", start_payout_runner_task)" not in src:
    src = replace_once(
        src,
        'app.add_event_handler("startup", start_subscription_renewal_task)',
        'app.add_event_handler("startup", start_payout_runner_task)  # PAY-D payout runner\n'
        '    app.add_event_handler("startup", start_subscription_renewal_task)',
        rel=rel,
    )
    changed.append(rel + ":register_task")
if "app.include_router(payd_admin_router)" not in src:
    src = replace_once(
        src,
        "app.include_router(admin_payouts_router)",
        "app.include_router(admin_payouts_router)\n"
        "    app.include_router(payd_admin_router)  # PAY-D runner trigger\n"
        "    app.include_router(payd_webhook_router)  # PAY-D provider webhook",
        rel=rel,
    )
    changed.append(rel + ":include_routers")
write(rel, src)


print("PAY-D patch applied. changed:")
for c in changed:
    print("  +", c)
if not changed:
    print("  (nothing — already patched)")
