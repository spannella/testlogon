import io, os, hashlib

ROOT = "/home/ubuntu/testlogon"

ANCHORS = {
    "app/services/subscription_access.py": [
        '        if status in {"active", "past_due", "trialing"}:\n            return True\n    return False\n',
    ],
    "app/core/settings.py": [
        'BILLING_DUNNING_RETRY_SCHEDULE_SECONDS", "3600,86400,172800")\n',
    ],
    "app/services/alerts.py": [
        '    "order_delivered",         # your order was delivered (buyer, D4)\n]\n',
    ],
    "app/main.py": [
        "from app.services.billing_dunning import start_billing_dunning_task\n",
        '    app.add_event_handler("startup", start_billing_dunning_task)\n',
    ],
    "app/routers/subscription_server.py": [
        "from fastapi import APIRouter, Header, HTTPException, Query, Request\n",
        "from app.services.subscription_cycle_orders import emit_subscription_cycle_order\n",
        '    sub["updated_at"] = ts\n    save_subscription(sub)\n    return {"ok": True, "event_id": event_id}\n',
    ],
}

MARKERS = {
    "app/services/subscription_access.py": "SUB-E1 expiry enforcement",
    "app/core/settings.py": "SUBSCRIPTION_RENEWAL_ENABLED",
    "app/services/alerts.py": "subscription_renewed",
    "app/main.py": "start_subscription_renewal_task",
    "app/routers/subscription_server.py": "/ui/admin/subscriptions/run-renewals",
}

print("=== SUB-E1 PROD PROBE ===")
for path, anchors in ANCHORS.items():
    full = os.path.join(ROOT, path)
    try:
        with io.open(full, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception as exc:
        print("MISSING FILE", path, exc)
        continue
    sha = hashlib.sha256(src.encode()).hexdigest()[:12]
    print(f"\n{path}  lines={src.count(chr(10))}  sha={sha}")
    print("  marker(%s): %s" % (MARKERS[path], "ALREADY_APPLIED" if MARKERS[path] in src else "absent"))
    for a in anchors:
        n = src.count(a)
        print("  anchor count=%d %s :: %r" % (n, "OK" if n == 1 else "!!PROBLEM", a[:55]))

renewal = os.path.join(ROOT, "app/services/subscription_renewal.py")
print("\nsubscription_renewal.py exists:", os.path.exists(renewal))
print("=== PROBE DONE ===")
