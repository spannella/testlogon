#!/usr/bin/env python3
"""selldash E1 prod fold — mirror the dev-clone E1 buyer-visible-tracking join to
PROD (i-08f937fc705ebea75) via SSM.

Probe (md5, this run's date) confirmed prod == dev pre-E1 baseline for the four
service/router files → copied VERBATIM. prod app/models.py DIVERGES from the
dev clone → anchor-patched (patch_models_prod.py; validated to reproduce the dev
final models.py byte-for-byte from the dev pre-E1 baseline).

  VERBATIM:
    app/services/order_lifecycle.py         (get_order_lifecycle buyer_sub + inline shipments)
    app/services/order_fulfillment_bridge.py(order_shipments_inline)
    app/routers/order_lifecycle.py          (list + detail + confirm-delivery buyer_sub)
    app/services/store_integration.py       (ECM-007 -> real ship groups via bridge)
  ANCHOR-PATCHED:
    app/models.py  (+ OrderShipmentOut; OrderLifecycleOut/OrderListItem shipments+fulfillment_status; rebuilds)

Backs up each touched file to .bak_selldash_e1_<ts>, chowns ubuntu:ubuntu,
import-sanity, restarts (root-uvicorn kill first), verifies openapi 200.
"""
import base64, gzip, subprocess, sys, os, time

HERE = os.path.dirname(os.path.abspath(__file__))
SSM = "/tmp/ssm_send.py"

VERBATIM = {
    "app/services/order_lifecycle.py": "order_lifecycle.py",
    "app/services/order_fulfillment_bridge.py": "order_fulfillment_bridge.py",
    "app/routers/order_lifecycle.py": "order_lifecycle_router.py",
    "app/services/store_integration.py": "store_integration.py",
}
PATCHERS = {
    "app/models.py": "patch_models_prod.py",
}

# md5 the four verbatim prod files must currently match (dev pre-E1 baseline).
EXPECT_MD5 = {
    "app/services/order_lifecycle.py": "070ef3261d8f29506c9be233d970b19e",
    "app/services/order_fulfillment_bridge.py": "e7fe567a03a63d39f7ff1ad657f57ec2",
    "app/routers/order_lifecycle.py": "3ef905df35aab547a5fde91809965821",
    "app/services/store_integration.py": "71965aa673fca7e7bb8681d3ff628c6f",
}


def b64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def gz64(path):
    """gzip then base64 — keeps the whole fold under the SSM 97KB param cap."""
    with open(path, "rb") as f:
        return base64.b64encode(gzip.compress(f.read(), 9)).decode()


def build_script():
    ts = str(int(time.time()))
    lines = [
        "set -e",
        "cd /home/ubuntu/testlogon",
        f"TS={ts}",
        'echo "PROD selldash E1 fold @ $TS"',
    ]
    # Guard: verify the verbatim files still match the expected baseline md5s.
    for dest, md5 in EXPECT_MD5.items():
        lines.append(
            f'have=$(md5sum {dest} | cut -d" " -f1); '
            f'if [ "$have" != "{md5}" ]; then echo "ABORT: {dest} md5 $have != {md5} (prod diverged)"; exit 3; fi'
        )
    # verbatim files (gzip+base64 to fit the SSM 97KB param cap)
    for dest, local in VERBATIM.items():
        payload = gz64(os.path.join(HERE, local))
        lines.append(f'cp {dest} {dest}.bak_selldash_e1_$TS')
        lines.append(f'echo "{payload}" | base64 -d | gunzip > {dest}')
        lines.append(f'chown ubuntu:ubuntu {dest}')
    # anchor patchers
    for target, patcher in PATCHERS.items():
        payload = gz64(os.path.join(HERE, patcher))
        lines.append(f'cp {target} {target}.bak_selldash_e1_$TS')
        lines.append(f'echo "{payload}" | base64 -d | gunzip > /tmp/{patcher}')
        lines.append(f'(cd /home/ubuntu/testlogon && python3 /tmp/{patcher})')
        lines.append(f'chown ubuntu:ubuntu {target}')
    # import sanity
    lines.append('sudo -u ubuntu bash -lc "cd /home/ubuntu/testlogon && set -a; . .env.local 2>/dev/null; . .venv/bin/activate 2>/dev/null; python3 -c \'import app.main; print(\\"import OK\\")\'"')
    # restart: kill root-owned uvicorn first, then ubuntu restart script
    lines.append('pkill -f "uvicorn app.main" || true')
    lines.append('sleep 3')
    lines.append('sudo -u ubuntu bash /home/ubuntu/restart_backend.sh || true')
    lines.append('sleep 6')
    lines.append('for i in $(seq 1 30); do c=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/openapi.json); [ "$c" = "200" ] && { echo "OPENAPI 200"; break; }; sleep 2; done')
    lines.append('grep -c "order_shipments_inline" app/services/order_fulfillment_bridge.py && grep -c "OrderShipmentOut" app/models.py && grep -c "_bridge_fulfillment_status" app/services/store_integration.py')
    return "\n".join(lines)


def main():
    script = build_script()
    p = subprocess.run(["python3", SSM], input=script, capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    if p.stderr.strip():
        sys.stderr.write(p.stderr)


if __name__ == "__main__":
    main()
