#!/usr/bin/env python3
"""D3 (buyer shipped push) + order_shipped default-ON registration.
Anchored, idempotent, self-verifying (py_compile; restore .bak on failure).
Run with ROOT env to target a probe copy: ROOT=/tmp/probe python apply_ecom_d3.py
"""
import os, sys, time, shutil, py_compile, subprocess

ROOT = os.environ.get("ROOT", "/home/ubuntu/testlogon")
TS = int(time.time())
ALERTS = os.path.join(ROOT, "app/services/alerts.py")
SSG = os.path.join(ROOT, "app/services/seller_ship_groups.py")

def read(p): 
    with open(p) as f: return f.read()
def write(p, s):
    with open(p, "w") as f: f.write(s)

def patch(path, edits, marker):
    src = read(path)
    if marker in src:
        print(f"SKIP {os.path.basename(path)} (already patched: marker present)")
        return None
    for old, new in edits:
        c = src.count(old)
        if c != 1:
            raise SystemExit(f"ANCHOR FAIL in {path}: expected 1 occurrence, found {c}:\n---\n{old}\n---")
        src = src.replace(old, new, 1)
    return src

# ---- alerts.py edits ----
alerts_edits = [
    (
        '    "commerce": {"cart.abandoned"},',
        '    "commerce": {"cart.abandoned", "order_shipped"},',
    ),
    (
        '    # Commerce / seller fulfillment (ECOM-SELLER G1)\n    "shop_item_sold",\n]',
        '    # Commerce / seller fulfillment (ECOM-SELLER G1)\n    "shop_item_sold",\n    # Commerce / buyer order lifecycle (ECOM D3)\n    "order_shipped",\n]',
    ),
    (
        '    "message_tip",           # you received a message tip\n]',
        '    "message_tip",           # you received a message tip\n    "order_shipped",         # your order has shipped (buyer, D3)\n]',
    ),
]
ALERTS_MARKER = '"order_shipped",         # your order has shipped (buyer, D3)'

# ---- seller_ship_groups.py edits ----
BUYER_FN = '''def _notify_buyer_shipped(row: Dict[str, Any]) -> None:
    """D3: when the seller marks a ship-group SHIPPED, notify the BUYER
    ("Your order has shipped") with an in-app alert (write_alert) + FCM push.
    Default-ON transactional event (order_shipped); carries tracking#+carrier +
    a deep-link to the buyer's order/tracking view. Idempotent by construction:
    only fires on the (approved->...->)shipped edge; 'shipped' is terminal in the
    state machine so a repeat shipped->shipped 409s before reaching here."""
    buyer = row.get("buyer_id")
    if not buyer:
        return
    sg_id = row.get("ship_group_id") or ""
    order_id = row.get("order_id") or ""
    lines = row.get("line_items", []) or []
    n = len(lines)
    first = (lines[0].get("name") if lines else "") or "your item"
    summary = first if n <= 1 else f"{first} +{n - 1} more"
    carrier = str(row.get("carrier") or "").strip()
    tracking = str(row.get("tracking_number") or "").strip()
    title = "Your order has shipped"
    tail = f" via {carrier}" if carrier else ""
    tail += f" (tracking {tracking})" if tracking else ""
    body = f"{summary} is on the way{tail}. Tap to track."
    action_url = f"/orders?order={order_id}&ship_group={sg_id}"
    alert_id = ""
    try:
        from app.services.alerts import write_alert
        res = write_alert(
            buyer,
            event="order_shipped",
            outcome="success",
            title=title,
            details={
                "alert_type": "order_shipped",
                "ship_group_id": sg_id,
                "order_id": order_id,
                "carrier": carrier,
                "tracking_number": tracking,
                "item_count": n,
                "summary": summary,
            },
            action_url=action_url,
            source_type="order_shipment",
            source_id=sg_id,
        )
        alert_id = (res or {}).get("alert_id", "") if isinstance(res, dict) else ""
    except Exception:
        logger.exception("write_alert(order_shipped) failed for buyer %s sg %s", buyer, sg_id)
    try:
        from app.services.push import send_push_for_alert
        send_push_for_alert(buyer, "order_shipped", title, body, alert_id or sg_id, action_url=action_url)
    except Exception:
        logger.exception("buyer shipped push failed for buyer %s sg %s", buyer, sg_id)


# -- seller-scoped reads ------------------------------------------------------'''

ssg_edits = [
    (
        '# -- seller-scoped reads ------------------------------------------------------',
        BUYER_FN,
    ),
    (
        '    resp = T.seller_ship_groups.update_item(\n'
        '        Key={"seller_id": seller_id, "ship_group_id": ship_group_id},\n'
        '        UpdateExpression="SET " + ", ".join(set_parts),\n'
        '        ExpressionAttributeNames={"#st": "status"},\n'
        '        ExpressionAttributeValues=vals,\n'
        '        ConditionExpression="#st = :cur",\n'
        '        ReturnValues="ALL_NEW",\n'
        '    )\n'
        '    return resp.get("Attributes", row)',
        '    resp = T.seller_ship_groups.update_item(\n'
        '        Key={"seller_id": seller_id, "ship_group_id": ship_group_id},\n'
        '        UpdateExpression="SET " + ", ".join(set_parts),\n'
        '        ExpressionAttributeNames={"#st": "status"},\n'
        '        ExpressionAttributeValues=vals,\n'
        '        ConditionExpression="#st = :cur",\n'
        '        ReturnValues="ALL_NEW",\n'
        '    )\n'
        '    updated = resp.get("Attributes", row)\n'
        '    # D3: notify the BUYER when this ship-group ships (default-ON push).\n'
        '    if target == "shipped":\n'
        '        _notify_buyer_shipped(updated)\n'
        '    return updated',
    ),
]
SSG_MARKER = 'def _notify_buyer_shipped('

def apply_file(path, edits, marker):
    new = patch(path, edits, marker)
    if new is None:
        return False
    bak = f"{path}.bak_ecomd3_{TS}"
    shutil.copy2(path, bak)
    write(path, new)
    try:
        py_compile.compile(path, doraise=True)
    except Exception as e:
        shutil.copy2(bak, path)
        raise SystemExit(f"py_compile FAILED for {path}: {e}\nRESTORED from {bak}")
    print(f"PATCHED {os.path.basename(path)}  (.bak = {os.path.basename(bak)})")
    # chown to ubuntu if running as root
    try:
        import pwd
        u = pwd.getpwnam("ubuntu")
        for f in (path, bak):
            os.chown(f, u.pw_uid, u.pw_gid)
    except Exception:
        pass
    return True

def main():
    a = apply_file(ALERTS, alerts_edits, ALERTS_MARKER)
    s = apply_file(SSG, ssg_edits, SSG_MARKER)
    print("DONE alerts_patched=%s ssg_patched=%s ROOT=%s" % (a, s, ROOT))

if __name__ == "__main__":
    main()
