import os, sys
p = os.path.join(os.environ.get("ROOT", "."), "app/services/alerts.py")
s = open(p).read()
if "order_shipped" in s:
    print("SKIP alerts.py already has order_shipped"); sys.exit(0)
edits = [
 ('    "commerce": {"cart.abandoned"},', '    "commerce": {"cart.abandoned", "order_shipped"},'),
 ('    "shop_item_sold",\n]',
  '    "shop_item_sold",\n    # Commerce / buyer order lifecycle (ECOM D3)\n    "order_shipped",\n]'),
 ('    "message_tip",           # you received a message tip\n]',
  '    "message_tip",           # you received a message tip\n    "order_shipped",         # your order has shipped (buyer, D3)\n]'),
]
for old, new in edits:
    c = s.count(old)
    assert c == 1, f"anchor count {c} for {old[:40]!r}"
    s = s.replace(old, new, 1)
open(p, "w").write(s)
import py_compile; py_compile.compile(p, doraise=True)
print("PATCHED app/services/alerts.py")
