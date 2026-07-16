p="app/routers/catalog.py"
s=open(p).read()
s=s.replace(
    "    user_sub = ctx[\"user_sub\"]\n    item_meta = _get_item_meta(item_id)\n    creator_id = item_meta.get(\"creator_id\")\n    if creator_id and not can_access_creator(user_sub, creator_id):\n        raise HTTPException(status_code=403, detail=\"Subscription required to review.\")",
    "    user_sub = ctx[\"user_sub\"]\n    item_meta = _find_item_by_id(item_id) or {}\n    creator_id = item_meta.get(\"creator_id\")\n    if creator_id and not can_access_creator(user_sub, creator_id):\n        raise HTTPException(status_code=403, detail=\"Subscription required to review.\")",
    1)
s=s.replace(
    "    is_admin = role in (\"admin\", \"root\")\n    item_meta = _get_item_meta(item_id)\n    creator_id = item_meta.get(\"creator_id\")\n    if not is_admin and creator_id and creator_id != user_sub:\n        raise HTTPException(status_code=403, detail=\"Only the seller can respond to a review.\")",
    "    is_admin = role in (\"admin\", \"root\")\n    item_meta = _find_item_by_id(item_id) or {}\n    creator_id = item_meta.get(\"creator_id\")\n    if not is_admin and creator_id and creator_id != user_sub:\n        raise HTTPException(status_code=403, detail=\"Only the seller can respond to a review.\")",
    1)
open(p,"w").write(s)
import ast; ast.parse(s); print("prod catalog find_item swap ok")
