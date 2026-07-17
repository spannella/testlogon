p="app/routers/catalog.py"
s=open(p).read()
old='''            from app.services.alerts import write_alert
            _stars = item["rating"]
            write_alert(
                creator_id,
                event="review_received",
                outcome="info",
                title=f"New {_stars}-star review on your item",
                details={
                    "alert_type": "review_received",
                    "item_id": item_id,
                    "review_id": review_id,
                    "rating": item["rating"],
                },
            )'''
new='''            from app.services.alerts import write_alert
            _stars = item["rating"]
            _title = f"New {_stars}-star review on your item"
            _res = write_alert(
                creator_id,
                event="review_received",
                outcome="info",
                title=_title,
                details={
                    "alert_type": "review_received",
                    "item_id": item_id,
                    "review_id": review_id,
                    "rating": item["rating"],
                },
            )
            try:
                from app.services.push import send_push_for_alert
                _aid = (_res or {}).get("alert_id", review_id) if isinstance(_res, dict) else review_id
                send_push_for_alert(
                    creator_id, "review_received", _title,
                    "Tap to read the review.", _aid,
                    action_url=f"/catalog/items/{item_id}#reviews",
                )
            except Exception:
                logger.exception("review_received push failed for item %s", item_id)'''
assert old in s, "catalog review alert block missing"
s=s.replace(old,new,1)
open(p,"w").write(s)
import ast; ast.parse(s); print("prod catalog push added")
