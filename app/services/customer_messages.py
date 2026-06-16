"""CUS-002: Customer message thread service."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor


@dataclass
class CustomerMessageStore:
    _table: Any = field(default=None)

    def __post_init__(self) -> None:
        if self._table is None:
            object.__setattr__(self, "_table", T.customers)

    def _cust_pk(self, customer_id: str) -> str:
        return f"CUST#{customer_id}"

    def _msg_sk(self, ts: int, message_id: str) -> str:
        return f"MSG#{ts:013d}#{message_id}"

    def post_message(
        self,
        customer_id: str,
        *,
        author_sub: str,
        author_role: Literal["STAFF", "CUSTOMER"],
        body: str,
    ) -> dict[str, Any]:
        ts = now_ts()
        message_id = f"cmsg_{uuid4().hex[:12]}"
        sk = self._msg_sk(ts, message_id)
        item: dict[str, Any] = {
            "pk": self._cust_pk(customer_id),
            "sk": sk,
            "customer_id": customer_id,
            "message_id": message_id,
            "author_sub": author_sub,
            "author_role": author_role,
            "body": body,
            "created_at": ts,
        }
        self._table.put_item(Item=item)

        # Notifications — best-effort
        if author_role == "STAFF":
            try:
                linked_user = self.get_linked_user(customer_id)
                if linked_user:
                    from app.services.alerts import write_alert
                    write_alert(
                        user_sub=linked_user,
                        event="customer.message",
                        outcome="info",
                        title="New message from support",
                        details={
                            "customer_id": customer_id,
                            "message_id": message_id,
                            "preview": body[:120],
                        },
                    )
            except Exception:
                pass
        elif author_role == "CUSTOMER":
            try:
                # Notify staff who have previously posted in this thread
                prior_msgs = self._list_messages_raw(customer_id, limit=50, newest_first=True)
                staff_subs = list({m["author_sub"] for m in prior_msgs if m.get("author_role") == "STAFF"})
                if staff_subs:
                    from app.services.alerts import write_alert
                    for staff_sub in staff_subs:
                        try:
                            write_alert(
                                user_sub=staff_sub,
                                event="customer.reply",
                                outcome="info",
                                title="Customer replied to message thread",
                                details={
                                    "customer_id": customer_id,
                                    "message_id": message_id,
                                    "preview": body[:120],
                                },
                            )
                        except Exception:
                            pass
            except Exception:
                pass

        return item

    def list_messages(
        self,
        customer_id: str,
        *,
        cursor: str | None = None,
        limit: int = 50,
        newest_first: bool = False,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk AND begins_with(sk, :pfx)",
            "ExpressionAttributeValues": {
                ":pk": self._cust_pk(customer_id),
                ":pfx": "MSG#",
            },
            "Limit": limit,
            "ScanIndexForward": not newest_first,
        }
        start_key = decode_cursor(cursor)
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = self._table.query(**kwargs)
        items = resp.get("Items", [])
        lek = resp.get("LastEvaluatedKey")
        return {
            "messages": items,
            "cursor": encode_cursor(lek),
        }

    def _list_messages_raw(self, customer_id: str, *, limit: int = 50, newest_first: bool = False) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={
                ":pk": self._cust_pk(customer_id),
                ":pfx": "MSG#",
            },
            Limit=limit,
            ScanIndexForward=not newest_first,
        )
        return resp.get("Items", [])

    def get_linked_user(self, customer_id: str) -> str | None:
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={
                ":pk": f"CUST#{customer_id}",
                ":pfx": "LINK#USER#",
            },
            Limit=1,
        )
        items = resp.get("Items", [])
        return items[0]["user_sub"] if items else None


MSG_STORE = CustomerMessageStore()
