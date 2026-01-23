from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.time import now_ts

BAL_FIELDS = [
    "owed_pending_cents",
    "owed_settled_cents",
    "payments_pending_cents",
    "payments_settled_cents",
]


def user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def ddb_get(table: Any, pk: str, sk: str) -> Optional[Dict[str, Any]]:
    resp = table.get_item(Key={"pk": pk, "sk": sk})
    return resp.get("Item")


def ddb_put(table: Any, item: Dict[str, Any], *, condition_expression: Optional[str] = None) -> None:
    kwargs: Dict[str, Any] = {"Item": item}
    if condition_expression:
        kwargs["ConditionExpression"] = condition_expression
    table.put_item(**kwargs)


def ddb_del(table: Any, pk: str, sk: str) -> None:
    table.delete_item(Key={"pk": pk, "sk": sk})


def ddb_query_pk(table: Any, pk: str) -> List[Dict[str, Any]]:
    resp = table.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": pk},
    )
    return resp.get("Items", [])


def ddb_update(
    table: Any,
    pk: str,
    sk: str,
    expr: str,
    values: Dict[str, Any],
    names: Optional[Dict[str, str]] = None,
) -> None:
    kwargs: Dict[str, Any] = {
        "Key": {"pk": pk, "sk": sk},
        "UpdateExpression": expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    table.update_item(**kwargs)


def ensure_balance_row(table: Any, pk: str, currency: str) -> None:
    if not ddb_get(table, pk, "BALANCE"):
        ddb_put(
            table,
            {
                "pk": pk,
                "sk": "BALANCE",
                "currency": currency,
                **{k: 0 for k in BAL_FIELDS},
                "updated_at": now_ts(),
            },
        )


def apply_balance_delta(table: Any, pk: str, delta: Dict[str, int], *, currency: str = "usd") -> None:
    ensure_balance_row(table, pk, currency)

    sets = []
    values: Dict[str, Any] = {":z": 0, ":t": now_ts()}
    names: Dict[str, str] = {}

    i = 0
    for key, value in delta.items():
        if value == 0:
            continue
        i += 1
        nk = f"#k{i}"
        dv = f":d{i}"
        names[nk] = key
        values[dv] = int(value)
        sets.append(f"{nk} = if_not_exists({nk}, :z) + {dv}")

    names["#u"] = "updated_at"
    sets.append("#u = :t")

    expr = "SET " + ", ".join(sets)
    ddb_update(table, pk, "BALANCE", expr, values, names=names)


def compute_due(balance_item: Dict[str, Any]) -> Dict[str, int]:
    owed_settled = int(balance_item.get("owed_settled_cents", 0))
    owed_pending = int(balance_item.get("owed_pending_cents", 0))
    pay_settled = int(balance_item.get("payments_settled_cents", 0))
    pay_pending = int(balance_item.get("payments_pending_cents", 0))

    due_settled = owed_settled - pay_settled
    due_if_all_settles = (owed_settled + owed_pending) - (pay_settled + pay_pending)

    return {
        "due_settled_cents": due_settled,
        "due_if_all_settles_cents": due_if_all_settles,
    }
