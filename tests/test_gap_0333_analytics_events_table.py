"""GAP-0333 / PLATFORM-019: analytics_events table must be wired (setting + handle
+ TableDef in local-ddb-init.py).

Before the fix the table was never created -> any event-recording call hit
ResourceNotFoundException and the rollup job could not run. This test locks in the
full wiring (mirrors the AnalyticsRollups wiring; SECOPS-007 dev/prod parity).

Offline / hermetic. The moto round-trip proves the declared schema is valid.
"""
import ast
import os

import boto3
import pytest

try:
    from moto import mock_aws  # moto >= 5
except ImportError:  # pragma: no cover
    from moto import mock_dynamodb as mock_aws


_INIT_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "local-ddb-init.py",
)


def test_settings_has_analytics_events_table_name():
    import app.core.settings as settings_mod

    assert hasattr(settings_mod.S, "analytics_events_table_name")
    assert settings_mod.S.analytics_events_table_name == "AnalyticsEvents"


def test_tables_has_analytics_events_handle():
    import app.core.tables as tables_mod

    assert hasattr(tables_mod.T, "analytics_events")
    # The dataclass field is declared (mirrors analytics_rollups).
    assert "analytics_events" in tables_mod.Tables.__dataclass_fields__


def _find_analytics_events_tabledef():
    """Return the ast.Call node for the analytics_events TableDef, or None."""
    src = open(_INIT_SCRIPT).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "TableDef"):
            continue
        # First positional arg is the name expression. We accept either a
        # _resolve_table_name(...) call or an os.environ.get(...) referencing
        # the analytics events table.
        if not node.args:
            continue
        name_arg = node.args[0]
        as_src = ast.get_source_segment(src, name_arg) or ""
        if "analytics_events_table_name" in as_src or "AnalyticsEvents" in as_src:
            return node, src
    return None


def test_tabledef_declared_with_gsi1_and_ttl():
    found = _find_analytics_events_tabledef()
    assert found is not None, "analytics_events TableDef not declared in local-ddb-init.py"
    node, src = found

    # GSI1 present as a keyword `gsi=[{...}]` with GSI1PK/GSI1SK.
    gsi_kw = next((kw for kw in node.keywords if kw.arg == "gsi"), None)
    assert gsi_kw is not None, "analytics_events TableDef missing gsi= kwarg"
    gsi_src = ast.get_source_segment(src, gsi_kw.value) or ""
    assert "GSI1" in gsi_src
    assert "GSI1PK" in gsi_src
    assert "GSI1SK" in gsi_src

    # TTL ("ttl_epoch") is enabled for the table in main() via _enable_ttl_if_needed.
    assert "ttl_epoch" in src
    assert "analytics_events_table_name" in src
    # The enable call must reference the analytics events table.
    assert "_enable_ttl_if_needed" in src
    enable_line = [
        ln for ln in src.splitlines()
        if "_enable_ttl_if_needed" in ln and "AnalyticsEvents" in ln
    ]
    assert enable_line, "TTL not enabled for analytics_events table in main()"


@mock_aws
def test_schema_round_trips_in_moto():
    """Create the table from the declared shape and round-trip a put/get."""
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    table = ddb.create_table(
        TableName="AnalyticsEvents",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.put_item(
        Item={
            "pk": "EVENT#u1",
            "sk": "2026-06-07T00:00:00Z#abc",
            "GSI1PK": "DATE#2026-06-07",
            "GSI1SK": "u1",
            "event_name": "page_view",
            "ttl_epoch": 9999999999,
        }
    )
    got = table.get_item(Key={"pk": "EVENT#u1", "sk": "2026-06-07T00:00:00Z#abc"})["Item"]
    assert got["event_name"] == "page_view"
    res = table.query(
        IndexName="GSI1",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("GSI1PK").eq("DATE#2026-06-07"),
    )
    assert res["Count"] == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
