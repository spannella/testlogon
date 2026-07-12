"""STU-001: Scaffolding tests — settings, tables, and DDB table defs.

Offline and hermetic. No moto, no real AWS.
"""
from __future__ import annotations

import importlib.util
import sys


# ---------------------------------------------------------------------------
# Test: Settings
# ---------------------------------------------------------------------------

class TestSettings:
    def test_crm_acl_enabled_default_off(self):
        from app.core.settings import S
        assert S.crm_acl_enabled is False

    def test_crm_studio_enabled_default_off(self):
        from app.core.settings import S
        assert S.crm_studio_enabled is False

    def test_all_table_name_settings_exist(self):
        from app.core.settings import S
        expected = [
            "crm_acl_roles_table_name",
            "crm_security_groups_table_name",
            "crm_studio_fields_table_name",
            "crm_studio_modules_table_name",
            "crm_studio_layouts_table_name",
            "crm_studio_dropdowns_table_name",
            "crm_audit_trail_table_name",
            "currencies_table_name",
            "search_config_table_name",
            "email_queue_table_name",
        ]
        for name in expected:
            assert hasattr(S, name), f"Missing setting: {name}"
            assert isinstance(getattr(S, name), str)
            assert getattr(S, name)  # non-empty default

    def test_default_table_names(self):
        from app.core.settings import S
        assert S.crm_acl_roles_table_name == "crm_acl_roles"
        assert S.crm_security_groups_table_name == "crm_security_groups"
        assert S.crm_studio_fields_table_name == "crm_studio_fields"
        assert S.crm_studio_modules_table_name == "crm_studio_modules"
        assert S.crm_studio_layouts_table_name == "crm_studio_layouts"
        assert S.crm_studio_dropdowns_table_name == "crm_studio_dropdowns"
        assert S.crm_audit_trail_table_name == "crm_audit_trail"
        assert S.currencies_table_name == "currencies"
        assert S.search_config_table_name == "search_config"
        assert S.email_queue_table_name == "email_queue"

    def test_studio_tunable_settings_exist(self):
        from app.core.settings import S
        assert isinstance(S.crm_studio_max_fields_per_entity, int)
        assert S.crm_studio_max_fields_per_entity > 0
        assert isinstance(S.crm_studio_field_cache_ttl_seconds, int)
        assert S.crm_studio_field_cache_ttl_seconds > 0


# ---------------------------------------------------------------------------
# Test: Table handles
# ---------------------------------------------------------------------------

class TestTables:
    def test_all_handles_exist(self):
        from app.core.tables import T
        expected = [
            "crm_acl_roles",
            "crm_security_groups",
            "crm_studio_fields",
            "crm_studio_modules",
            "crm_studio_layouts",
            "crm_studio_dropdowns",
            "crm_audit_trail",
            "currencies",
            "search_config",
            "email_queue",
        ]
        for name in expected:
            assert hasattr(T, name), f"Missing table handle: T.{name}"

    def test_handle_table_names(self):
        from app.core.settings import S
        from app.core.tables import T, _FloatSafeTable
        assert isinstance(T.crm_acl_roles, _FloatSafeTable)
        assert T.crm_acl_roles._t.name == S.crm_acl_roles_table_name
        assert T.email_queue._t.name == S.email_queue_table_name
        assert T.currencies._t.name == S.currencies_table_name
        assert T.crm_studio_fields._t.name == S.crm_studio_fields_table_name


# ---------------------------------------------------------------------------
# Test: TableDefs in local-ddb-init.py
# ---------------------------------------------------------------------------

def _load_defs():
    import sys
    spec = importlib.util.spec_from_file_location(
        "local_ddb_init",
        "scripts/local-ddb-init.py",
    )
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules so dataclasses can find the module's __dict__
    sys.modules["local_ddb_init"] = mod
    try:
        spec.loader.exec_module(mod)
        return mod._table_defs()
    finally:
        sys.modules.pop("local_ddb_init", None)


class TestTableDefs:
    def test_crm_tables_present(self):
        defs = _load_defs()
        names = {d.name for d in defs}
        for expected in [
            "crm_acl_roles", "crm_security_groups", "crm_studio_fields",
            "crm_studio_modules", "crm_studio_layouts", "crm_studio_dropdowns",
            "crm_audit_trail", "currencies", "search_config", "email_queue",
        ]:
            assert expected in names, f"Missing TableDef: {expected}"

    def test_numeric_gsi_attr_types(self):
        defs = {d.name: d for d in _load_defs()}
        assert defs["crm_acl_roles"].attr_types.get("assigned_at") == "N"
        assert defs["crm_security_groups"].attr_types.get("created_at") == "N"
        assert defs["crm_audit_trail"].attr_types.get("changed_at") == "N"
        assert defs["email_queue"].attr_types.get("queued_at") == "N"

    def test_gsi_index_names(self):
        defs = {d.name: d for d in _load_defs()}
        gsi_names = lambda t: [g["index_name"] for g in defs[t].gsi]
        assert "by-assignee" in gsi_names("crm_acl_roles")
        assert "by-record" in gsi_names("crm_security_groups")
        assert "by-actor" in gsi_names("crm_audit_trail")
        assert "by-status" in gsi_names("email_queue")

    def test_no_gsi_on_simple_tables(self):
        defs = {d.name: d for d in _load_defs()}
        for name in ("crm_studio_fields", "crm_studio_modules", "crm_studio_layouts",
                     "crm_studio_dropdowns", "currencies", "search_config"):
            assert defs[name].gsi == [], f"Expected no GSI on {name}"
