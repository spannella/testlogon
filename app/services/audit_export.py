"""Unified audit event schema for cross-source audit log exports (ENTERPRISE-004)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class UnifiedAuditEvent:
    event_id: str
    event_type: str
    event_action: str
    timestamp: str
    timestamp_unix: int
    actor_user_id: str
    actor_role: str
    actor_ip: Optional[str] = None
    actor_user_agent: Optional[str] = None
    target_user_id: Optional[str] = None
    target_resource_type: Optional[str] = None
    target_resource_id: Optional[str] = None
    outcome: str = "success"
    metadata: dict = field(default_factory=dict)
    source_table: str = ""
    tenant_id: str = ""
    impersonation_context: Optional[dict] = None

    def to_csv_row(self, columns: list[str]) -> list[str]:
        row = []
        for col in columns:
            val = getattr(self, col, "")
            if isinstance(val, dict):
                row.append(json.dumps(val, default=str))
            elif val is None:
                row.append("")
            else:
                row.append(str(val))
        return row

    def to_ndjson_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}

    def to_ndjson_line(self) -> str:
        return json.dumps(self.to_ndjson_dict(), default=str)
