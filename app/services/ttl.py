from __future__ import annotations
from typing import Any, Dict
from app.core.settings import S

def with_ttl(item: Dict[str, Any], ttl_epoch: int) -> Dict[str, Any]:
    item[S.ddb_ttl_attr] = int(ttl_epoch)
    return item
