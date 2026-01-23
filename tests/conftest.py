from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock
from importlib.machinery import ModuleSpec
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.modules.setdefault("prometheus_client", MagicMock())

if "multipart" not in sys.modules:
    multipart_mod = ModuleType("multipart")
    multipart_mod.__spec__ = ModuleSpec("multipart", loader=None)
    multipart_mod.__version__ = "0.0.0"

    multipart_inner = ModuleType("multipart.multipart")
    multipart_inner.__spec__ = ModuleSpec("multipart.multipart", loader=None)
    multipart_inner.parse_options_header = lambda value: (value, {})

    multipart_mod.multipart = multipart_inner
    sys.modules["multipart"] = multipart_mod
    sys.modules["multipart.multipart"] = multipart_inner
