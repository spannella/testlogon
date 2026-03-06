from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import Iterator

logger = logging.getLogger("app.vnc.observability")

try:  # pragma: no cover - optional dependency
    from opentelemetry import trace
except Exception:  # pragma: no cover - optional dependency
    trace = None


def resolve_correlation_id(raw: str | None) -> str:
    value = str(raw or "").strip()
    return value[:128] if value else uuid.uuid4().hex


@contextlib.contextmanager
def vnc_trace_span(name: str, **attributes: object) -> Iterator[None]:
    if trace is None:
        yield
        return

    tracer = trace.get_tracer("app.vnc")
    with tracer.start_as_current_span(name) as span:
        for key, value in attributes.items():
            if value is None:
                continue
            span.set_attribute(f"vnc.{key}", str(value))
        yield


def log_vnc_event(event: str, **fields: object) -> None:
    logger.info("vnc_event", extra={"event": event, **fields})
