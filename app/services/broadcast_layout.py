"""Layout engine for multi-input broadcasts (BCAST-016).

Supports four preset layouts: single, side_by_side, pip, grid.
"""

from __future__ import annotations

from typing import Optional

from fastapi import HTTPException

from app.models_broadcast import BroadcastLayoutConfig, LayoutPosition
from app.services.broadcast_store import get_session, update_session_fields, now_iso
from app.services.broadcast_input_store import list_inputs, save_layout

VALID_LAYOUTS = {"single", "side_by_side", "pip", "grid"}


def _layout_single(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    target = primary_input_id or input_ids[0]
    return [{"input_id": target, "x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0, "z_index": 0}]


def _layout_side_by_side(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    ids = input_ids[:2]
    if primary_input_id and primary_input_id in ids:
        ids = [primary_input_id] + [i for i in ids if i != primary_input_id]
    return [
        {"input_id": ids[0], "x": 0.0, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0},
        {"input_id": ids[1], "x": 0.5, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0},
    ]


def _layout_pip(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    primary = primary_input_id or input_ids[0]
    secondary = [i for i in input_ids if i != primary]
    if not secondary:
        return _layout_single(input_ids, primary)
    return [
        {"input_id": primary, "x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0, "z_index": 0},
        {"input_id": secondary[0], "x": 0.7, "y": 0.7, "width": 0.28, "height": 0.28, "z_index": 1},
    ]


def _layout_grid(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    _ = primary_input_id
    n = min(len(input_ids), 4)
    if n == 1:
        return [{"input_id": input_ids[0], "x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0, "z_index": 0}]
    positions = []
    cols = 2
    rows = 2 if n > 2 else 1
    w = 1.0 / cols
    h = 1.0 / rows
    for idx in range(n):
        col = idx % cols
        row = idx // cols
        positions.append({
            "input_id": input_ids[idx],
            "x": round(col * w, 4),
            "y": round(row * h, 4),
            "width": round(w, 4),
            "height": round(h, 4),
            "z_index": 0,
        })
    return positions


_LAYOUT_FUNCTIONS = {
    "single": _layout_single,
    "side_by_side": _layout_side_by_side,
    "pip": _layout_pip,
    "grid": _layout_grid,
}


def switch_layout(
    *,
    session_id: str,
    mode: str,
    primary_input_id: str | None = None,
    input_ids: list[str] | None = None,
) -> dict:
    """Validate session, compute layout, persist, return result."""
    session = get_session(session_id)
    if session.status not in ("live", "private"):
        raise HTTPException(status_code=409, detail="Layout switching requires a live session.")

    if mode not in VALID_LAYOUTS:
        raise HTTPException(status_code=400, detail=f"Invalid layout mode: {mode}. Valid: {', '.join(sorted(VALID_LAYOUTS))}")

    if not input_ids:
        inputs = list_inputs(session_id)
        input_ids = [inp.input_id for inp in inputs]

    if not input_ids:
        raise HTTPException(status_code=400, detail="No inputs available for layout.")

    if mode in ("side_by_side", "pip") and len(input_ids) < 2:
        raise HTTPException(status_code=400, detail=f"Layout '{mode}' requires at least 2 inputs, got {len(input_ids)}.")

    if mode == "pip" and primary_input_id and primary_input_id not in input_ids:
        raise HTTPException(status_code=400, detail="primary_input_id must be in input_ids for pip mode.")

    layout_fn = _LAYOUT_FUNCTIONS[mode]
    positions = layout_fn(input_ids, primary_input_id)

    layout_config = BroadcastLayoutConfig(
        mode=mode,
        positions=[LayoutPosition(**p) for p in positions],
        primary_input_id=primary_input_id,
        input_ids=input_ids,
        updated_at=now_iso(),
    )
    save_layout(session_id, layout_config)

    update_session_fields(session_id, {
        "active_layout": mode,
        "active_input_ids": input_ids,
        "primary_input_id": primary_input_id,
    })

    return {
        "mode": mode,
        "positions": positions,
        "primary_input_id": primary_input_id,
        "input_ids": input_ids,
    }
