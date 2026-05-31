"""Agent Memory router (AGENT-005).

Endpoints for managing agent identity, project context,
memory entries, context assembly, and export/import.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    AgentIdentityOut,
    AgentIdentityUpdateIn,
    FullContextOut,
    MemoryEntryIn,
    MemoryEntryOut,
    MemoryEntryUpdateIn,
    MemoryExportOut,
    MemoryImportIn,
    MemoryImportOut,
    MemoryListOut,
    MemoryTemplateOut,
    ProjectContextOut,
    ProjectContextUpdateIn,
)
from app.services import agent_memory as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agent/memory", tags=["agent-memory"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decimal_to_int(d: Any) -> int:
    """Coerce DynamoDB Decimal to int."""
    try:
        return int(d)
    except (TypeError, ValueError):
        return 0


def _identity_out(item: Dict[str, Any]) -> AgentIdentityOut:
    return AgentIdentityOut(
        agent_type=item.get("agent_type", ""),
        identity_text=item.get("identity_text", ""),
        custom_instructions=item.get("custom_instructions", ""),
        updated_at=_decimal_to_int(item.get("updated_at", 0)),
    )


def _project_out(item: Dict[str, Any]) -> ProjectContextOut:
    return ProjectContextOut(
        repo_url=item.get("repo_url", ""),
        branch_convention=item.get("branch_convention", ""),
        coding_standards=item.get("coding_standards", ""),
        pr_template=item.get("pr_template", ""),
        test_framework=item.get("test_framework", ""),
        ci_commands=item.get("ci_commands", ""),
        file_structure_notes=item.get("file_structure_notes", ""),
        updated_at=_decimal_to_int(item.get("updated_at", 0)),
    )


def _memory_out(item: Dict[str, Any]) -> MemoryEntryOut:
    return MemoryEntryOut(
        memory_id=item.get("memory_id", ""),
        category=item.get("category", ""),
        title=item.get("title", ""),
        content=item.get("content", ""),
        ticket_id=item.get("ticket_id", ""),
        importance=_decimal_to_int(item.get("importance", 3)),
        token_count=_decimal_to_int(item.get("token_count", 0)),
        created_at=_decimal_to_int(item.get("created_at", 0)),
        summarized=bool(item.get("summarized", False)),
        summary=item.get("summary", ""),
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@router.get("/templates", response_model=List[MemoryTemplateOut])
async def list_templates(_: Dict = Depends(require_ui_session)):
    """List available identity templates."""
    templates = svc.list_templates()
    return [
        MemoryTemplateOut(
            agent_type=t["agent_type"],
            identity_text=t["identity_text"],
            description=t["description"],
        )
        for t in templates
    ]


@router.get("/{worker_id}/identity", response_model=AgentIdentityOut)
async def get_identity(worker_id: str, _: Dict = Depends(require_ui_session)):
    """Get agent identity."""
    item = svc.get_identity(worker_id)
    if not item:
        raise HTTPException(status_code=404, detail="Identity not found")
    return _identity_out(item)


@router.put("/{worker_id}/identity", response_model=AgentIdentityOut)
async def update_identity(
    worker_id: str,
    body: AgentIdentityUpdateIn,
    _: Dict = Depends(require_ui_session),
):
    """Set or update agent identity."""
    result = svc.set_identity(
        worker_id,
        identity_text=body.identity_text,
        custom_instructions=body.custom_instructions,
    )
    return _identity_out(result)


# ---------------------------------------------------------------------------
# Project context
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/project", response_model=ProjectContextOut)
async def get_project_context(worker_id: str, _: Dict = Depends(require_ui_session)):
    """Get project context."""
    item = svc.get_project_context(worker_id)
    if not item:
        raise HTTPException(status_code=404, detail="Project context not found")
    return _project_out(item)


@router.put("/{worker_id}/project", response_model=ProjectContextOut)
async def update_project_context(
    worker_id: str,
    body: ProjectContextUpdateIn,
    _: Dict = Depends(require_ui_session),
):
    """Set or update project context."""
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    result = svc.set_project_context(worker_id, **fields)
    return _project_out(result)


# ---------------------------------------------------------------------------
# Memory entries
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/entries", response_model=MemoryListOut)
async def list_entries(
    worker_id: str,
    category: Optional[str] = None,
    _: Dict = Depends(require_ui_session),
):
    """List memory entries, optionally filtered by category."""
    entries = svc.list_memories(worker_id, category=category)
    out_entries = [_memory_out(e) for e in entries]
    total_tokens = sum(e.token_count for e in out_entries)
    return MemoryListOut(entries=out_entries, count=len(out_entries), total_tokens=total_tokens)


@router.post("/{worker_id}/entries", response_model=MemoryEntryOut, status_code=201)
async def add_entry(
    worker_id: str,
    body: MemoryEntryIn,
    _: Dict = Depends(require_ui_session),
):
    """Add a new memory entry."""
    result = svc.add_memory(
        worker_id,
        category=body.category,
        title=body.title,
        content=body.content,
        ticket_id=body.ticket_id,
        importance=body.importance,
    )
    return _memory_out(result)


@router.put("/{worker_id}/entries/{memory_id}", response_model=MemoryEntryOut)
async def update_entry(
    worker_id: str,
    memory_id: str,
    body: MemoryEntryUpdateIn,
    _: Dict = Depends(require_ui_session),
):
    """Update a memory entry."""
    result = svc.update_memory(
        worker_id,
        memory_id,
        title=body.title,
        content=body.content,
        importance=body.importance,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    return _memory_out(result)


@router.delete("/{worker_id}/entries/{memory_id}")
async def delete_entry(
    worker_id: str,
    memory_id: str,
    _: Dict = Depends(require_ui_session),
):
    """Delete a memory entry."""
    existing = svc.get_memory(worker_id, memory_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    svc.delete_memory(worker_id, memory_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Full context preview
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/full-context", response_model=FullContextOut)
async def get_full_context(
    worker_id: str,
    _: Dict = Depends(require_ui_session),
):
    """Preview the assembled full context injection payload."""
    context_text = svc.assemble_full_context(worker_id)
    sections = [s.strip().split("\n")[0] for s in context_text.split("===") if s.strip()]
    total_tokens = len(context_text) // 4
    return FullContextOut(
        context_text=context_text,
        total_tokens=total_tokens,
        sections=sections,
    )


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/export")
async def export_memory(worker_id: str, _: Dict = Depends(require_ui_session)):
    """Export all memory data as JSON."""
    data = svc.export_memory(worker_id)
    # Convert identity and project to serializable dicts
    if data.get("identity"):
        data["identity"] = {
            k: (int(v) if k in ("updated_at", "created_at") else v)
            for k, v in data["identity"].items()
            if k not in ("pk", "sk")
        }
    if data.get("project_context"):
        data["project_context"] = {
            k: (int(v) if k in ("updated_at", "created_at") else v)
            for k, v in data["project_context"].items()
            if k not in ("pk", "sk")
        }
    data["memories"] = [
        {
            k: (int(v) if k in ("importance", "token_count", "created_at") else v)
            for k, v in mem.items()
            if k not in ("pk", "sk")
        }
        for mem in data.get("memories", [])
    ]
    return data


@router.post("/{worker_id}/import", response_model=MemoryImportOut)
async def import_memory(
    worker_id: str,
    body: MemoryImportIn,
    _: Dict = Depends(require_ui_session),
):
    """Import memory data from a JSON export."""
    result = svc.import_memory(worker_id, body.model_dump())
    return MemoryImportOut(
        identity=result["identity"],
        project=result["project"],
        memories=result["memories"],
    )
