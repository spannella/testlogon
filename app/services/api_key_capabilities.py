from __future__ import annotations

from typing import Dict, Iterable, List, Set

CANONICAL_API_KEY_CAPABILITIES: tuple[str, ...] = (
    "ads:manage",
    "ads:read",
    "ads:serve",
    "filemanager:admin",
    "filemanager:read",
    "filemanager:share",
    "filemanager:write",
    "messager:manage",
    "messager:read",
    "messager:write",
    "newsfeed:moderate",
    "newsfeed:read",
    "newsfeed:write",
    "shopping:cart:write",
    "shopping:catalog:read",
    "shopping:checkout:write",
    "shopping:orders:read",
    "tickets:admin",
    "tickets:read",
    "tickets:write",
)

_CANONICAL_SET = set(CANONICAL_API_KEY_CAPABILITIES)

# Canonical inheritance semantics for broader capability grants.
# These are one-way implications: the broader scope implies the narrower scopes.
CAPABILITY_IMPLICATIONS: Dict[str, tuple[str, ...]] = {
    "ads:manage": ("ads:read", "ads:serve"),
    "filemanager:admin": ("filemanager:read", "filemanager:write", "filemanager:share"),
    "messager:manage": ("messager:read", "messager:write"),
    "newsfeed:moderate": ("newsfeed:read", "newsfeed:write"),
    "tickets:admin": ("tickets:read", "tickets:write"),
}


def normalize_capability_name(value: str | None) -> str:
    return (value or "").strip().lower()


def is_known_api_key_capability(value: str | None) -> bool:
    return normalize_capability_name(value) in _CANONICAL_SET


def normalize_api_key_capabilities(values: Iterable[str] | None) -> List[str]:
    out: set[str] = set()
    for capability in values or []:
        normalized = normalize_capability_name(capability)
        if not normalized:
            continue
        if normalized not in _CANONICAL_SET:
            raise ValueError(f"unknown api key capability: {capability}")
        out.add(normalized)
    return sorted(out)


def expand_api_key_capabilities(values: Iterable[str] | None) -> List[str]:
    expanded: Set[str] = set(normalize_api_key_capabilities(values))
    queue = list(expanded)
    while queue:
        current = queue.pop(0)
        for implied in CAPABILITY_IMPLICATIONS.get(current, ()):
            if implied in expanded:
                continue
            expanded.add(implied)
            queue.append(implied)
    return sorted(expanded)
