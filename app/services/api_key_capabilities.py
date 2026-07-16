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
    "kyc:admin",
    "kyc:read",
    "kyc:submit",
    "kyc:upload",
    "kyc:webhook",
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
    # APIK-E0-1: admin wildcard (grant-gated to admin/root owners in api_keys.create/set)
    "admin:all",
    # APIK-E0-2: groups capability family (routes wired in EPIC E4)
    "groups:read",
    "groups:write",
    "groups:manage",
    "groups:treasury",
    "fundraising:write",
    # APIK-E0-2: video capability family (routes wired in EPIC E5)
    "video:read",
    "video:write",
    "video:manage",
    "video:publish",
    "video:moderate",
    "video:monetize",
    # APIK-E0-2: newsfeed money scope (EPIC E1-2 gates tips/paid-unlock distinctly)
    "newsfeed:tips",
)

_CANONICAL_SET = set(CANONICAL_API_KEY_CAPABILITIES)

# APIK-E0-1: admin:all is a wildcard capability implying every canonical scope.
WILDCARD_API_KEY_CAPABILITY = "admin:all"

# Canonical inheritance semantics for broader capability grants.
# These are one-way implications: the broader scope implies the narrower scopes.
CAPABILITY_IMPLICATIONS: Dict[str, tuple[str, ...]] = {
    "ads:manage": ("ads:read", "ads:serve"),
    "filemanager:admin": ("filemanager:read", "filemanager:write", "filemanager:share"),
    "kyc:admin": ("kyc:read", "kyc:submit", "kyc:upload", "kyc:webhook"),
    "messager:manage": ("messager:read", "messager:write"),
    "newsfeed:moderate": ("newsfeed:read", "newsfeed:write"),
    "tickets:admin": ("tickets:read", "tickets:write"),
    # APIK-E0-2: groups/video inheritance. manage>=write>=read; moderate>=read.
    # treasury/fundraising:write/monetize/tips are standalone high-priv money scopes.
    "groups:manage": ("groups:write",),
    "groups:write": ("groups:read",),
    "video:manage": ("video:write", "video:publish"),
    "video:write": ("video:read",),
    "video:moderate": ("video:read",),
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
    if WILDCARD_API_KEY_CAPABILITY in expanded:
        # APIK-E0-1: the wildcard expands to the FULL canonical capability set.
        return sorted(set(CANONICAL_API_KEY_CAPABILITIES))
    queue = list(expanded)
    while queue:
        current = queue.pop(0)
        for implied in CAPABILITY_IMPLICATIONS.get(current, ()):
            if implied in expanded:
                continue
            expanded.add(implied)
            queue.append(implied)
    return sorted(expanded)
