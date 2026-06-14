from __future__ import annotations

from typing import Dict, Iterable, List, TypedDict


class RouteScopePolicy(TypedDict):
    product: str
    required_scopes: List[str]
    entitlement_required: bool


class RouteExemption(TypedDict):
    reason: str


# Initial rollout scope registry across filemanager, newsfeed, tickets, shopping, messager.
API_KEY_ROUTE_SCOPE_REGISTRY: Dict[str, RouteScopePolicy] = {
    # File Manager
    "GET:/v1/files": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/files/upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "GET:/v1/files/download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/files/share": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    # File Manager (actual router paths)
    "GET:/v1/fs/list": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/fs/folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "GET:/v1/fs/download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/fs/share": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    # Newsfeed
    "GET:/v1/newsfeed": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": False},
    "POST:/v1/newsfeed/posts": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": False},
    "DELETE:/v1/newsfeed/posts/{post_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:moderate"], "entitlement_required": False},
    # Tickets
    "GET:/tickets": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "POST:/tickets": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/admin/summary": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/messages": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/assign": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/status": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    # Ticket bounties (TBT-009). Board read uses tickets:read; mutations are
    # owner/claimant/admin-gated bounty flows.
    "GET:/tickets/bounties/open": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/claim": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/unclaim": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/submit": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/approve": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/reject": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/bounty/cancel": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    # TKA-001/002 — ticket file attachments
    "POST:/tickets/{ticket_id}/attachments/presign": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/attachments": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}/attachments": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}/attachments/{attachment_id}/download": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "DELETE:/tickets/{ticket_id}/attachments/{attachment_id}": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    # Shopping
    "GET:/ui/catalog/categories": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/categories/{category_id}/items": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/search": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/shoppingcart/carts": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "GET:/ui/shoppingcart/carts/{cart_id}/items": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/items": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/items/catalog": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "PATCH:/ui/shoppingcart/carts/{cart_id}/items/{sku}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "DELETE:/ui/shoppingcart/carts/{cart_id}/items/{sku}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/purchase": {"product": "shopping", "required_scopes": ["shopping:checkout:write"], "entitlement_required": True},
    "POST:/ui/purchase-history/transactions": {"product": "shopping", "required_scopes": ["shopping:checkout:write"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/{txn_id}": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/search": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    # Messager
    "GET:/messaging/conversations": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/image": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/file": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/revoke": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
}


API_KEY_ROUTE_EXEMPTIONS: Dict[str, RouteExemption] = {
    "GET:/feed/for-you": {"reason": "session-auth newsfeed For-You route, not in initial API-key rollout scope"},
    # OAU-002: OAuth2 authorization-server endpoints
    "GET:/oauth/authorize": {"reason": "OAuth2 authorization endpoint, auth handled by require_ui_session"},
    "POST:/oauth/token": {"reason": "OAuth2 token endpoint, auth handled by client credentials"},
    # OAU-003: OIDC public endpoints
    "GET:/.well-known/openid-configuration": {"reason": "OIDC discovery endpoint, no-auth public"},
    "GET:/oauth/jwks": {"reason": "OIDC public key endpoint, no-auth public"},
    "GET:/userinfo": {"reason": "OIDC userinfo, auth handled by OAuth bearer branch"},
    "POST:/ui/ats/integration/candidate-contact-links": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "POST:/ui/ats/integration/job-opportunity-links": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "GET:/ui/ats/integration/links": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "DELETE:/ui/ats/integration/links/{link_type}/{link_id}": {"reason": "session-auth ATS integration cross-link route, not in initial API-key rollout scope"},
    "GET:/health": {"reason": "health probe endpoint, not product API traffic"},
    "GET:/metrics": {"reason": "internal metrics endpoint"},
    "GET:/openapi.json": {"reason": "schema discovery endpoint"},
    # CSN-005: Open Data public endpoints — no auth required
    "GET:/open-data/branches": {"reason": "OBP open-data public endpoint, no auth required"},
    "GET:/open-data/branches/{branch_id}": {"reason": "OBP open-data public endpoint, no auth required"},
    "GET:/open-data/atms": {"reason": "OBP open-data public endpoint, no auth required"},
    "GET:/open-data/atms/{atm_id}": {"reason": "OBP open-data public endpoint, no auth required"},
    # PLT-003: Public glossary reads — unauthenticated, no API key required
    "GET:/v1/glossary": {"reason": "public unauthenticated glossary read endpoint"},
    "GET:/v1/glossary/{term_id}": {"reason": "public unauthenticated glossary term read"},
    "DELETE:/messaging/conversations/{conversation_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "DELETE:/messaging/conversations/{conversation_id}/drafts/{draft_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/hide": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/pin": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/schedule": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "DELETE:/messaging/conversations/{conversation_id}/participants/{participant_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "DELETE:/tickets/admin/kyc-sync-deadletter": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "DELETE:/tickets/{ticket_id}/external-links/{link_id}": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "DELETE:/ui/catalog/categories/{category_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "DELETE:/ui/catalog/categories/{category_id}/items/{item_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "DELETE:/ui/catalog/items/{item_id}/reviews/{review_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "DELETE:/ui/shoppingcart/carts/{cart_id}": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs/file": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs/folder": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs/mounts/{mount_id}": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs/shared-file": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "DELETE:/v1/fs/shared-folder": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/messaging/compliance/archive/events": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/compliance/archive/exports": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/compliance/archive/exports/{export_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/compliance/archive/exports/{export_id}/manifest": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/compliance/archive/exports/{export_id}/records": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/config": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/contacts/search": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/drafts": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/drafts/{draft_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/gallery": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/hidden-messages": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/legal-holds": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/messages/scheduled": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/messages/search": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/edits": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions/details": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/views": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/participants": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/pins": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/polls/{poll_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/routing-events": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/conversations/{conversation_id}/typing": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/events": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/events/stream": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/healthz": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/helpdesk/queue": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/mass-messages": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/mass-messages/{campaign_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/messages/search": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/messages/{message_id}/lottery": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/presence": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/messaging/threads/{thread_id}/messages": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "GET:/tickets/admin/kyc-sync-deadletter": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "GET:/tickets/admin/kyc-sync-metrics": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "GET:/tickets/{ticket_id}/sync-status": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "GET:/ui/catalog/images": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "GET:/ui/catalog/items/{item_id}/reviews": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "GET:/ui/purchase-history/transactions/{txn_id}/events": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "GET:/ui/purchase-history/transactions/{txn_id}/receipt": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/carts/items/search": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/carts/{cart_id}/total": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/recover/{token}": {"reason": "public one-time cart recovery link, not in initial API-key rollout scope"},
    "GET:/ui/shoppingcart/reminders/preferences": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "PUT:/ui/shoppingcart/reminders/preferences": {"reason": "session-auth shopping cart route, not in initial API-key rollout scope"},
    "POST:/ui/orders/{order_id}/transition": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "GET:/ui/orders/{order_id}/lifecycle": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "GET:/ui/orders/{order_id}/history": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "POST:/ui/orders/{order_id}/cancel": {"reason": "session-auth order-lifecycle route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/audit": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/list": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/mounts/reconcile": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/read": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/admin/search": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/info": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/mounts": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/mounts/{mount_id}": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/mounts/{mount_id}/mock-files": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/preview": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/search": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/search-text": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-download": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-info": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-list": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-preview": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-thumbnail": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-with": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/shared-with-me": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/thumbnail": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/usage/daily": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/usage/storage": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "GET:/v1/fs/usage/summary": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "PATCH:/messaging/conversations/{conversation_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "PATCH:/messaging/conversations/{conversation_id}/drafts/{draft_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "PATCH:/messaging/conversations/{conversation_id}/participants/{participant_id}": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "PATCH:/messaging/conversations/{conversation_id}/reports/{report_id}/status": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "PATCH:/ui/catalog/categories/{category_id}/items/{item_id}": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "PATCH:/v1/fs/mounts/{mount_id}": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/messaging/admin/users/upsert": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/compliance/archive/exports": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/dm/find-or-create": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/group": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/accept": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/drafts": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/images/presign": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/leave": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/legal-holds": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/legal-holds/{hold_id}/release": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/calendar-event": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/calendar-share": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/file-share": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/gallery": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/meeting-poll": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment/consume": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment/grant": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/hide": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/pin": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/report": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/tip": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/unlock": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/view": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/mute": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/participants": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/polls/{poll_id}/confirm": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/polls/{poll_id}/vote": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/read": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{conversation_id}/typing": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/conversations/{target_conversation_id}/messages/forward": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/helpdesk/conversations/{conversation_id}/claim": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/mass-messages": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/mass-messages/{campaign_id}/cancel": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/messages/calls/{call_id}/turn-credentials": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/messages/lottery": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/messages/{message_id}/lottery/unlock": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/messaging/presence/heartbeat": {"reason": "session-auth messaging route, not in initial API-key rollout scope"},
    "POST:/tickets/admin/kyc-sync-deadletter/replay-batch": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/admin/kyc-sync-deadletter/{entry_id}/replay": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/{ticket_id}/external-links/jira": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/{ticket_id}/external-links/jira/link-existing": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/tickets/{ticket_id}/external-links/{link_id}/resolve-conflict": {"reason": "session-auth tickets route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/api-packages": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/categories": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/categories/{category_id}/items": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/categories/{category_id}/items/{item_id}/images/upload": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/file-bundles": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/catalog/items/{item_id}/reviews": {"reason": "session-auth catalog route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/cancel/request": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/cancel/respond": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/complete": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/ui/purchase-history/transactions/{txn_id}/revert": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    "POST:/v1/fs/admin/mounts/{mount_id}/disable": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/admin/mounts/{mount_id}/reconcile-disable": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/client-telemetry": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/complete-upload": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/download-zip": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/initiate": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/revoke": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/rotate": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/icloud/verify": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/sftp": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/revoke": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/rotate-credential": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/status-override": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/test": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/mounts/{mount_id}/validate": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/move": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/move-resume": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/move-rollback": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/presign-upload": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/purge-deleted": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/rename-file": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/rename-folder": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-download-zip": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-folder": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-move": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-rename-file": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-rename-folder": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-upload": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-upload-archive": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/shared-upload-zip": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/unshare": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/upload-archive": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "POST:/v1/fs/upload-zip": {"reason": "session-auth file manager route, not in initial API-key rollout scope"},
    "PUT:/ui/purchase-history/transactions/{txn_id}/shipping": {"reason": "session-auth purchase-history route, not in initial API-key rollout scope"},
    # ATS — Job Orders (JOB-003, JOB-004, JOB-005)
    "GET:/ui/ats/job-orders/feature-status": {"reason": "session-auth-optional ATS feature flag probe, not in API-key rollout scope"},
    "POST:/ui/ats/job-orders": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/{job_id}": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "PATCH:/ui/ats/job-orders/{job_id}": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "POST:/ui/ats/job-orders/{job_id}/status": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/{job_id}/openings": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "DELETE:/ui/ats/job-orders/{job_id}": {"reason": "session-auth ATS job-orders route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/open": {"reason": "session-auth ATS route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/hot": {"reason": "session-auth ATS route, not in initial API-key rollout scope"},
    "GET:/ui/ats/job-orders/mine": {"reason": "session-auth ATS route, not in initial API-key rollout scope"},
    # Knowledge Base public portal (KB-011) — unauthenticated browse/search
    "GET:/public/kb/articles": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/articles/{article_id}": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/search": {"reason": "unauthenticated KB public search endpoint"},
    "GET:/public/kb/categories": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/categories/{category_id}": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/tags": {"reason": "unauthenticated KB public portal endpoint"},
    "GET:/public/kb/tags/{tag}/articles": {"reason": "unauthenticated KB public portal endpoint"},
    # Knowledge Base authenticated endpoints (KB-002..KB-011) — session-auth
    "GET:/kb/search": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/categories": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/categories": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/categories/{category_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "PUT:/kb/categories/{category_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "DELETE:/kb/categories/{category_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/articles": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/my-articles": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/articles/{article_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "PUT:/kb/articles/{article_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "DELETE:/kb/articles/{article_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/publish": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/expire": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/unpublish": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/rate": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "GET:/kb/articles/{article_id}/attachments": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "POST:/kb/articles/{article_id}/attachments": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    "DELETE:/kb/articles/{article_id}/attachments/{attachment_id}": {"reason": "session-auth KB endpoint, not in initial API-key rollout scope"},
    # PRT-001..PRT-005: ATS Career Portal public endpoints (no auth)
    "GET:/public/careers/config": {"reason": "Public unauthenticated career portal"},
    "GET:/public/careers/jobs": {"reason": "Public unauthenticated career portal"},
    "GET:/public/careers/jobs.rss": {"reason": "Public unauthenticated career portal RSS feed"},
    "GET:/public/careers/jobs/{slug}": {"reason": "Public unauthenticated career portal"},
    "POST:/public/careers/jobs/{slug}/apply": {"reason": "public career-portal self-apply endpoint; anonymous callers carry no API key"},
    "POST:/public/careers/jobs/{slug}/resume-presign": {"reason": "public unauthenticated career portal résumé presign — no API key scope required"},
    # Admin config endpoints (session-auth, not in API-key rollout scope)
    "GET:/ui/admin/career-portal/config": {"reason": "session-auth admin career portal endpoint, not in API-key rollout scope"},
    "PUT:/ui/admin/career-portal/config": {"reason": "session-auth admin career portal endpoint, not in API-key rollout scope"},
}

API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES = (
    "/v1/fs",
    "/v1/newsfeed",
    "/tickets",
    "/ui/catalog",
    "/ui/shoppingcart",
    "/ui/purchase-history",
    "/messaging",
)


# Tagged initial rollout routes that must be represented either as protected routes or explicit exemptions.
API_KEY_INITIAL_ROLLOUT_TAGGED_ROUTES: List[str] = sorted(
    set(list(API_KEY_ROUTE_SCOPE_REGISTRY.keys()) + list(API_KEY_ROUTE_EXEMPTIONS.keys()))
)


def get_route_scope_policy(route_id: str) -> RouteScopePolicy | None:
    return API_KEY_ROUTE_SCOPE_REGISTRY.get((route_id or "").strip())


def resolve_required_scopes_for_route(route_id: str) -> List[str]:
    policy = get_route_scope_policy(route_id)
    if not policy:
        return []
    return list(policy["required_scopes"])


def is_entitlement_required_for_route(route_id: str) -> bool:
    policy = get_route_scope_policy(route_id)
    if not policy:
        return False
    return bool(policy["entitlement_required"])


def get_route_exemption(route_id: str) -> RouteExemption | None:
    return API_KEY_ROUTE_EXEMPTIONS.get((route_id or "").strip())


def missing_registered_route_ids(live_route_ids: Iterable[str]) -> List[str]:
    live = {(route_id or "").strip() for route_id in live_route_ids if (route_id or "").strip()}
    return sorted(route_id for route_id in API_KEY_ROUTE_SCOPE_REGISTRY.keys() if route_id not in live)


def unregistered_live_route_ids(live_route_ids: Iterable[str]) -> List[str]:
    live = {(route_id or "").strip() for route_id in live_route_ids if (route_id or "").strip()}
    out: List[str] = []
    for route_id in sorted(live):
        if route_id in API_KEY_ROUTE_SCOPE_REGISTRY or route_id in API_KEY_ROUTE_EXEMPTIONS:
            continue
        _, _, path = route_id.partition(":")
        if not path:
            continue
        if any(path.startswith(prefix) for prefix in API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES):
            out.append(route_id)
    return out


def is_route_registered_or_exempt(route_id: str) -> bool:
    normalized = (route_id or "").strip()
    return normalized in API_KEY_ROUTE_SCOPE_REGISTRY or normalized in API_KEY_ROUTE_EXEMPTIONS


def summarize_registry_drift(live_route_ids: Iterable[str], *, preview_limit: int = 25) -> Dict[str, object]:
    missing = missing_registered_route_ids(live_route_ids)
    unregistered = unregistered_live_route_ids(live_route_ids)
    limit = max(0, int(preview_limit))
    return {
        "stale_route_count": len(missing),
        "stale_route_preview": missing[:limit],
        "unregistered_live_route_count": len(unregistered),
        "unregistered_live_route_preview": unregistered[:limit],
    }


def classify_registry_drift(*, stale_route_count: int, unregistered_live_route_count: int, warn_threshold: int) -> str:
    stale = max(0, int(stale_route_count))
    unregistered = max(0, int(unregistered_live_route_count))
    threshold = max(0, int(warn_threshold))
    if unregistered > 0:
        return "critical"
    if stale > threshold:
        return "warning"
    return "ok"
