# SEC-015: Org/Tenant Isolation & Membership Lifecycle

**Ticket**: SEC-015 · **Status**: Open · **Priority**: High · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 3)

## Problem
- **Missing membership check**: `app/routers/orgs.py:219` `add_org_payment_method`
  doesn't call `assert_org_membership(..., min_role="owner")` (sibling endpoints do) →
  a lower-role member (or non-member if id guessed) acts on org billing.
- **Invite not bound to email**: `app/services/org_service.py:236-291` `accept_invite`
  validates the token but **doesn't check `invite.email == accepting user`** → a leaked
  invite token can be accepted by any authenticated user → unauthorized org membership.
- **No revocation on membership change**: `remove_member` (`org_service.py:323`) and
  `archive_org` (`:178`) update DB but **don't revoke the affected users' sessions** →
  removed members retain access until token expiry; archived-org access persists; add
  `if org archived: 403` guards.

## Fix
- Add `assert_org_membership` with the correct min-role to every org-scoped mutating
  endpoint (sweep `orgs.py`); audit groups/spaces/syndicates for the same.
- Bind invite acceptance to the invited email (`invite.email == user`); short-lived,
  single-use tokens.
- On member-removal / org-archival, revoke that user's org-scoped sessions and
  invalidate cached membership; reject actions on archived orgs.

## Testing
pytest: non-owner/non-member 403 on org billing; an invite token cannot be redeemed by
a different user; a removed member's session is rejected immediately; archived-org
endpoints 403.
