# UPR-001 — Profile Visibility Policy and Ownership

**Status:** Ratified  
**Ratified on:** 2026-04-05

## Policy objective
Define a canonical, field-level visibility policy for profile reads across:
- `owner` self-view,
- authenticated `member` viewer,
- unauthenticated `public` viewer.

This document is the governing policy for audience-aware profile filtering and discoverability controls.

## Audience levels
- `owner`: profile owner (full self-view).
- `member`: authenticated users viewing another user.
- `public`: unauthenticated viewers using profile URL/direct links.

## Visibility semantics
Each field must be classified as exactly one visibility class:
- `public`: visible to `owner`, `member`, and `public`.
- `member`: visible to `owner` and `member`; hidden from `public`.
- `private`: visible only to `owner`.

## Canonical matrix (all serialized profile fields)

| Field | Classification | Notes |
|---|---|---|
| `display_name` | `public` | Primary name shown in all surfaces. |
| `first_name` | `member` | Shared with authenticated members only. |
| `middle_name` | `member` | Shared with authenticated members only. |
| `last_name` | `member` | Shared with authenticated members only. |
| `title` | `public` | Public-facing role/headline text. |
| `description` | `public` | Public profile bio/summary. |
| `birthday` | `private` | Sensitive personal data; owner-only. |
| `gender` | `private` | Sensitive personal data; owner-only. |
| `location` | `public` | Public region/city-level location string. |
| `displayed_email` | `private` | Contact detail; owner-only. |
| `displayed_telephone_number` | `private` | Contact detail; owner-only. |
| `mailing_address` | `private` | Physical address; owner-only. |
| `languages` | `member` | Shared with authenticated members. |
| `profile_photo_url` | `public` | Public avatar/profile image URL. |
| `cover_photo_url` | `public` | Public profile cover image URL. |

## Suppressed account policy + anti-enumeration safeguards
For non-active users, discoverability policy overrides field-level visibility:

- `hidden` user:
  - `owner`: allowed.
  - `member`/`public`: return `404 Not Found`.
- `deactivated` user:
  - `owner`: allowed only in account recovery/reactivation flows.
  - `member`/`public`: return `404 Not Found`.
- `deleted` user:
  - all audiences: return `404 Not Found`.

Anti-enumeration safeguards:
- Use the same `404 Not Found` response for unknown users and suppressed users.
- Do not include suppression reason in public/member API responses.
- Keep detailed suppression reasons in internal logs/metrics only.

## Ownership and change control
- **Policy owner (DRI):** Backend Platform team.
- **Co-approvers required for policy changes:** Product owner + Privacy/Security.
- **Implementation owner:** Backend API team for filter enforcement in profile-read services.

Change process (required for any field classification change):
1. Open PR updating this matrix and backend enforcement constants/tests.
2. Add privacy impact note for any downgrade from `private/member` to broader visibility.
3. Obtain approvals from Backend + Product + Privacy/Security before merge.
4. Record rollout notes (feature flags/migration impacts) in PR description.

## Exception handling and escalation path
- **Emergency exception (P0/P1 incident only):**
  - Backend on-call may temporarily tighten visibility (never broaden) with incident ticket linkage.
  - Any temporary override must be reverted or formally ratified within 24 hours.
- **Requested broadening exception (e.g., private → member/public):**
  - Requires explicit Privacy/Security approval and Product sign-off before release.
- **Escalation order:**
  1. Backend on-call owner
  2. Product owner for affected surface
  3. Privacy/Security reviewer
  4. Engineering manager (final tie-break authority)

## Ratification record (UPR-001 acceptance)
- [x] Backend approval
- [x] Product approval
- [x] Privacy/Security approval

Ratified by working group on **2026-04-05** under ticket **UPR-001**.
