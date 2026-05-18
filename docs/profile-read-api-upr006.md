# UPR-006 Profile Read API

## Endpoint
`GET /ui/profiles/{identifier}`

## Identifier support
The endpoint supports lookup by canonical identifier:
- `user_sub` (direct key lookup)
- `username` / `handle` alias fallback (if present on user records)
- Invalid identifiers (empty, control characters, or length > 256) are rejected with the same non-enumerating not-found behavior.

## Audience inference
Audience is inferred from current UI session:
- `owner`: requester is authenticated and `requester.user_sub == target.user_sub`
- `member`: requester is authenticated and viewing another user
- `public`: requester is not authenticated

## Response shape (stable)

```json
{
  "identifier": "string",
  "user_sub": "string",
  "audience": "owner|member|public",
  "profile": {
    "display_name": "string|null",
    "first_name": "string|null",
    "middle_name": "string|null",
    "last_name": "string|null",
    "title": "string|null",
    "description": "string|null",
    "birthday": "YYYY-MM-DD|null",
    "gender": "string|null",
    "location": "string|null",
    "displayed_email": "string|null",
    "displayed_telephone_number": "string|null",
    "mailing_address": "object|null",
    "languages": [],
    "profile_photo_url": "string|null",
    "cover_photo_url": "string|null"
  }
}
```

## Status codes
- `200 OK`: profile resolved and visible for inferred audience.
- `304 Not Modified`: profile representation unchanged when `If-None-Match` matches current ETag.
- `404 Not Found`: unknown identifier or discoverability-suppressed user (`hidden`, `deactivated`, `deleted`) per policy.
- `429 Too Many Requests`: profile lookup rate limit exceeded (tier-aware enforcement).

## Security notes
- Uses uniform `404` behavior for unknown and suppressed users to reduce account enumeration risk.
- Field-level filtering is applied based on audience and visibility matrix.
- Rate limiting is enforced in separate anonymous/authenticated tiers with standardized error payloads:
  - `{\"code\":\"profile_lookup_rate_limited\",\"tier\":\"anonymous\"}`
  - `{\"code\":\"profile_lookup_rate_limited\",\"tier\":\"authenticated\"}`

## Rollout flags (UPR-020)
- `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED=false` (default):
  - Backward-compatible behavior for profile lookup responses.
  - Suppression and audience field filtering are disabled.
- `PROFILE_LOOKUP_AUDIENCE_FILTERING_ENABLED=true`:
  - Enables discoverability suppression and audience-based field filtering semantics described above.
