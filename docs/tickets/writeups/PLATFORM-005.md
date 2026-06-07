# PLATFORM-005: SEO / Open Graph Meta Tags — Investigation & Implementation Write-up

> Type: feature | Priority: Medium | Status: Partially implemented (react-helmet-async + HelmetProvider present; backend meta endpoint not yet wired; public pages partially updated)

## 1. Summary & Classification

The platform is a client-side React SPA that previously served the same generic `<title>Control Panel</title>` and empty meta tags for every URL. Social media crawlers (Facebook, Twitter/X, Discord, Slack, WhatsApp, Telegram) cannot execute JavaScript, so when a user shared a link to a creator's profile (`/u/:identifier`) or a public event (`/event/:calendarId/:eventId`), the shared preview showed a blank title with no image or description. No `document.title` was ever updated — all browser tabs showed "Control Panel" regardless of page. PLATFORM-005 adds three components: (1) client-side `react-helmet-async` for dynamic meta management on every page, (2) a backend `GET /api/meta?url=...` endpoint returning Open Graph data for public URLs, and (3) a crawler-detection middleware that injects server-side meta into the HTML response for social bots.

- **Type**: Feature / growth
- **Priority**: Medium
- **User personas affected**: creators sharing profile links, event organizers, post authors, SEO/discoverability
- **Cross-references**: PLATFORM-004 (image variant URLs provide `og:image` with known dimensions), SECOPS-007 (dev/prod parity — meta endpoint reads DDB, same code path)

---

## 2. Current-State Investigation

### 2.1 index.html (static shell)

`frontend/index.html` (lines 1–19) contains only:
- `<meta charset="UTF-8">`
- `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
- `<title>Control Panel</title>`
- Font preconnects

No `og:*` tags, no `twitter:*` tags, no `<meta name="description">`, no `<link rel="canonical">`. Verified: zero Open Graph tags in the file.

### 2.2 PublicUserProfilePage (exists, partially updated)

`frontend/src/pages/profile/PublicUserProfilePage.tsx` (lines 22–42): fetches profile via `getProfileByIdentifier()` using `useQuery`. Has a canonical redirect (lines 38–42) that navigates to the canonical identifier form. Line 178 confirms `<meta property="og:title" content={displayName} />` is now present, and line 5 shows `import { Helmet } from "react-helmet-async"`. Lines 264–271 show a `<Helmet>` block.

So `PublicUserProfilePage` has been partially updated. Other pages may still lack Helmet coverage.

### 2.3 react-helmet-async installation status

`frontend/package.json:59`: `"react-helmet-async": "^3.0.0"` — installed.

`frontend/src/main.tsx` lines 18, 71, 84: `HelmetProvider` is imported and wraps the app. This is the correct setup.

### 2.4 Backend meta endpoint (not yet wired)

`app/routers/meta.py` is listed as a file to create in the ticket but was not found in the filesystem during investigation. `app/main.py` does not currently include a `meta_router` registration. This means the backend `GET /api/meta?url=...` endpoint does not yet exist — the crawler-detection middleware cannot function without it.

### 2.5 Service functions used by the meta endpoint

- `app/services/profile.py`: `get_profile_by_identifier()` — fetches by username/slug, returns profile dict including `display_name`, `description`, `profile_photo_url`.
- `app/routers/calendar.py`: Public event endpoints exist; a `get_public_event_details()` service function may need to be extracted from the router.
- `app/routers/newsfeed.py`: `_get_post_item()` (or equivalent) for post meta.

### 2.6 Crawler behaviour gap

Social media crawlers (Facebook `facebookexternalhit`, Twitter `Twitterbot`, Discord `Discordbot`, Slack `Slackbot`, WhatsApp `WhatsApp`) do not execute JavaScript. They fetch raw HTML and parse `<meta>` tags. Since `react-helmet-async` only updates the DOM after JS hydration, these crawlers see `<title>Control Panel</title>` with empty meta for every URL — destroying all social sharing virality.

Google's `Googlebot` does render JavaScript, so client-side Helmet benefits Google SEO. But the majority of social sharing crawlers require server-side injection.

### 2.7 Gaps remaining

1. `app/routers/meta.py` — not yet created
2. Meta router not registered in `app/main.py`
3. Crawler-detection middleware in `frontend/vite.config.ts` or production proxy — not yet implemented
4. Default `<Helmet>` in `App.tsx` — may be present but needs verification
5. Other pages beyond `PublicUserProfilePage` likely still lack `<Helmet>` blocks
6. `<meta name="description">` fallback in `index.html` — not yet added
7. `<link rel="canonical">` on public pages — needs verification

---

## 3. Gap / Threat Analysis

### 3.1 XSS via meta content attributes

User-controlled fields (display name, bio, post body) inserted into `content="..."` attributes must be HTML-escaped. In the crawler middleware's string replacement path, `escapeHtml()` must process all user data before injection:
```typescript
str.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
```
React's JSX escapes automatically, so client-side Helmet is safe. The server-side injection path is the risk vector.

### 3.2 Locked content leakage via meta tags

A locked newsfeed post (`lock_price_cents > 0`) must not expose its body text in `og:description`. The `_post_meta()` function in `app/routers/meta.py` checks `lock_price_cents` and returns a generic description ("This post is locked. Subscribe or pay to view.") instead of the body excerpt.

### 3.3 Enumeration via public meta endpoint

`GET /api/meta?url=/u/someuser` is a public unauthenticated endpoint. An attacker could iterate usernames to check which exist (same data already available via `GET /u/:identifier` public profile page). No new information is exposed beyond what the public profile page renders. Rate limiting to 120 req/min per IP is sufficient.

### 3.4 Canonical URL confusion

Without `<link rel="canonical">` on public pages, Google may index `/u/alice`, `/u/alice?ref=twitter`, and `/u/alice/` as separate pages, splitting PageRank. The `PublicUserProfilePage` already has a client-side canonical redirect (lines 38–42), but search engines benefit from explicit `<link rel="canonical" href="...">` in the `<head>`.

### 3.5 Code sites that must change

| File | Change |
|---|---|
| `frontend/index.html` | Add `<meta name="description">`, `og:site_name`, `og:locale`, `twitter:card` fallbacks |
| `frontend/src/main.tsx` | `HelmetProvider` (confirmed present) |
| `frontend/src/App.tsx` | Default `<Helmet>` with base meta tags |
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | `<Helmet>` with profile og tags (partially done) |
| `frontend/src/pages/calendar/PublicEventPage.tsx` | Add `<Helmet>` with event og tags |
| `frontend/src/pages/Login.tsx`, `Register.tsx`, etc. | Add `<Helmet>` title-only blocks |
| `app/routers/meta.py` | **New** — backend meta data endpoint |
| `app/main.py` | Register `meta_router` |
| `frontend/vite.config.ts` | Add crawler-detection Vite plugin for dev testing |
| Production proxy config | Crawler UA detection + meta injection |

---

## 4. Proposed Design / Fix

### 4.1 Default Helmet in App.tsx

```tsx
// frontend/src/App.tsx
import { Helmet } from "react-helmet-async";

function App() {
  return (
    <>
      <Helmet>
        <title>Control Panel</title>
        <meta name="description" content="Your all-in-one platform for messaging, commerce, and content creation." />
        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="Control Panel" />
        <meta property="og:locale" content="en_US" />
        <meta name="twitter:card" content="summary" />
      </Helmet>
      {/* routes */}
    </>
  );
}
```

Child `<Helmet>` blocks on specific pages override the parent's tags using react-helmet-async's last-rendered-wins merge strategy.

### 4.2 Per-page Helmet (public pages)

For `PublicUserProfilePage` (partially done — expand to include all required tags):

```tsx
<Helmet>
  <title>{data.display_name} | Control Panel</title>
  <meta name="description" content={(data.description || `${data.display_name}'s profile`).slice(0, 200)} />
  <meta property="og:title" content={data.display_name} />
  <meta property="og:description" content={(data.description || "").slice(0, 200)} />
  <meta property="og:image" content={data.profile_photo_url || "/favicon.svg"} />
  <meta property="og:type" content="profile" />
  <meta property="og:url" content={`${window.location.origin}/u/${canonicalIdentifier}`} />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content={data.display_name} />
  <meta name="twitter:image" content={data.profile_photo_url || "/favicon.svg"} />
  <link rel="canonical" href={`${window.location.origin}/u/${canonicalIdentifier}`} />
</Helmet>
```

Note: `data.description` is the correct field name — the profile service stores the bio as `description` (`app/services/profile.py:189`), not `bio`.

For `PublicEventPage`:

```tsx
<Helmet>
  <title>{evt.title} | Control Panel</title>
  <meta name="description" content={`${evt.title} — ${formatEventTime(...)}`} />
  <meta property="og:title" content={evt.title} />
  <meta property="og:type" content="event" />
  <meta property="og:url" content={window.location.href} />
  <meta name="twitter:card" content="summary" />
  <link rel="canonical" href={window.location.href} />
</Helmet>
```

### 4.3 Backend meta endpoint (app/routers/meta.py)

```python
@router.get("/api/meta")
async def get_meta(url: str = Query(..., max_length=512)):
    """No auth required — returns public data only."""
    if m := _PROFILE_RE.match(url):    # /u/{identifier}
        return _profile_meta(m.group(1))
    if m := _EVENT_RE.match(url):      # /event/{calId}/{evtId}
        return _event_meta(m.group(1), m.group(2))
    if m := _POST_RE.match(url):       # /posts/{post_id}
        return _post_meta(m.group(1))  # checks lock_price_cents; no body for locked posts
    if m := _VIDEO_RE.match(url):      # /videos/{id} or /gallery/{id}
        return _video_meta(m.group(1))
    return _default_meta()
```

The endpoint reads from existing service functions:
- `get_profile_by_identifier()` (`app/services/profile.py`)
- Calendar public event lookup (`app/routers/calendar.py` has existing public event routes)
- `_get_post_item()` or equivalent from `app/routers/newsfeed.py`

Each `_*_meta()` helper wraps its service call in a bare `try/except` and falls back to `_default_meta()` on any error — ensuring the endpoint always returns valid JSON.

Response includes `Cache-Control: public, max-age=300, s-maxage=3600` (5-minute browser cache, 1-hour CDN cache for high-traffic public profiles).

### 4.4 Crawler detection middleware

The production deployment (Express or Nginx proxy) intercepts requests from known crawler User-Agents:

```typescript
const CRAWLER_UA = /googlebot|bingbot|facebookexternalhit|twitterbot|linkedinbot|slackbot|discordbot|whatsapp|telegrambot|applebot/i;
```

For matching UAs on public paths (`/u/`, `/event/`, `/posts/`, `/videos/`, `/live/`), the middleware:
1. Reads `index.html`
2. Fetches `GET /api/meta?url={path}` from the backend
3. Replaces `<title>Control Panel</title>` in the HTML with the full set of OG/Twitter meta tags
4. Escapes all user-controlled values with `escapeHtml()`
5. Returns the injected HTML

For non-crawler UAs, zero overhead (early return). For regular users, client-side `react-helmet-async` handles all meta updates after JS hydration.

A Vite plugin (`frontend/vite.config.ts`) replicates this logic for local development, allowing developers to test crawler behaviour without a production proxy.

### 4.5 Fallback meta tags in index.html

```html
<!-- frontend/index.html -->
<meta name="description" content="Your all-in-one platform for messaging, commerce, and content creation." />
<meta property="og:site_name" content="Control Panel" />
<meta property="og:type" content="website" />
<meta property="og:locale" content="en_US" />
<meta name="twitter:card" content="summary" />
```

These ensure minimal correct meta is present even when neither the Vite plugin nor the production crawler middleware is active.

### 4.6 Dev/Prod parity (SECOPS-007)

- The `/api/meta` endpoint reads from DDB (profiles, events, posts) — same DDB Local in dev as production tables.
- The crawler-detection Vite plugin in dev calls `http://localhost:8000/api/meta`, matching the production proxy's call to the backend.
- No mock is needed — the meta endpoint is a simple read of public data.
- `CRAWLER_META_INJECTION_ENABLED` env var controls the production middleware; Vite plugin activation is separate (dev-only).

### 4.7 Alternatives considered

- **Full SSR with Next.js/Remix**: Would provide server-rendered HTML for all routes, eliminating the crawler gap entirely. Rejected — the architectural cost of migrating a 50+ page React SPA to SSR is disproportionate to the benefit; the crawler-detection middleware achieves the same result for crawlers with zero impact on the existing SPA architecture.
- **Pre-rendering with `react-snap`**: Generates static HTML snapshots at build time. Rejected — profile and event pages are dynamic; static snapshots would be stale.
- **Unhead / @unhead/react**: Alternative head management library; more complex API surface, Vue-first. `react-helmet-async` chosen for its simpler API and 2M+ weekly npm downloads.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (tests/test_meta.py)

| # | Test | What to assert |
|---|---|---|
| 1 | `test_profile_meta_display_name` | `GET /api/meta?url=/u/{alice_id}` → `title` contains Alice's display name |
| 2 | `test_profile_meta_bio_truncated` | Bio >200 chars → `description` truncated to 200 |
| 3 | `test_missing_user_returns_default` | Non-existent identifier → `title = "Control Panel"` |
| 4 | `test_event_meta_title` | Event URL → `title` contains event name |
| 5 | `test_post_meta_body_excerpt` | Unlocked post → `description` contains post body |
| 6 | `test_locked_post_hides_body` | Post with `lock_price_cents > 0` → generic description |
| 7 | `test_unknown_path_returns_default` | `/nonexistent` → default meta |
| 8 | `test_meta_url_max_length` | URL >512 chars → 422 |
| 9 | `test_live_meta_video_type` | `/live/sess1` → `type = "video.other"` |

All use moto-mocked DDB via `tests/conftest.py`.

### 5.2 Playwright E2E tests (frontend/e2e/seo-meta.spec.ts)

13 tests across 3 sections:

- Section 1 (5): Meta API — profile meta returns `type="profile"`; event meta returns event title; unknown path returns defaults; post meta includes image; locked post hides body.
- Section 2 (5): Client-side Helmet — `await page.title()` on profile page includes display name; event page title includes event name; feed page has `og:type="website"` meta; login page has description; profile page has canonical link.
- Section 3 (3): Crawler middleware (with Vite plugin enabled) — crawler UA gets injected OG tags in HTML source; regular UA gets normal SPA (no injection); injected content is HTML-escaped.

Auth: `injectAuth(page, "alice")` for data creation; public pages accessed without auth.

### 5.3 Manual QA using Facebook Sharing Debugger

After deploying Phase 2 (backend meta endpoint):
1. Use Facebook's Open Graph Debugger (`developers.facebook.com/tools/debug`) with a public profile URL.
2. Verify `og:title`, `og:description`, `og:image`, `og:type` all appear correctly.
3. Test Twitter Card validator (`cards-dev.twitter.com/validator`).
4. Test Discord: paste a profile link in a Discord channel; verify rich embed shows avatar + display name.

### 5.4 Observability

No new Prometheus metrics required for this feature. Monitor via:
- Google Search Console: verify public pages are indexed with correct titles after deployment.
- CDN cache hit rate for `/api/meta` responses: target >90% hit rate for public profiles.
- `4xx` rate on `/api/meta` — should be near zero; errors fall back to default meta without a 4xx response.

### 5.5 Rollout plan (phased)

| Phase | Scope | Risk | Rollback |
|---|---|---|---|
| 1 | Client-side Helmet in all pages | Low — additive change to HTML head | Remove `<Helmet>` blocks |
| 2 | Backend `/api/meta` endpoint | Low — new read-only endpoint | Remove `meta_router` from `main.py` |
| 3 | Crawler detection middleware | Medium — affects HTML responses for crawler UAs | Disable via `CRAWLER_META_INJECTION_ENABLED=0` |

Phases 1 and 2 are independently releasable. Phase 3 requires both Phase 1 (to have the meta endpoint) and Phase 2 (to verify endpoint correctness).

**Effort**: M (8–12 days as estimated; Phase 1 is mostly complete with react-helmet-async installed and `PublicUserProfilePage` partially updated).
