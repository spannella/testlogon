# PLATFORM-005: SEO / Open Graph Meta Tags

**Ticket**: PLATFORM-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 8-12 days

---

## 1. Executive Summary

The platform is a client-side React SPA served from a single `index.html` that contains no Open Graph, Twitter Card, or SEO meta tags beyond a basic viewport and charset declaration (`frontend/index.html:1-19`). When a user shares a link to a public profile (`/u/:identifier`), a public event (`/event/:calendarId/:eventId`), or any other page, social media crawlers (Facebook, Twitter/X, LinkedIn, Discord, Slack) receive the same generic `<title>Control Panel</title>` and empty meta for every URL. This means shared links show no preview image, no description, and a meaningless title -- destroying social sharing virality.

Public pages like `PublicUserProfilePage` (`frontend/src/pages/profile/PublicUserProfilePage.tsx`) and `PublicEventPage` (`frontend/src/pages/calendar/PublicEventPage.tsx`) have access to rich data (display name, bio, avatar, event title, event time) but never inject this data into `<head>` meta tags. There is no `react-helmet`, `react-helmet-async`, or `@unhead` library installed in the frontend. No page in the application sets `document.title` dynamically -- every browser tab shows "Control Panel" regardless of which page is active.

This feature introduces three components: (1) `react-helmet-async` for client-side dynamic meta tag management on every page, (2) a backend meta endpoint (`GET /api/meta?url=...`) that returns Open Graph data for any public URL, and (3) a lightweight crawler-detection middleware that intercepts crawler User-Agents and injects server-side meta tags into the HTML response before serving the SPA shell. The combination ensures that both human users (via client-side Helmet) and social crawlers (via server-side injection) see appropriate metadata.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Rich profile link sharing (creator)**
As a creator, I want my profile link shared on Twitter to show a rich preview with my display name, avatar, and bio, so that my followers are enticed to click through.

*Acceptance criteria:*
- `og:title` shows display name (e.g., "Alice Smith").
- `og:image` shows avatar URL (or a default platform image if no avatar).
- `og:description` shows bio text (truncated to 200 characters).
- `og:type` is "profile".
- `twitter:card` is "summary" (shows small avatar thumbnail).

**US-2: Event link sharing (creator)**
As an event organizer, I want event links shared on Discord to show event details, so potential attendees see the event name, date, and location at a glance.

*Acceptance criteria:*
- `og:title` shows event name.
- `og:description` shows formatted date/time and location.
- `og:type` is "event".
- No `og:image` required (events typically don't have images).

**US-3: Post link sharing (viewer)**
As a user who pastes a post link in Slack, I want the link preview to show the post's author and a text excerpt, so other Slack users understand what the link is about.

*Acceptance criteria:*
- `og:title` shows "Post by {author name}".
- `og:description` shows post body excerpt (200 characters).
- `og:image` shows first post image (if present).
- `og:type` is "article".
- `twitter:card` is "summary_large_image" when an image is present.

**US-4: Search engine indexing (admin)**
As a platform administrator, I want public pages to be properly indexed by search engines (Google, Bing) so creators can be discovered through organic search.

*Acceptance criteria:*
- Google sees correct `<title>` for public pages.
- `<meta name="description">` is populated on all pages.
- `<link rel="canonical">` prevents duplicate indexing from query params.
- JSON-LD structured data on profile and event pages (future enhancement).

**US-5: Browser tab titles (all users)**
As any user navigating the app, I want browser tabs to show the current page name so I can distinguish between multiple open tabs.

*Acceptance criteria:*
- Each page sets a descriptive `<title>` (e.g., "Messages | Control Panel", "Feed | Control Panel").
- Dynamic pages include content data (e.g., "Alice Smith | Control Panel" for a profile page).
- Default title remains "Control Panel" for the root page.

### 2.2 Pain Points

1. **No social sharing previews**: Every shared link displays "Control Panel" as the title with no image or description. This is the single most damaging gap for organic growth. Users who share platform links on social media provide free advertising -- but the platform wastes this opportunity by showing a blank preview.
2. **No SEO indexing**: Google's crawlers see empty meta tags. Public profiles, events, and posts have zero search engine discoverability. Creators cannot be found via Google search.
3. **No `document.title` updates**: Navigating between pages never changes the browser tab title. All tabs show "Control Panel". Users with multiple open tabs cannot distinguish between them.
4. **No canonical URLs**: Duplicate content risk from query parameters and trailing slashes. Google may index `/u/alice`, `/u/alice?ref=twitter`, and `/u/alice/` as separate pages.
5. **SPA crawling limitation**: Social media crawlers do NOT execute JavaScript. They fetch raw HTML and parse `<meta>` tags. Since `react-helmet-async` updates the DOM after JS execution, a server-side solution is required for crawlers.

### 2.3 Crawler Behavior

Social media crawlers do NOT execute JavaScript. They fetch the raw HTML and parse `<meta>` tags:

| Crawler | User-Agent fragment | Tags used | JS execution |
|---------|-------------------|-----------|-------------|
| Facebook/Meta | `facebookexternalhit` | `og:title`, `og:description`, `og:image`, `og:url`, `og:type` | No |
| Twitter/X | `Twitterbot` | `twitter:card`, `twitter:title`, `twitter:description`, `twitter:image` | No |
| Discord | `Discordbot` | Open Graph tags | No |
| Slack | `Slackbot` | Open Graph tags, falls back to `<title>` + `<meta name="description">` | No |
| LinkedIn | `LinkedInBot` | Open Graph tags, prefers `og:image` with dimensions | No |
| Google | `Googlebot` | `<title>`, `<meta name="description">`, structured data, canonical | Yes (renders JS) |
| Bing | `bingbot` | `<title>`, `<meta name="description">`, canonical | Limited JS |
| WhatsApp | `WhatsApp` | Open Graph tags | No |
| Telegram | `TelegramBot` | Open Graph tags | No |

Since the SPA renders meta tags client-side AFTER JavaScript execution, most crawlers will never see them. The server-side meta injection strategy handles this.

---

## 3. Current State Analysis

### 3.1 index.html

`frontend/index.html` (lines 1-19):

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Control Panel</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

No `og:*` tags, no `twitter:*` tags, no `<meta name="description">`, no dynamic title. The `<title>` is hardcoded to "Control Panel" and never changes.

### 3.2 PublicUserProfilePage

`frontend/src/pages/profile/PublicUserProfilePage.tsx` (lines 1-60):

- Fetches profile data via `getProfileByIdentifier(identifier)` (line 24: `useQuery`)
- Has access to `display_name`, `bio`, `profile_photo_url` from the query response (line 35: `const data = q.data`)
- Renders display name, bio, avatar in the component body
- **No `document.title` set**: No `useEffect(() => { document.title = ... })` or helmet usage
- **No meta tag injection**: No `<Helmet>` or equivalent component
- Has a canonical redirect (lines 38-42): if `canonicalIdentifier !== identifier`, navigates to the canonical URL

### 3.3 PublicEventPage

`frontend/src/pages/calendar/PublicEventPage.tsx` (lines 1-60):

- Fetches event data via `getPublicEvent(calendarId, eventId)` (line 52-56: `useQuery`)
- Has access to event `title`, `start_utc`, `end_utc`, `description`, `location`
- Has a `formatEventTime()` helper function (lines 10-46) that formats event times with timezone
- **No `document.title` set**
- **No meta tag injection**

### 3.4 Other Public Routes

From `frontend/src/App.tsx:86-93`:

```tsx
<Route path="/login" element={<Login />} />
<Route path="/register" element={<Register />} />
<Route path="/u/:identifier" element={<PublicUserProfilePage />} />
<Route path="/event/:calendarId/:eventId" element={<PublicEventPage />} />
<Route path="/questionnaires/published/:publishedSlug/respond" element={<QuestionnaireRespondentPage />} />
<Route path="live/:sessionId" element={<LivePlayer />} />
```

None of these pages set meta tags or document.title.

### 3.5 Head Management Libraries

No `react-helmet`, `react-helmet-async`, or `@unhead` in `frontend/package.json` (verified: zero results in package.json and all source files). No `document.title` assignment anywhere in `frontend/src/` (verified: zero results for `document.title`).

### 3.6 Vite Dev Server Configuration

`frontend/vite.config.ts` proxies API paths to the backend. The dev server serves `index.html` for all non-proxied routes (SPA fallback). No middleware exists for meta injection or crawler detection.

### 3.7 Backend Profile/Event Services

**Profile lookup**: `app/services/profile.py` has `get_profile_by_identifier()` which returns profile data including `display_name`, `bio`, `profile_photo_url`. This function is used by the frontend's `PublicUserProfilePage` and will also be used by the backend meta endpoint.

**Public event lookup**: `app/routers/calendar.py` has a public event endpoint. The meta endpoint will use the same data source.

### 3.8 Gaps

1. No Open Graph meta tags in `index.html` (`frontend/index.html:1-19`)
2. No `react-helmet-async` or head management library in `frontend/package.json`
3. No `document.title` updates on any page (zero occurrences)
4. No server-side meta injection for crawlers
5. No backend meta data endpoint
6. No `<meta name="description">` on any page
7. No `twitter:card` tags
8. No canonical URL tags (`<link rel="canonical">`)
9. No JSON-LD structured data

---

## 4. Implementation Plan

### 4.1 Phase 1: Client-Side Meta Tags (react-helmet-async)

**Install dependency:**

```bash
cd frontend && npm install react-helmet-async
```

**`frontend/src/main.tsx`** -- Wrap app in HelmetProvider:

```tsx
import { HelmetProvider } from "react-helmet-async";

root.render(
  <HelmetProvider>
    <App />
  </HelmetProvider>
);
```

### 4.2 Default Meta Tags

**`frontend/src/App.tsx`** -- Add default Helmet at the top of the component tree:

```tsx
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
      {/* ... routes ... */}
    </>
  );
}
```

Child components with their own `<Helmet>` override the parent's tags (react-helmet-async uses last-rendered-wins for duplicate tags).

### 4.3 Page-Specific Meta Tags

**`frontend/src/pages/profile/PublicUserProfilePage.tsx`** (after data loads):

```tsx
import { Helmet } from "react-helmet-async";

// Inside the component, after q.data is available:
{data && (
  <Helmet>
    <title>{data.display_name} | Control Panel</title>
    <meta name="description" content={data.bio || `${data.display_name}'s profile`} />
    <meta property="og:title" content={data.display_name} />
    <meta property="og:description" content={data.bio || `${data.display_name}'s profile`} />
    <meta property="og:image" content={data.profile_photo_url || "/favicon.svg"} />
    <meta property="og:type" content="profile" />
    <meta property="og:url" content={`${window.location.origin}/u/${canonicalIdentifier}`} />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content={data.display_name} />
    <meta name="twitter:description" content={data.bio || ""} />
    <meta name="twitter:image" content={data.profile_photo_url || "/favicon.svg"} />
    <link rel="canonical" href={`${window.location.origin}/u/${canonicalIdentifier}`} />
  </Helmet>
)}
```

**`frontend/src/pages/calendar/PublicEventPage.tsx`** (after event data loads):

```tsx
import { Helmet } from "react-helmet-async";

{evt && (
  <Helmet>
    <title>{evt.title} | Control Panel</title>
    <meta name="description" content={`${evt.title} - ${formatEventTime(evt.start_utc, evt.end_utc, evt.all_day, evt.all_day_date, evt.timezone)}`} />
    <meta property="og:title" content={evt.title} />
    <meta property="og:description" content={evt.description || formatEventTime(evt.start_utc, evt.end_utc)} />
    <meta property="og:type" content="event" />
    <meta property="og:url" content={window.location.href} />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content={evt.title} />
    <meta name="twitter:description" content={evt.description || ""} />
  </Helmet>
)}
```

**Additional pages to add Helmet to:**

| Page Component | File | Title Pattern | og:type |
|---------------|------|---------------|---------|
| `Login.tsx` | `pages/Login.tsx` | "Log In \| Control Panel" | website |
| `Register.tsx` | `pages/Register.tsx` | "Create Account \| Control Panel" | website |
| `FeedPage.tsx` | `pages/feed/FeedPage.tsx` | "Feed \| Control Panel" | website |
| `MessagesPage.tsx` | `pages/messages/MessagesPage.tsx` | "Messages \| Control Panel" | website |
| `GalleryPage.tsx` | `pages/gallery/GalleryPage.tsx` | "Video Gallery \| Control Panel" | website |
| `Dashboard.tsx` | `pages/Dashboard.tsx` | "Dashboard \| Control Panel" | website |
| `FilesPage.tsx` | `pages/files/FilesPage.tsx` | "Files \| Control Panel" | website |
| `CalendarPage.tsx` | `pages/calendar/CalendarPage.tsx` | "Calendar \| Control Panel" | website |
| `ProfilePage.tsx` | `pages/settings/ProfilePage.tsx` | "Profile Settings \| Control Panel" | website |
| `SecurityPage.tsx` | `pages/security/SecurityPage.tsx` | "Security \| Control Panel" | website |
| `BillingPage.tsx` | `pages/billing/BillingPage.tsx` | "Billing \| Control Panel" | website |
| `SavedPage.tsx` | `pages/saved/SavedPage.tsx` | "Saved \| Control Panel" | website |
| `LivePlayer.tsx` | `pages/LivePlayer.tsx` | "Live Stream \| Control Panel" | video.other |

For pages behind authentication, `og:type` is "website" and no `og:image` is set (private content).

### 4.4 Phase 2: Backend Meta Endpoint

**New file: `app/routers/meta.py`** (~120 lines)

```python
"""Lightweight meta-data endpoint for SSR meta injection.

Returns Open Graph metadata for any public URL path. Used by:
1. The crawler-detection middleware to inject meta into HTML for social crawlers.
2. Could be used by any external service that needs link previews.

No authentication required -- only returns data from publicly-visible entities.
"""
from fastapi import APIRouter, Query, HTTPException
from typing import Optional
import re
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["meta"])

_PROFILE_RE = re.compile(r"^/u/([^/]+)$")
_EVENT_RE = re.compile(r"^/event/([^/]+)/([^/]+)$")
_POST_RE = re.compile(r"^/posts/([^/]+)$")
_VIDEO_RE = re.compile(r"^/(?:videos|gallery)/([^/]+)$")
_LIVE_RE = re.compile(r"^/live/([^/]+)$")


@router.get("/api/meta")
async def get_meta(url: str = Query(..., max_length=512)):
    """Return Open Graph meta data for a given URL path.

    The `url` parameter is a path (e.g., "/u/alice"), not a full URL.
    Returns a JSON object with title, description, image, type, url fields.
    """
    meta = _default_meta()

    m = _PROFILE_RE.match(url)
    if m:
        return _profile_meta(m.group(1))

    m = _EVENT_RE.match(url)
    if m:
        return _event_meta(m.group(1), m.group(2))

    m = _POST_RE.match(url)
    if m:
        return _post_meta(m.group(1))

    m = _VIDEO_RE.match(url)
    if m:
        return _video_meta(m.group(1))

    m = _LIVE_RE.match(url)
    if m:
        return _live_meta(m.group(1))

    return meta


def _default_meta():
    return {
        "title": "Control Panel",
        "description": "Your all-in-one platform for messaging, commerce, and content creation.",
        "image": None,
        "type": "website",
        "url": None,
    }


def _profile_meta(identifier: str):
    """Fetch profile data and build meta."""
    try:
        from app.services.profile import get_profile_by_identifier
        profile = get_profile_by_identifier(identifier)
        if not profile:
            return _default_meta()
        display_name = profile.get("display_name", identifier)
        bio = profile.get("bio", "")
        return {
            "title": f"{display_name} | Control Panel",
            "description": (bio or f"{display_name}'s profile")[:200],
            "image": profile.get("profile_photo_url"),
            "type": "profile",
            "url": f"/u/{identifier}",
        }
    except Exception:
        logger.exception("Failed to fetch profile meta for %s", identifier)
        return _default_meta()


def _event_meta(calendar_id: str, event_id: str):
    """Fetch public event data and build meta."""
    try:
        from app.services.calendar import get_public_event_details
        event = get_public_event_details(calendar_id, event_id)
        if not event:
            return _default_meta()
        title = event.get("title", "Event")
        desc = event.get("description", "")
        start = event.get("start_utc", "")
        return {
            "title": f"{title} | Control Panel",
            "description": (desc or f"Event on {start}")[:200],
            "image": None,
            "type": "event",
            "url": f"/event/{calendar_id}/{event_id}",
        }
    except Exception:
        logger.exception("Failed to fetch event meta for %s/%s", calendar_id, event_id)
        return _default_meta()


def _post_meta(post_id: str):
    """Fetch post data and build meta. Only for published, non-locked posts."""
    try:
        from app.routers.newsfeed import _get_post_item
        post = _get_post_item(post_id)
        if not post:
            return _default_meta()
        # Don't expose locked post content in meta
        if post.get("lock_price_cents") and int(post.get("lock_price_cents", 0)) > 0:
            return {
                "title": "Post | Control Panel",
                "description": "This post is locked. Subscribe or pay to view.",
                "image": None,
                "type": "article",
                "url": f"/posts/{post_id}",
            }
        body = (post.get("body_plain") or post.get("body") or "")[:200]
        author = post.get("user_id", "")
        image_urls = post.get("image_urls") or []
        image = image_urls[0] if image_urls else None
        return {
            "title": f"Post by {author} | Control Panel",
            "description": body,
            "image": image,
            "type": "article",
            "url": f"/posts/{post_id}",
        }
    except Exception:
        logger.exception("Failed to fetch post meta for %s", post_id)
        return _default_meta()


def _video_meta(video_id: str):
    """Fetch video data and build meta."""
    try:
        from app.services.video_metadata_store import get_video
        video = get_video(video_id)
        if not video:
            return _default_meta()
        return {
            "title": f"{video.title} | Control Panel",
            "description": (video.description or "")[:200],
            "image": video.thumbnail_url,
            "type": "video.other",
            "url": f"/videos/{video_id}",
        }
    except Exception:
        logger.exception("Failed to fetch video meta for %s", video_id)
        return _default_meta()


def _live_meta(session_id: str):
    """Build meta for a live stream page."""
    return {
        "title": "Live Stream | Control Panel",
        "description": "Watch live on Control Panel.",
        "image": None,
        "type": "video.other",
        "url": f"/live/{session_id}",
    }
```

**Register in `app/main.py`:**

```python
from app.routers.meta import router as meta_router
app.include_router(meta_router)
```

### 4.5 Phase 3: Crawler Detection + Server-Side Meta Injection

**New file: `frontend/server/crawler-meta.ts`** (~80 lines, used in production Express/Nginx proxy)

```typescript
const CRAWLER_UA = /googlebot|bingbot|facebookexternalhit|twitterbot|linkedinbot|slackbot|discordbot|whatsapp|telegrambot|applebot/i;

export function isCrawler(userAgent: string): boolean {
  return CRAWLER_UA.test(userAgent);
}

export async function injectMeta(
  html: string,
  path: string,
  backendUrl: string,
): Promise<string> {
  try {
    const resp = await fetch(
      `${backendUrl}/api/meta?url=${encodeURIComponent(path)}`,
    );
    if (!resp.ok) return html;
    const meta = await resp.json();

    const tags = [
      `<title>${escapeHtml(meta.title)}</title>`,
      `<meta name="description" content="${escapeHtml(meta.description)}" />`,
      `<meta property="og:title" content="${escapeHtml(meta.title)}" />`,
      `<meta property="og:description" content="${escapeHtml(meta.description)}" />`,
      `<meta property="og:type" content="${meta.type}" />`,
      `<meta property="og:site_name" content="Control Panel" />`,
      meta.image
        ? `<meta property="og:image" content="${escapeHtml(meta.image)}" />`
        : "",
      meta.url
        ? `<meta property="og:url" content="${escapeHtml(meta.url)}" />`
        : "",
      `<meta name="twitter:card" content="${meta.image ? "summary_large_image" : "summary"}" />`,
      `<meta name="twitter:title" content="${escapeHtml(meta.title)}" />`,
      `<meta name="twitter:description" content="${escapeHtml(meta.description)}" />`,
      meta.image
        ? `<meta name="twitter:image" content="${escapeHtml(meta.image)}" />`
        : "",
      meta.url
        ? `<link rel="canonical" href="${escapeHtml(meta.url)}" />`
        : "",
    ]
      .filter(Boolean)
      .join("\n    ");

    // Replace the static <title> and inject OG tags before </head>
    return html.replace("<title>Control Panel</title>", tags);
  } catch {
    return html;
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
```

**Vite Dev Plugin (optional, for development testing):**

Add to `frontend/vite.config.ts` as a plugin:

```typescript
import { isCrawler, injectMeta } from "./server/crawler-meta";

// In the plugins array:
{
  name: "crawler-meta-injection",
  configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      const ua = req.headers["user-agent"] || "";
      if (!isCrawler(ua)) return next();

      // Only for GET requests to public routes
      const publicPaths = ["/u/", "/event/", "/posts/", "/videos/", "/gallery/", "/live/"];
      const reqUrl = req.url || "";
      if (!publicPaths.some(p => reqUrl.startsWith(p))) return next();

      try {
        const template = fs.readFileSync(
          path.resolve(__dirname, "index.html"), "utf-8"
        );
        const transformed = await server.transformIndexHtml(reqUrl, template);
        const injected = await injectMeta(transformed, reqUrl, "http://localhost:8000");
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(injected);
      } catch {
        next();
      }
    });
  }
}
```

### 4.6 Fallback Meta Tags in index.html

**`frontend/index.html`** -- Add minimal fallback meta tags for cases where the Vite plugin or crawler middleware is not active:

```html
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Control Panel</title>
  <meta name="description" content="Your all-in-one platform for messaging, commerce, and content creation." />
  <meta property="og:site_name" content="Control Panel" />
  <meta property="og:type" content="website" />
  <meta property="og:locale" content="en_US" />
  <meta name="twitter:card" content="summary" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <!-- ... fonts ... -->
</head>
```

### 4.7 Structured Data (JSON-LD) -- Future Enhancement

For enhanced search engine results (rich snippets), add JSON-LD structured data to public pages via Helmet:

**Profile page:**
```tsx
<Helmet>
  <script type="application/ld+json">
    {JSON.stringify({
      "@context": "https://schema.org",
      "@type": "Person",
      "name": data.display_name,
      "description": data.bio,
      "url": `${window.location.origin}/u/${canonicalIdentifier}`,
      "image": data.profile_photo_url,
    })}
  </script>
</Helmet>
```

**Event page:**
```tsx
<Helmet>
  <script type="application/ld+json">
    {JSON.stringify({
      "@context": "https://schema.org",
      "@type": "Event",
      "name": evt.title,
      "startDate": evt.start_utc,
      "endDate": evt.end_utc,
      "description": evt.description,
      "location": evt.location ? { "@type": "Place", "name": evt.location } : undefined,
    })}
  </script>
</Helmet>
```

This is tracked separately and not required for initial release.

---

## 5. Meta Tag Specification

### 5.1 Required Tags per Page Type

| Page Type | og:title | og:description | og:image | og:type | twitter:card |
|-----------|----------|---------------|----------|---------|-------------|
| Default (all pages) | "Control Panel" | App description | None | website | summary |
| Profile (`/u/:id`) | Display name | Bio (truncated 200 chars) | Avatar URL | profile | summary |
| Event (`/event/:cal/:evt`) | Event title | Date + location | None | event | summary |
| Post (`/posts/:id`) | "Post by {author}" | Body excerpt (200 chars) | First image URL | article | summary_large_image (if image) |
| Video (`/videos/:id`) | Video title | Description (200 chars) | Thumbnail URL | video.other | summary_large_image |
| Live Stream (`/live/:id`) | "Live Stream" | "Watch live" | None | video.other | summary |
| Login | "Log In \| Control Panel" | App description | None | website | summary |
| Register | "Create Account \| Control Panel" | App description | None | website | summary |
| Feed | "Feed \| Control Panel" | App description | None | website | summary |
| Messages | "Messages \| Control Panel" | App description | None | website | summary |

### 5.2 Standard Tags on Every Page

```html
<meta property="og:site_name" content="Control Panel" />
<meta property="og:locale" content="en_US" />
<meta name="twitter:card" content="summary" />
```

### 5.3 Canonical URL Rules

| URL | Canonical |
|-----|-----------|
| `/u/alice` | `/u/alice` |
| `/u/alice?ref=twitter` | `/u/alice` (strip query params) |
| `/event/cal1/evt1` | `/event/cal1/evt1` |
| `/posts/p_abc` | `/posts/p_abc` |
| `/login` | `/login` |

---

## 6. Security & Privacy

### 6.1 Public Data Only

The `/api/meta` endpoint performs no authentication. It only returns data from publicly-visible entities:
- Profile meta: only `display_name`, `bio`, `profile_photo_url` (all marked as `public` visibility in `PROFILE_FIELD_VISIBILITY`)
- Event meta: only public event details (events opted into public sharing)
- Post meta: only published, non-locked posts. Locked posts return generic "This post is locked" description.

### 6.2 Content Sanitization

All user-controlled fields inserted into meta tag `content` attributes are HTML-escaped via `escapeHtml()`:
- `&` -> `&amp;`
- `"` -> `&quot;`
- `<` -> `&lt;`
- `>` -> `&gt;`

This prevents XSS via user-controlled fields (display_name, bio, post body) in meta content attributes.

### 6.3 Crawler Detection Permissiveness

The crawler detection regex is intentionally permissive. False positives (regular users whose browser UA matches the pattern) simply receive pre-rendered HTML with meta tags injected. This is harmless -- the SPA JavaScript still executes normally and react-helmet-async updates the tags to their correct values.

### 6.4 Locked Content Protection

Locked/paywalled posts do NOT expose their body text in meta descriptions. The `_post_meta()` function checks `lock_price_cents > 0` and returns a generic description ("This post is locked. Subscribe or pay to view."). This prevents content leakage via social sharing previews.

### 6.5 Rate Limiting

The `/api/meta` endpoint is lightweight (single DDB read per request) but should be rate-limited to prevent abuse:
- 120 requests per minute per IP (no authentication required)
- This is sufficient for legitimate crawler traffic while preventing scraping

---

## 7. Performance Considerations

### 7.1 Meta Endpoint Latency

| URL Pattern | DDB Operations | Expected Latency |
|-------------|---------------|-----------------|
| `/u/:id` | 1 get_item (profile) | ~8ms |
| `/event/:cal/:evt` | 1 get_item (event) | ~8ms |
| `/posts/:id` | 1 get_item (post) | ~8ms |
| `/videos/:id` | 1 get_item (video) | ~8ms |
| Unknown path | 0 (returns defaults) | ~1ms |

### 7.2 Crawler Middleware Overhead

For crawler requests, the middleware adds one additional HTTP call to the backend `/api/meta` endpoint (~10ms). The total response time for a crawler is:
- Read `index.html` template: ~1ms
- Call `/api/meta`: ~10ms
- String replacement: ~1ms
- Total: ~12ms

For non-crawler requests, the middleware adds zero overhead (early return on UA check).

### 7.3 Client-Side Helmet Performance

`react-helmet-async` updates the DOM `<head>` synchronously during React rendering. For human users, this has zero visible impact -- the meta tags are updated before the page content renders. There is no FOUC (flash of unstyled content) because the `<title>` update happens before the browser paints.

### 7.4 Caching the Meta Endpoint

For high-traffic public profiles, the `/api/meta` response can be cached at the CDN/reverse-proxy level:
```
Cache-Control: public, max-age=300, s-maxage=3600
```
5-minute browser cache, 1-hour CDN cache. This reduces backend load while keeping meta tags reasonably fresh.

---

## 8. Testing Strategy

### 8.1 Unit Tests (pytest)

**File: `tests/test_meta.py`**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `test_profile_meta_returns_display_name` | `GET /api/meta?url=/u/alice` -> title contains display name |
| 2 | `test_profile_meta_bio_truncated` | Bio > 200 chars -> description truncated to 200 |
| 3 | `test_profile_meta_missing_user_returns_default` | Non-existent user -> default meta |
| 4 | `test_event_meta_returns_event_title` | `GET /api/meta?url=/event/cal1/evt1` -> title contains event title |
| 5 | `test_event_meta_missing_event_returns_default` | Non-existent event -> default meta |
| 6 | `test_post_meta_returns_body_excerpt` | `GET /api/meta?url=/posts/p_abc` -> description contains body text |
| 7 | `test_post_meta_includes_image` | Post with image_urls -> image field populated |
| 8 | `test_locked_post_meta_hides_body` | Locked post -> generic description, no body text |
| 9 | `test_video_meta_returns_thumbnail` | `GET /api/meta?url=/videos/v_abc` -> image is thumbnail URL |
| 10 | `test_unknown_path_returns_default` | `GET /api/meta?url=/nonexistent` -> default meta |
| 11 | `test_meta_url_max_length` | URL > 512 chars -> 422 validation error |
| 12 | `test_live_meta_returns_stream_type` | `GET /api/meta?url=/live/sess1` -> type is "video.other" |

### 8.2 E2E Tests

**File:** `frontend/e2e/seo-meta.spec.ts`

**Section 1: Meta API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Profile meta endpoint returns valid OG data | GET `/api/meta?url=/u/{identifier}` returns 200 with title, description, type="profile" |
| 2 | Event meta endpoint returns event data | GET `/api/meta?url=/event/{calId}/{evtId}` returns 200 with title containing event name |
| 3 | Unknown path returns defaults | GET `/api/meta?url=/nonexistent` returns default title "Control Panel" |
| 4 | Post meta includes image URL | Create post with image; GET `/api/meta?url=/posts/{id}` has image field |
| 5 | Locked post meta hides content | Create locked post; GET meta -> description is generic |

**Section 2: Client-Side Helmet (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | Profile page sets document.title | Navigate to `/u/{id}`; `await page.title()` contains display name |
| 7 | Event page sets document.title | Navigate to `/event/{cal}/{evt}`; title contains event name |
| 8 | Feed page has og:type meta | Navigate to `/feed`; `page.locator('meta[property="og:type"]')` exists with content "website" |
| 9 | Default description meta present | Navigate to `/login`; `meta[name="description"]` has content |
| 10 | Profile page has canonical link | Navigate to `/u/{id}`; `link[rel="canonical"]` has correct href |

**Section 3: Crawler Middleware (3 tests -- if Vite plugin enabled)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | Crawler UA gets injected meta | Fetch `/u/{id}` with `facebookexternalhit` UA; HTML contains `og:title` |
| 12 | Regular UA gets normal SPA | Fetch `/u/{id}` with Chrome UA; HTML has `<title>Control Panel</title>` (no injection) |
| 13 | Injected meta is properly escaped | Profile with `<script>alert(1)</script>` in display name; meta content is escaped |

---

## 9. Migration & Rollback

### 9.1 No Database Migration

This feature does not add or modify any DDB tables or items. The `/api/meta` endpoint reads existing data from profiles, events, and posts tables.

### 9.2 Deployment Phases

**Phase 1: Client-side only (low risk)**
1. Install `react-helmet-async`.
2. Add `HelmetProvider` to `main.tsx`.
3. Add default `<Helmet>` to `App.tsx`.
4. Add page-specific `<Helmet>` to all page components.
5. Result: browser tabs show correct titles. Client-side og tags set (benefits Google which renders JS).

**Phase 2: Backend meta endpoint (low risk)**
1. Deploy `app/routers/meta.py`.
2. Register in `app/main.py`.
3. Result: `/api/meta` endpoint available. No impact on existing functionality.

**Phase 3: Crawler middleware (medium risk)**
1. Add crawler-detection middleware to production proxy.
2. Result: social media crawlers see rich previews.

### 9.3 Rollback

- **Phase 1 rollback**: Remove `react-helmet-async` usage. Browser tabs revert to "Control Panel". No data loss.
- **Phase 2 rollback**: Remove meta router from `app/main.py`. `/api/meta` returns 404. No impact.
- **Phase 3 rollback**: Disable crawler middleware. Crawlers see generic "Control Panel" title (current behavior). No impact.

### 9.4 Feature Flag

No feature flag needed for Phases 1-2 (additive changes, no behavioral change for existing users). Phase 3 crawler middleware can be enabled/disabled via environment variable:

```
CRAWLER_META_INJECTION_ENABLED=true
```

---

## 10. Acceptance Criteria

1. `react-helmet-async` installed and `HelmetProvider` wraps the app in `main.tsx`.
2. Every page sets `<title>` via Helmet (dynamic where data is available).
3. Browser tab titles update on navigation (e.g., "Messages | Control Panel", "Alice Smith | Control Panel").
4. Public pages (`/u/:id`, `/event/:cal/:evt`, `/posts/:id`, `/videos/:id`) set `og:title`, `og:description`, `og:image` (where applicable), and `og:type`.
5. `twitter:card` meta tag present on all pages ("summary" default, "summary_large_image" for posts with images and videos).
6. `GET /api/meta?url=...` endpoint returns Open Graph data for public URLs.
7. `/api/meta` does not expose locked post content (returns generic description).
8. Crawler User-Agents receive HTML with pre-rendered meta tags (in production deployment).
9. `<link rel="canonical">` present on public pages (strips query parameters).
10. `<meta name="description">` present on all pages.
11. Fallback meta tags added to `index.html` for when JavaScript/middleware is unavailable.
12. Private/locked content does not leak body text in meta descriptions.

---

## 11. Files to Create

| File | Purpose | Est. Lines |
|------|---------|------------|
| `app/routers/meta.py` | Backend meta data endpoint | ~120 |
| `frontend/server/crawler-meta.ts` | Crawler detection + meta injection for production | ~80 |
| `frontend/e2e/seo-meta.spec.ts` | E2E tests | ~200 |
| `tests/test_meta.py` | Backend unit tests | ~150 |

## 12. Files to Modify

| File | Change |
|------|--------|
| `frontend/package.json` | Add `react-helmet-async` dependency |
| `frontend/src/main.tsx` | Wrap app in `HelmetProvider` |
| `frontend/src/App.tsx` | Add default `<Helmet>` with base meta tags |
| `frontend/src/pages/profile/PublicUserProfilePage.tsx` | Add `<Helmet>` with profile og tags + canonical |
| `frontend/src/pages/calendar/PublicEventPage.tsx` | Add `<Helmet>` with event og tags |
| `frontend/src/pages/feed/FeedPage.tsx` | Add `<Helmet>` with feed page title |
| `frontend/src/pages/messages/MessagesPage.tsx` | Add `<Helmet>` with messages title |
| `frontend/src/pages/Login.tsx` | Add `<Helmet>` with login title |
| `frontend/src/pages/Register.tsx` | Add `<Helmet>` with register title |
| `frontend/src/pages/Dashboard.tsx` | Add `<Helmet>` with dashboard title |
| `frontend/index.html` | Add fallback `<meta name="description">`, `og:site_name`, `og:locale`, `twitter:card` |
| `app/main.py` | Register `meta_router` |
| `frontend/vite.config.ts` | Add crawler meta injection plugin (optional for dev) |

---

## 13. Dependencies

- **`react-helmet-async`** (npm): Client-side head management. Chosen over `react-helmet` (unmaintained since 2020) and `@unhead/react` (heavier API surface, Vue-first). `react-helmet-async` is actively maintained, supports concurrent mode, and has 2M+ weekly downloads.
- **No SSR framework required**: The crawler detection middleware is a thin proxy, not a full SSR solution. It only injects static meta tags -- no React server rendering. This keeps the deployment architecture simple (no Node.js SSR server needed).
- **Profile service (existing)**: `app/services/profile.py:get_profile_by_identifier()` for profile meta.
- **Calendar service (existing)**: `app/services/calendar.py:get_public_event_details()` for event meta.
- **Newsfeed router (existing)**: `app/routers/newsfeed.py:_get_post_item()` for post meta.

---

## 14. Open Questions

| # | Question | Recommendation | Status |
|---|----------|---------------|--------|
| 1 | Should we add a `robots.txt` for search engine control? | Yes, add a static `robots.txt` to `frontend/public/` allowing crawling of `/u/`, `/event/`, `/posts/`. Block `/messages`, `/settings`, `/billing`. Track separately. | DEFERRED |
| 2 | Should we add a `sitemap.xml`? | Yes, dynamic sitemap generated from public profiles and events. Track as PLATFORM-005b. | DEFERRED |
| 3 | Should the meta endpoint require API key for non-crawler access? | No. The endpoint only returns public data. Rate limiting by IP is sufficient. | DECIDED |
| 4 | Should we support `og:image:width` and `og:image:height`? | Yes for posts with known image dimensions (from PLATFORM-004 image optimization). Not for avatars (unknown dimensions). | DEFERRED |
| 5 | Should we add JSON-LD structured data? | Yes, for profile and event pages. Track as Phase 2 of this ticket. | DEFERRED |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| index.html has only viewport + charset | `frontend/index.html` | 1-19 | VERIFIED |
| No og:title, og:description, og:image in index.html | `frontend/index.html` | 1-19 | VERIFIED |
| title is hardcoded "Control Panel" | `frontend/index.html` | 6 | VERIFIED |
| PublicUserProfilePage has no meta injection | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | 1-60 | VERIFIED |
| PublicUserProfilePage fetches by identifier | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | 22-27 | VERIFIED |
| PublicUserProfilePage has canonical redirect | `frontend/src/pages/profile/PublicUserProfilePage.tsx` | 38-42 | VERIFIED |
| PublicEventPage has no meta injection | `frontend/src/pages/calendar/PublicEventPage.tsx` | 1-60 | VERIFIED |
| PublicEventPage has formatEventTime helper | `frontend/src/pages/calendar/PublicEventPage.tsx` | 10-46 | VERIFIED |
| No react-helmet in package.json | `frontend/package.json` | N/A | VERIFIED (not present) |
| No document.title in any page | `frontend/src/pages/` | N/A | VERIFIED (zero occurrences) |
| Public routes in App.tsx | `frontend/src/App.tsx` | 86-93 | VERIFIED |
| Profile page fetches via getProfileByIdentifier | `PublicUserProfilePage.tsx` | 24 | VERIFIED |
| Event page fetches public event | `PublicEventPage.tsx` | 52-56 | VERIFIED |
| Sidebar navigation groups | `frontend/src/components/layout/Sidebar.tsx` | 68-137 | VERIFIED |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_meta.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_profile_meta_display_name` | GET /api/meta?url=/u/alice; title has display name |
| 2 | `test_profile_meta_bio_truncated` | Bio >200 chars truncated |
| 3 | `test_missing_user_default` | Non-existent user; default meta |
| 4 | `test_event_meta_title` | GET /api/meta?url=/event/cal/evt; event title in title |
| 5 | `test_locked_post_hides_body` | Locked post; generic description |
| 6 | `test_unknown_path_default` | GET /api/meta?url=/foo; default meta |
| 7 | `test_meta_url_max_length` | URL >512 chars; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Meta endpoint reads profile data | meta router + profile service |
| 2 | Meta endpoint reads event data | meta router + calendar service |
| 3 | Crawler middleware injects OG tags | Vite plugin + meta endpoint |

### E2E Tests (Playwright)

**File**: `frontend/e2e/seo-meta.spec.ts` -- 13 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Sections: 1 (meta API, 5), 2 (client-side Helmet, 5), 3 (crawler middleware, 3)

**Negative/edge tests**: Missing user returns defaults, locked post hides body, non-crawler gets normal SPA

### Test Data Requirements

- DDB seeds: profiles, calendar events, posts
- Test users: Alice with public profile
- Public event created in beforeAll

### CI/Pipeline

- Feature flags: CRAWLER_META_INJECTION_ENABLED=true
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone feature |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| PLATFORM-004 | Enhances | Image variants provide og:image dimensions |

### Merge Strategy

**Independent** -- No prerequisites. Additive changes to index.html and page components.

### Merge Checklist

- [ ] react-helmet-async installed
- [ ] HelmetProvider wraps app in main.tsx
- [ ] Default Helmet in App.tsx
- [ ] Page-specific Helmet on all pages
- [ ] /api/meta endpoint registered in main.py
- [ ] Crawler middleware for social media bots
- [ ] E2E pass: `npx playwright test e2e/seo-meta.spec.ts`
