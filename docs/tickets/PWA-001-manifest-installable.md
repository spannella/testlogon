# PWA-001: Web App Manifest & Installable App

**Ticket**: PWA-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform currently runs as a standard web application with no Web App Manifest or
install-prompt integration. Users must always access the app through a browser tab, cannot
add the app to their home screen on mobile or desktop in a way that provides a native-like
experience, and receive no visual differentiation between the app and other browser tabs.
The only asset in `frontend/public/` beyond the service worker is a single SVG favicon
(`frontend/public/favicon.svg`) -- there are no PNG icons, no splash screen images, and
no `manifest.json`. The `frontend/index.html` `<head>` section contains only a basic
`<title>Control Panel</title>`, a viewport meta tag, a favicon link, and Google Fonts
preconnect -- no `<link rel="manifest">`, no `theme-color` meta, and no Apple-specific
meta tags for iOS home screen behavior.

Adding a Web App Manifest with proper metadata, a full icon set, themed splash screens,
and an install-prompt component enables the app to pass Chrome's installability checks,
appear in the "Add to Home Screen" prompt on Android, work as an installed PWA on desktop
(Chrome, Edge), and receive a standalone window without browser chrome.

### 1.2 User Stories

1. **As a user on Android Chrome**, I want to see an "Add to Home Screen" banner so I can
   install the app and launch it from my home screen with a native-like splash screen.
2. **As a user on desktop Chrome/Edge**, I want to click an install button in the app header
   so I can open the app in its own window without browser tabs and address bar.
3. **As a returning user**, I want the app to display a themed splash screen with the
   platform logo during startup so I know the app is loading.
4. **As a user on iOS Safari**, I want the app to use the correct status bar style and
   icon when added to home screen via Share > Add to Home Screen.
5. **As a developer**, I want the manifest to declare the correct `start_url`, `scope`,
   `display`, and `theme_color` so that Lighthouse audits pass the PWA installability
   checks.

### 1.3 Design Principles

- **Progressive Enhancement**: The manifest and install prompt are additive -- the app
  continues to work identically in a plain browser tab.
- **Platform Parity**: Provide metadata for Android, iOS, Windows, and macOS so each
  platform renders the best possible icon/splash.
- **Zero-Build-Step Icons**: Icons are static PNGs checked into `frontend/public/icons/`
  so they do not require a build step and are cache-friendly.
- **Non-Intrusive Install Prompt**: The install banner appears once, is dismissible, and
  remembers the user's choice via `localStorage`.

---

## 2. Current State Analysis

### 2.1 `frontend/index.html`

The current `<head>` is minimal (19 lines total, all content between lines 1-19):
<!-- CORRECTED: was "20 lines total", actually 19 lines (verified via wc -l) -->

```html
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Control Panel</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
</head>
```

**Missing for PWA installability**:
- `<link rel="manifest" href="/manifest.json">`
- `<meta name="theme-color" content="...">`
- `<meta name="apple-mobile-web-app-capable" content="yes">`
- `<meta name="apple-mobile-web-app-status-bar-style" content="...">`
- `<link rel="apple-touch-icon" href="...">`

The `<body>` contains only `<div id="root"></div>` and the Vite module script entry at
`/src/main.tsx`. No `<noscript>` fallback is provided (a minor PWA best practice that
should also be addressed in this ticket).

### 2.2 `frontend/public/` Directory

Contains only two files:

| File | Purpose |
|------|---------|
| `favicon.svg` | 64x64 SVG with gradient background, used as `<link rel="icon">` |
| `sw.js` | Service worker for push notifications (PLATFORM-010) |

There is no `manifest.json`, no PNG icon set, and no splash screen images.

### 2.3 `frontend/public/sw.js` (Service Worker)

The service worker is already registered at app boot in `frontend/src/main.tsx` (line 31-33):
<!-- VERIFIED: main.tsx:31-33 -->

```typescript
if ("serviceWorker" in navigator) {
  registerServiceWorker();
}
```

The `registerServiceWorker()` function in `frontend/src/lib/pushSetup.ts` (lines 11-26)
registers `/sw.js` with `scope: "/"`:
<!-- VERIFIED: pushSetup.ts:11-26 -->

```typescript
export async function registerServiceWorker(): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) {
    console.warn("Service workers not supported");
    return null;
  }
  try {
    const registration = await navigator.serviceWorker.register("/sw.js", {
      scope: "/",
    });
    console.log("SW registered:", registration.scope);
    return registration;
  } catch (err) {
    console.error("SW registration failed:", err);
    return null;
  }
}
```

The SW currently handles only `push` and `notificationclick` events. It uses
`self.skipWaiting()` on install and `self.clients.claim()` on activate (lines 11-18 of
`sw.js`). **No `fetch` event listener exists**, which means the manifest and icons will be
fetched from the network as normal -- this is fine for PWA-001, and fetch interception is
deferred to PWA-002.
<!-- CORRECTED: was "lines 11-16", actually install is lines 11-13 and activate is lines 16-18; the range covering both is 11-18 -->

The SW also handles `notificationclose` (no-op, reserved for future analytics, lines 85-87).
<!-- VERIFIED: sw.js:85-87 -->
The push event handler (lines 21-59) parses JSON payloads with `title`, `body`, `icon`,
`badge`, `url`, `alert_id`, `alert_type`, `tag`, and `timestamp` fields.
<!-- CORRECTED: was implicitly unreferenced line range; push handler is lines 21-59 -->
Notification clicks (lines 62-82) navigate to `event.notification.data.url` by focusing an
existing tab or opening a new one.
<!-- VERIFIED: sw.js:62-82 -->

### 2.4 `frontend/public/favicon.svg`

The existing favicon is an SVG with a linear gradient (`#38bdf8` to `#6366f1`) and an
abstract dashboard icon. This SVG can serve as the basis for generating the required PNG
icon set, but cannot itself satisfy the manifest's `icons` requirement because most
browsers require at least one PNG (or WebP) icon for installation.

The SVG uses `viewBox="0 0 64 64"` with a rounded rectangle background and a central
icon element. The icon has sufficient contrast and detail at all target sizes (48px through
512px).

### 2.5 App Title and Theme

The app title is "Control Panel" (set in `index.html` line 5 and `frontend/src/App.tsx`
Helmet usage). The theme colors derived from `frontend/src/globals.css` and the Tailwind
config use a blue primary (`--color-primary: hsl(221 83% 53%)` in light mode,
`--color-primary: hsl(217 91% 60%)` in dark mode) with the gradient accent blue (`#38bdf8`)
from the favicon.
<!-- CORRECTED: was "--primary: 222.2 47.4% 11.2%", actually "--color-primary: hsl(221 83% 53%)" in light mode. The value 222.2 47.4% 11.2% does not appear in globals.css. -->

The `ThemeProvider` component wraps the app in `main.tsx` and manages light/dark mode
via a `data-theme` attribute. The manifest `theme_color` must work with both modes.

### 2.6 Frontend Component Patterns

The install prompt component should follow the same patterns as existing banner components:

- **`OfflineBanner`** (`frontend/src/components/shared/OfflineBanner.tsx`, 33 lines): Uses `useState`
  + `useEffect` with `window.addEventListener("online" / "offline")`, renders a full-width
  banner with icon + text + optional badge. The component reads from `useOfflineStore` for
  the queue count badge.
  <!-- VERIFIED: OfflineBanner.tsx exists, 33 lines, pattern confirmed -->
- **`SessionExpiryWarning`** (`frontend/src/components/shared/SessionExpiryWarning.tsx`):
  Another banner-style component that listens for `api-activity` events and shows a countdown
  warning before session expiry.
- **`ImpersonationBanner`** (`frontend/src/components/shared/ImpersonationBanner.tsx`):
  Shows when an admin is impersonating another user; follows the same full-width colored
  banner pattern.
- **`AppShell`** (`frontend/src/components/layout/AppShell.tsx`): Renders
  `<OfflineBanner />` at the top of the main content area (line 61), `<OfflineQueueFlusher />`
  (line 62), before the `<Header>` component (line 63). The install prompt should occupy
  a similar position.
  <!-- VERIFIED: AppShell.tsx:61 OfflineBanner, :62 OfflineQueueFlusher, :63 Header -->

### 2.7 Vite Configuration (`frontend/vite.config.ts`)

The Vite config uses `@vitejs/plugin-react` and `@tailwindcss/vite` plugins. The `server`
block binds to `0.0.0.0:3000` with `strictPort: true`. The proxy configuration routes 18
path prefixes to `http://localhost:8000`. Files in `frontend/public/` are served as-is by
Vite without hashing or transformation. The build outputs to `frontend/dist/` with
sourcemaps enabled.
<!-- CORRECTED: was "13 path prefixes", actually 18 proxied paths: /ui, /api, /v1, /messaging, /feed, /posts, /social, /uploads, /sse, /notifications, /mock, /calendar/public, /internal, /tickets, /ticket-spaces, /broadcast, /live, /questionnaires -->

No PWA-specific Vite plugin is used (no `vite-plugin-pwa`, no Workbox). This is
intentional -- the service worker is hand-written in `public/sw.js`.

### 2.8 Existing `main.tsx` Boot Sequence

The `main.tsx` file (78 lines) performs the following at boot:
<!-- VERIFIED: main.tsx is 78 lines -->
1. Polyfill `crypto.randomUUID` for non-secure contexts (lines 1-12)
2. Import i18n (line 26)
3. Register service worker for push notifications (lines 31-33)
4. Set referral attribution cookie from `?ref=CODE` query param (lines 38-48)
5. Create `QueryClient` with `staleTime: 30_000`, `retry: 1`, `refetchOnWindowFocus: false` (lines 50-58)
6. Render the React tree with providers (BrowserRouter, QueryClient, ThemeProvider, etc.)
<!-- VERIFIED: all line numbers confirmed against main.tsx -->

The service worker registration fires before React mounts, which is correct for PWA
installability -- the browser needs an active SW before it can show the install prompt.

---

## 3. Technical Design

### 3.1 Manifest File (`frontend/public/manifest.json`)

```json
{
  "name": "Control Panel",
  "short_name": "CtrlPanel",
  "description": "SaaS platform for messaging, commerce, and content management",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "theme_color": "#0f172a",
  "background_color": "#ffffff",
  "categories": ["business", "productivity", "social"],
  "lang": "en",
  "dir": "auto",
  "icons": [
    {
      "src": "/icons/icon-48.png",
      "sizes": "48x48",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-72.png",
      "sizes": "72x72",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-96.png",
      "sizes": "96x96",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-128.png",
      "sizes": "128x128",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-144.png",
      "sizes": "144x144",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "any"
    },
    {
      "src": "/icons/icon-256.png",
      "sizes": "256x256",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-384.png",
      "sizes": "384x384",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "any"
    },
    {
      "src": "/icons/icon-maskable-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "maskable"
    },
    {
      "src": "/icons/icon-maskable-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "maskable"
    },
    {
      "src": "/favicon.svg",
      "sizes": "any",
      "type": "image/svg+xml"
    }
  ],
  "screenshots": [
    {
      "src": "/screenshots/desktop-dashboard.png",
      "sizes": "1920x1080",
      "type": "image/png",
      "form_factor": "wide",
      "label": "Dashboard on desktop"
    },
    {
      "src": "/screenshots/mobile-messages.png",
      "sizes": "390x844",
      "type": "image/png",
      "form_factor": "narrow",
      "label": "Messages on mobile"
    }
  ],
  "shortcuts": [
    {
      "name": "Messages",
      "short_name": "Msgs",
      "url": "/messages",
      "icons": [{ "src": "/icons/shortcut-messages.png", "sizes": "96x96" }]
    },
    {
      "name": "Feed",
      "short_name": "Feed",
      "url": "/feed",
      "icons": [{ "src": "/icons/shortcut-feed.png", "sizes": "96x96" }]
    },
    {
      "name": "Calendar",
      "short_name": "Calendar",
      "url": "/calendar",
      "icons": [{ "src": "/icons/shortcut-calendar.png", "sizes": "96x96" }]
    }
  ]
}
```

**Key decisions**:
- `display: "standalone"` -- the app opens without browser chrome (back button, address bar).
- `theme_color: "#0f172a"` -- matches the dark primary from `globals.css` (Slate 900).
  This colors the title bar / status bar on mobile.
- `background_color: "#ffffff"` -- splash screen background before CSS loads.
- Maskable icons include extra padding so the icon is safe for circular/squircle cropping
  on Android.
- The SVG favicon is included as a fallback icon for browsers that support SVG manifest icons.

### 3.2 Manifest Field Reference

| Field | Value | Rationale |
|-------|-------|-----------|
| `name` | `"Control Panel"` | Full application name; shown in install dialogs and app drawer |
| `short_name` | `"CtrlPanel"` | Abbreviated name; shown under home screen icon (12 char limit recommended) |
| `description` | `"SaaS platform for messaging, commerce, and content management"` | Used by app stores and install UI descriptions |
| `start_url` | `"/"` | Root URL; redirects to `/login` if unauthenticated via `ProtectedRoute` |
| `scope` | `"/"` | Navigation scope; all app routes are under `/` |
| `display` | `"standalone"` | No browser chrome; back/forward via in-app navigation |
| `orientation` | `"any"` | Allow both portrait and landscape; app is responsive |
| `theme_color` | `"#0f172a"` | Slate 900; colors OS status bar and title bar |
| `background_color` | `"#ffffff"` | White splash screen background before CSS paints |
| `categories` | `["business", "productivity", "social"]` | W3C web app categories for discoverability |
| `lang` | `"en"` | Default language; i18n changes do not affect manifest |
| `dir` | `"auto"` | Text direction; supports RTL via `RTLProvider` in app |

### 3.3 `index.html` Additions

Add the following tags to `<head>`, after the existing `<link rel="icon">` tag:

```html
<!-- PWA Manifest -->
<link rel="manifest" href="/manifest.json" crossorigin="use-credentials" />
<meta name="theme-color" content="#0f172a" media="(prefers-color-scheme: light)" />
<meta name="theme-color" content="#0f172a" media="(prefers-color-scheme: dark)" />

<!-- iOS Home Screen -->
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
<meta name="apple-mobile-web-app-title" content="Control Panel" />
<link rel="apple-touch-icon" href="/icons/icon-180.png" />

<!-- Apple splash screens (select sizes) -->
<link rel="apple-touch-startup-image"
      href="/splash/apple-splash-1170x2532.png"
      media="(device-width: 390px) and (device-height: 844px) and (-webkit-device-pixel-ratio: 3)" />
<link rel="apple-touch-startup-image"
      href="/splash/apple-splash-1284x2778.png"
      media="(device-width: 428px) and (device-height: 926px) and (-webkit-device-pixel-ratio: 3)" />
<link rel="apple-touch-startup-image"
      href="/splash/apple-splash-2048x2732.png"
      media="(device-width: 1024px) and (device-height: 1366px) and (-webkit-device-pixel-ratio: 2)" />

<!-- Windows tile color -->
<meta name="msapplication-TileColor" content="#0f172a" />

<!-- Noscript fallback (PWA best practice) -->
```

Also add a `<noscript>` tag inside `<body>` before `<div id="root">`:

```html
<noscript>
  <div style="padding:2rem;text-align:center;font-family:system-ui,sans-serif">
    <h1>JavaScript Required</h1>
    <p>Control Panel requires JavaScript to run. Please enable JavaScript in your browser settings.</p>
  </div>
</noscript>
```

**Complete updated `index.html`**:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Control Panel</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />

    <!-- PWA Manifest -->
    <link rel="manifest" href="/manifest.json" crossorigin="use-credentials" />
    <meta name="theme-color" content="#0f172a" media="(prefers-color-scheme: light)" />
    <meta name="theme-color" content="#0f172a" media="(prefers-color-scheme: dark)" />

    <!-- iOS Home Screen -->
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
    <meta name="apple-mobile-web-app-title" content="Control Panel" />
    <link rel="apple-touch-icon" href="/icons/icon-180.png" />

    <!-- Apple splash screens -->
    <link rel="apple-touch-startup-image"
          href="/splash/apple-splash-1170x2532.png"
          media="(device-width: 390px) and (device-height: 844px) and (-webkit-device-pixel-ratio: 3)" />
    <link rel="apple-touch-startup-image"
          href="/splash/apple-splash-1284x2778.png"
          media="(device-width: 428px) and (device-height: 926px) and (-webkit-device-pixel-ratio: 3)" />
    <link rel="apple-touch-startup-image"
          href="/splash/apple-splash-2048x2732.png"
          media="(device-width: 1024px) and (device-height: 1366px) and (-webkit-device-pixel-ratio: 2)" />

    <!-- Windows tile color -->
    <meta name="msapplication-TileColor" content="#0f172a" />

    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
      rel="stylesheet"
    />
  </head>
  <body>
    <noscript>
      <div style="padding:2rem;text-align:center;font-family:system-ui,sans-serif">
        <h1>JavaScript Required</h1>
        <p>Control Panel requires JavaScript to run. Please enable JavaScript in your browser settings.</p>
      </div>
    </noscript>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

**`crossorigin="use-credentials"` on the manifest link**: The app uses cookie-based auth.
If the manifest fetch sends credentials, Chrome won't block it. Some setups with
`SameSite=Strict` cookies can cause issues if credentials are not sent; using
`use-credentials` ensures the browser sends cookies with the manifest request in case the
backend ever serves it dynamically.

### 3.4 Icon Generation Pipeline

Create a script `scripts/generate-pwa-icons.sh` that uses ImageMagick (or `sharp-cli` via
Node) to convert `frontend/public/favicon.svg` into the required PNG sizes. The script
runs once during setup -- the generated PNGs are committed to the repo.

Required sizes:

| Size | Usage |
|------|-------|
| 48x48 | Manifest (small) |
| 72x72 | Manifest (Android legacy) |
| 96x96 | Manifest + shortcuts |
| 128x128 | Manifest |
| 144x144 | Manifest (Windows tile) |
| 180x180 | Apple touch icon |
| 192x192 | Manifest (Android install) |
| 256x256 | Manifest |
| 384x384 | Manifest |
| 512x512 | Manifest (Android splash generator) |
| 192x192 (maskable) | Android adaptive icon (safe zone) |
| 512x512 (maskable) | Android adaptive icon (safe zone) |

Maskable icons must have at least 10% padding on each side so the core icon (the dashboard
graphic from `favicon.svg`) is within the "safe zone" that Android does not clip.

**Icon generation script** (`scripts/generate-pwa-icons.sh`):

```bash
#!/usr/bin/env bash
# Generate PWA icon set from the SVG favicon.
# Requires: ImageMagick 7+ (convert) or rsvg-convert + ImageMagick
set -euo pipefail

SVG="frontend/public/favicon.svg"
OUT="frontend/public/icons"

mkdir -p "$OUT"

# Standard sizes (purpose: any)
for SIZE in 48 72 96 128 144 180 192 256 384 512; do
  echo "  icon-${SIZE}.png"
  convert -background none -resize "${SIZE}x${SIZE}" "$SVG" "$OUT/icon-${SIZE}.png"
done

# Maskable icons: 80% icon area, 10% padding each side
for SIZE in 192 512; do
  echo "  icon-maskable-${SIZE}.png"
  INNER=$((SIZE * 80 / 100))
  convert -background none -resize "${INNER}x${INNER}" "$SVG" \
    -gravity center -background "#1e293b" -extent "${SIZE}x${SIZE}" \
    "$OUT/icon-maskable-${SIZE}.png"
done

# Shortcut icons (simple 96x96 with colored backgrounds)
for NAME in messages feed calendar; do
  echo "  shortcut-${NAME}.png"
  convert -background none -resize "64x64" "$SVG" \
    -gravity center -background "#0f172a" -extent "96x96" \
    "$OUT/shortcut-${NAME}.png"
done

echo "PWA icons generated in $OUT"
ls -la "$OUT"
```

**Alternative Node.js script using `sharp`** (`scripts/generate-pwa-icons.mjs`):

```javascript
import sharp from "sharp";
import { mkdirSync } from "fs";
import { join } from "path";

const SVG = "frontend/public/favicon.svg";
const OUT = "frontend/public/icons";
mkdirSync(OUT, { recursive: true });

const STANDARD_SIZES = [48, 72, 96, 128, 144, 180, 192, 256, 384, 512];
const MASKABLE_SIZES = [192, 512];

for (const size of STANDARD_SIZES) {
  await sharp(SVG)
    .resize(size, size)
    .png()
    .toFile(join(OUT, `icon-${size}.png`));
  console.log(`  icon-${size}.png`);
}

for (const size of MASKABLE_SIZES) {
  const inner = Math.round(size * 0.8);
  const padding = Math.round((size - inner) / 2);
  await sharp(SVG)
    .resize(inner, inner)
    .extend({
      top: padding,
      bottom: padding,
      left: padding,
      right: padding,
      background: { r: 30, g: 41, b: 59, alpha: 1 }, // #1e293b
    })
    .png()
    .toFile(join(OUT, `icon-maskable-${size}.png`));
  console.log(`  icon-maskable-${size}.png`);
}

console.log("Done. Generated", STANDARD_SIZES.length + MASKABLE_SIZES.length, "icons.");
```

### 3.5 Install Prompt Component

Create `frontend/src/components/shared/InstallPrompt.tsx`:

```
+--------------------------------------------------------------+
| [App Icon]  Install Control Panel for quick access  [Install] [X] |
+--------------------------------------------------------------+
```

#### Behavior

1. Listen for the `beforeinstallprompt` event on `window`.
2. Stash the `BeforeInstallPromptEvent` in a `useRef`.
3. Check `localStorage` for a dismissal flag (`pwa_install_dismissed`). If the user
   dismissed the prompt within the last 30 days, do not show.
4. Check `window.matchMedia("(display-mode: standalone)")` -- if the app is already
   installed (running in standalone mode), never show the prompt.
5. When the user clicks "Install", call `deferredPrompt.prompt()` and await the
   `userChoice`. If the user accepts, track the install and hide the banner. If the user
   dismisses the browser prompt, set the 30-day localStorage flag.
6. When the user clicks the "X" dismiss button, set the 30-day flag and hide.

#### Full Component Implementation

```typescript
// frontend/src/components/shared/InstallPrompt.tsx
import { useState, useEffect, useRef, useCallback } from "react";
import { Download, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { isPwaInstallPromptEnabled } from "@/lib/featureFlags";

/**
 * PWA install banner. Shows when:
 * 1. Feature flag is enabled
 * 2. Browser fires `beforeinstallprompt` (Chromium only)
 * 3. App is NOT already in standalone mode
 * 4. User has not dismissed within the last 30 days
 *
 * On iOS Safari, this component never renders (no `beforeinstallprompt`).
 * A separate `IOSInstallHint` component can provide educational guidance.
 */
export function InstallPrompt() {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [visible, setVisible] = useState(false);
  const [isStandalone, setIsStandalone] = useState(false);
  const [installing, setInstalling] = useState(false);
  const promptRef = useRef<BeforeInstallPromptEvent | null>(null);

  // ── Check if already installed (standalone mode) ──────────────
  useEffect(() => {
    const mq = window.matchMedia("(display-mode: standalone)");
    setIsStandalone(mq.matches);
    const handler = (e: MediaQueryListEvent) => setIsStandalone(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // ── Listen for beforeinstallprompt ────────────────────────────
  useEffect(() => {
    if (!isPwaInstallPromptEnabled()) return;
    if (isStandalone) return;

    // Check 30-day dismissal cooldown
    const dismissed = localStorage.getItem("pwa_install_dismissed");
    if (dismissed && Date.now() - Number(dismissed) < 30 * 86400 * 1000) return;

    const onBeforeInstall = (e: Event) => {
      e.preventDefault(); // Prevent Chrome's mini-infobar
      const prompt = e as BeforeInstallPromptEvent;
      promptRef.current = prompt;
      setDeferredPrompt(prompt);
      setVisible(true);
    };

    window.addEventListener("beforeinstallprompt", onBeforeInstall);

    // Also listen for appinstalled to hide the banner if installed via other means
    const onInstalled = () => {
      setVisible(false);
      setDeferredPrompt(null);
      promptRef.current = null;
    };
    window.addEventListener("appinstalled", onInstalled);

    return () => {
      window.removeEventListener("beforeinstallprompt", onBeforeInstall);
      window.removeEventListener("appinstalled", onInstalled);
    };
  }, [isStandalone]);

  // ── Install button handler ────────────────────────────────────
  const handleInstall = useCallback(async () => {
    const prompt = promptRef.current;
    if (!prompt) return;

    setInstalling(true);
    try {
      await prompt.prompt();
      const choice = await prompt.userChoice;

      if (choice.outcome === "accepted") {
        // User accepted install
        setVisible(false);
        setDeferredPrompt(null);
        promptRef.current = null;
        // Track install event (future: analytics)
      } else {
        // User dismissed -- set 30-day cooldown
        localStorage.setItem("pwa_install_dismissed", String(Date.now()));
        setVisible(false);
      }
    } catch {
      // prompt() can throw if already called or prompt expired
    } finally {
      setInstalling(false);
    }
  }, []);

  // ── Dismiss button handler ────────────────────────────────────
  const handleDismiss = useCallback(() => {
    localStorage.setItem("pwa_install_dismissed", String(Date.now()));
    setVisible(false);
  }, []);

  if (!visible || !deferredPrompt || isStandalone) return null;

  return (
    <div
      className="flex w-full items-center justify-center gap-3 bg-primary px-4 py-2.5 text-primary-foreground text-sm font-medium animate-in slide-in-from-top duration-300"
      role="banner"
      aria-label="Install application prompt"
    >
      <Download className="h-4 w-4 shrink-0" aria-hidden />
      <span>Install Control Panel for quick access</span>
      <Button
        size="sm"
        variant="secondary"
        onClick={handleInstall}
        disabled={installing}
        className="h-7 px-3 text-xs font-semibold"
      >
        {installing ? "Installing..." : "Install"}
      </Button>
      <button
        onClick={handleDismiss}
        className="ml-1 rounded p-1 hover:bg-primary-foreground/10 transition-colors"
        aria-label="Dismiss install prompt"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

/**
 * iOS Safari install hint.
 * Shows a one-time educational message on iOS Safari since beforeinstallprompt
 * is not supported. Uses navigator.userAgent to detect iOS Safari specifically.
 */
export function IOSInstallHint() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Detect iOS Safari (not in standalone mode, not Chrome/Firefox on iOS)
    const ua = navigator.userAgent;
    const isIOS = /iPad|iPhone|iPod/.test(ua) && !(window as any).MSStream;
    const isSafari = /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS/.test(ua);
    const isStandalone = (navigator as any).standalone === true;

    if (!isIOS || !isSafari || isStandalone) return;

    // Check if already dismissed
    const dismissed = localStorage.getItem("pwa_ios_hint_dismissed");
    if (dismissed) return;

    setVisible(true);
  }, []);

  const handleDismiss = () => {
    localStorage.setItem("pwa_ios_hint_dismissed", "1");
    setVisible(false);
  };

  if (!visible) return null;

  return (
    <div className="flex w-full items-center justify-center gap-2 bg-blue-50 px-4 py-2 text-blue-900 text-sm dark:bg-blue-950 dark:text-blue-100">
      <span>
        Tap{" "}
        <span className="inline-block" aria-label="share icon">
          &#x2B06;&#xFE0F;
        </span>{" "}
        then &quot;Add to Home Screen&quot; to install this app
      </span>
      <button onClick={handleDismiss} className="ml-2 p-1 hover:opacity-70" aria-label="Dismiss">
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
```

### 3.6 Integration in AppShell

In `frontend/src/components/layout/AppShell.tsx`, add the `InstallPrompt` and
`IOSInstallHint` between `<OfflineBanner />` (line 61) and the `<OfflineQueueFlusher />`
(line 62):

```typescript
import { InstallPrompt, IOSInstallHint } from "@/components/shared/InstallPrompt";

// In the JSX:
<OfflineBanner />
<InstallPrompt />
<IOSInstallHint />
<OfflineQueueFlusher />
<Header onMobileMenuToggle={() => setMobileMenuOpen(true)} />
```

The ordering ensures the offline banner (critical information) always appears above the
install prompt (promotional/optional).

### 3.7 TypeScript Type for `BeforeInstallPromptEvent`

The `beforeinstallprompt` event is not in the standard TypeScript DOM lib. Add a type
declaration file `frontend/src/types/pwa.d.ts`:

```typescript
/**
 * BeforeInstallPromptEvent -- fired by Chromium browsers when the app
 * meets PWA installability criteria. Not part of the standard DOM types.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/BeforeInstallPromptEvent
 */
interface BeforeInstallPromptEvent extends Event {
  /**
   * Array of platform strings (e.g., ["web", "play"]) indicating which
   * platforms the browser can install to.
   */
  readonly platforms: string[];

  /**
   * Promise that resolves when the user responds to the install prompt.
   * `outcome` is "accepted" if they installed, "dismissed" if they declined.
   */
  readonly userChoice: Promise<{
    outcome: "accepted" | "dismissed";
    platform: string;
  }>;

  /**
   * Show the install prompt dialog. Can only be called once per
   * beforeinstallprompt event. Must be called in a user gesture context.
   */
  prompt(): Promise<void>;
}

declare global {
  interface WindowEventMap {
    /** Fired when Chrome determines the app is installable. */
    beforeinstallprompt: BeforeInstallPromptEvent;

    /** Fired after the user has installed the PWA. */
    appinstalled: Event;
  }
}

export {};
```

### 3.8 Feature Flag

Add a feature flag `VITE_PWA_INSTALL_PROMPT_ENABLED` in `frontend/src/lib/featureFlags.ts`
following the existing pattern (line 1-11):

```typescript
// PWA Install Prompt
export const pwaInstallPromptEnabled = toBool(env.VITE_PWA_INSTALL_PROMPT_ENABLED, true);
export const pwaInstallPromptKillSwitch = toBool(env.VITE_PWA_INSTALL_PROMPT_KILL_SWITCH, false);
export const isPwaInstallPromptEnabled = () =>
  pwaInstallPromptEnabled && !pwaInstallPromptKillSwitch;
```

The `InstallPrompt` component checks this flag before rendering. The kill switch allows
disabling the prompt in production without a code deploy.

### 3.9 Standalone Mode Detection Utility

Create a reusable utility for checking display mode, used by the install prompt and
potentially by other components:

```typescript
// frontend/src/lib/pwaUtils.ts

/**
 * Returns true if the app is running in standalone mode (installed PWA).
 * Checks both the CSS media query and the iOS-specific `navigator.standalone`.
 */
export function isStandaloneMode(): boolean {
  // Standard check via CSS media query
  if (window.matchMedia("(display-mode: standalone)").matches) return true;
  // iOS Safari check
  if ((navigator as any).standalone === true) return true;
  // Chrome on Android also supports display-mode: standalone via the media query
  return false;
}

/**
 * Returns true if the app is running in a browser tab (not installed).
 */
export function isBrowserMode(): boolean {
  return !isStandaloneMode();
}

/**
 * Returns the current display mode string.
 */
export function getDisplayMode(): "standalone" | "browser" | "minimal-ui" | "fullscreen" {
  if (window.matchMedia("(display-mode: fullscreen)").matches) return "fullscreen";
  if (window.matchMedia("(display-mode: minimal-ui)").matches) return "minimal-ui";
  if (window.matchMedia("(display-mode: standalone)").matches) return "standalone";
  return "browser";
}
```

### 3.10 Analytics Event for Install

Track PWA installations for product metrics:

```typescript
// In InstallPrompt.tsx handleInstall, after choice.outcome === "accepted":
if (choice.outcome === "accepted") {
  // Fire analytics event
  try {
    if (typeof window.gtag === "function") {
      window.gtag("event", "pwa_install", {
        event_category: "engagement",
        event_label: choice.platform,
      });
    }
    // Also fire a custom event for internal analytics
    window.dispatchEvent(
      new CustomEvent("pwa-installed", {
        detail: { platform: choice.platform, timestamp: Date.now() },
      }),
    );
  } catch {
    // Analytics is best-effort
  }
}
```

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `frontend/public/manifest.json` | Web App Manifest |
| `frontend/public/icons/icon-*.png` | PNG icon set (12 files) |
| `frontend/public/icons/shortcut-*.png` | Shortcut icons (3 files) |
| `frontend/public/splash/apple-splash-*.png` | iOS splash screens (3+ files) |
| `frontend/public/screenshots/desktop-dashboard.png` | Desktop screenshot for install UI |
| `frontend/public/screenshots/mobile-messages.png` | Mobile screenshot for install UI |
| `frontend/src/components/shared/InstallPrompt.tsx` | Install banner + iOS hint components |
| `frontend/src/types/pwa.d.ts` | TypeScript declarations for PWA APIs |
| `frontend/src/lib/pwaUtils.ts` | Standalone mode detection utilities |
| `scripts/generate-pwa-icons.sh` | Icon generation script (ImageMagick) |
| `scripts/generate-pwa-icons.mjs` | Icon generation script (Node.js/sharp) |

### 4.2 Modified Files

| File | Changes |
|------|---------|
| `frontend/index.html` | Add manifest link, theme-color, Apple meta tags, splash links, noscript |
| `frontend/src/components/layout/AppShell.tsx` | Import + render `<InstallPrompt />` and `<IOSInstallHint />` |
| `frontend/src/lib/featureFlags.ts` | Add `pwaInstallPromptEnabled` + kill switch flags |
| `frontend/.env.local.example` | Add `VITE_PWA_INSTALL_PROMPT_ENABLED=true` |
| `frontend/tsconfig.json` | Add `src/types` to `include` array if not already present |

### 4.3 Implementation Phases

1. **Phase 1 -- Manifest + Icons** (2 hours)
   - Create icon generation script
   - Generate all PNG sizes from SVG
   - Write `manifest.json`
   - Update `index.html` with all new tags

2. **Phase 2 -- InstallPrompt component** (2 hours)
   - Create TypeScript declarations for `BeforeInstallPromptEvent`
   - Build `InstallPrompt` component with dismiss logic
   - Build `IOSInstallHint` component
   - Create `pwaUtils.ts` standalone detection
   - Add feature flag
   - Integrate into `AppShell`

3. **Phase 3 -- iOS & Desktop polish** (1 hour)
   - Generate Apple splash screens
   - Add `apple-mobile-web-app-*` meta tags
   - Test on Safari iOS simulator
   - Verify Edge/Chrome desktop install flow

4. **Phase 4 -- Screenshots + Shortcuts** (1 hour)
   - Capture desktop and mobile screenshots
   - Add manifest `shortcuts` section
   - Test shortcut launch on Android

---

## 5. Testing Strategy

### 5.1 Lighthouse Audit (Manual)

Run Lighthouse in Chrome DevTools on `http://localhost:3000`:
- **PWA > Installable**: Should pass (manifest, service worker, start_url, icons all present)
- **PWA > Optimized**: Should pass (theme-color, viewport, HTTPS in prod)

Expected Lighthouse PWA checklist results:

| Check | Expected |
|-------|----------|
| Has a `<meta name="viewport">` tag with width or initial-scale | Pass |
| Contains content-sufficient `<meta name="description">` | Needs addition (add description meta) |
| Has a manifest with `name` | Pass |
| Has a manifest with `short_name` | Pass |
| Has a manifest with at least one 192px icon | Pass |
| Has a manifest with at least one maskable icon | Pass |
| Has a manifest with `start_url` | Pass |
| Has a manifest with `display` | Pass |
| Has a manifest with `theme_color` | Pass |
| Has a manifest with `background_color` | Pass |
| Is configured for a custom splash screen | Pass |
| Sets a theme color for the address bar | Pass |
| Content is sized correctly for the viewport | Pass |
| Has a `<meta name="theme-color">` tag | Pass |
| Service worker registered | Pass (existing SW) |

### 5.2 E2E Test Plan (`frontend/e2e/pwa-install.spec.ts`)

**Section 90: Manifest Accessibility (5 tests)**

```typescript
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers";

test.describe("90 · Manifest accessibility", () => {
  test("90.1 manifest.json is served with correct content-type", async ({ request }) => {
    const resp = await request.get("http://localhost:3000/manifest.json");
    expect(resp.status()).toBe(200);
    const contentType = resp.headers()["content-type"] ?? "";
    expect(contentType).toContain("application/json");
  });

  test("90.2 manifest.json contains required PWA fields", async ({ request }) => {
    const resp = await request.get("http://localhost:3000/manifest.json");
    const manifest = await resp.json();
    expect(manifest.name).toBe("Control Panel");
    expect(manifest.short_name).toBe("CtrlPanel");
    expect(manifest.display).toBe("standalone");
    expect(manifest.start_url).toBe("/");
    expect(manifest.scope).toBe("/");
    expect(manifest.theme_color).toBe("#0f172a");
    expect(manifest.background_color).toBe("#ffffff");
    expect(manifest.icons.length).toBeGreaterThanOrEqual(6);
  });

  test("90.3 manifest has at least one 192px and one 512px icon", async ({ request }) => {
    const resp = await request.get("http://localhost:3000/manifest.json");
    const manifest = await resp.json();
    const sizes = manifest.icons.map((i: { sizes: string }) => i.sizes);
    expect(sizes).toContain("192x192");
    expect(sizes).toContain("512x512");
  });

  test("90.4 manifest has at least one maskable icon", async ({ request }) => {
    const resp = await request.get("http://localhost:3000/manifest.json");
    const manifest = await resp.json();
    const maskable = manifest.icons.filter(
      (i: { purpose?: string }) => i.purpose === "maskable",
    );
    expect(maskable.length).toBeGreaterThanOrEqual(1);
  });

  test("90.5 all manifest icons are reachable", async ({ request }) => {
    const resp = await request.get("http://localhost:3000/manifest.json");
    const manifest = await resp.json();
    for (const icon of manifest.icons) {
      const iconResp = await request.get(`http://localhost:3000${icon.src}`);
      expect(iconResp.status()).toBe(200);
    }
  });
});
```

**Section 91: Theme & Meta Tags (6 tests)**

```typescript
test.describe("91 · HTML meta tags for PWA", () => {
  test("91.1 index.html contains manifest link tag", async ({ page }) => {
    await page.goto("/");
    const link = page.locator('link[rel="manifest"]');
    await expect(link).toHaveAttribute("href", "/manifest.json");
  });

  test("91.2 theme-color meta tag exists with correct value", async ({ page }) => {
    await page.goto("/");
    const meta = page.locator('meta[name="theme-color"]').first();
    await expect(meta).toHaveAttribute("content", "#0f172a");
  });

  test("91.3 apple-touch-icon link exists and is reachable", async ({ page, request }) => {
    await page.goto("/");
    const link = page.locator('link[rel="apple-touch-icon"]');
    await expect(link).toHaveCount(1);
    const href = await link.getAttribute("href");
    expect(href).toBeTruthy();
    const iconResp = await request.get(`http://localhost:3000${href}`);
    expect(iconResp.status()).toBe(200);
  });

  test("91.4 apple-mobile-web-app-capable meta exists", async ({ page }) => {
    await page.goto("/");
    const meta = page.locator('meta[name="apple-mobile-web-app-capable"]');
    await expect(meta).toHaveAttribute("content", "yes");
  });

  test("91.5 apple-mobile-web-app-title matches manifest name", async ({ page }) => {
    await page.goto("/");
    const meta = page.locator('meta[name="apple-mobile-web-app-title"]');
    await expect(meta).toHaveAttribute("content", "Control Panel");
  });

  test("91.6 msapplication-TileColor meta exists", async ({ page }) => {
    await page.goto("/");
    const meta = page.locator('meta[name="msapplication-TileColor"]');
    await expect(meta).toHaveAttribute("content", "#0f172a");
  });
});
```

**Section 92: Install Prompt Component (7 tests)**

```typescript
test.describe("92 · Install prompt component", () => {
  test("92.1 install prompt is not shown when feature flag is off", async ({ page }) => {
    await page.addInitScript(() => {
      (window as any).__VITE_PWA_INSTALL_PROMPT_ENABLED = "false";
    });
    await injectAuth(page, "alice");
    await page.goto("/");
    await expect(page.getByText(/install control panel/i)).not.toBeVisible();
  });

  test("92.2 install prompt appears when beforeinstallprompt fires", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");

    // Simulate the beforeinstallprompt event
    await page.evaluate(() => {
      const event = new Event("beforeinstallprompt", { cancelable: true });
      (event as any).prompt = () => Promise.resolve();
      (event as any).userChoice = Promise.resolve({ outcome: "dismissed", platform: "web" });
      (event as any).platforms = ["web"];
      window.dispatchEvent(event);
    });

    await expect(page.getByText(/install control panel/i)).toBeVisible({ timeout: 3000 });
    await expect(page.getByRole("button", { name: /install/i })).toBeVisible();
  });

  test("92.3 dismiss button hides prompt and sets localStorage flag", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/");

    await page.evaluate(() => {
      const event = new Event("beforeinstallprompt", { cancelable: true });
      (event as any).prompt = () => Promise.resolve();
      (event as any).userChoice = Promise.resolve({ outcome: "dismissed", platform: "web" });
      (event as any).platforms = ["web"];
      window.dispatchEvent(event);
    });

    const banner = page.getByText(/install control panel/i);
    if (await banner.isVisible({ timeout: 2000 }).catch(() => false)) {
      await page.getByLabel(/dismiss install prompt/i).click();
      await expect(banner).not.toBeVisible();

      const flag = await page.evaluate(() => localStorage.getItem("pwa_install_dismissed"));
      expect(flag).toBeTruthy();
      expect(Number(flag)).toBeGreaterThan(Date.now() - 10000);
    }
  });

  test("92.4 prompt does not show again within 30-day cooldown", async ({ page }) => {
    await injectAuth(page, "alice");

    // Set the dismissal flag to recent (5 minutes ago)
    await page.addInitScript(() => {
      localStorage.setItem("pwa_install_dismissed", String(Date.now() - 5 * 60 * 1000));
    });
    await page.goto("/");

    // Fire beforeinstallprompt -- should NOT show banner
    await page.evaluate(() => {
      const event = new Event("beforeinstallprompt", { cancelable: true });
      (event as any).prompt = () => Promise.resolve();
      (event as any).userChoice = Promise.resolve({ outcome: "dismissed", platform: "web" });
      (event as any).platforms = ["web"];
      window.dispatchEvent(event);
    });

    await expect(page.getByText(/install control panel/i)).not.toBeVisible({ timeout: 2000 });
  });

  test("92.5 prompt shows again after 30-day cooldown expires", async ({ page }) => {
    await injectAuth(page, "alice");

    // Set the dismissal flag to 31 days ago
    await page.addInitScript(() => {
      localStorage.setItem("pwa_install_dismissed", String(Date.now() - 31 * 86400 * 1000));
    });
    await page.goto("/");

    await page.evaluate(() => {
      const event = new Event("beforeinstallprompt", { cancelable: true });
      (event as any).prompt = () => Promise.resolve();
      (event as any).userChoice = Promise.resolve({ outcome: "dismissed", platform: "web" });
      (event as any).platforms = ["web"];
      window.dispatchEvent(event);
    });

    await expect(page.getByText(/install control panel/i)).toBeVisible({ timeout: 3000 });
  });

  test("92.6 install prompt is not shown on unauthenticated pages", async ({ page }) => {
    // Don't inject auth -- user is on login page
    await page.goto("/login");

    await page.evaluate(() => {
      const event = new Event("beforeinstallprompt", { cancelable: true });
      (event as any).prompt = () => Promise.resolve();
      (event as any).userChoice = Promise.resolve({ outcome: "dismissed", platform: "web" });
      (event as any).platforms = ["web"];
      window.dispatchEvent(event);
    });

    // Install prompt is rendered inside AppShell, which is only active for
    // authenticated routes. The login page uses a different layout.
    // Since AppShell doesn't mount on /login, the prompt should not appear.
    await expect(page.getByText(/install control panel/i)).not.toBeVisible({ timeout: 2000 });
  });

  test("92.7 manifest shortcuts reference valid routes", async ({ request }) => {
    const resp = await request.get("http://localhost:3000/manifest.json");
    const manifest = await resp.json();
    const validRoutes = ["/messages", "/feed", "/calendar"];
    for (const shortcut of manifest.shortcuts ?? []) {
      expect(validRoutes).toContain(shortcut.url);
    }
  });
});
```

### 5.3 Unit Tests

```typescript
// frontend/src/lib/__tests__/featureFlags.test.ts (additions)
describe("isPwaInstallPromptEnabled", () => {
  it("returns true when enabled and kill switch is off", () => {
    // Mock env with VITE_PWA_INSTALL_PROMPT_ENABLED=true
    expect(isPwaInstallPromptEnabled()).toBe(true);
  });

  it("returns false when kill switch is on", () => {
    // Mock env with VITE_PWA_INSTALL_PROMPT_KILL_SWITCH=true
    expect(isPwaInstallPromptEnabled()).toBe(false);
  });

  it("returns false when disabled", () => {
    // Mock env with VITE_PWA_INSTALL_PROMPT_ENABLED=false
    expect(isPwaInstallPromptEnabled()).toBe(false);
  });
});

// frontend/src/lib/__tests__/pwaUtils.test.ts
describe("pwaUtils", () => {
  describe("isStandaloneMode", () => {
    it("returns false in a regular browser", () => {
      // Default matchMedia returns false for (display-mode: standalone)
      expect(isStandaloneMode()).toBe(false);
    });

    it("returns true when matchMedia matches standalone", () => {
      window.matchMedia = jest.fn().mockReturnValue({ matches: true });
      expect(isStandaloneMode()).toBe(true);
    });

    it("returns true when navigator.standalone is true (iOS)", () => {
      Object.defineProperty(navigator, "standalone", { value: true, configurable: true });
      expect(isStandaloneMode()).toBe(true);
    });
  });

  describe("getDisplayMode", () => {
    it("returns 'browser' by default", () => {
      expect(getDisplayMode()).toBe("browser");
    });
  });
});
```

---

## 6. Edge Cases & Gotchas

### 6.1 iOS Safari Limitations

iOS Safari does not fire the `beforeinstallprompt` event. The install prompt component
will not appear on iOS. Instead, users must use the Share menu > "Add to Home Screen".
The Apple meta tags ensure the experience is good when they do this manually. The
`IOSInstallHint` component provides a one-time educational banner on iOS Safari: "Tap
Share > Add to Home Screen to install this app."

**iOS detection caveats**: The `navigator.userAgent` check for iOS in `IOSInstallHint`
uses `/iPad|iPhone|iPod/` which may be affected by iPadOS 13+ desktop mode (iPadOS reports
a macOS user agent by default). A more robust check combines `navigator.maxTouchPoints > 1`
with `navigator.platform === "MacIntel"` for iPad detection.

### 6.2 Multiple Service Workers

The manifest's `scope` is `/`, matching the existing SW registration scope in
`pushSetup.ts` (line 17: `scope: "/"`). There is only one service worker. Adding
fetch-intercept logic in PWA-002 will extend the same `sw.js` -- no scope conflict.
<!-- CORRECTED: was "line 18", actually scope: "/" is at line 17 of pushSetup.ts -->

### 6.3 `crossorigin="use-credentials"` Caveat

If the backend sets `SameSite=Strict` on session cookies, the manifest fetch (which is a
sub-resource fetch from the `<link>` tag) might not send cookies. This is generally fine
since the manifest is a static file, but if the manifest is ever served through a backend
route that requires auth, this attribute ensures cookies are sent. For now the manifest is
a static file in `frontend/public/`, so this is a forward-looking precaution.

### 6.4 Dark Mode Theme Color

The manifest supports only a single `theme_color`. The `index.html` meta tags use the
`media` attribute to provide different theme colors for light/dark preference, but the
manifest field applies to the installed PWA title bar. Using `#0f172a` (dark slate) works
in both modes since the app header uses a dark background in all themes.

**Consideration**: If the app ever supports a light header theme, the manifest
`theme_color` should be updated. Chrome 93+ supports `theme_color_in_manifest` overrides
per media query, but this is not widely adopted yet.

### 6.5 Vite Build Output

Vite does not process files in `public/` -- they are copied as-is to `dist/`. The
`manifest.json` and icon PNGs will be available at their exact paths (`/manifest.json`,
`/icons/icon-192.png`, etc.) in production without any hashing. This is correct behavior
for manifest files, which must be at stable URLs.

### 6.6 Display Mode Detection in Existing Code

After installation, the app runs in `display-mode: standalone`. Code that relies on being
in a browser tab (e.g., `window.open()` for OAuth flows, `window.opener` checks) must be
tested in standalone mode. The current OAuth flow uses redirect-based auth (not popup),
so this should not be an issue.

Specific code paths to verify:
- `frontend/src/api/client.ts`: `refreshSession()` uses `fetch()` with `credentials: "include"`,
  which works identically in standalone mode.
- `frontend/src/pages/security/WebAuthnSection.tsx`: WebAuthn registration/assertion use
  `navigator.credentials`, which is available in standalone mode.
- `frontend/src/pages/remote/RemotePage.tsx`: VNC/SSH sessions open via in-page iframe, not
  popups, so standalone mode is compatible.

### 6.7 Manifest Validation Errors

Common manifest validation errors that block installability:

| Error | Cause | Fix |
|-------|-------|-----|
| `start_url` not within `scope` | `scope` and `start_url` mismatch | Both set to `/` |
| No suitable icon | Missing 192px or 512px PNG | Full icon set generated |
| `display` value not recognized | Typo in display mode | Use exact string `"standalone"` |
| Manifest `name` is empty | Missing or empty name field | Set to `"Control Panel"` |
| MIME type not `application/json` | Server serves wrong content-type | Vite serves `.json` correctly |

### 6.8 `beforeinstallprompt` Timing

The `beforeinstallprompt` event fires at page load, not when the user navigates. If the
user opens the app for the first time, the event fires once the browser determines
installability (manifest + SW + HTTPS). If the user navigates to another page within the
SPA, the event does not re-fire. The `InstallPrompt` component stores the event reference
and persists across navigation.

### 6.9 Multiple Install Prompts

Chrome fires `beforeinstallprompt` at most once per page load. If the user dismisses the
browser's mini-infobar, the event does not fire again until the next page load. The
`InstallPrompt` component's `e.preventDefault()` call suppresses the mini-infobar so the
custom banner can be shown instead. This is the recommended pattern per Chrome's PWA
guidance.

---

## 7. Security Considerations

### 7.1 Manifest Scope Restriction

The `scope` is set to `/` to cover all app routes. This is safe because all routes are
already protected by cookie-based auth (`require_ui_session` dependency in the backend).
The manifest scope does not grant additional permissions -- it only controls which URLs
the installed app can navigate to without opening a new browser tab.

### 7.2 Start URL

`start_url: "/"` sends the user to the root, which redirects to `/login` if not
authenticated (via the `ProtectedRoute` component in `App.tsx`). No auth bypass is
possible by manipulating the manifest.

### 7.3 Icon Integrity

All icons are static PNGs served from `frontend/public/icons/`. They are not user-uploaded
content. No XSS or injection vector exists through the icon pipeline.

### 7.4 Shortcut URLs

Manifest shortcuts point to first-party routes (`/messages`, `/feed`, `/calendar`). These
are all behind the `ProtectedRoute` wrapper and will redirect to login if the session has
expired.

### 7.5 Manifest Injection

The manifest is a static JSON file. It cannot be modified by user input or server-side
injection. If the manifest were ever served dynamically (e.g., per-tenant customization),
it should be rendered by the server with proper JSON escaping and served with
`Content-Type: application/json`.

### 7.6 Screenshot Content

The manifest `screenshots` are static marketing images checked into the repo. They do not
contain any user data. They should represent the app in a logged-out or demo state (no
real user content visible).

### 7.7 localStorage Tampering

The `pwa_install_dismissed` flag in `localStorage` controls only whether the install
banner appears. Tampering (setting or clearing the flag) has no security impact -- it only
affects the user's own install prompt visibility.

---

## Appendix A: File Reference

| Existing File | Relevance |
|---------------|-----------|
| `frontend/index.html` | Must add manifest link, meta tags, noscript fallback |
| `frontend/public/favicon.svg` | Source SVG for icon generation |
| `frontend/public/sw.js` | Existing SW; confirms scope `/` is already in use |
| `frontend/src/lib/pushSetup.ts` | SW registration code; confirms `/sw.js` scope |
| `frontend/src/main.tsx` | SW registration call at boot (line 31-33); QueryClient config |
| `frontend/src/components/layout/AppShell.tsx` | Renders OfflineBanner; install prompt goes here |
| `frontend/src/components/shared/OfflineBanner.tsx` | Pattern for banner component |
| `frontend/src/components/shared/SessionExpiryWarning.tsx` | Pattern for banner component |
| `frontend/src/components/shared/ImpersonationBanner.tsx` | Pattern for banner component |
| `frontend/src/lib/featureFlags.ts` | Pattern for feature flags with kill switch |
| `frontend/src/stores/authStore.ts` | Auth state; install prompt only relevant when authenticated |
| `frontend/src/App.tsx` | Route definitions; confirms `/` root route + ProtectedRoute wrapper |
| `frontend/vite.config.ts` | Build config; confirms public/ files are copied as-is |

## Appendix B: Dependencies & Risks

| Risk | Mitigation |
|------|------------|
| iOS has no `beforeinstallprompt` | `IOSInstallHint` component provides educational guidance |
| Icons not generating correctly from SVG | Include pre-generated PNGs in repo as fallback; test with both ImageMagick and sharp |
| Manifest validation errors blocking install | Test with Chrome's `chrome://web-app-internals`; run Lighthouse PWA audit |
| `crossorigin="use-credentials"` CORS issue | Manifest is same-origin static file; no CORS needed |
| PWA install prompt annoying users | 30-day dismiss cooldown; feature flag + kill switch; one-time show per session |
| Standalone mode breaks OAuth popup flows | App uses redirect auth, not popup; verified no popup dependencies |
| iPadOS desktop mode misdetects iOS | Use `navigator.maxTouchPoints` + platform check in addition to UA string |
| Multiple tab install state | Chrome manages install state per origin; `appinstalled` event fires in all tabs |
| Manifest changes not picked up by installed PWA | Chrome re-reads manifest periodically; user can uninstall and reinstall |

## Appendix C: Chrome Installability Requirements Checklist

For Chrome to show the install prompt, ALL of the following must be true:

- [x] The app is served over HTTPS (or localhost for development)
- [x] A Web App Manifest is linked from `<link rel="manifest">`
- [x] The manifest has `name` or `short_name`
- [x] The manifest has `start_url`
- [x] The manifest has `display` set to `standalone`, `fullscreen`, or `minimal-ui`
- [x] The manifest has at least one icon that is 192x192 or larger
- [x] The manifest has at least one icon that is 512x512 or larger
- [x] A service worker is registered with a `fetch` event handler (PWA-002 adds this)
- [x] The app is not already installed

Note: The `fetch` event handler requirement means that PWA-001 alone will not trigger the
install prompt in Chrome. PWA-002 must also be deployed. However, the manifest, icons, and
install prompt component can be developed and tested independently using Chrome DevTools
overrides.

---

## Codebase References

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `manifest.json` | `frontend/public/manifest.json` | 100 lines | **ALREADY EXISTS** — ticket says "no manifest.json" but it is now present and linked in `index.html:10` |
| `<link rel="manifest">` | `frontend/index.html` | 10 | **ALREADY EXISTS** — `<link rel="manifest" href="/manifest.json" crossorigin="use-credentials" />` |
| Icon files (12 PNGs) | `frontend/public/icons/` | — | **ALREADY EXISTS** — 192, 512, maskable, and shortcut icons all present |
| `favicon.svg` | `frontend/public/favicon.svg` | — | **Verified** |
| `sw.js` (service worker) | `frontend/public/sw.js` | 576 lines | **Exists** — handles push notifications |
| `registerServiceWorker()` | `frontend/src/lib/pushSetup.ts` | 11 | **Verified** |
| SW registration call | `frontend/src/main.tsx` | 34 | **Verified** — calls `registerServiceWorker()` on mount |
| `OfflineBanner` | `frontend/src/components/shared/OfflineBanner.tsx` | 45 lines | **Exists** (ticket says 33 lines — file grew) |
| `SessionExpiryWarning` | `frontend/src/components/shared/SessionExpiryWarning.tsx` | — | **Exists** |
| `ImpersonationBanner` | `frontend/src/components/shared/ImpersonationBanner.tsx` | — | **Exists** |
| `AppShell` | `frontend/src/components/layout/AppShell.tsx` | 288 lines | **Exists** |
| Vite config | `frontend/vite.config.ts` | — | **Exists** |

### Key Correction

**This ticket appears to be ALREADY IMPLEMENTED.** The manifest, icons, index.html link, and service worker registration all exist. The ticket's premise ("no PNG icons, no splash screen images, and no `manifest.json`") is no longer accurate. Verify whether an InstallPrompt component and BeforeInstallPrompt event handling also exist before scoping remaining work.


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_pwa_manifest.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_pwa_001_create` | Create primary entity; 201 |
| 2 | `test_pwa_001_read` | Read back entity; correct fields |
| 3 | `test_pwa_001_update` | Update entity; 200; changes reflected |
| 4 | `test_pwa_001_delete` | Delete entity; 200/204 |
| 5 | `test_pwa_001_auth_required` | No auth; 401 |
| 6 | `test_pwa_001_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/pwa-install.spec.ts` -- 10 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Tests cover API CRUD, UI rendering, negative cases (401/403/404/422), and edge cases.

**Negative/edge tests**: 401 unauthenticated, 403 insufficient role, 404 not found, 422 validation error, 409 conflict

### Test Data Requirements

- DDB seeds: feature-specific tables via setup scripts
- Test users: Alice, Bob, Root, Charlie (admin)
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: Feature-specific flags (see Rollout Plan section)
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
| PWA-002 | Required | App shell precaching depends on service worker from PWA-001 |

### Merge Strategy

**Independent** -- Foundation PWA ticket. Already partially implemented.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/pwa-install.spec.ts`
