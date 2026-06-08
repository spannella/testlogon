# Dark Theme Fix & Hardening — Implementation Tickets

This ticket set turns the "dark theme does nothing" bug into an implementation-ready backlog: a spike to reproduce and root-cause it, the core fix (Tailwind v4 dark variant), then hardening around system-mode/OS following, persistence + server sync correctness, no-flash-on-load (FOUC), and a regression suite. The suspected root cause is that the app runs Tailwind v4 (`@tailwindcss/vite` `^4.1.18`, `frontend/vite.config.ts:3,48`) with **no `@custom-variant dark` declared anywhere** (verified absent across `frontend/src/`), so the `.dark` class toggled onto `<html>` by `frontend/src/components/ThemeProvider.tsx:92` does not drive any `dark:` utility — Tailwind v4 falls back to the `prefers-color-scheme` media query by default.

## Milestone 1 — Reproduce & Root-Cause

### THM-001: Spike — reproduce "dark theme does nothing" and pin the real failure
**Type:** Spike  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Reproduce the bug end-to-end: select Dark in `frontend/src/pages/settings/Appearance.tsx:63` (`setTheme(t.value)`) and via the Header dropdown `frontend/src/components/layout/Header.tsx:354` (`onClick={() => setTheme(opt.value)}`); confirm `.dark` IS added to `<html>` by the reactive effect at `frontend/src/components/ThemeProvider.tsx:88-115` (`root.classList.toggle("dark", isDark)` at line 92) yet the page does not visibly darken.
- Confirm the Tailwind-v4 dark-variant misconfig hypothesis: there is **no `@custom-variant dark`** in `frontend/src/globals.css` (verified absent; the file imports `tailwindcss` at line 1 and `./styles/themeCustomization.css` at line 2), no `tailwind.config.js`, and Tailwind v4 is wired purely through the Vite plugin (`frontend/vite.config.ts:3,48`). In v4 the `dark:` variant defaults to `@media (prefers-color-scheme: dark)` unless a class strategy is declared — so the 41 source files using `dark:` utilities (e.g. `dark:bg-gray-800`, `dark:text-green-400`) ignore the `.dark` class entirely.
- Characterize the second failure surface: the design-system palette is driven by CSS custom properties redefined under `.dark { --color-background: … }` (`frontend/src/globals.css:112-153`) while the light values live in `@theme inline { … }` (`frontend/src/globals.css:12-68`). Determine empirically whether `bg-background`/`text-foreground` re-read `var(--color-*)` at runtime when `.dark` is present, or whether `@theme inline` inlined a static light value that `.dark` cannot override. (The existing test already documents this asymmetry: `frontend/e2e/theme-switcher.spec.ts:16-24`.)
- Distinguish first-load vs after-reload behavior: capture whether `.dark` is on `<html>` on the very first paint vs only after React mounts. There is no pre-paint theme script in `frontend/index.html` (verified — only the SPA `<script type="module">` at the end of `<body>`), so `.dark` can only appear after `ThemeProvider` mounts.
- Rule in/out the hydration race: `loadServerPreferences()` fires post-mount from `frontend/src/components/layout/AppShell.tsx:55-62`, and `getThemeCustomization()` fires post-mount from `frontend/src/components/ThemeProvider.tsx:180-193`. Verify whether either async path overrides the persisted local `theme` (note the latter already passes `{ skipAccent: true, skipMode: true }` at line 185, so it should NOT touch the `dark` class — confirm this empirically).

**Acceptance Criteria**
- A written root-cause note identifies the primary failure (missing `@custom-variant dark`) and any secondary failures (`@theme inline` override semantics, FOUC, server-sync race), each with a reproducible step and the exact file:line evidence.
- The note states, per failure, whether `.dark` is present on `<html>` and whether the rendered colors actually change, separately for first load and after reload.
- A minimal failing assertion (or screenshot diff) is attached demonstrating "`.dark` applied but colors unchanged".

**Dependencies**
- None.

---

## Milestone 2 — Core Fix

### THM-002: Declare the Tailwind v4 class-based dark variant
**Type:** Bug  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `@custom-variant dark (&:where(.dark, .dark *));` to `frontend/src/globals.css` (immediately after the `@import "tailwindcss";` at line 1) so every `dark:` utility keys off the `.dark` class on `<html>` instead of the OS media query. This is the v4 replacement for v3's `darkMode: "class"` and is the single missing piece that makes the `.dark` class toggled at `frontend/src/components/ThemeProvider.tsx:92` actually take effect.
- Audit the 41 files using `dark:` utilities for any that relied on the old implicit media-query behavior; ensure none break when the variant is switched to class-based.

**Acceptance Criteria**
- With `<html class="dark">`, all `dark:` utilities (e.g. `dark:bg-gray-800`, `dark:text-green-400`) render their dark values; without the class they render the light values regardless of OS setting.
- Selecting Dark in Settings or the Header dropdown produces a visibly dark UI on the current page with no reload.
- `npx vite build` (in `frontend/`) succeeds with the new at-rule.

**Dependencies**
- THM-001.

---

### THM-003: Make the design-system palette honor `.dark` reliably
**Type:** Bug  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Resolve the `@theme inline` vs `.dark` override interaction so the core palette (`--color-background`, `--color-foreground`, `--color-card`, `--color-primary`, sidebar tokens, etc.) flips correctly under `.dark`. The light tokens are declared in `@theme inline { … }` (`frontend/src/globals.css:12-68`) and re-declared under `.dark { … }` (`frontend/src/globals.css:112-153`).
- If the spike (THM-001) finds `inline` inlines a static light value that `.dark` cannot override for utilities like `bg-background`/`text-foreground` (used in the base layer at `frontend/src/globals.css:165-168`), switch the palette tokens off `@theme inline` to a runtime `var(--color-*)` definition (or otherwise restructure) so the `.dark` block wins at runtime. Keep the shadcn HSL-channel convention intact.
- Ensure accent-color CSS vars written imperatively by `frontend/src/components/ThemeProvider.tsx:134-144` (`--color-primary`, `--primary`, `--ring`, …) continue to coexist with the dark palette and are not clobbered.

**Acceptance Criteria**
- In dark mode `getComputedStyle(document.documentElement).getPropertyValue("--color-background")` is a low-lightness HSL (≈ `hsl(222 84% 5%)`) and `--color-foreground` is high-lightness (≈ `hsl(210 40% 98%)`), matching `frontend/src/globals.css:113-114`.
- `body` computed `background-color`/`color` actually invert between light and dark (not just the CSS var, the painted pixels).
- Accent color selection still overrides `--primary`/`--ring` in both light and dark mode.

**Dependencies**
- THM-002.

---

## Milestone 3 — System Mode & OS Following

### THM-004: System theme follows the OS and reacts to live OS changes
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Validate and harden the `theme === "system"` branch in `frontend/src/components/ThemeProvider.tsx:105-114`: it reads `window.matchMedia("(prefers-color-scheme: dark)")`, applies the initial match, and subscribes to `change` to keep `.dark` in sync. Confirm the listener is correctly torn down on theme change / unmount (cleanup at lines 113-114) and that there is exactly one source of truth for `.dark`.
- Confirm the helper `isDarkMode(mode)` in `frontend/src/lib/themeCustomization.ts:113-118` agrees with the ThemeProvider logic for `"system"` (it also reads the same media query) so server-config application and the reactive effect never disagree.
- Ensure the `"system"` option round-trips through the store default (`frontend/src/stores/uiStore.ts:62`, `theme: "system"`) and is reflected as `aria-pressed` in `frontend/src/pages/settings/Appearance.tsx:58,71`.

**Acceptance Criteria**
- With `theme = "system"` and OS = dark, `<html>` has `.dark`; with OS = light it does not — on first load.
- Toggling the OS color scheme at runtime (Playwright `emulateMedia({ colorScheme })` / `browser.newContext({ colorScheme })`) flips `.dark` live without a reload.
- The System button shows `aria-pressed="true"` when selected, and switching OS scheme does not change the selected option (still "system").

**Dependencies**
- THM-002, THM-003.

---

## Milestone 4 — Persistence & Server Sync

### THM-005: Correct local persistence + server-sync ordering (no clobbering)
**Type:** Bug  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Guarantee the persisted local theme is the authority on load and is never silently reverted by an async server fetch. `setTheme` persists to `localStorage` (`ui-store`) and debounce-syncs to the server (`frontend/src/stores/uiStore.ts:73-76`, `debouncedSyncToServer` at lines 12-20, `partialize` includes `theme` at `frontend/src/stores/uiStore.ts:160-161`).
- Reconcile the two competing async loaders so they cannot fight: `loadServerPreferences()` (`frontend/src/stores/uiStore.ts:138-156`) writes `prefs.theme` into the store (line 142), while `getThemeCustomization()` in `frontend/src/components/ThemeProvider.tsx:182-185` deliberately passes `{ skipMode: true }` so it does NOT touch `.dark` (rationale documented at `frontend/src/components/ThemeProvider.tsx:167-179` and `frontend/src/lib/themeCustomization.ts:131-139`). Define one authoritative server source for `theme`/`mode` and make the other read-only for mode.
- Decide and document the precedence policy: a fresh login should adopt the server's saved theme; a returning session with a locally-changed theme should not be stomped by a stale server value mid-session (the in-flight debounce at `frontend/src/stores/uiStore.ts:12-20` should win over a slower GET). Address the cross-test/cross-tab staleness the existing suite works around by stubbing both GETs (`frontend/e2e/theme-switcher.spec.ts:79-112`).
- Keep accent/density/font/high-contrast sync behavior intact — only the theme/mode precedence is in scope here.

**Acceptance Criteria**
- After `setTheme("dark")`, `localStorage["ui-store"].state.theme === "dark"` and the value survives a full reload (no dependence on the network).
- `loadServerPreferences()` and `getThemeCustomization()` running after mount never override a theme the user just selected locally within the same session.
- A documented, deterministic precedence rule exists (login adopts server; mid-session local edits win) and is covered by a test.
- The PATCH debounce still fires once per change (500 ms) and failures are swallowed without logging the user out.

**Dependencies**
- THM-002, THM-004.

---

## Milestone 5 — No Flash On Load (FOUC)

### THM-006: Eliminate the dark-mode flash-on-load with a pre-paint script
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add a small synchronous, render-blocking inline script in `<head>` of `frontend/index.html` (currently has no theme script — the only script is the deferred module at the end of `<body>`) that reads the persisted theme from `localStorage["ui-store"]` (and falls back to `matchMedia("(prefers-color-scheme: dark)")` for `"system"`/missing) and sets `document.documentElement.classList.toggle("dark", …)` BEFORE first paint.
- Keep the script the single pre-paint authority and ensure it agrees with the runtime owner (`frontend/src/components/ThemeProvider.tsx:88-115`) so the class is not toggled twice with conflicting results. The script must parse the persisted zustand shape (`{ state: { theme }, version }`) used by `partialize` (`frontend/src/stores/uiStore.ts:160-170`).
- The script must be defensive (wrapped in try/catch, no crash if `localStorage` is unavailable) and tiny enough to inline without a network round-trip.

**Acceptance Criteria**
- On a hard reload with a persisted dark theme, the first painted frame is already dark — no light flash before React mounts.
- On first-ever load with `theme = "system"` and OS = dark, the first frame is dark.
- Disabling JS shows the `<noscript>` block (`frontend/index.html`) unchanged; the pre-paint script never throws on private-mode/blocked storage.

**Dependencies**
- THM-002, THM-003.

---

## Milestone 6 — Regression Coverage

### THM-007: Playwright e2e regression for dark mode, CSS vars, and persistence
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Extend / mirror the existing pattern in `frontend/e2e/theme-switcher.spec.ts` (section 96, helpers `hasDarkClass` at lines 179-181, `getCSSVar` at 146-151, `getStoredTheme` at 184-190, `stubServerTheme` at 79-112) to lock in every fix above. Reuse the session bootstrap + `injectAuth` helpers (lines 114-124).
- Assert all three core invariants together: (1) `.dark` class on `<html>`, (2) a real CSS-var value flips — `--color-background` lightness < 15% in dark vs body bg luminance > 230 in light (cf. lines 245-254, 294-299), and (3) persistence of `theme` across a full reload (cf. lines 320-338).
- Add a guard that would have caught the original bug specifically: with `.dark` present, assert a `dark:`-utility element actually renders its dark value (computed color), not just that the class exists — this fails fast if `@custom-variant dark` (THM-002) is ever removed.
- Cover system-mode OS following via `browser.newContext({ colorScheme })` (cf. lines 399-445) and the no-clobber server-sync precedence (THM-005) by NOT stubbing the server in at least one persistence case where appropriate, or by asserting the debounce-wins behavior.
- Add a FOUC assertion: navigate with a persisted dark theme and assert `<html>` has `.dark` before the SPA bundle's first React render (e.g. via an early `page.evaluate` immediately after `domcontentloaded`).

**Acceptance Criteria**
- New/updated spec passes under `cd frontend && npx playwright test e2e/theme-switcher.spec.ts` and exercises: class toggle, CSS-var inversion, `dark:`-utility paint, reload persistence, navigation persistence, header/settings sync, OS-follow (dark + light), and FOUC.
- Removing `@custom-variant dark` (THM-002) makes at least one test fail (the `dark:`-utility paint guard).
- Removing the pre-paint script (THM-006) makes the FOUC assertion fail.
- Tests are deterministic across runs (no reliance on stale shared server theme; server GETs stubbed where local-only behavior is asserted, per the existing `stubServerTheme` pattern).

**Dependencies**
- THM-002, THM-003, THM-004, THM-005, THM-006.

---
