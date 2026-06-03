# PLATFORM-013: Advanced Theme Customization — Accent Colors, Density Modes, and Accessibility

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 8-12 days

---

## 1. Overview & Motivation

### The Gap

The platform currently supports three theme modes --- light, dark, and system --- managed by the `ThemeProvider` (`frontend/src/components/ThemeProvider.tsx`, line 77) <!-- CORRECTED: was "line 9"; ThemeProvider function is at line 77; line 9 is ACCENT_COLORS constant --> and the `uiStore` (`frontend/src/stores/uiStore.ts`, line 59) <!-- CORRECTED: was "line 38"; useUiStore create() is at line 59 -->. The theme system toggles a single `.dark` class on the `<html>` element (line 90 in `ThemeProvider.tsx`) <!-- CORRECTED: was "line 16"; classList.toggle("dark", isDark) is at line 90 -->, which activates Tailwind's dark mode CSS custom properties. This provides a binary light/dark experience with no room for:

1. **Custom accent colors**: The primary/accent color is hardcoded in the Tailwind theme configuration. Users cannot choose their brand color or personal preference. The current primary color is a blue-purple shade defined as a static HSL value in the Tailwind CSS.

2. **Font size preferences**: The base font size is fixed at the browser default (16px). Users with vision impairments or those who prefer larger text have no in-app option to adjust it. They must rely on browser zoom, which also scales the layout.

3. **Density modes**: The spacing between elements is fixed. Power users who want to see more content on screen ("compact mode") have no option, nor do users who prefer more breathing room ("spacious mode").

4. **High contrast mode**: The current dark mode uses a background of `hsl(222 84% 5%)` with foreground of `hsl(210 40% 98%)` (confirmed in `theme-switcher.spec.ts`, test 96.2 at line 193 and 96.3 at line 206). While the contrast ratio is excellent in dark mode, the light mode uses relatively subtle borders and muted colors that may not meet WCAG AAA contrast requirements for all users.

5. **Theme preview**: Users must commit to a theme change to see the effect. There is no preview mechanism that shows how the UI would look before applying.

6. **Server-side persistence**: The `uiStore` persists theme preferences to both localStorage and the server via `debouncedSyncToServer` (`uiStore.ts`, line 12) <!-- CORRECTED: was "line 11"; debouncedSyncToServer function is at line 12 --> which calls `patchPreferences` (`frontend/src/api/endpoints/preferences.ts`, line 40) <!-- CORRECTED: was "line 22"; patchPreferences is at line 40 -->. However, the `UiPreferences` interface (line 7) <!-- CORRECTED: was "line 3"; UiPreferences interface is at line 7; line 3 is AccentColor type --> only supports `theme` and `sidebar_collapsed` --- no accent color, font size, or density. <!-- NOTE: This gap description is outdated — the current UiPreferences interface (preferences.ts:7) already includes accent_color, custom_accent_hex, font_size, density, and high_contrast. The feature has been implemented. -->

### Why This Is Needed

1. **Accessibility compliance**: WCAG 2.1 AA requires a contrast ratio of at least 4.5:1 for normal text and 3:1 for large text. A high-contrast mode ensures compliance for users with low vision.
2. **Creator branding**: Creators who use the platform professionally want their experience to reflect their brand colors. A customizable accent color adds personality without requiring custom CSS.
3. **User comfort**: Font size and spacing preferences are deeply personal. Users who spend hours on the platform daily should be able to adjust the information density to their preference.
4. **Competitive parity**: Discord, Slack, Notion, and GitHub all offer accent color customization. This is an expected feature for modern SaaS platforms.

### Architecture After This Change

```
Settings Page -> Appearance Section
    |
    +--- Theme: Light / Dark / System [existing]
    |
    +--- Accent Color: Preset palette + custom hex picker
    |       |
    |       v
    |     CSS var --color-primary / --color-accent overridden on <html>
    |
    +--- Font Size: Small (14px) / Default (16px) / Large (18px) / Extra Large (20px)
    |       |
    |       v
    |     CSS var --base-font-size on <html>, all rem values scale automatically
    |
    +--- Density: Compact / Comfortable / Spacious
    |       |
    |       v
    |     CSS class: density-compact / density-comfortable / density-spacious on <html>
    |     Each class adjusts --spacing-unit, padding, gaps, and line-height
    |
    +--- High Contrast: Toggle
    |       |
    |       v
    |     CSS class: high-contrast on <html>
    |     Overrides border widths, text opacity, and minimum contrast values
    |
    +--- Preview: Live preview in a split-pane before committing
    |
    +--- Sync to server: PATCH /ui/settings/preferences
```

### State Flow Diagram

```
User changes accent color in Settings
    |
    v
AppearanceSection.tsx
    |--- setAccentColor("purple") calls uiStore.setAccentColor()
    |
    v
uiStore.ts (Zustand)
    |--- set({ accentColor: "purple" })
    |--- localStorage persist via partialize
    |--- debouncedSyncToServer({ accent_color: "purple" })
    |       |
    |       v
    |     PATCH /ui/settings/preferences { accent_color: "purple" }
    |       |
    |       v
    |     Backend: update DDB preferences record
    |
    v
ThemeProvider.tsx (useEffect triggered by accentColor change)
    |--- const accentHsl = ACCENT_COLORS["purple"]  // "262 83% 58%"
    |--- document.documentElement.style.setProperty("--color-primary", accentHsl)
    |--- document.documentElement.style.setProperty("--color-primary-foreground", contrastForeground(accentHsl))
    |
    v
All components using bg-primary, text-primary, border-primary
automatically update because they reference the CSS variable
```

---

## 2. Current State Analysis

### 2.1 ThemeProvider (`frontend/src/components/ThemeProvider.tsx`)

The `ThemeProvider` (line 77) <!-- CORRECTED: was "line 9"; ThemeProvider function is at line 77 --> is a React component that applies the `dark` class to `document.documentElement`:

```tsx
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const theme = useUiStore((s) => s.theme);

  useEffect(() => {
    const root = document.documentElement;
    function apply(isDark: boolean) {
      root.classList.toggle("dark", isDark);
    }
    if (theme === "dark") { apply(true); return; }
    if (theme === "light") { apply(false); return; }
    // "system" -- match OS preference
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    apply(mq.matches);
    // ...listener for OS changes
  }, [theme]);

  return <>{children}</>;
}
```

The provider only handles the dark/light toggle. It does not set any CSS custom properties for accent colors, font sizes, or density. Extending this component is the natural integration point for all theme customization.

The current `useEffect` dependency array only contains `[theme]` <!-- CORRECTED: was "line 39"; the dark/light useEffect dep array [theme] is at line 113. Additional separate useEffects for accent (line 144), fontSize (line 149), density (line 158), and highContrast (line 163) now exist -->. After this change, it must include all new preference values to trigger re-application when they change.

### 2.2 UI Store (`frontend/src/stores/uiStore.ts`)

The Zustand store (line 59) <!-- CORRECTED: was "line 38"; useUiStore = create<UiState>()( is at line 59; UiState interface at line 22 --> with `persist` middleware currently tracks:

```typescript
interface UiState {
  theme: Theme;                    // "system" | "light" | "dark"
  sidebarCollapsed: boolean;
  recentCommands: string[];
  prefsLoaded: boolean;
  setTheme: (theme: Theme) => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  trackRecentCommand: (label: string) => void;
  loadServerPreferences: () => Promise<void>;
}
```

The `setTheme` function (line 73) <!-- CORRECTED: was "line 46"; setTheme is at line 73 --> calls `debouncedSyncToServer({ theme })` which PATCHes the server. The same pattern should be used for new preference fields.

The localStorage key is `ui-store` (line 159) and `partialize` (line 160) <!-- CORRECTED: was "line 84/85"; name: "ui-store" is at line 159, partialize is at line 160 --> controls which fields are persisted:

```typescript
partialize: (state) => ({
  theme: state.theme,
  sidebarCollapsed: state.sidebarCollapsed,
  recentCommands: state.recentCommands,
}),
```

The `debouncedSyncToServer` function (line 12) <!-- CORRECTED: was "line 11"; function definition at line 12 --> uses a 500ms debounce timer:

```typescript
let syncTimer: ReturnType<typeof setTimeout> | null = null;

function debouncedSyncToServer(prefs: Partial<UiPreferences>) {
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    patchPreferences(prefs).catch(() => {
      // Fire-and-forget: swallow errors.
    });
  }, 500);
}
```

This means rapid changes (e.g., clicking through accent colors) coalesce into a single server PATCH. The local state is applied immediately via Zustand, providing instant feedback.

### 2.3 Server-Side Preferences (`frontend/src/api/endpoints/preferences.ts`)

The `UiPreferences` interface (line 7) <!-- CORRECTED: was "line 3"; UiPreferences is at line 7; line 3 is AccentColor type --> is minimal: <!-- NOTE: This description is outdated — the actual UiPreferences interface already includes all PLATFORM-013 fields (accent_color, custom_accent_hex, font_size, density, high_contrast). -->

```typescript
export interface UiPreferences {
  theme?: "system" | "light" | "dark";
  sidebar_collapsed?: boolean;
}
```

The `patchPreferences` function (line 40) <!-- CORRECTED: was "line 22"; patchPreferences is at line 40 --> sends a `PATCH /ui/settings/preferences` with partial updates. The backend merges these into the existing preferences record.

The `getPreferences` function (line 30) <!-- CORRECTED: was "line 12"; getPreferences is at line 30 --> fetches the full preferences object from the server. It is called by `loadServerPreferences` in the uiStore during app initialization.

### 2.4 Tailwind CSS Configuration

The app uses Tailwind CSS v4 with `@theme inline` mode. In dark mode, CSS custom properties like `--color-background`, `--color-foreground`, `--color-primary` are set via the `.dark` class block. In light mode, values are compiled statically at build time (confirmed by the comment in `theme-switcher.spec.ts`, line 18-24).

This means runtime accent color changes in dark mode can use CSS custom property overrides directly, but light mode requires a different approach --- either generating CSS at runtime or using a CSS-in-JS solution.

**Key CSS variables used by Tailwind/shadcn**:

```css
/* These are the variables that --color-primary maps to in shadcn/ui */
--primary: 221.2 83.2% 53.3%;        /* HSL values without hsl() wrapper */
--primary-foreground: 210 40% 98%;
--accent: 210 40% 96.1%;
--accent-foreground: 222.2 47.4% 11.2%;
--ring: 221.2 83.2% 53.3%;           /* focus ring color = primary */
```

To change the accent color, we override `--primary` and `--primary-foreground` on `document.documentElement.style`. This works in both light and dark modes because the CSS variables are referenced by Tailwind utility classes (`bg-primary`, `text-primary`, etc.) regardless of the mode.

### 2.5 Settings Page

The current Settings page at `/settings` includes a Theme section with three toggle buttons (Light, Dark, System) controlled by `aria-pressed` attributes. The E2E tests (`theme-switcher.spec.ts`) use `settingsBtn(page, "dark")` (line 152) to locate these buttons via `page.locator("button[aria-pressed]", { hasText: ... })`.

The settings page layout currently places the theme buttons inline. The expanded Appearance section will need a restructured layout with labeled rows for each setting.

### 2.6 Existing Theme E2E Tests (`frontend/e2e/theme-switcher.spec.ts`)

Section 96 contains 17 tests verifying:
- CSS class toggling (96.1, 96.6)
- CSS variable values in dark mode (96.2-96.4)
- Text visibility in both modes (96.5, 96.9)
- Persistence across reload and navigation (96.10-96.11)
- Header dropdown sync with Settings cards (96.12-96.14)
- System theme media query matching (96.15-96.16)
- Light/dark CSS variable difference (96.17)

New E2E tests for this ticket must not break any of these existing tests. The theme toggle buttons must remain in the same location and with the same `aria-pressed` behavior.

### 2.7 App Entry Point (`frontend/src/main.tsx`)

The render tree (line 73) <!-- CORRECTED: was "line 60"; ThemeProvider wrapping is at line 73 --> wraps the app in `ThemeProvider`:

```tsx
<ThemeProvider>
  <TooltipProvider delayDuration={300}>
    <RTLProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
      <Toaster richColors position="top-right" />
    </RTLProvider>
  </TooltipProvider>
</ThemeProvider>
```

The `ThemeProvider` is the outermost visual wrapper, making it the right place to inject additional CSS classes and custom properties.

### 2.8 Backend Preferences Storage

The backend stores preferences in the `app_single_table` with:

```
PK: USER#{user_sub}
SK: PREFS
```

The `preferences` attribute is a DDB Map that merges on each PATCH. The backend preferences handler (`app/routers/settings.py`) validates incoming fields and rejects unknown keys. The new preference fields (`accent_color`, `custom_accent_hex`, `font_size`, `density`, `high_contrast`) must be added to the validation schema.

---

## 3. Technical Design

### 3.1 Extended UiState

Add new fields to the Zustand store:

```typescript
export type AccentColor = "blue" | "purple" | "green" | "orange" | "pink" | "red" | "teal" | "custom";
export type FontSize = "small" | "default" | "large" | "xlarge";
export type Density = "compact" | "comfortable" | "spacious";

interface UiState {
  // ... existing fields ...
  accentColor: AccentColor;
  customAccentHex: string;         // only used when accentColor === "custom"
  fontSize: FontSize;
  density: Density;
  highContrast: boolean;

  setAccentColor: (color: AccentColor, customHex?: string) => void;
  setFontSize: (size: FontSize) => void;
  setDensity: (density: Density) => void;
  setHighContrast: (enabled: boolean) => void;
}
```

Each setter calls `debouncedSyncToServer(...)` with the updated preference.

Full implementation of the new store fields:

```typescript
export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      // ... existing fields ...
      accentColor: "blue" as AccentColor,
      customAccentHex: "#3B82F6",
      fontSize: "default" as FontSize,
      density: "comfortable" as Density,
      highContrast: false,

      setAccentColor: (color, customHex) => {
        const updates: Partial<UiState> = { accentColor: color };
        if (customHex) updates.customAccentHex = customHex;
        set(updates);
        const serverPrefs: Partial<UiPreferences> = { accent_color: color };
        if (customHex) serverPrefs.custom_accent_hex = customHex;
        debouncedSyncToServer(serverPrefs);
      },

      setFontSize: (size) => {
        set({ fontSize: size });
        debouncedSyncToServer({ font_size: size });
      },

      setDensity: (density) => {
        set({ density });
        debouncedSyncToServer({ density });
      },

      setHighContrast: (enabled) => {
        set({ highContrast: enabled });
        debouncedSyncToServer({ high_contrast: enabled });
      },

      loadServerPreferences: async () => {
        try {
          const prefs = await getPreferences();
          const updates: Partial<UiState> = { prefsLoaded: true };
          if (prefs.theme) updates.theme = prefs.theme;
          if (prefs.sidebar_collapsed !== undefined) updates.sidebarCollapsed = prefs.sidebar_collapsed;
          // New fields
          if (prefs.accent_color) updates.accentColor = prefs.accent_color as AccentColor;
          if (prefs.custom_accent_hex) updates.customAccentHex = prefs.custom_accent_hex;
          if (prefs.font_size) updates.fontSize = prefs.font_size as FontSize;
          if (prefs.density) updates.density = prefs.density as Density;
          if (prefs.high_contrast !== undefined) updates.highContrast = prefs.high_contrast;
          set(updates);
        } catch {
          set({ prefsLoaded: true });
        }
      },
    }),
    {
      name: "ui-store",
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
        recentCommands: state.recentCommands,
        accentColor: state.accentColor,
        customAccentHex: state.customAccentHex,
        fontSize: state.fontSize,
        density: state.density,
        highContrast: state.highContrast,
      }),
    },
  ),
);
```

### 3.2 Extended UiPreferences (Server)

```typescript
export interface UiPreferences {
  theme?: "system" | "light" | "dark";
  sidebar_collapsed?: boolean;
  accent_color?: AccentColor;
  custom_accent_hex?: string;
  font_size?: FontSize;
  density?: Density;
  high_contrast?: boolean;
}
```

Backend Pydantic model update:

```python
from pydantic import BaseModel, Field, field_validator
import re

class UiPreferencesIn(BaseModel):
    theme: Optional[Literal["system", "light", "dark"]] = None
    sidebar_collapsed: Optional[bool] = None
    accent_color: Optional[Literal["blue", "purple", "green", "orange", "pink", "red", "teal", "custom"]] = None
    custom_accent_hex: Optional[str] = Field(None, max_length=7)
    font_size: Optional[Literal["small", "default", "large", "xlarge"]] = None
    density: Optional[Literal["compact", "comfortable", "spacious"]] = None
    high_contrast: Optional[bool] = None

    @field_validator("custom_accent_hex")
    @classmethod
    def validate_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Strip leading # if present
        hex_str = v.lstrip("#")
        if not re.match(r"^[0-9A-Fa-f]{6}$", hex_str):
            raise ValueError("Invalid hex color: must be 6 hex characters")
        return f"#{hex_str.upper()}"
```

### 3.3 Enhanced ThemeProvider

The `ThemeProvider` component gains responsibility for applying all visual preferences to the DOM:

```tsx
// Color constants
const ACCENT_COLORS: Record<AccentColor, string> = {
  blue:   "221.2 83.2% 53.3%",
  purple: "262 83% 58%",
  green:  "142 71% 45%",
  orange: "25 95% 53%",
  pink:   "330 81% 60%",
  red:    "0 84% 60%",
  teal:   "173 80% 40%",
  custom: "",  // resolved from customAccentHex
};

const FONT_SIZE_MAP: Record<FontSize, string> = {
  small:   "14px",
  default: "16px",
  large:   "18px",
  xlarge:  "20px",
};

/**
 * Convert a hex color string to HSL values (space-separated, no hsl() wrapper).
 * Used for custom accent colors.
 */
function hexToHsl(hex: string): string {
  const hexClean = hex.replace("#", "");
  const r = parseInt(hexClean.substring(0, 2), 16) / 255;
  const g = parseInt(hexClean.substring(2, 4), 16) / 255;
  const b = parseInt(hexClean.substring(4, 6), 16) / 255;

  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  let h = 0;
  let s = 0;
  const l = (max + min) / 2;

  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break;
      case g: h = ((b - r) / d + 2) / 6; break;
      case b: h = ((r - g) / d + 4) / 6; break;
    }
  }

  return `${Math.round(h * 360)} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
}

/**
 * Determine whether white or dark text provides better contrast
 * against the given HSL background color.
 */
function contrastForeground(hsl: string): string {
  const parts = hsl.match(/[\d.]+/g);
  if (!parts || parts.length < 3) return "0 0% 100%";
  const l = parseFloat(parts[2]);
  // If lightness > 55%, use dark text; otherwise white text
  return l > 55 ? "222.2 47.4% 11.2%" : "210 40% 98%";
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const theme = useUiStore((s) => s.theme);
  const accentColor = useUiStore((s) => s.accentColor);
  const customAccentHex = useUiStore((s) => s.customAccentHex);
  const fontSize = useUiStore((s) => s.fontSize);
  const density = useUiStore((s) => s.density);
  const highContrast = useUiStore((s) => s.highContrast);

  useEffect(() => {
    const root = document.documentElement;

    // 1. Dark/light toggle (existing logic)
    function apply(isDark: boolean) {
      root.classList.toggle("dark", isDark);
    }
    if (theme === "dark") { apply(true); }
    else if (theme === "light") { apply(false); }
    else {
      const mq = window.matchMedia("(prefers-color-scheme: dark)");
      apply(mq.matches);
      const onChange = (e: MediaQueryListEvent) => apply(e.matches);
      mq.addEventListener("change", onChange);
      // Cleanup below
    }

    // 2. Accent color: set --primary and derived vars
    let accentHsl: string;
    if (accentColor === "custom" && customAccentHex) {
      accentHsl = hexToHsl(customAccentHex);
    } else {
      accentHsl = ACCENT_COLORS[accentColor] || ACCENT_COLORS.blue;
    }
    root.style.setProperty("--primary", accentHsl);
    root.style.setProperty("--primary-foreground", contrastForeground(accentHsl));
    root.style.setProperty("--ring", accentHsl);

    // 3. Font size: set base font size on <html>
    root.style.fontSize = FONT_SIZE_MAP[fontSize] ?? "16px";

    // 4. Density: toggle class
    root.classList.remove("density-compact", "density-comfortable", "density-spacious");
    root.classList.add(`density-${density}`);

    // 5. High contrast: toggle class
    root.classList.toggle("high-contrast", highContrast);

    // Cleanup for system theme listener
    return () => {
      if (theme === "system") {
        const mq = window.matchMedia("(prefers-color-scheme: dark)");
        mq.removeEventListener("change", () => {});
      }
    };
  }, [theme, accentColor, customAccentHex, fontSize, density, highContrast]);

  return <>{children}</>;
}
```

### 3.4 Accent Color Palette

Define 8 preset accent colors with their HSL values:

| Name    | HSL                    | Hex     |
|---------|------------------------|---------|
| Blue    | hsl(221 83% 53%)       | #3B82F6 |
| Purple  | hsl(262 83% 58%)       | #8B5CF6 |
| Green   | hsl(142 71% 45%)       | #22C55E |
| Orange  | hsl(25 95% 53%)        | #F97316 |
| Pink    | hsl(330 81% 60%)       | #EC4899 |
| Red     | hsl(0 84% 60%)         | #EF4444 |
| Teal    | hsl(173 80% 40%)       | #14B8A6 |
| Custom  | User-specified         | #XXXXXX |

The custom color picker validates that the hex value has sufficient contrast against both light and dark backgrounds before accepting it.

### 3.5 Density CSS Classes

Define three density levels via CSS custom properties:

```css
:root {
  --spacing-unit: 1rem;      /* default: comfortable */
  --line-height: 1.5;
  --sidebar-item-py: 0.5rem;
  --table-row-py: 0.75rem;
  --card-padding: 1.5rem;
  --input-height: 2.5rem;
}

.density-compact {
  --spacing-unit: 0.75rem;
  --line-height: 1.35;
  --sidebar-item-py: 0.25rem;
  --table-row-py: 0.375rem;
  --card-padding: 1rem;
  --input-height: 2rem;
}

.density-comfortable {
  --spacing-unit: 1rem;
  --line-height: 1.5;
  --sidebar-item-py: 0.5rem;
  --table-row-py: 0.75rem;
  --card-padding: 1.5rem;
  --input-height: 2.5rem;
}

.density-spacious {
  --spacing-unit: 1.25rem;
  --line-height: 1.75;
  --sidebar-item-py: 0.75rem;
  --table-row-py: 1rem;
  --card-padding: 2rem;
  --input-height: 3rem;
}
```

Components that use `gap-*`, `p-*`, `py-*` classes should be updated to use `gap-[var(--spacing-unit)]` where density sensitivity is desired. For most components, Tailwind's default spacing is fine; the density classes primarily affect:

- Sidebar link padding (`py-[var(--sidebar-item-py)]`)
- Message bubble spacing
- Alert list item padding
- Table row heights (`py-[var(--table-row-py)]`)
- Form input heights (`h-[var(--input-height)]`)
- Card internal padding (`p-[var(--card-padding)]`)

**Components to update**:

| Component | File | Change |
|-----------|------|--------|
| Sidebar nav links | `Sidebar.tsx` | `py-2` -> `py-[var(--sidebar-item-py)]` |
| Message bubbles | `MessageBubble.tsx` | `p-3` -> `p-[var(--spacing-unit)]` |
| Alert rows | `AlertCenter.tsx` | `py-3` -> `py-[var(--table-row-py)]` |
| Table rows | `DataTable.tsx` (if exists) | `py-3` -> `py-[var(--table-row-py)]` |
| Card content | All `CardContent` usages | Inherit from global `--card-padding` |
| Input heights | Form inputs | `h-10` -> `h-[var(--input-height)]` |
| Dialog body | `DialogContent` | Spacing adjustments |

### 3.6 High Contrast Mode

```css
.high-contrast {
  --border-width: 2px;
  --border: 0 0% 30%;  /* darker borders in light mode */
}

.high-contrast.dark {
  --border: 0 0% 70%;  /* lighter borders in dark mode */
}

.high-contrast .border {
  border-width: 2px !important;
}

.high-contrast .text-muted-foreground {
  opacity: 1 !important;
  color: var(--foreground) !important;
}

.high-contrast .bg-muted {
  background-color: transparent !important;
  border: 1px solid var(--border) !important;
}

/* Ensure focus rings are highly visible */
.high-contrast *:focus-visible {
  outline: 3px solid var(--primary) !important;
  outline-offset: 2px !important;
}

/* Increase badge contrast */
.high-contrast .bg-secondary {
  border: 1px solid var(--border) !important;
}
```

**WCAG contrast requirements**:

| Element | Normal Mode Ratio | High Contrast Ratio | WCAG AA (4.5:1) | WCAG AAA (7:1) |
|---------|-------------------|---------------------|-----------------|----------------|
| Body text (dark) | 15.4:1 | 15.4:1 | Pass | Pass |
| Body text (light) | 12.6:1 | 14.8:1 | Pass | Pass |
| Muted text (dark) | 4.6:1 | 15.4:1 | Pass (AA) | Pass (HC) |
| Muted text (light) | 4.2:1 | 14.8:1 | Fail (AA) | Pass (HC) |
| Border (dark) | 2.1:1 | 5.2:1 | N/A | Improved |

The high contrast mode specifically targets `text-muted-foreground` (the weakest contrast element) by setting it to full foreground color, ensuring AAA compliance.

### 3.7 Theme Preview

Add a `ThemePreview` component that renders a miniature version of the UI (sidebar, header, message bubble, card) inside an `<iframe>` or a scoped `<div>` with isolated CSS. The preview reflects the currently-edited (but not yet committed) settings.

Implementation approach:
1. Create a `ThemePreviewPane` component that shows mock UI elements.
2. Apply the candidate theme settings to the preview pane using inline CSS variables (scoped to the preview container).
3. The Settings page shows a split layout: customization controls on the left, preview on the right.
4. An "Apply" button commits the changes; a "Reset" button reverts to the current settings.

```tsx
interface ThemePreviewPaneProps {
  accentColor: AccentColor;
  customAccentHex: string;
  fontSize: FontSize;
  density: Density;
  highContrast: boolean;
  isDark: boolean;
}

export function ThemePreviewPane({
  accentColor, customAccentHex, fontSize, density, highContrast, isDark,
}: ThemePreviewPaneProps) {
  const accentHsl = accentColor === "custom"
    ? hexToHsl(customAccentHex)
    : ACCENT_COLORS[accentColor];

  const previewStyles: React.CSSProperties = {
    "--primary": accentHsl,
    "--primary-foreground": contrastForeground(accentHsl),
    fontSize: FONT_SIZE_MAP[fontSize],
  } as React.CSSProperties;

  return (
    <div
      className={cn(
        "rounded-lg border overflow-hidden",
        isDark && "dark",
        `density-${density}`,
        highContrast && "high-contrast",
      )}
      style={previewStyles}
    >
      {/* Mini sidebar */}
      <div className="flex h-64">
        <div className="w-16 bg-card border-r p-2 space-y-2">
          <div className="w-8 h-8 rounded bg-primary mx-auto" />
          <div className="w-8 h-2 rounded bg-muted mx-auto" />
          <div className="w-8 h-2 rounded bg-muted mx-auto" />
          <div className="w-8 h-2 rounded bg-muted mx-auto" />
        </div>
        {/* Mini content area */}
        <div className="flex-1 bg-background p-3 space-y-2">
          {/* Header bar */}
          <div className="h-6 bg-card rounded flex items-center px-2 gap-2">
            <div className="w-16 h-3 bg-muted rounded" />
            <div className="flex-1" />
            <div className="w-4 h-4 rounded-full bg-primary" />
          </div>
          {/* Card */}
          <div className="bg-card rounded border p-2 space-y-1">
            <div className="w-24 h-3 bg-foreground/20 rounded" />
            <div className="w-full h-2 bg-muted rounded" />
            <div className="w-3/4 h-2 bg-muted rounded" />
          </div>
          {/* Button */}
          <button className="bg-primary text-primary-foreground px-3 py-1 rounded text-xs">
            Button
          </button>
          {/* Message bubble */}
          <div className="flex gap-2 items-end">
            <div className="w-5 h-5 rounded-full bg-muted" />
            <div className="bg-muted rounded-lg px-2 py-1 text-xs max-w-[60%]">
              <span className="text-foreground">Preview message</span>
            </div>
          </div>
          <div className="flex gap-2 items-end justify-end">
            <div className="bg-primary text-primary-foreground rounded-lg px-2 py-1 text-xs max-w-[60%]">
              Your reply
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
```

### 3.8 Contrast Validation Helper

```typescript
/**
 * Calculate the relative luminance of an HSL color.
 * Used for WCAG contrast ratio calculations.
 */
function relativeLuminance(hsl: string): number {
  // Parse HSL string "H S% L%"
  const parts = hsl.match(/[\d.]+/g);
  if (!parts || parts.length < 3) return 0;
  const h = parseFloat(parts[0]) / 360;
  const s = parseFloat(parts[1]) / 100;
  const l = parseFloat(parts[2]) / 100;

  // HSL to sRGB
  const hue2rgb = (p: number, q: number, t: number) => {
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1/6) return p + (q - p) * 6 * t;
    if (t < 1/2) return q;
    if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
    return p;
  };

  let r: number, g: number, b: number;
  if (s === 0) {
    r = g = b = l;
  } else {
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
    const p = 2 * l - q;
    r = hue2rgb(p, q, h + 1/3);
    g = hue2rgb(p, q, h);
    b = hue2rgb(p, q, h - 1/3);
  }

  // sRGB to linear
  const toLinear = (c: number) => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
}

/**
 * Calculate the WCAG contrast ratio between two HSL colors.
 */
function contrastRatio(hsl1: string, hsl2: string): number {
  const l1 = relativeLuminance(hsl1);
  const l2 = relativeLuminance(hsl2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}
```

---

## 4. API Endpoints

### 4.1 Enhanced Preferences

```
PATCH /ui/settings/preferences
  Body: {
    theme?: "system" | "light" | "dark",
    sidebar_collapsed?: boolean,
    accent_color?: "blue" | "purple" | "green" | "orange" | "pink" | "red" | "teal" | "custom",
    custom_accent_hex?: string,     // validated: 6-char hex, sufficient contrast
    font_size?: "small" | "default" | "large" | "xlarge",
    density?: "compact" | "comfortable" | "spacious",
    high_contrast?: boolean
  }
  Auth: require_ui_session (CSRF required for PATCH)
  Response 200: { ok: true }
  Response 422: { detail: "Invalid hex color: must be 6 hex characters" }
```

### 4.2 Get Preferences (Enhanced)

```
GET /ui/settings/preferences
  Auth: require_ui_session
  Response 200: {
    preferences: {
      theme: "system",
      sidebar_collapsed: false,
      accent_color: "blue",
      custom_accent_hex: null,
      font_size: "default",
      density: "comfortable",
      high_contrast: false
    }
  }
```

### 4.3 Validate Custom Color

```
POST /ui/settings/validate-color
  Body: { hex: str }
  Auth: require_ui_session (CSRF required)
  Response 200: {
    valid: bool,
    contrast_light: float,    // contrast ratio against light bg (hsl(0 0% 100%))
    contrast_dark: float,     // contrast ratio against dark bg (hsl(222 84% 5%))
    wcag_aa: bool,            // true if ratio >= 4.5:1 against both backgrounds
    wcag_aaa: bool,           // true if ratio >= 7:1 against both backgrounds
    suggestion: str | null    // adjusted hex if original fails contrast
  }
  Response 400: { detail: "Invalid hex format" }
```

**Backend implementation**:

```python
import colorsys
import math

@router.post("/validate-color")
def validate_custom_color(
    body: Dict[str, str],
    session=Depends(require_ui_session),
):
    hex_str = body.get("hex", "").lstrip("#")
    if not re.match(r"^[0-9A-Fa-f]{6}$", hex_str):
        raise HTTPException(status_code=400, detail="Invalid hex format")

    # Convert hex to RGB
    r, g, b = int(hex_str[0:2], 16), int(hex_str[2:4], 16), int(hex_str[4:6], 16)

    # Calculate relative luminance
    def to_linear(c: int) -> float:
        cs = c / 255
        return cs / 12.92 if cs <= 0.03928 else ((cs + 0.055) / 1.055) ** 2.4

    lum = 0.2126 * to_linear(r) + 0.7152 * to_linear(g) + 0.0722 * to_linear(b)

    # Light background luminance (~1.0 for white)
    light_bg_lum = 1.0
    # Dark background luminance (~0.01 for hsl(222 84% 5%))
    dark_bg_lum = 0.005

    contrast_light = (max(light_bg_lum, lum) + 0.05) / (min(light_bg_lum, lum) + 0.05)
    contrast_dark = (max(dark_bg_lum, lum) + 0.05) / (min(dark_bg_lum, lum) + 0.05)

    wcag_aa = contrast_light >= 4.5 and contrast_dark >= 3.0
    wcag_aaa = contrast_light >= 7.0 and contrast_dark >= 4.5

    # Generate suggestion if contrast fails
    suggestion = None
    if not wcag_aa:
        # Adjust lightness to improve contrast
        h, s, l = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
        # Try darker for light bg
        adjusted_l = max(0.0, min(0.4, l))
        ar, ag, ab = colorsys.hls_to_rgb(h, adjusted_l, s)
        suggestion = f"#{int(ar*255):02X}{int(ag*255):02X}{int(ab*255):02X}"

    return {
        "valid": True,
        "contrast_light": round(contrast_light, 2),
        "contrast_dark": round(contrast_dark, 2),
        "wcag_aa": wcag_aa,
        "wcag_aaa": wcag_aaa,
        "suggestion": suggestion,
    }
```

---

## 5. Frontend Components

### 5.1 Enhanced Settings Appearance Section

**File**: `frontend/src/pages/settings/AppearanceSection.tsx` (new)

- **Theme row**: Existing Light/Dark/System toggle buttons (moved from Settings page).
- **Accent Color row**: 8 color swatches + "Custom" button that opens a hex input with color preview.
- **Font Size row**: 4 radio buttons (Small/Default/Large/Extra Large) with sample text preview.
- **Density row**: 3 radio buttons (Compact/Comfortable/Spacious) with mini-preview.
- **High Contrast row**: Toggle switch with description of what it does.
- **Preview pane**: Right-side panel showing `ThemePreviewPane`.
- **Apply/Reset buttons**: Commit or revert changes.

```tsx
export function AppearanceSection() {
  const currentAccent = useUiStore((s) => s.accentColor);
  const currentCustomHex = useUiStore((s) => s.customAccentHex);
  const currentFontSize = useUiStore((s) => s.fontSize);
  const currentDensity = useUiStore((s) => s.density);
  const currentHighContrast = useUiStore((s) => s.highContrast);
  const theme = useUiStore((s) => s.theme);

  // Preview state (not yet committed)
  const [previewAccent, setPreviewAccent] = useState(currentAccent);
  const [previewCustomHex, setPreviewCustomHex] = useState(currentCustomHex);
  const [previewFontSize, setPreviewFontSize] = useState(currentFontSize);
  const [previewDensity, setPreviewDensity] = useState(currentDensity);
  const [previewHighContrast, setPreviewHighContrast] = useState(currentHighContrast);

  const hasChanges = previewAccent !== currentAccent || previewFontSize !== currentFontSize
    || previewDensity !== currentDensity || previewHighContrast !== currentHighContrast
    || (previewAccent === "custom" && previewCustomHex !== currentCustomHex);

  const applyChanges = () => {
    useUiStore.getState().setAccentColor(previewAccent, previewAccent === "custom" ? previewCustomHex : undefined);
    useUiStore.getState().setFontSize(previewFontSize);
    useUiStore.getState().setDensity(previewDensity);
    useUiStore.getState().setHighContrast(previewHighContrast);
  };

  const resetChanges = () => {
    setPreviewAccent(currentAccent);
    setPreviewCustomHex(currentCustomHex);
    setPreviewFontSize(currentFontSize);
    setPreviewDensity(currentDensity);
    setPreviewHighContrast(currentHighContrast);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
      {/* Left: Controls */}
      <div className="space-y-6">
        {/* Accent Color */}
        <div>
          <Label className="text-sm font-medium mb-2 block">Accent Color</Label>
          <div className="flex flex-wrap gap-2">
            {(Object.keys(ACCENT_COLORS) as AccentColor[]).filter(c => c !== "custom").map((color) => (
              <ColorSwatch
                key={color}
                color={color}
                hex={hslToHex(ACCENT_COLORS[color])}
                selected={previewAccent === color}
                onClick={() => setPreviewAccent(color)}
              />
            ))}
            <CustomColorSwatch
              selected={previewAccent === "custom"}
              hex={previewCustomHex}
              onSelect={(hex) => { setPreviewAccent("custom"); setPreviewCustomHex(hex); }}
            />
          </div>
        </div>

        {/* Font Size */}
        <div>
          <Label className="text-sm font-medium mb-2 block">Font Size</Label>
          <div className="flex gap-2">
            {(["small", "default", "large", "xlarge"] as FontSize[]).map((size) => (
              <Button
                key={size}
                variant={previewFontSize === size ? "default" : "outline"}
                size="sm"
                onClick={() => setPreviewFontSize(size)}
              >
                {size === "xlarge" ? "Extra Large" : size.charAt(0).toUpperCase() + size.slice(1)}
              </Button>
            ))}
          </div>
          <p className="text-xs text-muted-foreground mt-1" style={{ fontSize: FONT_SIZE_MAP[previewFontSize] }}>
            Sample text at {FONT_SIZE_MAP[previewFontSize]}
          </p>
        </div>

        {/* Density */}
        <div>
          <Label className="text-sm font-medium mb-2 block">Density</Label>
          <div className="flex gap-2">
            {(["compact", "comfortable", "spacious"] as Density[]).map((d) => (
              <Button
                key={d}
                variant={previewDensity === d ? "default" : "outline"}
                size="sm"
                onClick={() => setPreviewDensity(d)}
              >
                {d.charAt(0).toUpperCase() + d.slice(1)}
              </Button>
            ))}
          </div>
        </div>

        {/* High Contrast */}
        <div className="flex items-center justify-between">
          <div>
            <Label className="text-sm font-medium">High Contrast</Label>
            <p className="text-xs text-muted-foreground">Increases border widths and text contrast for better readability</p>
          </div>
          <Switch checked={previewHighContrast} onCheckedChange={setPreviewHighContrast} />
        </div>

        {/* Apply/Reset */}
        {hasChanges && (
          <div className="flex gap-2">
            <Button onClick={applyChanges}>Apply</Button>
            <Button variant="outline" onClick={resetChanges}>Reset</Button>
          </div>
        )}
      </div>

      {/* Right: Preview */}
      <div>
        <Label className="text-sm font-medium mb-2 block">Preview</Label>
        <ThemePreviewPane
          accentColor={previewAccent}
          customAccentHex={previewCustomHex}
          fontSize={previewFontSize}
          density={previewDensity}
          highContrast={previewHighContrast}
          isDark={theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches)}
        />
      </div>
    </div>
  );
}
```

### 5.2 ColorSwatch Component

**File**: `frontend/src/components/shared/ColorSwatch.tsx` (new)

- Circular swatch with check mark when selected.
- Hover tooltip showing color name and hex value.
- Custom swatch opens a popover with hex input + color preview square.

```tsx
interface ColorSwatchProps {
  color: AccentColor;
  hex: string;
  selected: boolean;
  onClick: () => void;
}

export function ColorSwatch({ color, hex, selected, onClick }: ColorSwatchProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          className={cn(
            "w-8 h-8 rounded-full border-2 transition-all",
            selected ? "border-foreground scale-110 ring-2 ring-primary ring-offset-2" : "border-transparent hover:scale-105",
          )}
          style={{ backgroundColor: hex }}
          onClick={onClick}
          aria-label={`Select ${color} accent color`}
          aria-pressed={selected}
        >
          {selected && <Check className="h-4 w-4 text-white mx-auto" />}
        </button>
      </TooltipTrigger>
      <TooltipContent>
        <p>{color.charAt(0).toUpperCase() + color.slice(1)} ({hex})</p>
      </TooltipContent>
    </Tooltip>
  );
}
```

### 5.3 ThemePreviewPane Component

**File**: `frontend/src/components/shared/ThemePreviewPane.tsx` (new)

- Miniature mock of the app UI (sidebar, header, card, message bubble, button).
- Applies candidate CSS variables via inline styles on a container div.
- Updates in real-time as the user changes settings.

### 5.4 Updated ThemeProvider

**File**: `frontend/src/components/ThemeProvider.tsx`

- Expanded to apply accent color, font size, density, and high contrast (see Design 3.3).

### 5.5 Updated uiStore

**File**: `frontend/src/stores/uiStore.ts`

- Add `accentColor`, `customAccentHex`, `fontSize`, `density`, `highContrast` state fields.
- Add corresponding setters that call `debouncedSyncToServer`.
- Update `partialize` to include new fields.
- Update `loadServerPreferences` to read new fields from server response.

### 5.6 CSS File for Density and High Contrast

**File**: `frontend/src/styles/density.css` (new)

```css
/* Density modes */
:root {
  --spacing-unit: 1rem;
  --sidebar-item-py: 0.5rem;
  --table-row-py: 0.75rem;
  --card-padding: 1.5rem;
  --input-height: 2.5rem;
}

.density-compact {
  --spacing-unit: 0.75rem;
  --sidebar-item-py: 0.25rem;
  --table-row-py: 0.375rem;
  --card-padding: 1rem;
  --input-height: 2rem;
}

.density-spacious {
  --spacing-unit: 1.25rem;
  --sidebar-item-py: 0.75rem;
  --table-row-py: 1rem;
  --card-padding: 2rem;
  --input-height: 3rem;
}

/* High contrast mode */
.high-contrast .text-muted-foreground {
  opacity: 1 !important;
  color: hsl(var(--foreground)) !important;
}

.high-contrast .border {
  border-width: 2px !important;
}

.high-contrast *:focus-visible {
  outline: 3px solid hsl(var(--primary)) !important;
  outline-offset: 2px !important;
}

/* Print: reset to defaults */
@media print {
  html {
    font-size: 12pt !important;
  }
  .density-compact, .density-spacious {
    --spacing-unit: 1rem;
    --sidebar-item-py: 0.5rem;
    --table-row-py: 0.75rem;
  }
}
```

---

## 6. E2E Test Plan

### Section 109: Accent Color

```
109.1  Selecting "Purple" accent sets --primary CSS variable to purple HSL
109.2  Selecting "Custom" with hex #FF5722 sets the correct CSS variable
109.3  Accent color persists after page reload (read from localStorage)
109.4  Accent color visible on primary buttons (background color matches selected accent)
109.5  Invalid hex (e.g., "ZZZZZZ") is rejected with validation error
109.6  Custom color validation endpoint returns contrast ratios
109.7  Accent color syncs to server (PATCH /ui/settings/preferences called)
109.8  Loading server preferences applies accent color on new device
109.9  "Blue" is the default accent color for new users
109.10 Changing accent updates the focus ring color (--ring variable)
```

### Section 110: Font Size

```
110.1  Selecting "Large" sets html fontSize to 18px
110.2  Font size change is reflected in body text computed font size
110.3  Font size persists after page reload
110.4  "Small" (14px) makes sidebar nav text smaller than default
110.5  "Extra Large" (20px) increases all rem-based sizes proportionally
110.6  Font size does not affect fixed-pixel layouts (sidebar width stays 240px)
110.7  Font size syncs to server via preferences PATCH
```

### Section 111: Density Mode

```
111.1  Selecting "Compact" adds density-compact class to <html>
111.2  Compact mode reduces sidebar padding (computed padding < default)
111.3  Spacious mode increases sidebar padding (computed padding > default)
111.4  Density persists after page reload
111.5  Density does not affect minimum touch target sizes (buttons still >= 44px)
111.6  Density syncs to server via preferences PATCH
111.7  "Comfortable" is the default density for new users
```

### Section 112: High Contrast

```
112.1  Enabling high contrast adds high-contrast class to <html>
112.2  Muted text becomes fully opaque in high contrast mode
112.3  Borders become thicker (2px) in high contrast mode
112.4  High contrast setting persists after page reload
112.5  Focus rings are 3px solid primary in high contrast mode
112.6  High contrast syncs to server via preferences PATCH
112.7  High contrast works correctly in both light and dark modes
```

### Section 113: Theme Preview

```
113.1  Preview pane updates in real-time when accent color changes
113.2  Preview pane reflects font size changes without affecting main UI
113.3  "Apply" button commits changes; main UI updates
113.4  "Reset" button reverts preview to current settings
113.5  Preview pane shows dark mode when theme is dark
113.6  Preview pane shows density changes (compact = tighter spacing)
113.7  Preview pane shows high contrast mode (thicker borders)
```

---

## 7. Edge Cases

1. **Custom accent color with poor contrast**: A user might enter a yellow hex (#FFFF00) that has excellent contrast on dark backgrounds but terrible contrast on light backgrounds. The validation endpoint (`/ui/settings/validate-color`) must check contrast against both light and dark background colors. The frontend should warn but not block --- allow the user to proceed with an "insufficient contrast" warning tooltip. Show a suggested alternative color that meets WCAG AA.

2. **Font size interaction with viewport**: At `xlarge` (20px base), some layouts may overflow on small screens. The responsive breakpoints are defined in pixels, not ems, so they are unaffected by font size. However, fixed-width elements (e.g., sidebar at `w-60` = 240px) may feel cramped with larger text. The sidebar should collapse to icon-only mode automatically when font size is `xlarge` and viewport width is < 1024px.

3. **Density and touch targets**: In compact mode, buttons and clickable elements must still meet WCAG's minimum touch target size of 44x44 CSS pixels. The density CSS must ensure that interactive elements have a minimum height even in compact mode. Add a CSS guard: `.density-compact button, .density-compact a { min-height: 44px; }` (or use `min-h-[44px]` via Tailwind).

4. **Server preference sync race**: If the user rapidly changes multiple settings, `debouncedSyncToServer` (500ms debounce at line 12) <!-- CORRECTED: was "line 11"; function at line 12 --> coalesces them into a single PATCH. But if the user navigates away before the debounce fires, the preference is lost on the server (though preserved in localStorage). Consider flushing pending sync on `beforeunload`:

   ```typescript
   window.addEventListener("beforeunload", () => {
     if (syncTimer) {
       clearTimeout(syncTimer);
       patchPreferences(pendingPrefs).catch(() => {});
     }
   });
   ```

5. **Theme migration**: Existing users have `ui-store` in localStorage with only `theme`, `sidebarCollapsed`, and `recentCommands`. The Zustand store's default values (`accentColor: "blue"`, `fontSize: "default"`, `density: "comfortable"`, `highContrast: false`) must be applied when loading state from localStorage that lacks these fields. Zustand's `persist` middleware handles this automatically --- missing fields use the default values from the store definition.

6. **CSS specificity conflicts**: The `high-contrast` class uses `!important` overrides. This may conflict with component-level Tailwind utilities. Testing must verify that high contrast does not break any component's visual integrity. Specifically, test the following components with high contrast enabled: Dialog, Popover, Toast, Badge, Alert, Select dropdown.

7. **Print styles**: Font size and density changes should NOT affect print output. Add a `@media print` block that resets font size to 12pt and uses comfortable density. This is included in the density CSS file.

8. **Color blindness considerations**: The accent color presets should be distinguishable for common forms of color blindness (protanopia, deuteranopia, tritanopia). The chosen preset colors (blue, purple, green, orange, pink, red, teal) cover a wide gamut, but red and green may be confusable for deuteranopia. Consider adding a "Color blind-friendly" palette option that avoids red-green confusion.

9. **Performance of CSS variable updates**: Changing CSS custom properties on `document.documentElement` triggers a full repaint of all elements using those variables. For most modern browsers this takes < 1ms. However, if the ThemeProvider's `useEffect` fires on every render (e.g., due to missing memoization), this could cause jank. Ensure the dependency array is correct and avoid unnecessary re-renders.

10. **RTL layout interaction**: The app uses an `RTLProvider`. Density changes must not break RTL layout. The `--spacing-unit` and `--sidebar-item-py` variables are direction-agnostic (they control padding and gap, not margin-left/right). Verify with RTL mode enabled.

---

## 8. Security Considerations

1. **Custom hex injection**: The `custom_accent_hex` field must be strictly validated on the backend as a 6-character hexadecimal string (`/^[0-9A-Fa-f]{6}$/`). Any non-hex characters must be rejected to prevent CSS injection. The Pydantic `field_validator` in `UiPreferencesIn` enforces this. The frontend should also validate before sending to avoid unnecessary 422 responses.

2. **Preference data size**: The preferences record should be capped at 4KB total to prevent abuse. Each field has bounded values (enum for most, 6-char hex for custom color). The backend should enforce a maximum payload size on the PATCH endpoint. With the current field set, the maximum serialized size is approximately 200 bytes.

3. **Cross-device consistency**: Preferences are synced to the server and loaded on login via `loadServerPreferences` (`uiStore.ts`, line 138) <!-- CORRECTED: was "line 68"; loadServerPreferences is at line 138 -->. If a user logs in on a new device, they get their customized theme. Ensure the `loadServerPreferences` function handles all new fields gracefully when the server returns a partial response (some fields undefined). The implementation uses conditional checks (`if (prefs.accent_color) updates.accentColor = ...`) which handles undefined fields correctly.

4. **CSRF on PATCH**: The `PATCH /ui/settings/preferences` endpoint requires CSRF validation for cookie-authenticated requests (enforced by `require_ui_session` in `app/auth/deps.py`). The existing `api.patch` method in `frontend/src/api/client.ts` already sends the CSRF header.

5. **No admin override**: Theme preferences are purely personal. Admins cannot set or reset another user's theme preferences, even via impersonation. The preferences endpoint should use `ctx["user_sub"]` directly, not the impersonated user's sub. If the admin is impersonating a user, `ctx["user_sub"]` already resolves to the impersonated user's sub --- this means impersonating admins CAN change the target user's theme. Consider using the admin's real sub instead if this is undesirable.

6. **CSS custom property names**: The CSS variable names (`--primary`, `--primary-foreground`, etc.) are set via `style.setProperty()` which is safe against injection. The variable name is hardcoded (not user-controlled), and the value is validated to be an HSL string. There is no path for XSS through CSS custom properties in this implementation.

---

## Codebase References

> **NOTE**: This feature has already been implemented. The "Current State Analysis" sections describe the pre-implementation state; the actual codebase now contains all proposed changes.

| File | Line(s) | What |
|------|---------|------|
| `frontend/src/components/ThemeProvider.tsx` | 9 | `ACCENT_COLORS` constant (8 preset HSL values) |
| `frontend/src/components/ThemeProvider.tsx` | 21 | `FONT_SIZES` constant |
| `frontend/src/components/ThemeProvider.tsx` | 31 | `hexToHsl()` utility function |
| `frontend/src/components/ThemeProvider.tsx` | 61 | `contrastForeground()` utility function |
| `frontend/src/components/ThemeProvider.tsx` | 77 | `ThemeProvider` component (dark/light + accent + fontSize + density + highContrast) |
| `frontend/src/components/ThemeProvider.tsx` | 90 | `classList.toggle("dark", isDark)` |
| `frontend/src/components/ThemeProvider.tsx` | 113 | Dark/light `useEffect` dependency `[theme]` |
| `frontend/src/components/ThemeProvider.tsx` | 116-144 | Accent color `useEffect` (sets CSS vars) |
| `frontend/src/components/ThemeProvider.tsx` | 147-149 | Font size `useEffect` |
| `frontend/src/components/ThemeProvider.tsx` | 152-158 | Density `useEffect` |
| `frontend/src/components/ThemeProvider.tsx` | 161-163 | High contrast `useEffect` |
| `frontend/src/stores/uiStore.ts` | 12 | `debouncedSyncToServer()` (500ms debounce) |
| `frontend/src/stores/uiStore.ts` | 22 | `UiState` interface (includes accentColor, fontSize, density, highContrast) |
| `frontend/src/stores/uiStore.ts` | 59 | `useUiStore = create<UiState>()` |
| `frontend/src/stores/uiStore.ts` | 73 | `setTheme` setter |
| `frontend/src/stores/uiStore.ts` | 108 | `setAccentColor` setter |
| `frontend/src/stores/uiStore.ts` | 118 | `setCustomAccentHex` setter |
| `frontend/src/stores/uiStore.ts` | 123 | `setFontSize` setter |
| `frontend/src/stores/uiStore.ts` | 128 | `setDensity` setter |
| `frontend/src/stores/uiStore.ts` | 133 | `setHighContrast` setter |
| `frontend/src/stores/uiStore.ts` | 138 | `loadServerPreferences` (loads all new fields from server) |
| `frontend/src/stores/uiStore.ts` | 159 | `name: "ui-store"` localStorage key |
| `frontend/src/stores/uiStore.ts` | 160 | `partialize` (includes all new fields) |
| `frontend/src/api/endpoints/preferences.ts` | 3 | `AccentColor` type export |
| `frontend/src/api/endpoints/preferences.ts` | 4 | `FontSize` type export |
| `frontend/src/api/endpoints/preferences.ts` | 5 | `Density` type export |
| `frontend/src/api/endpoints/preferences.ts` | 7 | `UiPreferences` interface (includes accent_color, font_size, density, etc.) |
| `frontend/src/api/endpoints/preferences.ts` | 17 | `ValidateColorResponse` interface |
| `frontend/src/api/endpoints/preferences.ts` | 30 | `getPreferences()` |
| `frontend/src/api/endpoints/preferences.ts` | 40 | `patchPreferences()` |
| `frontend/src/api/endpoints/preferences.ts` | 47 | `validateColor()` |
| `frontend/src/main.tsx` | 73 | `<ThemeProvider>` wrapping in render tree |
| `frontend/src/pages/settings/AppearanceSection.tsx` | — | Appearance section component (accent, fontSize, density, highContrast, preview) |
| `frontend/src/components/shared/ColorSwatch.tsx` | — | Color swatch picker component |
| `frontend/src/components/shared/ThemePreviewPane.tsx` | — | Live theme preview pane component |
| `frontend/src/styles/density.css` | — | CSS density modes + high-contrast overrides |
| `app/models.py` | 1381 | `PreferencesPatchReq` Pydantic model (all 7 preference fields) |
| `app/routers/profile.py` | 592 | `GET /settings/preferences` handler |
| `app/routers/profile.py` | 605 | `PATCH /settings/preferences` handler |
| `app/routers/profile.py` | 651 | `POST /settings/validate-color` handler |
| `app/services/user_preferences.py` | 22 | `update_user_preferences()` |
| `app/services/user_preferences.py` | 56 | `get_user_preferences()` |
| `frontend/e2e/theme-switcher.spec.ts` | 152 | `settingsBtn()` helper |
| `frontend/e2e/theme-switcher.spec.ts` | 193 | Test 96.2 (dark mode CSS variable) |
| `frontend/e2e/theme-switcher.spec.ts` | 206 | Test 96.3 (dark mode foreground CSS variable) |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_theme_customization.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_platform_013_create` | Create primary entity; 201 |
| 2 | `test_platform_013_read` | Read back entity; correct fields |
| 3 | `test_platform_013_update` | Update entity; 200; changes reflected |
| 4 | `test_platform_013_delete` | Delete entity; 200/204 |
| 5 | `test_platform_013_auth_required` | No auth; 401 |
| 6 | `test_platform_013_validation` | Invalid input; 422 |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | End-to-end happy path through all layers | router + service + DDB |
| 2 | Error handling propagates correctly | router + service layer |
| 3 | Feature flag disables functionality | settings + router |

### E2E Tests (Playwright)

**File**: `frontend/e2e/theme-customization.spec.ts` -- 14 tests

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
| (none) | -- | No downstream dependents identified |

### Merge Strategy

**Independent** -- Frontend-only changes to ThemeProvider + preferences.

### Merge Checklist

- [ ] Backend service and router implemented
- [ ] DDB tables created in local-ddb-init.py (if new)
- [ ] Frontend types added to api/types.ts
- [ ] Frontend page/component created
- [ ] Route added to App.tsx
- [ ] E2E pass: `npx playwright test e2e/theme-customization.spec.ts`
