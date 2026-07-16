/**
 * PLATFORM-013: Theme customization apply helpers.
 *
 * Pure, framework-agnostic functions that translate a persisted ThemeConfig
 * into DOM mutations (CSS custom properties + classes on <html>). Shared by
 * the ThemeProvider (applies the saved config on load) and the settings page
 * preview pane.
 */

import type {
  ThemeConfig,
  ThemeAccentColor,
  ThemeFontScale,
  ThemeDensity,
  ThemePreset,
} from "@/api/types";

/** Default config — mirrors the backend DEFAULT_THEME_CONFIG. */
export const DEFAULT_THEME_CONFIG: ThemeConfig = {
  mode: "system",
  accent_color: "blue",
  custom_accent_hex: null,
  font_scale: "default",
  density: "comfortable",
  preset: "default",
  high_contrast: false,
};

/** Preset accent colors — HSL (no hsl() wrapper), shadcn convention. */
export const ACCENT_HSL: Record<Exclude<ThemeAccentColor, "custom">, string> = {
  blue: "221.2 83.2% 53.3%",
  purple: "262 83% 58%",
  green: "142 71% 45%",
  orange: "25 95% 53%",
  pink: "330 81% 60%",
  red: "0 84% 60%",
  teal: "173 80% 40%",
};

/** Hex equivalents for preset accents (for swatch fills in the UI). */
export const ACCENT_HEX: Record<Exclude<ThemeAccentColor, "custom">, string> = {
  blue: "#3B82F6",
  purple: "#8B5CF6",
  green: "#22C55E",
  orange: "#F97316",
  pink: "#EC4899",
  red: "#EF4444",
  teal: "#14B8A6",
};

/** Base font size applied to <html> for each scale. */
export const FONT_SCALE_PX: Record<ThemeFontScale, string> = {
  small: "14px",
  default: "16px",
  large: "18px",
  xlarge: "20px",
};

/**
 * Preset themes layer an accent override on top of the user's chosen accent.
 * "default" applies no preset override (uses accent_color directly).
 */
export const PRESET_ACCENT_HSL: Record<Exclude<ThemePreset, "default">, string> = {
  midnight: "230 70% 60%",
  sunrise: "20 90% 55%",
  forest: "140 60% 40%",
  ocean: "195 80% 45%",
};

const HEX6 = /^[0-9A-Fa-f]{6}$/;

/** Convert "#RRGGBB" (or "RRGGBB") to "H S% L%". Returns "" if invalid. */
export function hexToHsl(hex: string): string {
  const raw = (hex || "").replace("#", "");
  if (!HEX6.test(raw)) return "";
  const r = parseInt(raw.slice(0, 2), 16) / 255;
  const g = parseInt(raw.slice(2, 4), 16) / 255;
  const b = parseInt(raw.slice(4, 6), 16) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  if (max === min) return `0 0% ${Math.round(l * 100)}%`;
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h = 0;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
  else if (max === g) h = ((b - r) / d + 2) / 6;
  else h = ((r - g) / d + 4) / 6;
  return `${Math.round(h * 360)} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
}

/** Pick a readable foreground HSL for a given background HSL. */
export function contrastForeground(hsl: string): string {
  const m = hsl.match(/(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%/);
  if (!m) return "210 40% 98%";
  return parseFloat(m[3] ?? "0") > 55 ? "222 84% 5%" : "210 40% 98%";
}

/** Resolve the effective accent HSL for a config (preset > custom > preset-color). */
export function resolveAccentHsl(config: ThemeConfig): string {
  if (config.preset && config.preset !== "default") {
    return PRESET_ACCENT_HSL[config.preset];
  }
  if (config.accent_color === "custom") {
    const hsl = hexToHsl(config.custom_accent_hex || "");
    if (hsl) return hsl;
    return ACCENT_HSL.blue;
  }
  return ACCENT_HSL[config.accent_color] || ACCENT_HSL.blue;
}

/** Whether the given mode resolves to dark, honoring the OS for "system". */
export function isDarkMode(mode: ThemeConfig["mode"]): boolean {
  if (mode === "dark") return true;
  if (mode === "light") return false;
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/**
 * Apply a full ThemeConfig to the document root (<html>). Idempotent.
 * Only touches PLATFORM-013-owned vars/classes plus the shared `dark` class.
 */
export function applyThemeConfig(
  config: ThemeConfig,
  opts: { skipAccent?: boolean; skipMode?: boolean } = {},
): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;

  // Mode → dark class.
  // When `skipMode` is set the caller owns the `dark` class reactively (e.g.
  // ThemeProvider's uiStore-driven theme effect, which is the single source of
  // truth for light/dark). Toggling it here from an async server fetch would
  // race against — and revert — the user's live preference (theme-switcher
  // dark-mode regression), so we leave it untouched.
  if (!opts.skipMode) {
    root.classList.toggle("dark", isDarkMode(config.mode));
  }

  // Accent → CSS variables.
  // When `skipAccent` is set the caller owns the accent vars reactively (e.g.
  // ThemeProvider's uiStore-driven effect) — writing them here would race
  // against the user's latest swatch selection and revert it to a stale
  // server value, so we leave them untouched.
  if (!opts.skipAccent) {
    const hsl = resolveAccentHsl(config);
    const fg = contrastForeground(hsl);
    root.style.setProperty("--primary", hsl);
    root.style.setProperty("--primary-foreground", fg);
    root.style.setProperty("--ring", hsl);
    root.style.setProperty("--color-primary", `hsl(${hsl})`);
    root.style.setProperty("--color-primary-foreground", `hsl(${fg})`);
    root.style.setProperty("--color-ring", `hsl(${hsl})`);
  }

  // Font scale → base font-size
  root.style.fontSize = FONT_SCALE_PX[config.font_scale] || FONT_SCALE_PX.default;

  // Density → class
  const densities: ThemeDensity[] = ["compact", "comfortable", "spacious"];
  for (const d of densities) {
    root.classList.toggle(`tc-density-${d}`, config.density === d);
  }

  // High contrast → class
  root.classList.toggle("tc-high-contrast", config.high_contrast);

  // Preset marker (for any preset-specific CSS hooks)
  root.setAttribute("data-theme-preset", config.preset);
}

/** Inline-style object for a scoped preview container reflecting a config. */
export function previewStyle(config: ThemeConfig): Record<string, string> {
  const hsl = resolveAccentHsl(config);
  const fg = contrastForeground(hsl);
  return {
    "--primary": hsl,
    "--primary-foreground": fg,
    "--color-primary": `hsl(${hsl})`,
    "--color-primary-foreground": `hsl(${fg})`,
    fontSize: FONT_SCALE_PX[config.font_scale],
  };
}

export function isValidHex(hex: string): boolean {
  return HEX6.test((hex || "").replace("#", ""));
}
