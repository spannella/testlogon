import { useEffect } from "react";
import { useUiStore } from "@/stores/uiStore";
import type { AccentColor, FontSize, Density } from "@/stores/uiStore";

/**
 * Accent color presets — HSL values (without `hsl()` wrapper) matching
 * the shadcn/ui convention used in globals.css.
 */
const ACCENT_COLORS: Record<AccentColor, string> = {
  blue:   "221.2 83.2% 53.3%",
  purple: "262 83% 58%",
  green:  "142 71% 45%",
  orange: "25 95% 53%",
  pink:   "330 81% 60%",
  red:    "0 84% 60%",
  teal:   "173 80% 40%",
  custom: "",
};

/** Font size map — absolute px values applied to `<html>`. */
const FONT_SIZES: Record<FontSize, string> = {
  small:   "14px",
  default: "16px",
  large:   "18px",
  xlarge:  "20px",
};

/**
 * Convert a hex color (#RRGGBB) to HSL string "H S% L%".
 */
export function hexToHsl(hex: string): string {
  const raw = hex.replace("#", "");
  if (raw.length !== 6) return "";
  const r = parseInt(raw.slice(0, 2), 16) / 255;
  const g = parseInt(raw.slice(2, 4), 16) / 255;
  const b = parseInt(raw.slice(4, 6), 16) / 255;

  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;

  if (max === min) {
    return `0 0% ${Math.round(l * 100)}%`;
  }

  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);

  let h = 0;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
  else if (max === g) h = ((b - r) / d + 2) / 6;
  else h = ((r - g) / d + 4) / 6;

  return `${Math.round(h * 360)} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
}

/**
 * Determine the best foreground color for a given HSL background.
 * Returns a light or dark foreground HSL string.
 */
export function contrastForeground(hsl: string): string {
  const match = hsl.match(/(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%/);
  if (!match) return "210 40% 98%";
  const l = parseFloat(match[3]);
  // If lightness > 55%, use dark foreground; else light
  return l > 55 ? "222 84% 5%" : "210 40% 98%";
}

/**
 * Applies the correct `dark` class to <html> based on the theme
 * preference stored in uiStore. Listens for OS-level changes when
 * the preference is "system".
 *
 * Also applies accent color, font size, density, and high contrast
 * settings (PLATFORM-013).
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const theme = useUiStore((s) => s.theme);
  const accentColor = useUiStore((s) => s.accentColor);
  const customAccentHex = useUiStore((s) => s.customAccentHex);
  const fontSize = useUiStore((s) => s.fontSize);
  const density = useUiStore((s) => s.density);
  const highContrast = useUiStore((s) => s.highContrast);

  // ── Dark / Light theme toggle ──────────────────────────────────────
  useEffect(() => {
    const root = document.documentElement;

    function apply(isDark: boolean) {
      root.classList.toggle("dark", isDark);
    }

    if (theme === "dark") {
      apply(true);
      return;
    }

    if (theme === "light") {
      apply(false);
      return;
    }

    // "system" — match OS preference and listen for changes
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    apply(mq.matches);

    function onChange(e: MediaQueryListEvent) {
      apply(e.matches);
    }

    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  // ── Accent color ───────────────────────────────────────────────────
  useEffect(() => {
    const root = document.documentElement;
    let hsl: string;

    if (accentColor === "custom" && customAccentHex) {
      hsl = hexToHsl(customAccentHex);
    } else {
      hsl = ACCENT_COLORS[accentColor] || ACCENT_COLORS.blue;
    }

    if (hsl) {
      const fg = contrastForeground(hsl);
      // Mark that accent is active so density.css overrides kick in
      root.setAttribute("data-accent", accentColor);
      // --accent-primary / --accent-primary-fg are consumed by density.css
      // to override Tailwind v4's statically-compiled utility values
      root.style.setProperty("--accent-primary", `hsl(${hsl})`);
      root.style.setProperty("--accent-primary-fg", `hsl(${fg})`);
      // Also set the standard --color-* vars for non-utility usage
      root.style.setProperty("--color-primary", `hsl(${hsl})`);
      root.style.setProperty("--color-primary-foreground", `hsl(${fg})`);
      root.style.setProperty("--color-ring", `hsl(${hsl})`);
      root.style.setProperty("--color-sidebar-ring", `hsl(${hsl})`);
      // Bare --primary/--ring for CSS that references var(--primary)
      root.style.setProperty("--primary", hsl);
      root.style.setProperty("--primary-foreground", fg);
      root.style.setProperty("--ring", hsl);
    }
  }, [accentColor, customAccentHex]);

  // ── Font size ──────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.style.fontSize = FONT_SIZES[fontSize] || FONT_SIZES.default;
  }, [fontSize]);

  // ── Density ────────────────────────────────────────────────────────
  useEffect(() => {
    const root = document.documentElement;
    const densityClasses: Density[] = ["compact", "comfortable", "spacious"];
    for (const d of densityClasses) {
      root.classList.toggle(`density-${d}`, density === d);
    }
  }, [density]);

  // ── High contrast ──────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.classList.toggle("high-contrast", highContrast);
  }, [highContrast]);

  return <>{children}</>;
}
