import { useState } from "react";
import { Check, Palette } from "lucide-react";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/uiStore";
import type { AccentColor, FontSize, Density } from "@/stores/uiStore";
import { ColorSwatch } from "@/components/shared/ColorSwatch";
import { ThemePreviewPane } from "@/components/shared/ThemePreviewPane";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

// ── Accent color presets ────────────────────────────────────────────

const ACCENT_PRESETS: { value: AccentColor; label: string; color: string }[] = [
  { value: "blue",   label: "Blue",   color: "hsl(221.2 83.2% 53.3%)" },
  { value: "purple", label: "Purple", color: "hsl(262 83% 58%)" },
  { value: "green",  label: "Green",  color: "hsl(142 71% 45%)" },
  { value: "orange", label: "Orange", color: "hsl(25 95% 53%)" },
  { value: "pink",   label: "Pink",   color: "hsl(330 81% 60%)" },
  { value: "red",    label: "Red",    color: "hsl(0 84% 60%)" },
  { value: "teal",   label: "Teal",   color: "hsl(173 80% 40%)" },
];

// ── Font size options ───────────────────────────────────────────────

const FONT_SIZES: { value: FontSize; label: string }[] = [
  { value: "small",   label: "Small" },
  { value: "default", label: "Default" },
  { value: "large",   label: "Large" },
  { value: "xlarge",  label: "Extra Large" },
];

// ── Density options ─────────────────────────────────────────────────

const DENSITIES: { value: Density; label: string }[] = [
  { value: "compact",     label: "Compact" },
  { value: "comfortable", label: "Comfortable" },
  { value: "spacious",    label: "Spacious" },
];

// ── Toggle button helper ────────────────────────────────────────────

function OptionButton({
  label,
  selected,
  onClick,
}: {
  label: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      className={cn(
        "relative flex items-center gap-1.5 rounded-md border-2 px-3 py-1.5 text-sm font-medium transition-all",
        "hover:border-primary/50",
        selected
          ? "border-primary bg-primary/10 text-primary"
          : "border-border bg-card text-muted-foreground",
      )}
    >
      {selected && <Check className="h-3.5 w-3.5" />}
      {label}
    </button>
  );
}

// ── Main component ──────────────────────────────────────────────────

export function AppearanceSection() {
  const accentColor = useUiStore((s) => s.accentColor);
  const customAccentHex = useUiStore((s) => s.customAccentHex);
  const fontSize = useUiStore((s) => s.fontSize);
  const density = useUiStore((s) => s.density);
  const highContrast = useUiStore((s) => s.highContrast);
  const setAccentColor = useUiStore((s) => s.setAccentColor);
  const setCustomAccentHex = useUiStore((s) => s.setCustomAccentHex);
  const setFontSize = useUiStore((s) => s.setFontSize);
  const setDensity = useUiStore((s) => s.setDensity);
  const setHighContrast = useUiStore((s) => s.setHighContrast);

  const [customHexInput, setCustomHexInput] = useState(customAccentHex || "");
  const [hexError, setHexError] = useState("");

  function handleCustomHexChange(value: string) {
    setCustomHexInput(value);
    const raw = value.trim().replace(/^#/, "");
    if (/^[0-9A-Fa-f]{6}$/.test(raw)) {
      setHexError("");
      setCustomAccentHex(`#${raw.toUpperCase()}`);
    } else if (raw.length > 0) {
      setHexError("Enter a valid 6-digit hex color (e.g. FF5722)");
    } else {
      setHexError("");
    }
  }

  return (
    <div className="space-y-6" data-testid="appearance-section">
      {/* ── Accent Color ──────────────────────────────────────────── */}
      <div className="space-y-3">
        <div>
          <p className="text-sm font-medium">Accent Color</p>
          <p className="text-xs text-muted-foreground">
            Choose a primary color for buttons, links, and highlights.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {ACCENT_PRESETS.map((preset) => (
            <ColorSwatch
              key={preset.value}
              color={preset.color}
              label={preset.label}
              selected={accentColor === preset.value}
              onClick={() => setAccentColor(preset.value)}
            />
          ))}
          {/* Custom color swatch */}
          <button
            type="button"
            aria-label="Custom"
            aria-pressed={accentColor === "custom"}
            onClick={() => setAccentColor("custom")}
            className={cn(
              "relative flex h-8 w-8 items-center justify-center rounded-full border-2 transition-all",
              "hover:scale-110",
              accentColor === "custom"
                ? "border-foreground ring-2 ring-ring ring-offset-2 ring-offset-background"
                : "border-dashed border-muted-foreground",
            )}
            style={
              accentColor === "custom" && customAccentHex
                ? { backgroundColor: customAccentHex }
                : undefined
            }
            data-testid="color-swatch-custom"
          >
            {accentColor === "custom" ? (
              <Check className="h-4 w-4 text-white drop-shadow" />
            ) : (
              <Palette className="h-3.5 w-3.5 text-muted-foreground" />
            )}
          </button>
        </div>

        {/* Custom hex input — shown when custom is selected */}
        {accentColor === "custom" && (
          <div className="flex items-center gap-2">
            <Label htmlFor="custom-hex" className="text-xs whitespace-nowrap">
              Hex color:
            </Label>
            <Input
              id="custom-hex"
              placeholder="#FF5722"
              value={customHexInput}
              onChange={(e) => handleCustomHexChange(e.target.value)}
              className="h-8 w-32 font-mono text-xs"
              data-testid="custom-hex-input"
            />
            {hexError && (
              <span className="text-xs text-destructive" data-testid="hex-error">
                {hexError}
              </span>
            )}
          </div>
        )}
      </div>

      {/* ── Font Size ─────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div>
          <p className="text-sm font-medium">Font Size</p>
          <p className="text-xs text-muted-foreground">
            Adjust the base text size across the application.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {FONT_SIZES.map((size) => (
            <OptionButton
              key={size.value}
              label={size.label}
              selected={fontSize === size.value}
              onClick={() => setFontSize(size.value)}
            />
          ))}
        </div>
      </div>

      {/* ── Density ───────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div>
          <p className="text-sm font-medium">Density</p>
          <p className="text-xs text-muted-foreground">
            Control how much space appears between UI elements.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {DENSITIES.map((d) => (
            <OptionButton
              key={d.value}
              label={d.label}
              selected={density === d.value}
              onClick={() => setDensity(d.value)}
            />
          ))}
        </div>
      </div>

      {/* ── High Contrast ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium">High Contrast</p>
          <p className="text-xs text-muted-foreground">
            Increase border thickness and text opacity for better readability.
          </p>
        </div>
        <Switch
          checked={highContrast}
          onCheckedChange={setHighContrast}
          aria-label="Toggle high contrast"
          data-testid="high-contrast-toggle"
        />
      </div>

      {/* ── Preview ───────────────────────────────────────────────── */}
      <div className="space-y-2">
        <p className="text-sm font-medium">Preview</p>
        <ThemePreviewPane />
      </div>
    </div>
  );
}
