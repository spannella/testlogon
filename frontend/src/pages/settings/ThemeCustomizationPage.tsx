import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Loader2, RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type {
  ThemeConfig,
  ThemeAccentColor,
  ThemeFontScale,
  ThemeDensity,
  ThemeMode,
  ThemePreset,
} from "@/api/types";
import {
  getThemeCustomization,
  patchThemeCustomization,
  resetThemeCustomization,
} from "@/api/endpoints/themeCustomization";
import {
  DEFAULT_THEME_CONFIG,
  ACCENT_HEX,
  applyThemeConfig,
  isValidHex,
} from "@/lib/themeCustomization";
import { ThemeCustomizationPreview } from "./ThemeCustomizationPreview";

const MODES: { value: ThemeMode; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

const ACCENTS: Exclude<ThemeAccentColor, "custom">[] = [
  "blue",
  "purple",
  "green",
  "orange",
  "pink",
  "red",
  "teal",
];

const FONT_SCALES: { value: ThemeFontScale; label: string }[] = [
  { value: "small", label: "Small" },
  { value: "default", label: "Default" },
  { value: "large", label: "Large" },
  { value: "xlarge", label: "Extra Large" },
];

const DENSITIES: { value: ThemeDensity; label: string }[] = [
  { value: "compact", label: "Compact" },
  { value: "comfortable", label: "Comfortable" },
  { value: "spacious", label: "Spacious" },
];

const PRESETS: { value: ThemePreset; label: string }[] = [
  { value: "default", label: "Default" },
  { value: "midnight", label: "Midnight" },
  { value: "sunrise", label: "Sunrise" },
  { value: "forest", label: "Forest" },
  { value: "ocean", label: "Ocean" },
];

export default function ThemeCustomizationPage() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery<ThemeConfig>({
    queryKey: ["theme-customization"],
    queryFn: getThemeCustomization,
  });

  const saved = data ?? DEFAULT_THEME_CONFIG;

  // Local (uncommitted) draft state for the preview.
  const [draft, setDraft] = useState<ThemeConfig>(saved);

  useEffect(() => {
    if (data) setDraft(data);
  }, [data]);

  const dirty = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(saved),
    [draft, saved],
  );

  const customHexValid =
    draft.accent_color !== "custom" ||
    !draft.custom_accent_hex ||
    isValidHex(draft.custom_accent_hex);

  const saveMut = useMutation({
    mutationFn: (config: ThemeConfig) => patchThemeCustomization(config),
    onSuccess: (config) => {
      queryClient.setQueryData(["theme-customization"], config);
      applyThemeConfig(config);
    },
  });

  const resetMut = useMutation({
    mutationFn: resetThemeCustomization,
    onSuccess: (config) => {
      queryClient.setQueryData(["theme-customization"], config);
      setDraft(config);
      applyThemeConfig(config);
    },
  });

  function update<K extends keyof ThemeConfig>(key: K, value: ThemeConfig[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-semibold">Theme Customization</h1>
        <p className="text-sm text-muted-foreground">
          Personalize how the app looks. Changes are saved to your account and
          applied across all your devices.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* ── Controls ─────────────────────────────────────────── */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Appearance</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Mode */}
            <div>
              <Label className="mb-2 block text-sm font-medium">Mode</Label>
              <div className="flex flex-wrap gap-2">
                {MODES.map((m) => (
                  <Button
                    key={m.value}
                    type="button"
                    size="sm"
                    variant={draft.mode === m.value ? "default" : "outline"}
                    aria-pressed={draft.mode === m.value}
                    data-testid={`theme-mode-${m.value}`}
                    onClick={() => update("mode", m.value)}
                  >
                    {m.label}
                  </Button>
                ))}
              </div>
            </div>

            {/* Accent color */}
            <div>
              <Label className="mb-2 block text-sm font-medium">Accent Color</Label>
              <div className="flex flex-wrap items-center gap-2">
                {ACCENTS.map((c) => (
                  <button
                    key={c}
                    type="button"
                    aria-label={`Accent ${c}`}
                    aria-pressed={draft.accent_color === c}
                    data-testid={`theme-accent-${c}`}
                    onClick={() => update("accent_color", c)}
                    className={cn(
                      "flex h-8 w-8 items-center justify-center rounded-full border-2 transition-all",
                      draft.accent_color === c
                        ? "border-foreground ring-2 ring-offset-2"
                        : "border-transparent hover:scale-105",
                    )}
                    style={{ backgroundColor: ACCENT_HEX[c] }}
                  >
                    {draft.accent_color === c && (
                      <Check className="h-4 w-4 text-white" />
                    )}
                  </button>
                ))}
                <button
                  type="button"
                  aria-label="Custom accent color"
                  aria-pressed={draft.accent_color === "custom"}
                  data-testid="theme-accent-custom"
                  onClick={() => update("accent_color", "custom")}
                  className={cn(
                    "flex h-8 items-center rounded-full border-2 px-3 text-xs transition-all",
                    draft.accent_color === "custom"
                      ? "border-foreground"
                      : "border-input hover:bg-accent",
                  )}
                >
                  Custom
                </button>
              </div>
              {draft.accent_color === "custom" && (
                <div className="mt-3 flex items-center gap-2">
                  <Input
                    aria-label="Custom hex color"
                    data-testid="theme-custom-hex"
                    placeholder="#3B82F6"
                    maxLength={7}
                    value={draft.custom_accent_hex ?? ""}
                    onChange={(e) =>
                      update("custom_accent_hex", e.target.value || null)
                    }
                    className="w-32 font-mono"
                  />
                  {!customHexValid && (
                    <span
                      className="text-xs text-destructive"
                      data-testid="theme-hex-error"
                    >
                      Enter a 6-digit hex color
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Preset */}
            <div>
              <Label className="mb-2 block text-sm font-medium">Preset</Label>
              <div className="flex flex-wrap gap-2">
                {PRESETS.map((p) => (
                  <Button
                    key={p.value}
                    type="button"
                    size="sm"
                    variant={draft.preset === p.value ? "default" : "outline"}
                    aria-pressed={draft.preset === p.value}
                    data-testid={`theme-preset-${p.value}`}
                    onClick={() => update("preset", p.value)}
                  >
                    {p.label}
                  </Button>
                ))}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                A preset overrides the accent color with a curated palette.
              </p>
            </div>

            {/* Font scale */}
            <div>
              <Label className="mb-2 block text-sm font-medium">Font Size</Label>
              <div className="flex flex-wrap gap-2">
                {FONT_SCALES.map((f) => (
                  <Button
                    key={f.value}
                    type="button"
                    size="sm"
                    variant={draft.font_scale === f.value ? "default" : "outline"}
                    aria-pressed={draft.font_scale === f.value}
                    data-testid={`theme-font-${f.value}`}
                    onClick={() => update("font_scale", f.value)}
                  >
                    {f.label}
                  </Button>
                ))}
              </div>
            </div>

            {/* Density */}
            <div>
              <Label className="mb-2 block text-sm font-medium">Density</Label>
              <div className="flex flex-wrap gap-2">
                {DENSITIES.map((d) => (
                  <Button
                    key={d.value}
                    type="button"
                    size="sm"
                    variant={draft.density === d.value ? "default" : "outline"}
                    aria-pressed={draft.density === d.value}
                    data-testid={`theme-density-${d.value}`}
                    onClick={() => update("density", d.value)}
                  >
                    {d.label}
                  </Button>
                ))}
              </div>
            </div>

            {/* High contrast */}
            <div className="flex items-center justify-between">
              <div>
                <Label className="text-sm font-medium">High Contrast</Label>
                <p className="text-xs text-muted-foreground">
                  Increase contrast and border weight for readability.
                </p>
              </div>
              <Switch
                checked={draft.high_contrast}
                data-testid="theme-high-contrast"
                onCheckedChange={(v) => update("high_contrast", v)}
              />
            </div>

            {/* Actions */}
            <div className="flex flex-wrap gap-2 pt-2">
              <Button
                type="button"
                data-testid="theme-save"
                disabled={!dirty || !customHexValid || saveMut.isPending}
                onClick={() => saveMut.mutate(draft)}
              >
                {saveMut.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Save
              </Button>
              <Button
                type="button"
                variant="outline"
                data-testid="theme-revert"
                disabled={!dirty || saveMut.isPending}
                onClick={() => setDraft(saved)}
              >
                Revert
              </Button>
              <Button
                type="button"
                variant="ghost"
                data-testid="theme-reset"
                disabled={resetMut.isPending}
                onClick={() => resetMut.mutate()}
              >
                <RotateCcw className="mr-2 h-4 w-4" />
                Reset to defaults
              </Button>
            </div>
            {saveMut.isError && (
              <p className="text-xs text-destructive" data-testid="theme-save-error">
                Could not save your theme. Please check your settings and try again.
              </p>
            )}
          </CardContent>
        </Card>

        {/* ── Preview ──────────────────────────────────────────── */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Preview</CardTitle>
          </CardHeader>
          <CardContent>
            <ThemeCustomizationPreview config={draft} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
