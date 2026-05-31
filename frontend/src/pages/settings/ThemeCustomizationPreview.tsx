import { cn } from "@/lib/utils";
import type { ThemeConfig } from "@/api/types";
import { previewStyle, isDarkMode } from "@/lib/themeCustomization";

/**
 * PLATFORM-013: Live, scoped preview of a candidate ThemeConfig.
 * Renders a miniature mock of the app shell with the candidate accent,
 * font scale, density, and contrast applied via inline CSS variables —
 * without affecting the rest of the page.
 */
export function ThemeCustomizationPreview({ config }: { config: ThemeConfig }) {
  const dark = isDarkMode(config.mode);
  const style = previewStyle(config) as React.CSSProperties;

  return (
    <div
      data-testid="theme-customization-preview"
      className={cn(
        "rounded-lg border overflow-hidden",
        dark && "dark",
        `tc-density-${config.density}`,
        config.high_contrast && "tc-high-contrast",
      )}
      style={style}
    >
      <div className="flex h-64 bg-background text-foreground">
        {/* Mini sidebar */}
        <div className="w-16 bg-card border-r p-2 space-y-2">
          <div className="w-8 h-8 rounded mx-auto" style={{ background: "var(--primary)" }} />
          <div className="w-8 h-2 rounded bg-muted mx-auto" />
          <div className="w-8 h-2 rounded bg-muted mx-auto" />
          <div className="w-8 h-2 rounded bg-muted mx-auto" />
        </div>
        {/* Mini content */}
        <div className="flex-1 p-3 space-y-2">
          <div className="h-6 bg-card rounded flex items-center px-2 gap-2">
            <div className="w-16 h-3 bg-muted rounded" />
            <div className="flex-1" />
            <div className="w-4 h-4 rounded-full" style={{ background: "var(--primary)" }} />
          </div>
          <div className="bg-card rounded border p-2 space-y-1">
            <div className="w-24 h-3 rounded" style={{ background: "var(--foreground)", opacity: 0.2 }} />
            <div className="w-full h-2 bg-muted rounded" />
            <div className="w-3/4 h-2 bg-muted rounded" />
          </div>
          <button
            type="button"
            className="px-3 py-1 rounded text-xs"
            style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
          >
            Primary action
          </button>
          <div className="flex gap-2 items-end">
            <div className="w-5 h-5 rounded-full bg-muted" />
            <div className="bg-muted rounded-lg px-2 py-1 text-xs max-w-[60%]">
              Preview message
            </div>
          </div>
          <div className="flex gap-2 items-end justify-end">
            <div
              className="rounded-lg px-2 py-1 text-xs max-w-[60%]"
              style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
            >
              Your reply
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
