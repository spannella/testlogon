import { useUiStore } from "@/stores/uiStore";

/**
 * Miniature mock UI preview showing the current theme settings.
 * Renders a sidebar, header, card, message bubble, and button
 * using inline styles to reflect the current accent / density / font size.
 */
export function ThemePreviewPane() {
  const highContrast = useUiStore((s) => s.highContrast);
  const density = useUiStore((s) => s.density);

  const padScale = density === "compact" ? 0.75 : density === "spacious" ? 1.5 : 1;

  return (
    <div
      data-testid="theme-preview-pane"
      className="overflow-hidden rounded-lg border-2 border-border bg-background"
    >
      <div className="flex h-36">
        {/* Sidebar mock */}
        <div
          className="flex w-16 flex-col gap-1 border-r border-border bg-card"
          style={{ padding: `${0.5 * padScale}rem` }}
        >
          <div className="h-2 w-10 rounded bg-muted" />
          <div className="h-2 w-8 rounded bg-primary opacity-80" />
          <div className="h-2 w-10 rounded bg-muted" />
          <div className="h-2 w-6 rounded bg-muted" />
        </div>

        {/* Main content */}
        <div className="flex flex-1 flex-col">
          {/* Header bar */}
          <div
            className="flex items-center gap-2 border-b border-border bg-card"
            style={{ padding: `${0.375 * padScale}rem ${0.5 * padScale}rem` }}
          >
            <div className="h-2 w-12 rounded bg-foreground opacity-70" />
            <div className="ml-auto h-3 w-3 rounded-full bg-primary" />
          </div>

          {/* Content area */}
          <div
            className="flex flex-1 flex-col gap-1 bg-background"
            style={{ padding: `${0.5 * padScale}rem` }}
          >
            {/* Card mock */}
            <div
              className="rounded border bg-card"
              style={{
                padding: `${0.375 * padScale}rem`,
                borderWidth: highContrast ? "2px" : "1px",
              }}
            >
              <div className="h-1.5 w-16 rounded bg-foreground opacity-60" />
              <div className="mt-1 h-1 w-24 rounded bg-muted-foreground opacity-40" />
            </div>

            {/* Message bubble mock */}
            <div className="flex gap-1" style={{ marginTop: `${0.25 * padScale}rem` }}>
              <div className="h-3 w-3 rounded-full bg-muted" />
              <div className="rounded-lg bg-muted px-2 py-1">
                <div className="h-1 w-12 rounded bg-muted-foreground opacity-50" />
              </div>
            </div>

            {/* Button mock */}
            <div className="mt-auto flex gap-1">
              <div
                className="h-4 w-12 rounded bg-primary"
                style={{ opacity: 0.9 }}
              />
              <div className="h-4 w-8 rounded border border-border bg-background" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
