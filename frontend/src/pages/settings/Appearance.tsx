import * as React from "react";
import { Monitor, Sun, Moon, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { useUiStore, type Theme } from "@/stores/uiStore";

const THEMES: { value: Theme; label: string; icon: React.ReactNode; preview: React.ReactNode }[] = [
  {
    value: "system",
    label: "System",
    icon: <Monitor className="h-4 w-4" />,
    preview: (
      <div className="flex h-10 w-full overflow-hidden rounded-sm">
        <div className="flex-1 bg-white" />
        <div className="flex-1 bg-zinc-900" />
      </div>
    ),
  },
  {
    value: "light",
    label: "Light",
    icon: <Sun className="h-4 w-4" />,
    preview: (
      <div className="flex h-10 w-full flex-col gap-1 rounded-sm bg-white p-1.5">
        <div className="h-1.5 w-1/2 rounded-full bg-zinc-200" />
        <div className="h-1.5 w-3/4 rounded-full bg-zinc-100" />
        <div className="h-1.5 w-2/3 rounded-full bg-zinc-100" />
      </div>
    ),
  },
  {
    value: "dark",
    label: "Dark",
    icon: <Moon className="h-4 w-4" />,
    preview: (
      <div className="flex h-10 w-full flex-col gap-1 rounded-sm bg-zinc-900 p-1.5">
        <div className="h-1.5 w-1/2 rounded-full bg-zinc-600" />
        <div className="h-1.5 w-3/4 rounded-full bg-zinc-700" />
        <div className="h-1.5 w-2/3 rounded-full bg-zinc-700" />
      </div>
    ),
  },
];

export function Appearance() {
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);

  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm font-medium">Theme</p>
        <p className="text-xs text-muted-foreground">
          Choose how the app looks. Your preference is saved automatically.
        </p>
      </div>
      <div className="grid grid-cols-3 gap-3">
        {THEMES.map((t) => {
          const active = theme === t.value;
          return (
            <button
              key={t.value}
              type="button"
              onClick={() => setTheme(t.value)}
              className={cn(
                "group relative flex flex-col gap-2 rounded-lg border-2 p-2 text-left transition-all",
                "hover:border-primary/50 hover:bg-accent/40",
                active
                  ? "border-primary bg-accent/30"
                  : "border-border bg-card",
              )}
              aria-pressed={active}
            >
              {/* Active check */}
              {active && (
                <span className="absolute right-2 top-2 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground">
                  <Check className="h-2.5 w-2.5" />
                </span>
              )}

              {/* Mini preview swatch */}
              <div className="overflow-hidden rounded-sm border border-border">
                {t.preview}
              </div>

              {/* Label */}
              <span className="flex items-center gap-1.5 text-xs font-medium text-foreground">
                {t.icon}
                {t.label}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
