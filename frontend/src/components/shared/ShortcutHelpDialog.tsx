import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { Shortcut } from "@/hooks/useGlobalShortcuts";
import { getGroupedShortcuts } from "@/hooks/useGlobalShortcuts";

interface ShortcutHelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  shortcuts: Shortcut[];
}

function formatKey(key: string): string {
  return key
    .split("+")
    .map((k) => {
      if (k === "ctrl")
        return typeof navigator !== "undefined" && navigator.userAgent.includes("Mac")
          ? "Cmd"
          : "Ctrl";
      if (k === "shift") return "Shift";
      if (k === "alt") return "Alt";
      if (k === "escape") return "Esc";
      if (k === "enter") return "Enter";
      if (k === "?") return "?";
      return k.length === 1 ? k.toUpperCase() : k.charAt(0).toUpperCase() + k.slice(1);
    })
    .join(" + ");
}

export default function ShortcutHelpDialog({
  open,
  onOpenChange,
  shortcuts,
}: ShortcutHelpDialogProps) {
  const grouped = getGroupedShortcuts(shortcuts);
  const groupOrder = ["General", "Navigation", "Actions", "Messaging"];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg" aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle>Keyboard Shortcuts</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 max-h-[60vh] overflow-y-auto">
          {groupOrder
            .filter((g) => grouped[g]?.length)
            .map((group) => (
              <div key={group}>
                <h3 className="text-sm font-semibold text-muted-foreground mb-2">
                  {group}
                </h3>
                <div className="space-y-1">
                  {grouped[group]!.map((s) => (
                    <div
                      key={s.key}
                      className="flex items-center justify-between py-1"
                    >
                      <span className="text-sm">{s.label}</span>
                      <kbd className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
                        {formatKey(s.key)}
                      </kbd>
                    </div>
                  ))}
                </div>
              </div>
            ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
