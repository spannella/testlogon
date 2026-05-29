import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { Shortcut, ChordMapping } from "@/hooks/useGlobalShortcuts";
import { getGroupedShortcuts } from "@/hooks/useGlobalShortcuts";

interface ShortcutHelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  shortcuts: Shortcut[];
  chords?: ChordMapping[];
}

function formatKey(key: string): string {
  // Handle chord notation: "g,m" -> "G then M"
  if (key.includes(",")) {
    return key
      .split(",")
      .map((k) => k.trim().toUpperCase())
      .join(" then ");
  }

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

/** Convert ChordMapping[] into Shortcut[] for display in the grouped list */
function chordMappingsToShortcuts(chords: ChordMapping[]): Shortcut[] {
  return chords.map((c) => ({
    key: `${c.first},${c.second}`,
    label: c.label,
    group: c.group,
    action: c.action,
  }));
}

export default function ShortcutHelpDialog({
  open,
  onOpenChange,
  shortcuts,
  chords,
}: ShortcutHelpDialogProps) {
  const chordShortcuts = chords ? chordMappingsToShortcuts(chords) : [];
  const allShortcuts = [...shortcuts, ...chordShortcuts];
  const grouped = getGroupedShortcuts(allShortcuts);
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
