import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  useKeyboardShortcutsApi,
  type ShortcutDef,
  type ShortcutEntry,
  type ShortcutGroup,
} from "@/hooks/useKeyboardShortcuts";

const GROUP_ORDER: ShortcutGroup[] = ["Navigation", "Trading", "General"];

const KEY_LABELS: Record<string, string> = {
  escape: "Esc",
  enter: "Enter",
  " ": "Space",
};

function keyLabel(k: string): string {
  return KEY_LABELS[k] ?? (k.length === 1 ? k.toUpperCase() : k);
}

/** Render the key hint for a definition as one or two <kbd> chips. */
function KeyHint({ def }: { def: ShortcutDef }) {
  if (def.hint) {
    return (
      <kbd className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
        {def.hint}
      </kbd>
    );
  }
  if (def.kind === "chord") {
    return (
      <span className="flex items-center gap-1">
        <kbd className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
          {keyLabel(def.first)}
        </kbd>
        <span className="text-[10px] text-muted-foreground">then</span>
        <kbd className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
          {keyLabel(def.second)}
        </kbd>
      </span>
    );
  }
  return (
    <kbd className="rounded border border-border bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">
      {keyLabel(def.key)}
    </kbd>
  );
}

function groupEntries(entries: ShortcutEntry[]): Record<string, ShortcutEntry[]> {
  const out: Record<string, ShortcutEntry[]> = {};
  const seen = new Set<string>();
  for (const e of entries) {
    // De-dupe by label so scoped re-registrations do not double up in the list.
    const id = `${e.def.group}:${e.def.label}`;
    if (seen.has(id)) continue;
    seen.add(id);
    (out[e.def.group] ??= []).push(e);
  }
  return out;
}

/**
 * Shortcuts help overlay. Opened by "?" (and from Settings / the command
 * palette). Lists every registered shortcut grouped by category and exposes
 * the enable/disable toggle.
 */
export default function ShortcutsHelp({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const api = useKeyboardShortcutsApi();
  // Snapshot the registry each time the dialog opens so scoped (trade-view)
  // shortcuts that are active right now are reflected.
  const entries = open && api ? api.getEntries() : [];
  const grouped = groupEntries(entries);

  const enabled = api?.enabled ?? true;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Speed up navigation and trading. Shortcuts are ignored while you are
            typing in a field.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center justify-between rounded-md border border-border bg-muted/40 px-3 py-2">
          <Label htmlFor="kbd-enabled" className="text-sm">
            Enable keyboard shortcuts
          </Label>
          <Switch
            id="kbd-enabled"
            checked={enabled}
            onCheckedChange={(v) => api?.setEnabled(v)}
            aria-label="Enable keyboard shortcuts"
          />
        </div>

        <Separator />

        <div
          className={
            "space-y-4 max-h-[55vh] overflow-y-auto pr-1" +
            (enabled ? "" : " opacity-50")
          }
        >
          {GROUP_ORDER.filter((g) => grouped[g]?.length).map((group) => (
            <div key={group}>
              <h3 className="mb-2 text-sm font-semibold text-muted-foreground">
                {group}
              </h3>
              <div className="space-y-1">
                {grouped[group]!.map((e) => (
                  <div
                    key={`${e.def.group}:${e.def.label}`}
                    className="flex items-center justify-between gap-4 py-1"
                  >
                    <span className="text-sm">{e.def.label}</span>
                    <KeyHint def={e.def} />
                  </div>
                ))}
              </div>
            </div>
          ))}
          {entries.length === 0 && (
            <p className="py-4 text-center text-sm text-muted-foreground">
              No shortcuts registered.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
