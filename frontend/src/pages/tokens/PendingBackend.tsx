import { Info } from "lucide-react";

/**
 * Honest "pending backend" note shown when a `/me/tokens/*` read 404s (the
 * surface is UI-complete but the backend has not shipped yet). Reused across
 * every token screen so the empty state reads the same everywhere.
 */
export function PendingBackend({ label = "This data" }: { label?: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-dashed bg-muted/30 p-4 text-sm text-muted-foreground">
      <Info className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium text-foreground">Pending backend</p>
        <p>
          {label} is not available yet — the creator-token endpoints have not shipped on this
          environment. The surface is wired and will populate automatically once they do.
        </p>
      </div>
    </div>
  );
}

/** Small labelled note flagging the flippable shortfall-vs-flat upkeep assumption. */
export function ShortfallAssumptionNote() {
  return (
    <p className="rounded-md border border-amber-300/50 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-300">
      <span className="font-semibold">Assumption (flippable):</span> upkeep is billed as a{" "}
      <span className="font-semibold">shortfall top-up</span> — amount due = max(0, $100 − trading
      fees this month), $0 once the book&rsquo;s monthly fees reach $100. This can be switched to a
      flat $100/month later.
    </p>
  );
}
