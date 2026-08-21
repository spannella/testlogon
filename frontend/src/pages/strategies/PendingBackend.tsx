import { Info, Layers } from "lucide-react";

/**
 * Honest "pending backend" note shown when a `/me/strategies/*` read 404s (the
 * surface is UI-complete but the backend has not shipped yet). Reused across
 * every strategy screen so the empty state reads the same everywhere.
 */
export function PendingBackend({ label = "This data" }: { label?: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-dashed bg-muted/30 p-4 text-sm text-muted-foreground">
      <Info className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium text-foreground">Pending backend</p>
        <p>
          {label} is not available yet — the strategy / basket-fund endpoints have not shipped on
          this environment. The surface is wired and will populate automatically once they do.
        </p>
      </div>
    </div>
  );
}

/**
 * Small labelled note flagging the flippable fund-structure assumption: the
 * fund is modelled as a POOLED NAV FUND (investors own units, subscribe/redeem
 * at NAV) rather than copy / replication trading.
 */
export function PooledNavNote() {
  return (
    <p className="flex items-start gap-2 rounded-md border border-sky-300/50 bg-sky-50 px-3 py-2 text-xs text-sky-800 dark:border-sky-500/30 dark:bg-sky-950/40 dark:text-sky-300">
      <Layers className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>
        <span className="font-semibold">Assumption (flippable):</span> this is a{" "}
        <span className="font-semibold">pooled NAV fund</span> — you subscribe and redeem at the
        fund&rsquo;s net-asset-value per unit and own units. It is not copy / replication trading.
      </span>
    </p>
  );
}
