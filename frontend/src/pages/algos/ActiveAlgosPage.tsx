// Active Algos monitor — a READ + CONTROL view of the client-side TWAP / Iceberg
// algo orders persisted by algoStore. Per-algo it shows filled/total progress,
// slices done, the next-slice countdown, and pause / resume / cancel controls.
// Placement itself happens in the trade ticket's runner (which must be open for
// that symbol) — this page just reflects and steers the persisted state. Algos
// run ONLY while a tab is open; cancelling stops all further scheduling.
import SurfaceIntro from "@/components/onboarding/SurfaceIntro";
import { useEffect, useMemo, useState } from "react";
import { Timer, Layers, Pause, Play, X, Trash2, Info } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import {
  useAlgoOrders,
  filledQty,
  slicesDone,
  progressFrac,
  nextPending,
  type AlgoOrder,
} from "@/lib/algoStore";

function statusTone(s: AlgoOrder["status"]): string {
  switch (s) {
    case "running":
      return "bg-emerald-600/15 text-emerald-600 dark:text-emerald-400";
    case "paused":
      return "bg-amber-500/15 text-amber-600 dark:text-amber-400";
    case "done":
      return "bg-sky-500/15 text-sky-600 dark:text-sky-400";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function countdown(a: AlgoOrder, now: number): string {
  if (a.status !== "running") return "—";
  const child = nextPending(a);
  if (!child) return "—";
  if (a.kind === "twap" && child.atMs != null) {
    const ms = child.atMs - now;
    if (ms <= 0) return "due";
    const s = Math.ceil(ms / 1000);
    return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
  }
  // Iceberg replenishes on fill, so "next" is on the prior clip filling.
  const anyPlaced = a.children.some((c) => c.status === "placed");
  return anyPlaced ? "on fill" : "next";
}

function AlgoCard({ a, now }: { a: AlgoOrder; now: number }) {
  const { setStatus, remove } = useAlgoOrders();
  const filled = filledQty(a);
  const done = slicesDone(a);
  const pct = Math.round(progressFrac(a) * 100);
  const KindIcon = a.kind === "twap" ? Timer : Layers;
  const terminal = a.status === "done" || a.status === "cancelled";

  return (
    <Card data-testid={`algo_card_${a.id}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <KindIcon className="h-4 w-4" />
            {a.kind === "twap" ? "TWAP" : "Iceberg"}
            <span className={cn("uppercase", a.side === "buy" ? "text-emerald-600" : "text-rose-600")}>
              {a.side}
            </span>
            <span className="text-sm font-normal text-muted-foreground">
              {a.symbolLabel ?? `#${a.symbolId}`}
            </span>
          </CardTitle>
          <div className="flex items-center gap-2">
            {a.paper && <Badge variant="outline">Paper</Badge>}
            <Badge className={cn("capitalize", statusTone(a.status))}>{a.status}</Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div>
          <div className="mb-1 flex justify-between text-xs text-muted-foreground">
            <span>
              Filled {filled} / {a.totalQty} ({pct}%)
            </span>
            <span data-testid={`algo_slices_${a.id}`}>
              {a.kind === "twap"
                ? `slice ${done}/${a.children.length}`
                : `clip ${done}/${a.children.length}`}
            </span>
          </div>
          <Progress value={pct} data-testid={`algo_progress_${a.id}`} />
        </div>

        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Child type</span>
            <span className="uppercase">{a.childType}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Next slice</span>
            <span className="tabular-nums" data-testid={`algo_countdown_${a.id}`}>
              {countdown(a, now)}
            </span>
          </div>
          {a.kind === "twap" && (
            <div className="flex justify-between">
              <span className="text-muted-foreground">Slices</span>
              <span>{a.slices}</span>
            </div>
          )}
          {a.kind === "iceberg" && (
            <div className="flex justify-between">
              <span className="text-muted-foreground">Visible</span>
              <span>{a.visibleQty}</span>
            </div>
          )}
        </div>

        <div className="flex flex-wrap gap-2 pt-1">
          {a.status === "running" && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              data-testid={`algo_pause_${a.id}`}
              onClick={() => setStatus(a.id, "paused")}
            >
              <Pause className="mr-1 h-3.5 w-3.5" /> Pause
            </Button>
          )}
          {a.status === "paused" && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              data-testid={`algo_resume_${a.id}`}
              onClick={() => setStatus(a.id, "running")}
            >
              <Play className="mr-1 h-3.5 w-3.5" /> Resume
            </Button>
          )}
          {!terminal && (
            <Button
              type="button"
              variant="destructive"
              size="sm"
              data-testid={`algo_cancel_${a.id}`}
              onClick={() => setStatus(a.id, "cancelled")}
            >
              <X className="mr-1 h-3.5 w-3.5" /> Cancel
            </Button>
          )}
          {terminal && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              data-testid={`algo_remove_${a.id}`}
              onClick={() => remove(a.id)}
            >
              <Trash2 className="mr-1 h-3.5 w-3.5" /> Remove
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default function ActiveAlgosPage() {
  const { algos, clearTerminal } = useAlgoOrders();
  // Live "now" so countdowns tick.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const active = useMemo(
    () => algos.filter((a) => a.status === "running" || a.status === "paused"),
    [algos],
  );
  const terminal = useMemo(
    () => algos.filter((a) => a.status === "done" || a.status === "cancelled"),
    [algos],
  );

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4">
      <SurfaceIntro surfaceId="algos" />

      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <Timer className="h-5 w-5" /> Active Algos
        </h1>
        {terminal.length > 0 && (
          <Button type="button" variant="outline" size="sm" onClick={clearTerminal} data-testid="algo_clear_terminal">
            Clear finished
          </Button>
        )}
      </div>

      <div
        className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/[0.06] p-3 text-sm"
        data-testid="algo_client_side_banner"
      >
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
        <div>
          <p className="font-medium text-amber-700 dark:text-amber-300">
            Client-side algos run only while this tab is open.
          </p>
          <p className="text-xs text-muted-foreground">
            Child orders are scheduled locally from the trade ticket — keep the ticket for the
            algo&apos;s symbol open. Closing the tab pauses scheduling; cancelling stops it for good.
          </p>
        </div>
      </div>

      {algos.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted-foreground" data-testid="algo_empty">
          No algo orders yet. Start a TWAP or Iceberg from a market&apos;s trade ticket (Algo mode).
        </p>
      ) : (
        <>
          {active.length > 0 && (
            <div className="space-y-3">
              {active.map((a) => (
                <AlgoCard key={a.id} a={a} now={now} />
              ))}
            </div>
          )}
          {terminal.length > 0 && (
            <>
              <h2 className="pt-2 text-sm font-semibold text-muted-foreground">Finished</h2>
              <div className="space-y-3 opacity-80">
                {terminal.map((a) => (
                  <AlgoCard key={a.id} a={a} now={now} />
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
