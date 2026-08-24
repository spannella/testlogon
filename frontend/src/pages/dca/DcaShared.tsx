import { useMemo, useState } from "react";
import { Info, ServerCog, Search } from "lucide-react";
import type { DcaTarget, DcaTargetKind } from "@/lib/dca";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useSymbols } from "@/hooks/useMarketData";
import { useTokenMarket } from "@/hooks/useTokens";
import { useStrategyMarket } from "@/hooks/useStrategies";

/**
 * Honest "recurring buys need the backend runner" note shown when a `/me/dca/*`
 * read 404s (the surface is UI-complete but the SERVER-SIDE runner has not
 * shipped). Reused across every DCA screen so the empty state reads the same.
 */
export function PendingBackend({ label = "This data" }: { label?: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-dashed bg-muted/30 p-4 text-sm text-muted-foreground">
      <Info className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        <p className="font-medium text-foreground">Recurring buys need the backend runner</p>
        <p>
          {label} is not available yet — the recurring-buys endpoints and the periodic executor
          have not shipped on this environment. The surface is wired and will populate automatically
          once they do.
        </p>
      </div>
    </div>
  );
}

/**
 * Small labelled note making the execution model explicit: once a plan is
 * scheduled, the buys run AUTOMATICALLY on a SERVER-SIDE runner — the browser
 * does not need to be open.
 */
export function ServerRunnerNote() {
  return (
    <p className="flex items-start gap-2 rounded-md border border-sky-300/50 bg-sky-50 px-3 py-2 text-xs text-sky-800 dark:border-sky-500/30 dark:bg-sky-950/40 dark:text-sky-300">
      <ServerCog className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>
        <span className="font-semibold">How it runs:</span> recurring buys run{" "}
        <span className="font-semibold">automatically server-side</span> once scheduled — you
        don&rsquo;t need to keep this page open. Each buy debits your USD cash wallet.
      </span>
    </p>
  );
}

const KIND_LABELS: Record<DcaTargetKind, string> = {
  symbol: "Market",
  token: "Creator token",
  strategy: "Strategy",
};

interface TargetOption extends DcaTarget {
  sublabel?: string;
}

/**
 * A unified target picker across the three investable target kinds — market
 * SYMBOLS (`useSymbols`), creator TOKENS (`useTokenMarket`), and STRATEGY funds
 * (`useStrategyMarket`). Each source degrades independently (tokens/strategies
 * 404 until their backends ship), so the picker simply shows whatever is
 * available. The selected target carries its stable id + a human label.
 */
export function TargetPicker({
  value,
  onChange,
}: {
  value: DcaTarget | null;
  onChange: (t: DcaTarget) => void;
}) {
  const [kind, setKind] = useState<DcaTargetKind>("symbol");
  const [q, setQ] = useState("");

  const symbols = useSymbols();
  const tokens = useTokenMarket();
  const strategies = useStrategyMarket();

  const options: TargetOption[] = useMemo(() => {
    if (kind === "symbol") {
      return (symbols.data?.symbols ?? []).map((s) => ({
        kind: "symbol" as const,
        id: String(s.symbol_id),
        label: s.symbol,
        sublabel: s.is_perpetual ? "Perp" : "Spot",
      }));
    }
    if (kind === "token") {
      return (tokens.data?.tokens ?? []).map((t) => ({
        kind: "token" as const,
        id: t.token_id,
        label: `${t.name} (${t.ticker})`,
        sublabel: "Creator token",
      }));
    }
    return (strategies.data?.strategies ?? []).map((s) => ({
      kind: "strategy" as const,
      id: s.strategy_id,
      label: s.name,
      sublabel: s.kind === "rule" ? "Rule-based" : "Basket",
    }));
  }, [kind, symbols.data, tokens.data, strategies.data]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const base = needle
      ? options.filter((o) => o.label.toLowerCase().includes(needle))
      : options;
    return base.slice(0, 50);
  }, [options, q]);

  const loading =
    (kind === "symbol" && symbols.isLoading) ||
    (kind === "token" && tokens.isLoading) ||
    (kind === "strategy" && strategies.isLoading);

  return (
    <div className="space-y-3">
      <Tabs value={kind} onValueChange={(v) => setKind(v as DcaTargetKind)}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="symbol">Markets</TabsTrigger>
          <TabsTrigger value="token">Tokens</TabsTrigger>
          <TabsTrigger value="strategy">Strategies</TabsTrigger>
        </TabsList>
      </Tabs>

      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={`Search ${KIND_LABELS[kind].toLowerCase()}s…`}
          className="pl-8"
          data-testid="target-search"
        />
      </div>

      <div className="max-h-56 overflow-y-auto rounded-md border">
        {loading ? (
          <div className="p-4 text-center text-sm text-muted-foreground">Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="p-4 text-center text-sm text-muted-foreground">
            {kind === "symbol"
              ? "No markets found."
              : `No ${KIND_LABELS[kind].toLowerCase()}s available yet on this environment.`}
          </div>
        ) : (
          <ul className="divide-y">
            {filtered.map((o) => {
              const selected = value?.kind === o.kind && value?.id === o.id;
              return (
                <li key={`${o.kind}:${o.id}`}>
                  <button
                    type="button"
                    onClick={() => onChange({ kind: o.kind, id: o.id, label: o.label })}
                    data-testid="target-option"
                    className={
                      "flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent " +
                      (selected ? "bg-accent font-medium" : "")
                    }
                  >
                    <span className="truncate">{o.label}</span>
                    {o.sublabel ? (
                      <Badge variant="outline" className="shrink-0 text-[10px]">
                        {o.sublabel}
                      </Badge>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {value ? (
        <p className="text-xs text-muted-foreground">
          Selected: <span className="font-medium text-foreground">{value.label}</span>{" "}
          <Badge variant="secondary" className="ml-1 text-[10px]">
            {KIND_LABELS[value.kind]}
          </Badge>
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">No target selected yet.</p>
      )}
    </div>
  );
}

/** Human label for a target kind (exported for reuse in tables). */
export function targetKindLabel(kind: DcaTargetKind): string {
  return KIND_LABELS[kind] ?? kind;
}
