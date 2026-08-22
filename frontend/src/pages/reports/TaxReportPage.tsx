// Tax Lots & Realized-Gains report — a READ-ONLY, CLIENT-SIDE cost-basis report
// computed from the caller's REAL executed fills (`GET /me/fills/fees`, the live
// per-account fills feed). NO new backend: it reuses the typed feed hook, the
// /md/symbols catalog (for names + price scalers), and the indicative USD marks
// (`GET /me/prices`) for the unrealized view. The pure `taxLots` engine does all
// the FIFO/LIFO/average-cost matching; this page only NORMALIZES the engine's
// int64 ticks into integer cents, drives the method/period selectors, and
// renders. Every dependency DEGRADES independently: if the fills feed 404s
// (edge-undeployed) or is thin, a banner says so; missing marks just leave the
// unrealized column blank.
import { useMemo, useState } from "react";
import { FileText, Download, Info, RefreshCw, TrendingUp, TrendingDown } from "lucide-react";

import { ApiError } from "@/api/client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { useFillsFees, usePrices } from "@/hooks/useTrading";
import { useSymbols } from "@/hooks/useMarketData";
import type { MarketSymbol } from "@/api/endpoints/marketData";
import type { FillFee } from "@/api/endpoints/trading";
import {
  computeLots,
  realizedSummary,
  unrealized,
  lotsToCsv,
  type TaxFill,
  type Method,
  type Marks,
  type RealizedLot,
} from "@/lib/taxLots";
import { downloadCsv } from "@/lib/exportReport";

// ── helpers ──────────────────────────────────────────────────────────

/** True when an error is a 404/403 — "not available on this backend". */
function isUnavailable(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 404 || err.status === 403;
  const msg = (err as Error)?.message ?? "";
  return /\b40[34]\b/.test(msg);
}

const MS_THRESHOLD = 1e12;
const toMs = (ts: number): number => (ts < MS_THRESHOLD ? ts * 1000 : ts);

/** Format integer cents as a $ decimal string. */
function money(cents: number): string {
  const v = cents / 100;
  return v.toLocaleString(undefined, {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function isoDate(ts: number): string {
  const d = new Date(toMs(ts));
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().slice(0, 10);
}

const gainColor = (v: number): string | undefined =>
  v > 0 ? "rgb(16 185 129)" : v < 0 ? "rgb(239 68 68)" : undefined;

type SortKey = "closeTs" | "symbol" | "gainCents" | "qty";

// ── page ─────────────────────────────────────────────────────────────

export default function TaxReportPage() {
  const [method, setMethod] = useState<Method>("fifo");
  const [year, setYear] = useState<string>("all");
  const [sortKey, setSortKey] = useState<SortKey>("closeTs");
  const [sortAsc, setSortAsc] = useState(false);

  const symbolsQuery = useSymbols();
  const fillsQuery = useFillsFees();
  const pricesQuery = usePrices();

  // symbolid -> { name, scaler } resolver from the /md/symbols catalog.
  const symById = useMemo(() => {
    const m = new Map<number, MarketSymbol>();
    for (const s of symbolsQuery.data?.symbols ?? []) m.set(s.symbol_id, s);
    return m;
  }, [symbolsQuery.data]);

  const rawFills: FillFee[] = Array.isArray(fillsQuery.data?.fills) ? fillsQuery.data!.fills! : [];

  // Normalize the engine feed → integer-cents TaxFill list. price/fee are int64
  // ticks scaled per-symbol; we scale to a decimal then to integer cents.
  const normalized: TaxFill[] = useMemo(() => {
    const out: TaxFill[] = [];
    for (const f of rawFills) {
      const sym = symById.get(f.symbolid);
      const scaler = sym?.price_scaler || 1;
      const name = sym?.symbol ?? `#${f.symbolid}`;
      const side = String(f.side).toLowerCase().startsWith("s") ? "sell" : "buy";
      const priceCents = Math.round((f.price / scaler) * 100);
      const feeCents = Math.round((Math.abs(f.fee ?? 0) / scaler) * 100);
      const qty = Math.abs(f.qty);
      if (!qty) continue;
      out.push({ ts: f.ts, symbol: name, side, qty, priceCents, feeCents });
    }
    return out;
  }, [rawFills, symById]);

  // Distinct calendar years present (for the year filter).
  const years = useMemo(() => {
    const set = new Set<number>();
    for (const f of normalized) set.add(new Date(toMs(f.ts)).getUTCFullYear());
    return [...set].sort((a, b) => b - a);
  }, [normalized]);

  // Fills passed to the engine are ALL fills (lots must open in prior years to
  // match sells in the selected year); the year filter is applied to the
  // REALIZED rows by close date, which is the correct tax-year semantics.
  const engine = useMemo(() => computeLots(normalized, method), [normalized, method]);

  const realizedFiltered: RealizedLot[] = useMemo(() => {
    if (year === "all") return engine.realized;
    const y = Number(year);
    return engine.realized.filter((r) => new Date(toMs(r.closeTs)).getUTCFullYear() === y);
  }, [engine.realized, year]);

  const summary = useMemo(() => realizedSummary(realizedFiltered), [realizedFiltered]);

  // Indicative USD marks: /me/prices maps ASSET SYMBOL -> USD decimal string.
  const marks: Marks = useMemo(() => {
    const m: Marks = {};
    const p = pricesQuery.data?.prices;
    if (p) {
      for (const [sym, usd] of Object.entries(p)) {
        const n = Number(usd);
        if (Number.isFinite(n)) m[sym] = Math.round(n * 100);
      }
    }
    // Fallback: reference_price from the symbols catalog (engine ticks).
    for (const s of symbolsQuery.data?.symbols ?? []) {
      if (m[s.symbol] == null && s.reference_price) {
        m[s.symbol] = Math.round((s.reference_price / (s.price_scaler || 1)) * 100);
      }
    }
    return m;
  }, [pricesQuery.data, symbolsQuery.data]);

  const unrealizedRows = useMemo(() => unrealized(engine.openLots, marks), [engine.openLots, marks]);
  const totalUnrealized = useMemo(
    () => unrealizedRows.reduce((s, r) => s + r.unrealizedCents, 0),
    [unrealizedRows],
  );

  const sortedRealized = useMemo(() => {
    const rows = [...realizedFiltered];
    rows.sort((a, b) => {
      let d = 0;
      if (sortKey === "symbol") d = a.symbol.localeCompare(b.symbol);
      else if (sortKey === "gainCents") d = a.gainCents - b.gainCents;
      else if (sortKey === "qty") d = a.qty - b.qty;
      else d = toMs(a.closeTs) - toMs(b.closeTs);
      return sortAsc ? d : -d;
    });
    return rows;
  }, [realizedFiltered, sortKey, sortAsc]);

  const toggleSort = (k: SortKey) => {
    if (k === sortKey) setSortAsc((v) => !v);
    else {
      setSortKey(k);
      setSortAsc(false);
    }
  };

  const onExport = () => {
    const label = year === "all" ? "all" : year;
    downloadCsv(`tax-lots-${method}-${label}.csv`, lotsToCsv(realizedFiltered));
  };

  // ── degrade state ──
  const fillsUnavailable = fillsQuery.isError && isUnavailable(fillsQuery.error);
  const thin = !fillsQuery.isError && rawFills.length > 0 && rawFills.length < 2;
  const loading = fillsQuery.isLoading || symbolsQuery.isLoading;

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-4">
      {/* header + controls */}
      <div className="flex flex-wrap items-center gap-3">
        <FileText className="h-6 w-6" />
        <div className="flex-1">
          <h1 className="text-xl font-semibold">Tax &amp; Gains</h1>
          <p className="text-sm text-muted-foreground">
            Cost-basis &amp; realized-gains report computed on-device from your trade fills.
          </p>
        </div>
        {fillsQuery.isFetching && (
          <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" aria-label="refreshing" />
        )}
        <Select value={method} onValueChange={(v) => setMethod(v as Method)}>
          <SelectTrigger className="w-[170px]" aria-label="Accounting method">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="fifo">FIFO</SelectItem>
            <SelectItem value="lifo">LIFO</SelectItem>
            <SelectItem value="avg">Average cost</SelectItem>
          </SelectContent>
        </Select>
        <Select value={year} onValueChange={setYear}>
          <SelectTrigger className="w-[140px]" aria-label="Tax year">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All years</SelectItem>
            {years.map((y) => (
              <SelectItem key={y} value={String(y)}>
                {y}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          type="button"
          variant="outline"
          onClick={onExport}
          disabled={realizedFiltered.length === 0}
        >
          <Download className="mr-2 h-4 w-4" />
          Download CSV
        </Button>
      </div>

      <Alert>
        <Info className="h-4 w-4" />
        <AlertDescription className="text-xs">
          Covers spot &amp; margin trade fills. Creator-token distributions and strategy payouts are
          not yet included. Marks for unrealized value are indicative. This is not tax advice.
        </AlertDescription>
      </Alert>

      {fillsUnavailable && (
        <Alert variant="destructive">
          <AlertTitle>Trade history unavailable</AlertTitle>
          <AlertDescription>
            The fills feed is not available on this backend yet. The report will populate once trade
            history is served.
          </AlertDescription>
        </Alert>
      )}
      {thin && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Limited trade history</AlertTitle>
          <AlertDescription>
            Only a small number of fills were returned — the report may be incomplete.
          </AlertDescription>
        </Alert>
      )}
      {engine.warnings.length > 0 && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Data notes ({engine.warnings.length})</AlertTitle>
          <AlertDescription className="text-xs">
            {engine.warnings.slice(0, 4).map((w, i) => (
              <div key={i}>{w}</div>
            ))}
            {engine.warnings.length > 4 && <div>…and {engine.warnings.length - 4} more.</div>}
          </AlertDescription>
        </Alert>
      )}

      {/* summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total realized</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold" style={{ color: gainColor(summary.totalGainCents) }}>
              {money(summary.totalGainCents)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Short-term</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold" style={{ color: gainColor(summary.byTerm.shortCents) }}>
              {money(summary.byTerm.shortCents)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Long-term</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold" style={{ color: gainColor(summary.byTerm.longCents) }}>
              {money(summary.byTerm.longCents)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Unrealized</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-semibold" style={{ color: gainColor(totalUnrealized) }}>
              {money(totalUnrealized)}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* realized lots */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            {summary.totalGainCents >= 0 ? (
              <TrendingUp className="h-4 w-4" />
            ) : (
              <TrendingDown className="h-4 w-4" />
            )}
            Realized gains ({realizedFiltered.length} lot{realizedFiltered.length === 1 ? "" : "s"})
          </CardTitle>
          <CardDescription>Closed lots via {method.toUpperCase()} matching.</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-8 text-center text-sm text-muted-foreground">Loading fills…</div>
          ) : sortedRealized.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">
              No realized lots for this selection.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <SortableHead label="Closed" onClick={() => toggleSort("closeTs")} />
                    <SortableHead label="Opened" />
                    <SortableHead label="Symbol" onClick={() => toggleSort("symbol")} />
                    <SortableHead label="Qty" onClick={() => toggleSort("qty")} align="right" />
                    <SortableHead label="Proceeds" align="right" />
                    <SortableHead label="Cost basis" align="right" />
                    <SortableHead label="Fee" align="right" />
                    <SortableHead label="Gain/Loss" onClick={() => toggleSort("gainCents")} align="right" />
                    <SortableHead label="Days" align="right" />
                    <SortableHead label="Term" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedRealized.map((r, i) => (
                    <TableRow key={`${r.symbol}:${r.closeTs}:${i}`}>
                      <TableCell>{isoDate(r.closeTs)}</TableCell>
                      <TableCell>{isoDate(r.openTs)}</TableCell>
                      <TableCell className="font-medium">{r.symbol}</TableCell>
                      <TableCell className="text-right">{r.qty}</TableCell>
                      <TableCell className="text-right">{money(r.proceedsCents)}</TableCell>
                      <TableCell className="text-right">{money(r.costBasisCents)}</TableCell>
                      <TableCell className="text-right">{money(r.feeCents)}</TableCell>
                      <TableCell className="text-right" style={{ color: gainColor(r.gainCents) }}>
                        {money(r.gainCents)}
                      </TableCell>
                      <TableCell className="text-right">{r.holdingDays}</TableCell>
                      <TableCell>
                        <Badge variant={r.term === "long" ? "secondary" : "outline"}>{r.term}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* by-symbol + unrealized side by side */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Realized by symbol</CardTitle>
          </CardHeader>
          <CardContent>
            {summary.bySymbol.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">No data.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Symbol</TableHead>
                    <TableHead className="text-right">Proceeds</TableHead>
                    <TableHead className="text-right">Gain/Loss</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.bySymbol.map((s) => (
                    <TableRow key={s.symbol}>
                      <TableCell className="font-medium">{s.symbol}</TableCell>
                      <TableCell className="text-right">{money(s.proceedsCents)}</TableCell>
                      <TableCell className="text-right" style={{ color: gainColor(s.gainCents) }}>
                        {money(s.gainCents)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Unrealized (open lots vs mark)</CardTitle>
            <CardDescription>
              {pricesQuery.data?.stub ? "Indicative marks." : "Open positions valued at mark."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {unrealizedRows.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">No open lots.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Symbol</TableHead>
                    <TableHead className="text-right">Qty</TableHead>
                    <TableHead className="text-right">Cost</TableHead>
                    <TableHead className="text-right">Mkt value</TableHead>
                    <TableHead className="text-right">Unrealized</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {unrealizedRows.map((r) => (
                    <TableRow key={r.symbol}>
                      <TableCell className="font-medium">{r.symbol}</TableCell>
                      <TableCell className="text-right">{r.qty}</TableCell>
                      <TableCell className="text-right">{money(r.costBasisCents)}</TableCell>
                      <TableCell className="text-right">
                        {r.noMark ? "—" : money(r.marketValueCents)}
                      </TableCell>
                      <TableCell className="text-right" style={{ color: gainColor(r.unrealizedCents) }}>
                        {r.noMark ? "—" : money(r.unrealizedCents)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── small sortable header ────────────────────────────────────────────

function SortableHead({
  label,
  onClick,
  align,
}: {
  label: string;
  onClick?: () => void;
  align?: "right";
}) {
  return (
    <TableHead className={align === "right" ? "text-right" : undefined}>
      {onClick ? (
        <button type="button" onClick={onClick} className="font-medium hover:underline">
          {label}
        </button>
      ) : (
        label
      )}
    </TableHead>
  );
}
