import { useEffect, useMemo, useRef, useState } from "react";
import { useRegisterShortcuts, type ShortcutEntry } from "@/hooks/useKeyboardShortcuts";
import { useQuery } from "@tanstack/react-query";
import { getFeeSchedule } from "@/api/endpoints/custody";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import {
  useMarginAccount,
  usePmState,
  useExecEvents,
  usePlaceOrder,
  useCancelOrder,
  useBulkCancel,
  useDeposit,
  usePlaceQuote,
  usePlaceAlgo,
  usePlaceOto,
  usePlaceOco,
  usePlaceFunding,
  useSpotBalance,
  useSpotDeposit,
  useMarginConfig,
} from "@/hooks/useTrading";
import { isAck, ackMessage, impliedYes, marginUsedFraction } from "@/api/endpoints/trading";
import type { OrderSide, Fill, PlaceOrderRequest, MarginConfigRequest } from "@/api/endpoints/trading";
import { formatPrice, formatQty, formatTimeNs } from "./format";
import { notional as calcNotional, maxQtyForBalance, riskSizedQty, pctOfBuyingPowerQty, estLiquidationPrice } from "@/lib/orderMath";
import { vibrate, notify, ensureNotifyPermission } from "@/lib/tradeFeedback";
import { tradingFeatures } from "./tradingFeatures";
import { useAuthStore } from "@/stores/authStore";
import { EngineConfigPanel } from "./EngineConfigPanel";
import { PmAdminPanel } from "./PmAdminPanel";
import { StakingAuctionsPanel } from "./StakingAuctionsPanel";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { usePaperMode, selectMarketPrice, isPaperOrderType } from "@/lib/paperMode";
import { placeOrder as placePaperOrder, type PaperAccount } from "@/lib/paperEngine";
import { loadAccount as loadPaperAccount, saveAccount as savePaperAccount, PAPER_ACCOUNT_KEY } from "@/lib/paperStore";
import {
  positionSizeQty,
  riskReward,
  liquidationPreview,
  breakevenPrice,
  twapSchedule,
  icebergClips,
} from "@/lib/orderCalc";
import {
  useAlgoOrders,
  nextAlgoId,
  type AlgoOrder,
  type AlgoChild,
} from "@/lib/algoStore";
import { useAlgoRunner } from "@/lib/algoRunner";

type OrderType = "limit" | "market" | "stop" | "stop_limit" | "take_profit" | "quote" | "oto" | "oco" | "funding";
type Section = "trade" | "positions" | "orders" | "fills";
type SetStr = React.Dispatch<React.SetStateAction<string>>;

const ORDER_TYPES: { id: OrderType; label: string }[] = [
  { id: "limit", label: "Limit" },
  { id: "market", label: "Market" },
  { id: "stop", label: "Stop" },
  { id: "stop_limit", label: "Stop-Limit" },
  { id: "take_profit", label: "Take-Profit" },
  { id: "quote", label: "Quote" },
  { id: "oto", label: "OTO" },
  // Staged surfaces — only surface when their feature flag is on.
  ...(tradingFeatures.OCO_ENABLED ? [{ id: "oco" as OrderType, label: "OCO" }] : []),
  ...(tradingFeatures.FUNDING_ENABLED ? [{ id: "funding" as OrderType, label: "Funding" }] : []),
];
const TIFS = ["GTC", "IOC", "FOK", "GTD"] as const;

interface WorkingOrder {
  clordid: string;
  side: OrderSide;
  price: number;
  qty: number;
  orderid?: number;
}

function Pill({
  active,
  onClick,
  children,
  tag,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  tag?: string;
}) {
  return (
    <button
      type="button"
      data-testid={tag}
      onClick={onClick}
      className={cn(
        "rounded-md border px-2.5 py-1 text-xs font-semibold whitespace-nowrap transition-colors",
        active
          ? "border-primary bg-primary text-primary-foreground"
          : "border-border bg-background text-muted-foreground hover:text-foreground"
      )}
    >
      {children}
    </button>
  );
}

function Field({
  label,
  value,
  onChange,
  onStep,
  dataField,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  onStep?: (delta: number) => void;
  dataField?: string;
}) {
  return (
    <div className="w-full">
      <label className="text-xs text-muted-foreground">{label}</label>
      <div className="mt-1 flex items-center gap-1.5">
        {onStep && (
          <Button type="button" variant="outline" size="icon" aria-label={`Decrease ${label}`} className="h-9 w-9 shrink-0" onClick={() => onStep(-1)}>
            −
          </Button>
        )}
        <Input
          value={value}
          inputMode="numeric"
          placeholder="0"
          data-trade-field={dataField}
          onChange={(e) => onChange(e.target.value.replace(/[^0-9]/g, ""))}
          className="tabular-nums"
        />
        {onStep && (
          <Button type="button" variant="outline" size="icon" aria-label={`Increase ${label}`} className="h-9 w-9 shrink-0" onClick={() => onStep(1)}>
            +
          </Button>
        )}
      </div>
    </div>
  );
}


// ─── Admin: per-symbol margin/fee config ───────────────────────

const MARGIN_CONFIG_FIELDS: {
  key: keyof Omit<MarginConfigRequest, "symbolid">;
  label: string;
  def: string;
}[] = [
  { key: "initial_margin_bps", label: "Initial margin (bps)", def: "1000" },
  { key: "maintenance_margin_bps", label: "Maintenance margin (bps)", def: "500" },
  { key: "liquidation_fee_bps", label: "Liquidation fee (bps)", def: "100" },
  { key: "hourly_borrow_rate_bps", label: "Hourly borrow rate (bps)", def: "1" },
  { key: "maker_fee_bps", label: "Maker fee (bps)", def: "2" },
  { key: "taker_fee_bps", label: "Taker fee (bps)", def: "5" },
  { key: "max_position_qty", label: "Max position qty", def: "1000000" },
];

// Compact maker/taker/liquidation fee schedule card. Sourced from the
// /me/fees/schedule route (per-symbol); 404s until the exchange edge deploys,
// in which case the card hides itself entirely (retry:false, graceful). When
// the backend has no engine-configured row it echoes venue-default rates.
function useIsMobile(bp = 767): boolean {
  const [m, setM] = useState(
    () =>
      typeof window !== "undefined" &&
      window.matchMedia(`(max-width: ${bp}px)`).matches,
  );
  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${bp}px)`);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [bp]);
  return m;
}

function FeeSchedulePanel({ symbolId }: { symbolId: number }) {
  const isMobile = useIsMobile();
  const q = useQuery({
    queryKey: ["fees", "schedule", symbolId],
    queryFn: () => getFeeSchedule(symbolId),
    enabled: symbolId > 0,
    retry: false,
    staleTime: 60_000,
  });

  // Hide entirely when the route isn't available on this backend yet.
  if (q.isError || (!q.isLoading && !q.data)) return null;

  const maker = q.data?.maker_fee_bps;
  const taker = q.data?.taker_fee_bps;
  const liq = q.data?.liquidation_fee_bps;
  const venueDefault = q.data?.source === "venue_default" || q.data?.configured === false;
  const sourceLabel = venueDefault ? "venue default" : "engine";

  return (
    <Card className="mt-3">
      <CardContent className="space-y-2 p-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Fee schedule
          </span>
          <Badge
            variant="outline"
            className={cn(
              "gap-1 text-[10px]",
              venueDefault
                ? "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                : "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
            )}
          >
            {sourceLabel}
          </Badge>
        </div>
        {q.isLoading ? (
          <p className="py-2 text-center text-xs text-muted-foreground">Loading…</p>
        ) : (
          <div className={cn("grid gap-2 text-center", isMobile ? "grid-cols-1" : "grid-cols-3")}>
            <div className="rounded-md border bg-muted/30 p-2">
              <div className="text-[10px] uppercase text-muted-foreground">Maker</div>
              <div className="text-sm font-semibold tabular-nums">{maker ?? "—"} bps</div>
            </div>
            <div className="rounded-md border bg-muted/30 p-2">
              <div className="text-[10px] uppercase text-muted-foreground">Taker</div>
              <div className="text-sm font-semibold tabular-nums">{taker ?? "—"} bps</div>
            </div>
            <div className="rounded-md border bg-muted/30 p-2">
              <div className="text-[10px] uppercase text-muted-foreground">Liq.</div>
              <div className="text-sm font-semibold tabular-nums">{liq ?? "—"} bps</div>
            </div>
          </div>
        )}
        {venueDefault && (
          <p className="text-[10px] text-muted-foreground">
            Shown fees are venue defaults; engine-configured per-symbol rates
            apply once this symbol has a fee schedule set.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function MarginConfigPanel({ symbolId }: { symbolId: number }) {
  const isMobile = useIsMobile();
  const isAdmin = useAuthStore((st) => st.isAdmin);
  const configM = useMarginConfig();
  const [open, setOpen] = useState(false);
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [vals, setVals] = useState<Record<string, string>>(() =>
    Object.fromEntries(MARGIN_CONFIG_FIELDS.map((f) => [f.key, f.def]))
  );
  const [ack, setAck] = useState<{ text: string; error: boolean } | null>(null);

  // Keep the symbol id defaulted to the currently viewed symbol until edited.
  useEffect(() => {
    setSymId(String(symbolId || ""));
  }, [symbolId]);

  if (!isAdmin) return null;

  const symN = parseInt(symId) || 0;
  const nums = Object.fromEntries(
    MARGIN_CONFIG_FIELDS.map((f) => [f.key, parseInt(vals[f.key] ?? "") || 0])
  ) as Record<keyof Omit<MarginConfigRequest, "symbolid">, number>;
  const allValid =
    symN > 0 && MARGIN_CONFIG_FIELDS.every((f) => (parseInt(vals[f.key] ?? "") || 0) >= 0);

  const submit = () => {
    if (!allValid) {
      setAck({ text: "Symbol id must be > 0 and all bps values ≥ 0.", error: true });
      return;
    }
    setAck(null);
    const body: MarginConfigRequest = {
      symbolid: symN,
      initial_margin_bps: nums.initial_margin_bps,
      maintenance_margin_bps: nums.maintenance_margin_bps,
      liquidation_fee_bps: nums.liquidation_fee_bps,
      hourly_borrow_rate_bps: nums.hourly_borrow_rate_bps,
      maker_fee_bps: nums.maker_fee_bps,
      taker_fee_bps: nums.taker_fee_bps,
      max_position_qty: nums.max_position_qty,
    };
    configM.mutate(body, {
      onSuccess: (a) => {
        const okd = a.status === "ack" && (a.result ?? 0) === 0;
        setAck({
          text: okd
            ? `Applied to symbol ${a.symbolid ?? symN}.`
            : `Rejected${a.result != null ? ` (result ${a.result})` : ""}${
                a.detail || a.error || a.note ? `: ${a.detail || a.error || a.note}` : ""
              }`,
          error: !okd,
        });
      },
      onError: (e) => setAck({ text: (e as Error)?.message ?? "Request failed", error: true }),
    });
  };

  return (
    <Card className="border-amber-500/40">
      <CardContent className="pt-4">
        <button
          type="button"
          aria-expanded={open}
          className="flex w-full items-center justify-between text-sm font-semibold text-amber-600 dark:text-amber-400"
          onClick={() => setOpen((v) => !v)}
        >
          <span>Margin config (admin)</span>
          <span aria-hidden>{open ? "▲" : "▼"}</span>
        </button>
        {open && (
          <div className="mt-3 space-y-2">
            <Field label="Symbol id" value={symId} onChange={setSymId} />
            <div className={cn("grid gap-2", isMobile ? "grid-cols-1" : "grid-cols-2")}>
              {MARGIN_CONFIG_FIELDS.map((f) => (
                <Field
                  key={f.key}
                  label={f.label}
                  value={vals[f.key] ?? ""}
                  onChange={(v) => setVals((prev) => ({ ...prev, [f.key]: v }))}
                />
              ))}
            </div>
            <Button
              type="button"
              variant="secondary"
              className="w-full"
              disabled={configM.isPending || !allValid}
              onClick={submit}
            >
              {configM.isPending ? "Applying…" : "Apply margin config"}
            </Button>
            {ack && (
              <p
                className={cn(
                  "text-xs font-mono",
                  ack.error
                    ? "text-rose-600 dark:text-rose-400"
                    : "text-emerald-600 dark:text-emerald-400"
                )}
              >
                {ack.text}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}


export function TradeTicket({
  symbolId,
  scaler,
  lastPrice,
  bestBid,
  bestAsk,
  prefill,
}: {
  symbolId: number;
  scaler: number;
  lastPrice?: number;
  bestBid?: number;
  bestAsk?: number;
  prefill?: { price?: number; side?: OrderSide; nonce: number };
}) {
  const account = useMarginAccount();
  const pm = usePmState(symbolId);
  const exec = useExecEvents();
  const placeM = usePlaceOrder();
  const cancelM = useCancelOrder();
  const bulkM = useBulkCancel();
  const depositM = useDeposit();
  const quoteM = usePlaceQuote();
  const algoM = usePlaceAlgo();
  const otoM = usePlaceOto();
  const ocoM = usePlaceOco();
  const fundingM = usePlaceFunding();
  const spot = useSpotBalance(tradingFeatures.SPOT_ENABLED);
  const spotDepositM = useSpotDeposit();

  // ── PAPER MODE ──────────────────────────────────────────────────────
  // Shared flag + shared `paper.account.v1` account (same one the Paper
  // Trading page uses). When ON, market/limit submits route to the local
  // paper engine instead of the live /me/orders mutations.
  const { enabled: paperMode, setEnabled: setPaperMode } = usePaperMode();
  const [paperAcct, setPaperAcct] = useState<PaperAccount>(() => loadPaperAccount());
  const algoStore = useAlgoOrders();
  const [, forceAlgoTick] = useState(0);
  // Re-read the paper account if another surface (Paper page / other tab) mutates it.
  useEffect(() => {
    const reload = (e?: StorageEvent) => {
      if (e && e.key && e.key !== PAPER_ACCOUNT_KEY) return;
      setPaperAcct(loadPaperAccount());
    };
    window.addEventListener("storage", reload);
    return () => window.removeEventListener("storage", reload);
  }, []);

  const acct = account.data;
  const pmState = pm.data?.is_binary ? pm.data : undefined;

  const [section, setSection] = useState<Section>("trade");
  const [orderType, setOrderType] = useState<OrderType>("limit");
  const [side, setSide] = useState<OrderSide>("buy");
  const [price, setPrice] = useState("");
  const [qty, setQty] = useState("");
  const [stop, setStop] = useState("");
  const [bid, setBid] = useState("");
  const [ask, setAsk] = useState("");
  const [childPrice, setChildPrice] = useState("");
  const [childQty, setChildQty] = useState("");
  const [tif, setTif] = useState<(typeof TIFS)[number]>("GTC");
  const [expiryMin, setExpiryMin] = useState("");
  const [postOnly, setPostOnly] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [aon, setAon] = useState(false);
  const [displayQty, setDisplayQty] = useState("");
  const [minQty, setMinQty] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [depositAmt, setDepositAmt] = useState("");
  const [depositConfirmOpen, setDepositConfirmOpen] = useState(false);
  const [isBorrow, setIsBorrow] = useState(true);
  const [rateBps, setRateBps] = useState("");
  const [fundingQty, setFundingQty] = useState("");
  const [durationSec, setDurationSec] = useState("");
  const [spotAsset, setSpotAsset] = useState("");
  const [spotAmt, setSpotAmt] = useState("");
  const [armed, setArmed] = useState<"market" | "close" | null>(null);
  const [oneTap, setOneTap] = useState(false);
  const [workingOrders, setWorkingOrders] = useState<WorkingOrder[]>([]);
  const [fills, setFills] = useState<Fill[]>([]);
  const [msg, setMsg] = useState<{ text: string; error: boolean } | null>(null);
  // Position-size / risk calculator (collapsible) local inputs.
  const [riskOpen, setRiskOpen] = useState(false);
  const [riskAmt, setRiskAmt] = useState("");
  const [riskStop, setRiskStop] = useState("");
  // Calculators — extra depth inputs (R:R target, leverage, fee bps).
  const [calcTarget, setCalcTarget] = useState("");
  const [calcLeverage, setCalcLeverage] = useState("10");
  const [calcFeeBps, setCalcFeeBps] = useState("10");
  const [riskPct, setRiskPct] = useState("1");
  // Bracket helper — optional attached take-profit + stop-loss on an entry.
  const [bracketOn, setBracketOn] = useState(false);
  const [bracketTp, setBracketTp] = useState("");
  const [bracketSl, setBracketSl] = useState("");
  // Algo mode — client-side TWAP / Iceberg.
  const [algoMode, setAlgoMode] = useState(false);
  const [algoKind, setAlgoKind] = useState<"twap" | "iceberg">("twap");
  const [algoQty, setAlgoQty] = useState("");
  const [algoSlices, setAlgoSlices] = useState("5");
  const [algoDurationSec, setAlgoDurationSec] = useState("60");
  const [algoVisible, setAlgoVisible] = useState("");
  const [algoChildType, setAlgoChildType] = useState<"market" | "limit">("market");

  const seq = useRef(0);
  const nextClordid = () => `t${Date.now()}${seq.current++ % 100}`;

  // ── Trade-view keyboard shortcuts (scoped to the ticket) ─────────────
  const ticketRef = useRef<HTMLDivElement>(null);
  const focusTradeField = (field: "price" | "qty") => {
    const root = ticketRef.current;
    if (!root) return;
    const el = root.querySelector<HTMLInputElement>(`input[data-trade-field="${field}"]`);
    if (el) {
      el.focus();
      el.select();
    }
  };
  const tradeShortcuts = useMemo<ShortcutEntry[]>(() => [
    {
      def: { kind: "single", key: "b", label: "Buy side", group: "Trading" },
      action: () => { setSide("buy"); setArmed((a) => (a ? null : a)); },
    },
    {
      def: { kind: "single", key: "s", label: "Sell side", group: "Trading" },
      action: () => { setSide("sell"); setArmed((a) => (a ? null : a)); },
    },
    {
      def: { kind: "single", key: "p", label: "Focus price", group: "Trading" },
      action: () => focusTradeField("price"),
    },
    {
      def: { kind: "single", key: "q", label: "Focus quantity", group: "Trading" },
      action: () => focusTradeField("qty"),
    },
    {
      def: { kind: "single", key: "escape", label: "Clear / blur inputs", group: "Trading" },
      action: () => {
        const active = document.activeElement as HTMLElement | null;
        if (active && ticketRef.current?.contains(active)) active.blur();
        setArmed((a) => (a ? null : a));
      },
    },
  ], []);
  useRegisterShortcuts(tradeShortcuts);

  // In paper mode only market & limit are simulated — snap the selector back
  // to Limit if a non-paper type was active when paper mode was enabled.
  useEffect(() => {
    if (paperMode && !isPaperOrderType(orderType)) {
      setOrderType("limit");
      resetArmed();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paperMode]);

  // Prefill the price from the last trade while untouched.
  useEffect(() => {
    if (!price && lastPrice && lastPrice > 0) setPrice(String(lastPrice));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastPrice]);

  // Click-to-trade prefill from the book/chart (nonce re-fires on each pick).
  useEffect(() => {
    if (!prefill) return;
    if (prefill.price != null) setPrice(String(prefill.price));
    if (prefill.side) setSide(prefill.side);
    setSection("trade");
    setArmed(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.nonce]);

  // Fold async fills + triggers from the exec-events drain into the local state.
  useEffect(() => {
    const ev = exec.data;
    if (!ev) return;
    if (ev.fills && ev.fills.length) {
      setFills((f) => [...ev.fills!, ...f].slice(0, 100));
      vibrate("success");
      notify("Fill", `Filled ${ev.fills.reduce((sum, x) => sum + (x.qty ?? 0), 0)} on a resting order`);
    }
    const triggers = (ev.triggered?.length ?? 0) + (ev.oto_triggered?.length ?? 0);
    if (triggers > 0) {
      setMsg({ text: `${triggers} algo/OTO trigger(s)`, error: false });
      notify("Algo/OTO triggered", `${triggers} order(s) fired`);
      vibrate("success");
      account.refetch();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [exec.data]);

  const effectiveOrderTypes = paperMode
    ? ORDER_TYPES.filter((t) => isPaperOrderType(t.id))
    : ORDER_TYPES;
  const priceN = parseInt(price) || 0;
  const qtyN = parseInt(qty) || 0;
  const stopN = parseInt(stop) || 0;
  const bidN = parseInt(bid) || 0;
  const askN = parseInt(ask) || 0;
  const childPriceN = parseInt(childPrice) || 0;
  const childQtyN = parseInt(childQty) || 0;
  const rateBpsN = parseInt(rateBps) || 0;
  const fundingQtyN = parseInt(fundingQty) || 0;
  const durationSecN = parseInt(durationSec) || 0;
  const refPrice = priceN || stopN || lastPrice || 0;
  // Buying power reflects the PAPER account cash when paper mode is on so
  // sizing / Max / order-value all key off the simulated balance.
  const avail = paperMode ? paperAcct.cash : (acct?.available_balance ?? 0);
  const orderValue = priceN > 0 && qtyN > 0 ? priceN * qtyN : undefined;
  // ── Order preview math (all client-side, EXACT except the clearly-labeled est.) ──
  // Notional uses the effective ticket price: limit/stop-limit use the entered
  // price; market/stop use the best available quote or last trade as a proxy.
  const previewPrice =
    orderType === "market"
      ? (side === "buy" ? bestAsk : bestBid) ?? lastPrice ?? refPrice
      : refPrice;
  const previewNotional = calcNotional(previewPrice, qtyN);
  const maxAffordableQty = maxQtyForBalance(avail, previewPrice);
  // The exchange does NOT expose initial/maintenance margin bps to the client
  // (the fee schedule only carries maker/taker/liquidation-fee bps). So any
  // liquidation number here is a ROUGH estimate under an assumed default margin,
  // shown with an explicit "(est.)" tag — never presented as authoritative.
  const ASSUMED_INITIAL_MARGIN_BPS = 1000; // 10% — venue-default placeholder
  const ASSUMED_MAINT_MARGIN_BPS = 500; // 5% — venue-default placeholder
  const estMarginRequired =
    previewNotional > 0 ? Math.ceil((previewNotional * ASSUMED_INITIAL_MARGIN_BPS) / 10000) : 0;
  const estLiq =
    previewPrice > 0 && qtyN > 0
      ? estLiquidationPrice(previewPrice, side, ASSUMED_INITIAL_MARGIN_BPS, ASSUMED_MAINT_MARGIN_BPS)
      : null;

  // Fill the qty to the max affordable at the current price for the current side.
  const fillMaxQty = () => {
    if (maxAffordableQty <= 0) return;
    setQty(String(maxAffordableQty));
    vibrate("tick");
    resetArmed();
  };

  // Position-size calculator outputs.
  const riskAmtN = parseInt(riskAmt) || 0;
  const riskStopN = parseInt(riskStop) || 0;
  const riskEntry = refPrice;
  const suggestedQty = riskSizedQty(riskAmtN, riskEntry, riskStopN);
  const applyRiskQty = () => {
    if (suggestedQty <= 0) return;
    setQty(String(suggestedQty));
    vibrate("tick");
    resetArmed();
  };

  // ── Order-entry DEPTH calculators (all pure, via orderCalc). ──────────
  const riskPctN = parseInt(riskPct) || 0;
  const calcTargetN = parseInt(calcTarget) || 0;
  const calcLeverageN = parseInt(calcLeverage) || 0;
  const calcFeeBpsN = parseInt(calcFeeBps) || 0;
  // Risk% sizing keys off the account equity (paper cash in paper mode).
  const equityForSizing = avail;
  const riskPctSuggestedQty = positionSizeQty({
    equityCents: equityForSizing,
    riskPct: riskPctN,
    entryPrice: riskEntry,
    stopPrice: riskStopN,
  });
  const rr = riskReward({
    side,
    entry: riskEntry,
    stop: riskStopN,
    target: calcTargetN,
    qty: qtyN || suggestedQty || riskPctSuggestedQty,
  });
  const liqPrev = liquidationPreview({
    side,
    entry: previewPrice,
    qty: qtyN,
    leverage: calcLeverageN,
    maintenanceMarginBps: ASSUMED_MAINT_MARGIN_BPS,
  });
  const breakeven = breakevenPrice({ side, entry: previewPrice, feeBps: calcFeeBpsN });
  const applyRiskPctQty = () => {
    if (riskPctSuggestedQty <= 0) return;
    setQty(String(riskPctSuggestedQty));
    vibrate("tick");
    resetArmed();
  };

  // ── Bracket helper: attached TP + SL exits on the entry. ──────────────
  const bracketTpN = parseInt(bracketTp) || 0;
  const bracketSlN = parseInt(bracketSl) || 0;
  // Bracket only makes sense on a plain entry (limit / market) with a qty.
  const bracketEligible = orderType === "limit" || orderType === "market";
  const bracketReady = bracketOn && bracketEligible && qtyN > 0 && (bracketTpN > 0 || bracketSlN > 0);

  // ── Algo mode derived preview. ───────────────────────────────────────
  const algoQtyN = parseInt(algoQty) || 0;
  const algoSlicesN = parseInt(algoSlices) || 0;
  const algoDurationSecN = parseInt(algoDurationSec) || 0;
  const algoVisibleN = parseInt(algoVisible) || 0;
  const twapPreview = twapSchedule({
    totalQty: algoQtyN,
    slices: algoSlicesN,
    durationMs: algoDurationSecN * 1000,
    startMs: 0,
  });
  const icebergPreview = icebergClips({ totalQty: algoQtyN, visibleQty: algoVisibleN });
  const algoStartReady =
    algoQtyN > 0 &&
    (algoChildType === "market" || priceN > 0) &&
    (algoKind === "twap"
      ? twapPreview.length > 0 && algoDurationSecN > 0
      : icebergPreview.clips > 0);

  // One-click bid/ask/market prefill — sets side + price only; the user still
  // confirms and submits through the existing money-safety path.
  const prefillBid = () => {
    if (!(bestBid && bestBid > 0)) return;
    setOrderType("limit");
    setSide("buy");
    setPrice(String(bestBid));
    resetArmed();
    vibrate("tick");
  };
  const prefillAsk = () => {
    if (!(bestAsk && bestAsk > 0)) return;
    setOrderType("limit");
    setSide("sell");
    setPrice(String(bestAsk));
    resetArmed();
    vibrate("tick");
  };
  const prefillMarketBuy = () => {
    setOrderType("market");
    setSide("buy");
    resetArmed();
    vibrate("tick");
  };
  const prefillMarketSell = () => {
    setOrderType("market");
    setSide("sell");
    resetArmed();
    vibrate("tick");
  };
  const posQty = acct?.pos_qty ?? 0;
  const hasPosition = (acct?.num_positions ?? 0) > 0 || posQty !== 0;
  const liqPrice = acct?.pos_liquidation_price ?? 0;
  const upnl = acct?.pos_unrealized_pnl ?? 0;
  const liqNear = !!acct?.is_liquidating || (acct?.distress_level ?? 0) > 0;
  const marginPct = Math.round(marginUsedFraction(acct) * 100);

  const resetArmed = () => armed && setArmed(null);
  const setQtyPct = (pct: number) => {
    if (!avail || !refPrice) return;
    const max = Math.floor(avail / refPrice);
    setQty(String(Math.max(pct > 0 ? 1 : 0, Math.floor((max * pct) / 100))));
    vibrate("tick");
    resetArmed();
  };
  const stepField = (setter: SetStr, val: string, delta: number) => {
    vibrate("tick");
    const n = Math.max(0, (parseInt(val) || 0) + delta);
    setter(n === 0 ? "" : String(n));
    resetArmed();
  };

  const canSubmit =
    !placeM.isPending &&
    !algoM.isPending &&
    !quoteM.isPending &&
    !otoM.isPending &&
    !ocoM.isPending &&
    !fundingM.isPending &&
    (() => {
      switch (orderType) {
        case "limit":
          return priceN > 0 && qtyN > 0;
        case "market":
          return qtyN > 0;
        case "stop":
        case "take_profit":
          return stopN > 0 && qtyN > 0;
        case "stop_limit":
          return stopN > 0 && priceN > 0 && qtyN > 0;
        case "quote":
          return bidN > 0 && askN > 0 && qtyN > 0;
        case "oto":
          return priceN > 0 && qtyN > 0 && childPriceN > 0 && childQtyN > 0;
        case "oco":
          return priceN > 0 && qtyN > 0 && childPriceN > 0 && childQtyN > 0;
        case "funding":
          return rateBpsN > 0 && fundingQtyN > 0;
        default:
          return false;
      }
    })();

  type AnyAck = {
    status?: string;
    orderid?: number;
    fills?: Fill[];
    clordid?: string;
    cancelled_qty?: number;
    algo_id?: number;
    oto_id?: number;
    funding_id?: number;
    bid_orderid?: number;
    ask_orderid?: number;
    new_balance?: number;
    detail?: string;
    error?: string;
    note?: string;
    reason?: string | number;
    reasoncode?: number;
  };

  async function handleAck(
    p: Promise<AnyAck>,
    opts: { workingSide?: OrderSide; workingPrice?: number; workingQty?: number; okMsg: (a: AnyAck) => string }
  ) {
    try {
      const a = await p;
      if (isAck(a)) {
        const fl = a.fills ?? [];
        if (fl.length) setFills((f) => [...fl, ...f].slice(0, 100));
        const filled = fl.reduce((s, x) => s + (x.qty ?? 0), 0);
        const leaves = (opts.workingQty ?? 0) - filled;
        if (opts.workingSide && leaves > 0 && a.clordid) {
          setWorkingOrders((w) => [
            ...w,
            { clordid: a.clordid!, side: opts.workingSide!, price: opts.workingPrice ?? 0, qty: leaves, orderid: a.orderid },
          ]);
        }
        setMsg({ text: opts.okMsg(a), error: false });
        if (filled > 0) {
          vibrate("success");
          notify("Order filled", `Filled ${filled}`);
        } else {
          vibrate("tick");
        }
        account.refetch();
      } else {
        vibrate("error");
        setMsg({ text: ackMessage(a) ?? "Rejected", error: true });
      }
    } catch (e) {
      vibrate("error");
      setMsg({ text: (e as Error)?.message ?? "Network error", error: true });
    }
  }

  function submit() {
    ensureNotifyPermission();
    if (orderType === "market" && !oneTap && armed !== "market") {
      vibrate("warn");
      setArmed("market");
      setMsg({
        text: paperMode ? "Tap Confirm paper order to simulate the fill" : "Tap Confirm to send the market order",
        error: false,
      });
      return;
    }
    setArmed(null);
    const cl = nextClordid();
    // PAPER MODE: simulate market & limit locally against the shared paper
    // account. Never hits /me/orders. Other order types are unreachable here
    // because the selector is restricted to market & limit while paper is on.
    if (paperMode && (orderType === "market" || orderType === "limit")) {
      const isMkt = orderType === "market";
      const marketPrice = selectMarketPrice(side, {
        bestBid,
        bestAsk,
        lastPrice,
        refPrice: previewPrice || refPrice,
      });
      const { account: nextAcct, order, fill } = placePaperOrder(
        paperAcct,
        { symbolId, side, type: orderType, price: isMkt ? undefined : priceN, qty: qtyN },
        marketPrice,
      );
      setPaperAcct(nextAcct);
      savePaperAccount(nextAcct);
      if (order.status === "cancelled") {
        vibrate("error");
        setMsg({ text: "Paper order rejected (no market price / zero qty)", error: true });
        toast.error("Paper order rejected");
        return;
      }
      if (fill) {
        vibrate("success");
        setMsg({ text: `Paper ${side} ${qtyN} filled @ ${formatPrice(fill.price, scaler)}`, error: false });
        toast.success("Paper order placed");
      } else {
        vibrate("tick");
        setWorkingOrders((w) => [
          ...w,
          { clordid: order.id, side, price: priceN, qty: qtyN },
        ]);
        setMsg({ text: `Paper limit resting: ${side} ${qtyN} @ ${formatPrice(priceN, scaler)}`, error: false });
        toast.success("Paper order placed");
      }
      return;
    }
    if (orderType === "limit" || orderType === "market") {
      const isMarket = orderType === "market";
      const body: PlaceOrderRequest = {
        symbolid: symbolId,
        side,
        price: isMarket ? 0 : priceN,
        qty: qtyN,
        clordid: cl,
        market: isMarket || undefined,
        tif: !isMarket && tif !== "GTC" ? tif : undefined,
        post_only: postOnly || undefined,
        hidden: hidden || undefined,
        aon: aon || undefined,
        display_qty: parseInt(displayQty) || undefined,
        min_qty: parseInt(minQty) || undefined,
        expiry_ns:
          !isMarket && tif === "GTD" && expiryMin
            ? (Date.now() + parseInt(expiryMin) * 60000) * 1_000_000
            : undefined,
      };
      const entryQty = qtyN;
      const entrySide = side;
      const attachBracket = bracketReady;
      void handleAck(placeM.mutateAsync(body), {
        workingSide: side,
        workingPrice: priceN,
        workingQty: isMarket ? 0 : qtyN,
        okMsg: (a) => `Placed #${a.orderid ?? "?"}`,
      }).then(() => {
        if (attachBracket) placeBracketExits(entrySide, entryQty);
      });
    } else if (orderType === "stop" || orderType === "stop_limit" || orderType === "take_profit") {
      const algoType = orderType === "stop" ? "stop_market" : orderType === "stop_limit" ? "stop_limit" : "take_profit";
      void handleAck(
        algoM.mutateAsync({
          algo_type: algoType,
          symbolid: symbolId,
          side,
          qty: qtyN,
          stop_price: stopN,
          limit_price: algoType === "stop_market" ? undefined : priceN || undefined,
        }),
        { okMsg: (a) => `Algo #${(a as { algo_id?: number }).algo_id ?? "?"} armed` }
      );
    } else if (orderType === "quote") {
      void handleAck(
        quoteM.mutateAsync({ symbolid: symbolId, bid_price: bidN, ask_price: askN, bid_qty: qtyN, ask_qty: qtyN }),
        {
          okMsg: (a) =>
            `Quote bid #${(a as { bid_orderid?: number }).bid_orderid ?? 0} / ask #${
              (a as { ask_orderid?: number }).ask_orderid ?? 0
            }`,
        }
      );
    } else if (orderType === "oto") {
      const childSide: OrderSide = side === "buy" ? "sell" : "buy";
      void handleAck(
        otoM.mutateAsync({
          symbolid: symbolId,
          parent_side: side,
          parent_price: priceN,
          parent_qty: qtyN,
          child_side: childSide,
          child_price: childPriceN,
          child_qty: childQtyN,
        }),
        { okMsg: (a) => `OTO #${(a as { oto_id?: number }).oto_id ?? "?"}` }
      );
    } else if (orderType === "oco") {
      const legBSide: OrderSide = side === "buy" ? "sell" : "buy";
      void handleAck(
        ocoM.mutateAsync({
          symbolId,
          legs: [
            { side, price: priceN, qty: qtyN },
            { side: legBSide, price: childPriceN, qty: childQtyN },
          ],
        }),
        { okMsg: (a) => `OCO placed #${a.orderid ?? "?"}` }
      );
    } else if (orderType === "funding") {
      void handleAck(
        fundingM.mutateAsync({
          rate_bps: rateBpsN,
          qty: fundingQtyN,
          is_borrow: isBorrow,
          duration_seconds: durationSecN > 0 ? durationSecN : undefined,
          symbolid: symbolId,
        }),
        { okMsg: (a) => `Funding #${(a as { funding_id?: number }).funding_id ?? "?"} (${isBorrow ? "borrow" : "lend"})` }
      );
    }
  }

  function closePosition() {
    if (!posQty) return;
    if (!oneTap && armed !== "close") {
      vibrate("warn");
      setArmed("close");
      setMsg({ text: "Tap Confirm close to flatten the position", error: false });
      return;
    }
    setArmed(null);
    const closeSide: OrderSide = posQty > 0 ? "sell" : "buy";
    const q = Math.abs(posQty);
    const colliding = workingOrders.filter((w) => w.side !== closeSide);
    colliding.forEach((w) => cancelM.mutate({ clordid: w.clordid, symbolId }));
    if (colliding.length) setWorkingOrders((w) => w.filter((x) => !colliding.some((c) => c.clordid === x.clordid)));
    void handleAck(
      placeM.mutateAsync({ symbolid: symbolId, side: closeSide, price: 0, qty: q, clordid: nextClordid(), market: true }),
      { okMsg: () => `Closing (${closeSide === "sell" ? "sold" : "bought"} ${q})` }
    );
  }

  // Bracket: place the linked TP + SL exit legs after the entry submits. TP is a
  // take-profit exit and SL a stop-market exit, both on the OPPOSITE side of the
  // entry (a long brackets with sell exits). Reuses the existing algo order types;
  // if a leg is rejected the user gets a clear, non-fatal message.
  function placeBracketExits(entrySide: OrderSide, entryQty: number) {
    if (entryQty <= 0) return;
    const exitSide: OrderSide = entrySide === "buy" ? "sell" : "buy";
    const legs: Promise<AnyAck>[] = [];
    if (bracketTpN > 0) {
      legs.push(
        algoM.mutateAsync({
          algo_type: "take_profit",
          symbolid: symbolId,
          side: exitSide,
          qty: entryQty,
          stop_price: bracketTpN,
        }) as Promise<AnyAck>,
      );
    }
    if (bracketSlN > 0) {
      legs.push(
        algoM.mutateAsync({
          algo_type: "stop_market",
          symbolid: symbolId,
          side: exitSide,
          qty: entryQty,
          stop_price: bracketSlN,
        }) as Promise<AnyAck>,
      );
    }
    if (legs.length === 0) return;
    Promise.allSettled(legs).then((results) => {
      const ok = results.filter((r) => r.status === "fulfilled" && isAck(r.value as AnyAck)).length;
      const rejected = results.length - ok;
      if (rejected > 0) {
        setMsg({
          text: `Entry placed; ${ok}/${results.length} bracket exit(s) attached — ${rejected} rejected by the venue`,
          error: true,
        });
        toast.error("Some bracket legs were rejected");
      } else {
        setMsg({ text: `Bracket attached: ${ok} exit leg(s) armed`, error: false });
        toast.success("Bracket exits attached");
      }
      account.refetch();
    });
  }

  const cancelOne = (clo: string) => {
    // Paper resting orders are local-only — never hit the real cancel endpoint.
    if (paperMode) {
      setWorkingOrders((w) => w.filter((x) => x.clordid !== clo));
      setMsg({ text: "Paper order cancelled", error: false });
      return;
    }
    return cancelM.mutate(
      { clordid: clo, symbolId },
      {
        onSuccess: (a) => {
          if (isAck(a)) {
            setWorkingOrders((w) => w.filter((x) => x.clordid !== clo));
            setMsg({ text: `Cancelled ${a.cancelled_qty ?? ""}`, error: false });
            account.refetch();
          }
        },
      }
    );
  };
  const cancelAll = () =>
    bulkM.mutate(undefined, {
      onSuccess: (a) => {
        setWorkingOrders([]);
        setMsg({ text: `Cancelled all (${a.cancelled_count ?? 0})`, error: false });
        account.refetch();
      },
    });
  const depositAmtN = parseInt(depositAmt) || 0;
  const deposit = () => {
    const amt = depositAmtN;
    if (amt <= 0) return;
    depositM.mutate(amt, {
      onSuccess: (a) => {
        setDepositAmt("");
        setDepositConfirmOpen(false);
        vibrate(isAck(a) ? "success" : "error");
        setMsg({ text: isAck(a) ? `Deposited ${amt} collateral (available ${a.available_balance ?? a.new_balance})` : ackMessage(a) ?? "Deposit rejected", error: !isAck(a) });
        account.refetch();
      },
      onError: () => {
        setDepositConfirmOpen(false);
        vibrate("error");
        setMsg({ text: "Deposit failed", error: true });
      },
    });
  };

  const isPm = !!pmState;
  const buyLabel = isPm ? "YES" : "Buy";
  const sellLabel = isPm ? "NO" : "Sell";
  const submitLabel = useMemo(() => {
    if (armed === "market")
      return paperMode
        ? `Confirm paper order — ${side === "buy" ? "Buy" : "Sell"} ${qty} @ market`
        : `Confirm ${side === "buy" ? "Buy" : "Sell"} ${qty} @ market`;
    const s = side === "buy" ? "Buy" : "Sell";
    switch (orderType) {
      case "limit":
        return `${s} ${qty}`.trim();
      case "market":
        return `${s} ${qty} (market)`.trim();
      case "stop":
        return `${s} Stop`;
      case "stop_limit":
        return `${s} Stop-Limit`;
      case "take_profit":
        return `${s} Take-Profit`;
      case "quote":
        return "Place quote";
      case "oto":
        return `Place OTO (${s} parent)`;
      case "oco":
        return `Place OCO (${s} leg A)`;
      case "funding":
        return isBorrow ? "Borrow funding" : "Lend funding";
      default:
        return "Submit";
    }
  }, [armed, side, qty, orderType, isBorrow, paperMode]);

  // ── ALGO ORDERS: client-side runner wiring. ──────────────────────────
  // The runner places child orders for RUNNING algos on THIS symbol via the
  // same primitives the ticket uses. Live children go through placeM; paper
  // children route to the shared paper engine. Runs only while mounted.
  const placeLiveChild = async (args: {
    side: OrderSide;
    type: "market" | "limit";
    price?: number;
    qty: number;
  }): Promise<{ filled: boolean; fillPrice?: number }> => {
    const isMarket = args.type === "market";
    const a = await placeM.mutateAsync({
      symbolid: symbolId,
      side: args.side,
      price: isMarket ? 0 : args.price ?? 0,
      qty: args.qty,
      clordid: nextClordid(),
      market: isMarket || undefined,
    });
    if (isAck(a)) {
      const fl = a.fills ?? [];
      if (fl.length) {
        const filledQ = fl.reduce((sum, x) => sum + (x.qty ?? 0), 0);
        const fillPrice = fl[0]?.price;
        if (filledQ >= args.qty) return { filled: true, fillPrice };
      }
      // Placed but not (fully) filled — for a market child treat as filled, for a
      // limit child leave resting (advance on the next ack cycle).
      return { filled: isMarket, fillPrice: undefined };
    }
    throw new Error(ackMessage(a) ?? "child rejected");
  };

  useAlgoRunner({
    symbolId,
    quotes: { bestBid, bestAsk, lastPrice },
    placeLiveChild,
    paperAccount: paperAcct,
    commitPaper: (acctNext) => {
      setPaperAcct(acctNext);
      savePaperAccount(acctNext);
    },
    onProgress: () => forceAlgoTick((n) => n + 1),
  });

  // Build + persist a new algo, then it starts running immediately (status
  // "running" is picked up by the runner on its next tick).
  function startAlgo() {
    if (!algoStartReady) return;
    const now = Date.now();
    const isTwap = algoKind === "twap";
    let children: AlgoChild[];
    if (isTwap) {
      children = twapPreview.map((sl) => ({
        seq: sl.seq,
        qty: sl.qty,
        atMs: now + sl.atMs,
        status: "pending" as const,
      }));
    } else {
      const ic = icebergClips({ totalQty: algoQtyN, visibleQty: algoVisibleN });
      children = [];
      for (let i = 0; i < ic.clips; i++) {
        children.push({
          seq: i,
          qty: i === ic.clips - 1 ? ic.lastClipQty : ic.clipQty,
          status: "pending" as const,
        });
      }
    }
    const order: AlgoOrder = {
      id: nextAlgoId(),
      kind: algoKind,
      symbolId,
      symbolLabel: `#${symbolId}`,
      side,
      childType: algoChildType,
      limitPrice: algoChildType === "limit" ? priceN : undefined,
      totalQty: algoQtyN,
      slices: isTwap ? twapPreview.length : undefined,
      durationMs: isTwap ? algoDurationSecN * 1000 : undefined,
      visibleQty: isTwap ? undefined : algoVisibleN,
      paper: paperMode,
      status: "running",
      children,
      createdAt: now,
      updatedAt: now,
    };
    algoStore.add(order);
    vibrate("success");
    toast.success(`${isTwap ? "TWAP" : "Iceberg"} started — ${children.length} ${isTwap ? "slices" : "clips"}`);
    setMsg({
      text: `${isTwap ? "TWAP" : "Iceberg"} ${side} ${algoQtyN} started (${children.length} children)`,
      error: false,
    });
  }

  const sections: { id: Section; label: string; count?: number }[] = [
    { id: "trade", label: "Trade" },
    { id: "positions", label: "Positions", count: posQty ? 1 : 0 },
    { id: "orders", label: "Orders", count: workingOrders.length },
    { id: "fills", label: "Fills", count: fills.length },
  ];

  return (
    <div className="space-y-3" ref={ticketRef}>
    <Card className={cn(paperMode && "border-2 border-amber-500/70 bg-amber-500/[0.03]")}>
      <CardContent className="space-y-3 pt-6">
        {/* Paper-mode toggle + banner */}
        <div className="flex items-center justify-between rounded-lg border px-3 py-2">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold">Paper</span>
            {paperMode && (
              <Badge
                data-testid="paper_badge"
                className="bg-amber-500 text-amber-950 hover:bg-amber-500"
              >
                PAPER
              </Badge>
            )}
          </div>
          <Switch
            checked={paperMode}
            onCheckedChange={(v) => {
              setPaperMode(v);
              resetArmed();
              vibrate("tick");
            }}
            aria-label="Paper trading mode"
            data-testid="paper_toggle"
            className="data-[state=checked]:bg-amber-500"
          />
        </div>
        {paperMode && (
          <div
            data-testid="paper_banner"
            className="rounded-lg border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-xs font-semibold text-amber-700 dark:text-amber-300"
          >
            PAPER MODE — orders are simulated locally against your paper account. Nothing is sent to the exchange.
          </div>
        )}
        {/* Prediction-market banner */}
        {isPm && pmState && (
          <div
            className={cn(
              "rounded-lg border p-3",
              pmState.state === "resolved" ? "border-border bg-muted/40" : "border-primary/50"
            )}
          >
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-primary">Prediction market</span>
              <span className="text-xs tabular-nums text-muted-foreground">payout {formatPrice(pmState.face_value, scaler)}</span>
            </div>
            {pmState.state === "resolved" ? (
              <p
                className={cn(
                  "mt-1 text-sm font-bold",
                  pmState.outcome === 1 ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"
                )}
              >
                Resolved: {pmState.outcome === 1 ? "YES" : "NO"} —{" "}
                {pmState.outcome === 1 ? `YES pays ${formatPrice(pmState.face_value, scaler)}` : "YES pays 0"}
              </p>
            ) : (
              <>
                <div className="mt-1 flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Implied YES</span>
                  <span className="font-bold tabular-nums text-emerald-600 dark:text-emerald-400">
                    {(() => {
                      const p = impliedYes(lastPrice, pmState.face_value);
                      return p == null ? "—" : `${Math.round(p * 100)}%`;
                    })()}
                  </span>
                </div>
                <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-rose-500/30">
                  <div
                    className="h-full bg-emerald-500"
                    style={{ width: `${Math.round((impliedYes(lastPrice, pmState.face_value) ?? 0) * 100)}%` }}
                  />
                </div>
              </>
            )}
          </div>
        )}

        {/* Account strip */}
        {paperMode && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/[0.04] p-3 text-sm" data-testid="paper_account_strip">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Paper cash</span>
              <span className="tabular-nums font-semibold">{formatPrice(paperAcct.cash, scaler)}</span>
            </div>
            <div className="mt-1 flex justify-between text-xs text-muted-foreground">
              <span>Buying power</span>
              <span className="tabular-nums">{formatPrice(paperAcct.cash, scaler)}</span>
            </div>
            <div className="mt-1 flex justify-between text-xs text-muted-foreground">
              <span>Realized PnL</span>
              <span
                className={cn(
                  "tabular-nums",
                  paperAcct.realizedPnl >= 0
                    ? "text-emerald-600 dark:text-emerald-400"
                    : "text-rose-600 dark:text-rose-400",
                )}
              >
                {paperAcct.realizedPnl >= 0 ? "+" : ""}
                {formatPrice(paperAcct.realizedPnl, scaler)}
              </span>
            </div>
          </div>
        )}

        {/* Real account strip (hidden in paper mode) */}
        {!paperMode && acct && (
          <div className="rounded-lg border p-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Available</span>
              <span className="tabular-nums">{formatPrice(acct.available_balance, scaler)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Reserved margin</span>
              <span className="tabular-nums">{formatPrice(acct.reserved_margin, scaler)}</span>
            </div>
            <div className="mt-1 flex items-center justify-between text-xs text-muted-foreground">
              <span>Margin used</span>
              <span className="tabular-nums">{marginPct}%</span>
            </div>
            <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-muted">
              <div className={cn("h-full", acct.is_liquidating ? "bg-rose-500" : "bg-primary")} style={{ width: `${Math.max(1, marginPct)}%` }} />
            </div>
            {(acct.is_liquidating || (acct.distress_level ?? 0) > 0) && (
              <p className="mt-1 text-xs font-bold text-rose-600 dark:text-rose-400">
                ⚠ {acct.is_liquidating ? "Liquidating" : `Distress ${acct.distress_level}`}
              </p>
            )}
            {hasPosition && (
              <div className="mt-2 border-t pt-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-muted-foreground">Position</span>
                  <span
                    className={cn(
                      "text-xs font-bold tabular-nums",
                      posQty > 0
                        ? "text-emerald-600 dark:text-emerald-400"
                        : posQty < 0
                        ? "text-rose-600 dark:text-rose-400"
                        : "text-muted-foreground"
                    )}
                  >
                    {posQty > 0 ? "Long" : posQty < 0 ? "Short" : "Flat"} {formatQty(Math.abs(posQty), scaler)}
                  </span>
                </div>
                <div className="mt-1 grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <div className="text-muted-foreground">Entry</div>
                    <div className="tabular-nums">{formatPrice(acct.pos_entry_price, scaler)}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Liq.</div>
                    <div className={cn("tabular-nums font-medium", liqNear && "text-rose-600 dark:text-rose-400")}>
                      {liqPrice ? formatPrice(liqPrice, scaler) : "—"}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-muted-foreground">uPnL</div>
                    <div
                      className={cn(
                        "tabular-nums font-medium",
                        upnl >= 0 ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"
                      )}
                    >
                      {upnl >= 0 ? "+" : ""}
                      {formatPrice(upnl, scaler)}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Section tabs — horizontally scrollable on mobile, equal-width segmented on sm+ */}
        <div className="flex gap-1 overflow-x-auto rounded-lg bg-muted p-1 scrollbar-hide">
          {sections.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => {
                setSection(s.id);
                resetArmed();
              }}
              className={cn(
                "shrink-0 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors sm:flex-1 sm:shrink sm:px-0",
                section === s.id ? "bg-background text-foreground shadow-sm" : "text-muted-foreground"
              )}
            >
              {s.label}
              {s.count ? ` ${s.count}` : ""}
            </button>
          ))}
        </div>

        {section === "trade" && (
          <div className="space-y-3">
            {/* Order type */}
            <div className="flex gap-1.5 overflow-x-auto pb-1">
              {effectiveOrderTypes.map((t) => (
                <Pill
                  key={t.id}
                  active={orderType === t.id}
                  onClick={() => {
                    vibrate("tick");
                    setOrderType(t.id);
                    resetArmed();
                  }}
                  tag={`otype_${t.id}`}
                >
                  {t.label}
                </Pill>
              ))}
            </div>
            {paperMode && (
              <p className="-mt-1 text-[11px] text-amber-600 dark:text-amber-400" data-testid="paper_order_type_note">
                Simulated in paper mode: market &amp; limit only.
              </p>
            )}

            {/* ── ALGO MODE (client-side TWAP / Iceberg) ─────────────── */}
            {!isPm && (
              <div className="rounded-lg border p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold">Algo order</p>
                    <p className="text-[11px] text-muted-foreground">Client-side TWAP / Iceberg</p>
                  </div>
                  <Switch checked={algoMode} onCheckedChange={setAlgoMode} data-testid="algo_mode_toggle" />
                </div>
                {algoMode && (
                  <div className="mt-3 space-y-3">
                    <div className="flex gap-1.5">
                      <Pill active={algoKind === "twap"} onClick={() => setAlgoKind("twap")} tag="algo_kind_twap">
                        TWAP
                      </Pill>
                      <Pill active={algoKind === "iceberg"} onClick={() => setAlgoKind("iceberg")} tag="algo_kind_iceberg">
                        Iceberg
                      </Pill>
                    </div>
                    <div className="flex gap-1.5">
                      <Pill active={algoChildType === "market"} onClick={() => setAlgoChildType("market")} tag="algo_child_market">
                        Market children
                      </Pill>
                      <Pill active={algoChildType === "limit"} onClick={() => setAlgoChildType("limit")} tag="algo_child_limit">
                        Limit children
                      </Pill>
                    </div>
                    {algoChildType === "limit" && (
                      <Field label="Child limit price" value={price} onChange={setPrice} dataField="price" />
                    )}
                    <Field label="Total quantity" value={algoQty} onChange={setAlgoQty} />
                    {algoKind === "twap" ? (
                      <div className="grid grid-cols-2 gap-2">
                        <Field label="# slices" value={algoSlices} onChange={setAlgoSlices} />
                        <Field label="Duration (sec)" value={algoDurationSec} onChange={setAlgoDurationSec} />
                      </div>
                    ) : (
                      <Field label="Visible clip size" value={algoVisible} onChange={setAlgoVisible} />
                    )}
                    <div className="rounded-md border bg-muted/20 p-2 text-xs" data-testid="algo_preview">
                      {algoKind === "twap" ? (
                        <span>
                          {twapPreview.length > 0
                            ? `${twapPreview.length} slice(s) · ~${formatQty(twapPreview[0]!.qty, scaler)}/slice over ${algoDurationSecN}s`
                            : "Enter qty, slices & duration"}
                        </span>
                      ) : (
                        <span>
                          {icebergPreview.clips > 0
                            ? `${icebergPreview.clips} clip(s) · ${formatQty(icebergPreview.clipQty, scaler)} visible, last ${formatQty(icebergPreview.lastClipQty, scaler)}`
                            : "Enter total & visible size"}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-amber-600 dark:text-amber-400">
                      Client-side algos run only while this tab is open.
                      {paperMode ? " Children route to your paper account." : ""}
                    </p>
                    <Button
                      type="button"
                      className={cn("w-full", side === "buy" ? "bg-emerald-600 hover:bg-emerald-600/90" : "bg-rose-600 hover:bg-rose-600/90")}
                      disabled={!algoStartReady}
                      onClick={startAlgo}
                      data-testid="algo_start"
                    >
                      Start {algoKind === "twap" ? "TWAP" : "Iceberg"} ({side === "buy" ? "Buy" : "Sell"})
                    </Button>
                  </div>
                )}
              </div>
            )}

            {/* One-click bid/ask + market quick-actions (prefill only — the
                user still confirms/submits via the existing path). */}
            {!isPm && orderType !== "quote" && orderType !== "funding" && (bestBid || bestAsk) && (
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  data-testid="quick_bid"
                  disabled={!(bestBid && bestBid > 0)}
                  onClick={prefillBid}
                  className="flex-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-xs font-semibold tabular-nums text-emerald-600 disabled:opacity-40 dark:text-emerald-400"
                >
                  Buy @ bid {bestBid ? formatPrice(bestBid, scaler) : "—"}
                </button>
                <button
                  type="button"
                  data-testid="quick_ask"
                  disabled={!(bestAsk && bestAsk > 0)}
                  onClick={prefillAsk}
                  className="flex-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-xs font-semibold tabular-nums text-rose-600 disabled:opacity-40 dark:text-rose-400"
                >
                  Sell @ ask {bestAsk ? formatPrice(bestAsk, scaler) : "—"}
                </button>
                <button
                  type="button"
                  data-testid="quick_market_buy"
                  onClick={prefillMarketBuy}
                  className="rounded-md border px-2 py-1 text-xs font-semibold text-muted-foreground hover:text-foreground"
                >
                  Mkt buy
                </button>
                <button
                  type="button"
                  data-testid="quick_market_sell"
                  onClick={prefillMarketSell}
                  className="rounded-md border px-2 py-1 text-xs font-semibold text-muted-foreground hover:text-foreground"
                >
                  Mkt sell
                </button>
              </div>
            )}

            {/* Side (hidden for quote / funding) */}
            {orderType !== "quote" && orderType !== "funding" && (
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant={side === "buy" ? "default" : "outline"}
                  className={cn("flex-1", side === "buy" && "bg-emerald-600 hover:bg-emerald-600/90")}
                  onClick={() => {
                    vibrate("tick");
                    setSide("buy");
                    resetArmed();
                  }}
                >
                  {buyLabel}
                </Button>
                <Button
                  type="button"
                  variant={side === "sell" ? "default" : "outline"}
                  className={cn("flex-1", side === "sell" && "bg-rose-600 hover:bg-rose-600/90")}
                  onClick={() => {
                    vibrate("tick");
                    setSide("sell");
                    resetArmed();
                  }}
                >
                  {sellLabel}
                </Button>
              </div>
            )}

            {/* Type-specific fields */}
            {orderType === "limit" && (
              <>
                <Field label="Price" value={price} onChange={setPrice} onStep={(d) => stepField(setPrice, price, d)} dataField="price" />
                <Field label="Quantity" value={qty} onChange={setQty} onStep={(d) => stepField(setQty, qty, d)} dataField="qty" />
              </>
            )}
            {orderType === "market" && <Field label="Quantity" value={qty} onChange={setQty} onStep={(d) => stepField(setQty, qty, d)} />}
            {orderType === "stop" && (
              <>
                <Field label="Stop (trigger) price" value={stop} onChange={setStop} onStep={(d) => stepField(setStop, stop, d)} />
                <Field label="Quantity" value={qty} onChange={setQty} onStep={(d) => stepField(setQty, qty, d)} />
              </>
            )}
            {orderType === "stop_limit" && (
              <>
                <Field label="Stop (trigger) price" value={stop} onChange={setStop} onStep={(d) => stepField(setStop, stop, d)} />
                <Field label="Limit price" value={price} onChange={setPrice} onStep={(d) => stepField(setPrice, price, d)} />
                <Field label="Quantity" value={qty} onChange={setQty} onStep={(d) => stepField(setQty, qty, d)} />
              </>
            )}
            {orderType === "take_profit" && (
              <>
                <Field label="Take-profit trigger" value={stop} onChange={setStop} onStep={(d) => stepField(setStop, stop, d)} />
                <Field label="Limit price (optional)" value={price} onChange={setPrice} />
                <Field label="Quantity" value={qty} onChange={setQty} onStep={(d) => stepField(setQty, qty, d)} />
              </>
            )}
            {orderType === "quote" && (
              <div className="grid grid-cols-2 gap-2">
                <Field label="Bid price" value={bid} onChange={setBid} />
                <Field label="Ask price" value={ask} onChange={setAsk} />
                <div className="col-span-2">
                  <Field label="Quantity (each side)" value={qty} onChange={setQty} />
                </div>
              </div>
            )}
            {orderType === "oto" && (
              <div className="grid grid-cols-2 gap-2">
                <Field label="Parent price" value={price} onChange={setPrice} />
                <Field label="Parent qty" value={qty} onChange={setQty} />
                <Field label="Child price" value={childPrice} onChange={setChildPrice} />
                <Field label="Child qty" value={childQty} onChange={setChildQty} />
                <p className="col-span-2 text-xs text-muted-foreground">
                  Child = {side === "buy" ? "Sell" : "Buy"} · triggers when the parent fills
                </p>
              </div>
            )}
            {orderType === "oco" && (
              <div className="grid grid-cols-2 gap-2">
                <Field label={`Leg A price (${side === "buy" ? "Buy" : "Sell"})`} value={price} onChange={setPrice} />
                <Field label="Leg A qty" value={qty} onChange={setQty} />
                <Field label={`Leg B price (${side === "buy" ? "Sell" : "Buy"})`} value={childPrice} onChange={setChildPrice} />
                <Field label="Leg B qty" value={childQty} onChange={setChildQty} />
                <p className="col-span-2 text-xs text-muted-foreground">
                  Leg B = opposite side; a fill on one cancels the other.
                </p>
              </div>
            )}
            {orderType === "funding" && (
              <div className="space-y-2">
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant={isBorrow ? "default" : "outline"}
                    className={cn("flex-1", isBorrow && "bg-emerald-600 hover:bg-emerald-600/90")}
                    onClick={() => {
                      vibrate("tick");
                      setIsBorrow(true);
                      resetArmed();
                    }}
                  >
                    Borrow
                  </Button>
                  <Button
                    type="button"
                    variant={!isBorrow ? "default" : "outline"}
                    className={cn("flex-1", !isBorrow && "bg-rose-600 hover:bg-rose-600/90")}
                    onClick={() => {
                      vibrate("tick");
                      setIsBorrow(false);
                      resetArmed();
                    }}
                  >
                    Lend
                  </Button>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Rate (bps)" value={rateBps} onChange={setRateBps} onStep={(d) => stepField(setRateBps, rateBps, d)} />
                  <Field label="Quantity" value={fundingQty} onChange={setFundingQty} onStep={(d) => stepField(setFundingQty, fundingQty, d)} />
                </div>
                <Field label="Duration (seconds, optional)" value={durationSec} onChange={setDurationSec} />
              </div>
            )}

            {/* Quick-size */}
            {(orderType === "limit" ||
              orderType === "market" ||
              orderType === "stop" ||
              orderType === "stop_limit" ||
              orderType === "take_profit") && (
              <div className="flex gap-1.5">
                {[25, 50, 75, 100].map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setQtyPct(p)}
                    className="flex-1 rounded-md border py-1 text-xs tabular-nums text-muted-foreground hover:text-foreground"
                  >
                    {p === 100 ? "Max" : `${p}%`}
                  </button>
                ))}
              </div>
            )}

            {/* ── BRACKET HELPER: attached TP + SL on the entry ──────── */}
            {!isPm && bracketEligible && !algoMode && (
              <div className="rounded-lg border p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold">Bracket exits</p>
                    <p className="text-[11px] text-muted-foreground">
                      Attach take-profit + stop-loss on this {side === "buy" ? "long" : "short"} entry
                    </p>
                  </div>
                  <Switch checked={bracketOn} onCheckedChange={setBracketOn} data-testid="bracket_toggle" />
                </div>
                {bracketOn && (
                  <div className="mt-3 grid grid-cols-2 gap-2">
                    <Field label="Take-profit price" value={bracketTp} onChange={setBracketTp} />
                    <Field label="Stop-loss price" value={bracketSl} onChange={setBracketSl} />
                    <p className="col-span-2 text-[11px] text-muted-foreground" data-testid="bracket_note">
                      Exits are placed as {side === "buy" ? "Sell" : "Buy"} take-profit / stop after the entry submits.
                      {bracketReady ? "" : " Enter a qty and at least one exit price."}
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* TIF (limit only) */}
            {orderType === "limit" && (
              <div>
                <label className="text-xs text-muted-foreground">Time in force</label>
                <div className="mt-1 flex gap-1.5">
                  {TIFS.map((t) => (
                    <Pill key={t} active={tif === t} onClick={() => setTif(t)} tag={`tif_${t}`}>
                      {t}
                    </Pill>
                  ))}
                </div>
                {tif === "GTD" && <Field label="Expires in (minutes)" value={expiryMin} onChange={setExpiryMin} />}
              </div>
            )}

            {/* Order value */}
            {orderType === "limit" && (
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Order value</span>
                <span className={cn("tabular-nums", orderValue && orderValue > avail ? "text-rose-600 dark:text-rose-400" : "")}>
                  {orderValue != null ? formatPrice(orderValue, scaler) : "—"} · avail {formatPrice(avail, scaler)}
                </span>
              </div>
            )}

            {/* Advanced */}
            {(orderType === "limit" || orderType === "market") && (
              <div>
                <button type="button" aria-expanded={advancedOpen} className="text-xs font-semibold text-primary" onClick={() => setAdvancedOpen((v) => !v)}>
                  Advanced <span aria-hidden>{advancedOpen ? "▲" : "▼"}</span>
                </button>
                {advancedOpen && (
                  <div className="mt-2 space-y-2">
                    <div className="flex flex-wrap gap-1.5">
                      {orderType === "limit" && (
                        <Pill active={postOnly} onClick={() => setPostOnly((v) => !v)} tag="flag_post_only">
                          Post-only
                        </Pill>
                      )}
                      <Pill active={hidden} onClick={() => setHidden((v) => !v)} tag="flag_hidden">
                        Hidden
                      </Pill>
                      <Pill active={aon} onClick={() => setAon((v) => !v)} tag="flag_aon">
                        AON
                      </Pill>
                      <Pill active={oneTap} onClick={() => setOneTap((v) => !v)} tag="flag_one_tap">
                        1-tap
                      </Pill>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <Field label="Display qty (iceberg)" value={displayQty} onChange={setDisplayQty} />
                      <Field label="Min qty" value={minQty} onChange={setMinQty} />
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Order preview — live, computed client-side. */}
            {orderType !== "funding" && orderType !== "quote" && (
              <div className="space-y-1.5 rounded-lg border bg-muted/20 p-3 text-sm" data-testid="order_preview">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                    Order preview
                  </span>
                  {orderType === "market" && (
                    <span className="text-[10px] text-muted-foreground">at {previewPrice ? formatPrice(previewPrice, scaler) : "—"} (proxy)</span>
                  )}
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Notional</span>
                  <span className="tabular-nums" data-testid="preview_notional">
                    {previewNotional > 0 ? formatPrice(previewNotional, scaler) : "—"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Buying power</span>
                  <span className="tabular-nums">
                    {formatPrice(avail, scaler)}
                    {maxAffordableQty > 0 && (
                      <span className="text-muted-foreground"> · max {formatQty(maxAffordableQty, scaler)}</span>
                    )}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Max qty affordable</span>
                  <button
                    type="button"
                    data-testid="preview_max"
                    disabled={maxAffordableQty <= 0}
                    onClick={fillMaxQty}
                    className="rounded border px-2 py-0.5 text-xs font-semibold text-primary disabled:opacity-40"
                  >
                    Max {maxAffordableQty > 0 ? formatQty(maxAffordableQty, scaler) : ""}
                  </button>
                </div>
                {/* Margin impact + est. liquidation — margin bps are NOT readable
                    client-side, so these are ROUGH estimates under an assumed
                    default, clearly tagged. */}
                {previewNotional > 0 && (
                  <div className="mt-1 border-t pt-1.5">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Est. margin <span className="text-[10px]">({(ASSUMED_INITIAL_MARGIN_BPS / 100).toFixed(0)}% assumed)</span>
                      </span>
                      <span className="tabular-nums">~{formatPrice(estMarginRequired, scaler)} (est.)</span>
                    </div>
                    {estLiq != null && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Est. liq. price</span>
                        <span className="tabular-nums">~{formatPrice(Math.round(estLiq), scaler)} (est.)</span>
                      </div>
                    )}
                    <p className="mt-0.5 text-[10px] text-muted-foreground">
                      Margin figures are rough estimates — the venue's real margin
                      rates aren't exposed to the client.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Position-size / risk calculator (collapsible). */}
            {orderType !== "funding" && orderType !== "quote" && (
              <div className="rounded-lg border p-3">
                <button
                  type="button"
                  aria-expanded={riskOpen}
                  data-testid="risk_calc_toggle"
                  className="flex w-full items-center justify-between text-xs font-semibold text-primary"
                  onClick={() => setRiskOpen((v) => !v)}
                >
                  <span>Calculators</span>
                  <span aria-hidden>{riskOpen ? "▲" : "▼"}</span>
                </button>
                {riskOpen && (
                  <div className="mt-2 space-y-2">
                    <div className="grid grid-cols-2 gap-2">
                      <Field label="Risk amount (quote)" value={riskAmt} onChange={setRiskAmt} />
                      <Field label="Stop price" value={riskStop} onChange={setRiskStop} />
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">
                        Entry {riskEntry ? formatPrice(riskEntry, scaler) : "—"} · suggested qty
                      </span>
                      <span className="font-semibold tabular-nums" data-testid="risk_suggested_qty">
                        {suggestedQty > 0 ? formatQty(suggestedQty, scaler) : "—"}
                      </span>
                    </div>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      className="w-full"
                      data-testid="risk_apply"
                      disabled={suggestedQty <= 0}
                      onClick={applyRiskQty}
                    >
                      Apply qty
                    </Button>
                    {/* Risk% sizing — size off a % of account equity. */}
                    <div className="rounded-md border bg-muted/20 p-2">
                      <div className="grid grid-cols-2 gap-2">
                        <Field label="Risk % of equity" value={riskPct} onChange={setRiskPct} />
                        <div className="flex flex-col justify-end pb-1 text-xs">
                          <span className="text-muted-foreground">Suggested qty</span>
                          <span className="font-semibold tabular-nums" data-testid="riskpct_suggested_qty">
                            {riskPctSuggestedQty > 0 ? formatQty(riskPctSuggestedQty, scaler) : "—"}
                          </span>
                        </div>
                      </div>
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        className="mt-2 w-full"
                        data-testid="riskpct_apply"
                        disabled={riskPctSuggestedQty <= 0}
                        onClick={applyRiskPctQty}
                      >
                        Apply risk% qty
                      </Button>
                    </div>
                    {/* Risk : Reward readout. */}
                    <div className="rounded-md border bg-muted/20 p-2 text-xs">
                      <Field label="Target price" value={calcTarget} onChange={setCalcTarget} />
                      <div className="mt-2 grid grid-cols-3 gap-1 tabular-nums">
                        <div>
                          <div className="text-muted-foreground">Risk</div>
                          <div data-testid="rr_risk">{rr.riskCents > 0 ? formatPrice(rr.riskCents, scaler) : "—"}</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Reward</div>
                          <div data-testid="rr_reward">{rr.rewardCents > 0 ? formatPrice(rr.rewardCents, scaler) : "—"}</div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">R:R</div>
                          <div data-testid="rr_ratio" className={rr.rr >= 1 ? "text-emerald-600 dark:text-emerald-400" : ""}>
                            {rr.rr > 0 ? `${rr.rr.toFixed(2)}:1` : "—"}
                          </div>
                        </div>
                      </div>
                    </div>
                    {/* Est. liq (leverage) + breakeven. */}
                    <div className="rounded-md border bg-muted/20 p-2 text-xs">
                      <div className="grid grid-cols-2 gap-2">
                        <Field label="Leverage (x)" value={calcLeverage} onChange={setCalcLeverage} />
                        <Field label="Fee (bps/side)" value={calcFeeBps} onChange={setCalcFeeBps} />
                      </div>
                      <div className="mt-2 space-y-0.5">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Margin required</span>
                          <span className="tabular-nums" data-testid="calc_margin_req">
                            {liqPrev.marginRequiredCents > 0 ? `~${formatPrice(liqPrev.marginRequiredCents, scaler)}` : "—"}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Est. liq. price</span>
                          <span className="tabular-nums" data-testid="calc_liq_price">
                            {liqPrev.liqPrice != null ? `~${formatPrice(Math.round(liqPrev.liqPrice), scaler)} (est.)` : "—"}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Breakeven (fees)</span>
                          <span className="tabular-nums" data-testid="calc_breakeven">
                            {breakeven > 0 ? formatPrice(breakeven, scaler) : "—"}
                          </span>
                        </div>
                      </div>
                      <p className="mt-1 text-[10px] text-muted-foreground">
                        Liquidation is a rough estimate under an assumed maintenance margin — not the venue's authoritative figure.
                      </p>
                    </div>
                    <div>
                      <label className="text-xs text-muted-foreground">% of buying power</label>
                      <div className="mt-1 flex gap-1.5">
                        {[25, 50, 100].map((pct) => (
                          <button
                            key={pct}
                            type="button"
                            data-testid={`risk_bp_${pct}`}
                            disabled={maxAffordableQty <= 0}
                            onClick={() => {
                              const q = pctOfBuyingPowerQty(avail, previewPrice, pct);
                              if (q > 0) {
                                setQty(String(q));
                                vibrate("tick");
                                resetArmed();
                              }
                            }}
                            className="flex-1 rounded-md border py-1 text-xs tabular-nums text-muted-foreground hover:text-foreground disabled:opacity-40"
                          >
                            {pct}%
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Submit */}
            <Button
              type="button"
              disabled={!canSubmit}
              onClick={submit}
              data-testid="trade_place"
              className={cn(
                "w-full",
                armed === "market"
                  ? "bg-primary"
                  : side === "buy"
                  ? "bg-emerald-600 hover:bg-emerald-600/90"
                  : "bg-rose-600 hover:bg-rose-600/90"
              )}
            >
              {submitLabel}
            </Button>

            {/* Deposit collateral */}
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <Field label="Deposit collateral" value={depositAmt} onChange={setDepositAmt} />
              </div>
              <Button
                type="button"
                variant="secondary"
                onClick={() => setDepositConfirmOpen(true)}
                disabled={depositM.isPending || depositAmtN <= 0}
              >
                Review
              </Button>
            </div>
            {depositAmt.trim() !== "" && depositAmtN <= 0 && (
              <p className="text-xs text-rose-600 dark:text-rose-400">Amount must be greater than 0.</p>
            )}

            <Dialog open={depositConfirmOpen} onOpenChange={setDepositConfirmOpen}>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Confirm collateral deposit</DialogTitle>
                  <DialogDescription>
                    Add collateral to your margin account for this market.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-2 rounded-lg border bg-muted/30 p-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Amount</span>
                    <span className="font-medium tabular-nums">{depositAmtN}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Destination</span>
                    <span className="font-medium">Margin collateral</span>
                  </div>
                  {acct && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Available before</span>
                      <span className="tabular-nums">{formatPrice(acct.available_balance, scaler)}</span>
                    </div>
                  )}
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setDepositConfirmOpen(false)} disabled={depositM.isPending}>
                    Cancel
                  </Button>
                  <Button onClick={deposit} disabled={depositM.isPending || depositAmtN <= 0}>
                    Confirm deposit
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>

            {/* Spot wallet (staged surface) */}
            {tradingFeatures.SPOT_ENABLED && (
              <div className="rounded-lg border p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold">Spot balances</span>
                  {spot.isLoading && <span className="text-xs text-muted-foreground">loading…</span>}
                </div>
                {spot.data?.balances && spot.data.balances.length > 0 ? (
                  <div className="mt-2 space-y-0.5 text-sm">
                    {spot.data.balances.map((b, i) => (
                      <div key={b.asset ?? i} className="flex justify-between">
                        <span className="text-muted-foreground">{b.symbol ?? `asset ${b.asset ?? "?"}`}</span>
                        <span className="tabular-nums">{formatQty(b.available ?? b.balance ?? 0, scaler)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  !spot.isLoading && <p className="mt-2 text-xs text-muted-foreground">No spot balances</p>
                )}
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <Field label="Asset id" value={spotAsset} onChange={setSpotAsset} />
                  <Field label="Amount" value={spotAmt} onChange={setSpotAmt} />
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  className="mt-2 w-full"
                  disabled={spotDepositM.isPending || (parseInt(spotAsset) || 0) <= 0 || (parseInt(spotAmt) || 0) <= 0}
                  onClick={() =>
                    spotDepositM.mutate(
                      { asset: parseInt(spotAsset) || 0, amount: parseInt(spotAmt) || 0 },
                      {
                        onSuccess: (a) => {
                          vibrate(isAck(a) ? "success" : "error");
                          setMsg({ text: isAck(a) ? "Spot deposit ok" : ackMessage(a) ?? "Spot deposit rejected", error: !isAck(a) });
                          setSpotAmt("");
                          spot.refetch();
                        },
                      }
                    )
                  }
                >
                  Deposit spot
                </Button>
              </div>
            )}
          </div>
        )}

        {section === "positions" &&
          (posQty ? (
            <div className="rounded-lg border p-3">
              <div className="flex items-center justify-between">
                <span className={cn("font-bold tabular-nums", posQty > 0 ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400")}>
                  {posQty > 0 ? "Long" : "Short"} {formatQty(Math.abs(posQty), scaler)}
                </span>
                <Button type="button" size="sm" variant={armed === "close" ? "default" : "destructive"} onClick={closePosition} data-testid="close_position">
                  {armed === "close" ? "Confirm close" : "Close"}
                </Button>
              </div>
              <div className="mt-2 space-y-0.5 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Entry</span>
                  <span className="tabular-nums">{formatPrice(acct?.pos_entry_price, scaler)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Liq. price</span>
                  <span className="tabular-nums">{acct?.pos_liquidation_price ? formatPrice(acct.pos_liquidation_price, scaler) : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Unrealized PnL</span>
                  <span className={cn("tabular-nums", (acct?.pos_unrealized_pnl ?? 0) >= 0 ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400")}>
                    {(acct?.pos_unrealized_pnl ?? 0) >= 0 ? "+" : ""}
                    {formatPrice(acct?.pos_unrealized_pnl, scaler)}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <p className="py-6 text-center text-sm text-muted-foreground">No open position</p>
          ))}

        {section === "orders" && (
          <div className="space-y-2">
            {workingOrders.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">No resting orders this session</p>
            ) : (
              workingOrders.map((w) => (
                <div key={w.clordid} className="flex items-center justify-between text-sm">
                  <span className={cn("tabular-nums", w.side === "buy" ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400")}>
                    {w.side === "buy" ? "Buy" : "Sell"} {formatQty(w.qty, scaler)} @ {formatPrice(w.price, scaler)}
                  </span>
                  <Button type="button" size="sm" variant="outline" onClick={() => cancelOne(w.clordid)}>
                    Cancel
                  </Button>
                </div>
              ))
            )}
            <Button type="button" variant="outline" size="sm" onClick={cancelAll} data-testid="cancel_all" className="text-rose-600 dark:text-rose-400">
              Cancel all resting orders
            </Button>
          </div>
        )}

        {section === "fills" &&
          (fills.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">No fills this session</p>
          ) : (
            <div className="max-h-72 overflow-y-auto">
              <div className="flex justify-between px-1 pb-1 text-xs uppercase text-muted-foreground">
                <span>Price</span>
                <span>Qty</span>
                <span>Time</span>
              </div>
              {fills.slice(0, 60).map((f, i) => (
                <div key={i} className="flex justify-between px-1 py-0.5 text-sm tabular-nums">
                  <span>{formatPrice(f.price, scaler)}</span>
                  <span className="text-muted-foreground">{formatQty(f.qty, scaler)}</span>
                  <span className="text-muted-foreground">{formatTimeNs(f.ts_ns)}</span>
                </div>
              ))}
            </div>
          ))}

        {msg && <p className={cn("text-xs font-mono", msg.error ? "text-rose-600 dark:text-rose-400" : "text-emerald-600 dark:text-emerald-400")}>{msg.text}</p>}
      </CardContent>
    </Card>
    <FeeSchedulePanel symbolId={symbolId} />
    <MarginConfigPanel symbolId={symbolId} />
    <EngineConfigPanel symbolId={symbolId} />
    <PmAdminPanel symbolId={symbolId} />
    <StakingAuctionsPanel symbolId={symbolId} scaler={scaler} />
    </div>
  );
}
