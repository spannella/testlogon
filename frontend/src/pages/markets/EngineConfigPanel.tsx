import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  useMatchingAlgo,
  useSpreadConfig,
  useTradingParams,
  useRiskConfig,
  useSpotIndex,
  useSpotConfig,
} from "@/hooks/useTrading";
import type { EngineConfigAck } from "@/api/endpoints/trading";
import { useAuthStore } from "@/stores/authStore";

// ─── Admin: matching-engine config surfaces ────────────────────────
// A single admin-gated panel grouping the six engine-config POST routes as
// compact collapsible forms. Mirrors MarginConfigPanel styling (amber accent,
// collapsible). Returns null for non-admins. Every route MAY 404 (not deployed
// to all backends) — failures surface inline, never crash the ticket.

type Ack = { text: string; error: boolean } | null;

/** Turn an engine ack into inline "applied vs rejected" feedback. */
function ackFeedback(a: EngineConfigAck, appliedText: string): { text: string; error: boolean } {
  const okd = a.status === "ack" && (a.result ?? 0) === 0;
  if (okd) return { text: appliedText, error: false };
  const why = a.detail || a.error || a.note;
  const code = a.result != null ? ` (result ${a.result})` : "";
  return { text: `Rejected${code}${why ? `: ${why}` : ""}`, error: true };
}

function errText(e: unknown): string {
  return (e as Error)?.message ?? "Request failed";
}

/** A single labeled numeric input (digits only; optional). */
function NumField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="w-full">
      <label className="text-xs text-muted-foreground">{label}</label>
      <Input
        value={value}
        inputMode="numeric"
        placeholder="0"
        onChange={(e) => onChange(e.target.value.replace(/[^0-9]/g, ""))}
        className="mt-1 tabular-nums"
      />
    </div>
  );
}

/** A single labeled free-text input (for MPIDs). */
function TextField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="w-full">
      <label className="text-xs text-muted-foreground">{label}</label>
      <Input
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1"
      />
    </div>
  );
}

/** Signed integer field (allows a leading minus, e.g. spread leg ratios). */
function SignedField({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="w-full">
      <label className="text-xs text-muted-foreground">{label}</label>
      <Input
        value={value}
        inputMode="numeric"
        placeholder="0"
        onChange={(e) => onChange(e.target.value.replace(/[^0-9-]/g, ""))}
        className="mt-1 tabular-nums"
      />
    </div>
  );
}

/** Inline ack line (green applied / red rejected), shared across sub-forms. */
function AckLine({ ack }: { ack: Ack }) {
  if (!ack) return null;
  return (
    <p
      className={cn(
        "text-xs font-mono",
        ack.error ? "text-rose-600 dark:text-rose-400" : "text-emerald-600 dark:text-emerald-400",
      )}
    >
      {ack.text}
    </p>
  );
}

/** A collapsible titled sub-section wrapping one config form. */
function SubForm({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border">
      <button
        type="button"
        className="flex w-full items-center justify-between px-3 py-2 text-xs font-semibold"
        onClick={() => setOpen((v) => !v)}
      >
        <span>{title}</span>
        <span className="text-muted-foreground">{open ? "▲" : "▼"}</span>
      </button>
      {open && <div className="space-y-2 border-t px-3 py-3">{children}</div>}
    </div>
  );
}

// ─── 1. Matching algorithm ─────────────────────────────────────────
const ALGO_OPTS: { value: number; label: string }[] = [
  { value: 0, label: "0 — Price-Time (default)" },
  { value: 1, label: "1 — Pro-rata" },
  { value: 2, label: "2 — Specialist" },
];

function MatchingAlgoForm({ symbolId }: { symbolId: number }) {
  const m = useMatchingAlgo();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [algo, setAlgo] = useState("0");
  const [mpid, setMpid] = useState("");
  const [pct, setPct] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const algoN = parseInt(algo) || 0;
  const pctN = pct === "" ? undefined : parseInt(pct) || 0;
  const valid = symN > 0 && (pctN === undefined || (pctN >= 0 && pctN <= 100));

  const submit = () => {
    if (!valid) {
      setAck({ text: "Symbol id must be > 0 and specialist % in 0–100.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      {
        symbolid: symN,
        algo: algoN,
        specialist_mpid: mpid.trim() || undefined,
        specialist_pct: pctN,
      },
      {
        onSuccess: (a) => setAck(ackFeedback(a, `Algo ${algoN} set on symbol ${a.symbolid ?? symN}.`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <NumField label="Symbol id" value={symId} onChange={setSymId} />
      <div>
        <label className="text-xs text-muted-foreground">Algorithm</label>
        <select
          value={algo}
          onChange={(e) => setAlgo(e.target.value)}
          className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
        >
          {ALGO_OPTS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
      {algoN >= 2 && (
        <div className="grid grid-cols-2 gap-2">
          <TextField label="Specialist MPID" value={mpid} onChange={setMpid} placeholder="MPID" />
          <NumField label="Specialist %" value={pct} onChange={setPct} />
        </div>
      )}
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Applying…" : "Apply matching algo"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 2. Spread config ──────────────────────────────────────────────
function SpreadConfigForm({ symbolId }: { symbolId: number }) {
  const m = useSpreadConfig();
  const [spreadSym, setSpreadSym] = useState(String(symbolId || ""));
  const [leg1, setLeg1] = useState("");
  const [leg2, setLeg2] = useState("");
  const [r1, setR1] = useState("1");
  const [r2, setR2] = useState("-1");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSpreadSym(String(symbolId || "")), [symbolId]);

  const spreadN = parseInt(spreadSym) || 0;
  const leg1N = parseInt(leg1) || 0;
  const leg2N = parseInt(leg2) || 0;
  // Ratios may be negative (short leg); parse signed.
  const r1N = r1.trim() === "" ? 1 : parseInt(r1, 10);
  const r2N = r2.trim() === "" ? -1 : parseInt(r2, 10);
  const valid = spreadN > 0 && leg1N > 0 && leg2N > 0 && Number.isFinite(r1N) && Number.isFinite(r2N);

  const submit = () => {
    if (!valid) {
      setAck({ text: "Spread symbol + both legs must be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { spread_symbolid: spreadN, leg1: leg1N, leg2: leg2N, leg1_ratio: r1N, leg2_ratio: r2N },
      {
        onSuccess: (a) => setAck(ackFeedback(a, `Spread ${a.symbolid ?? spreadN} = ${r1N}×${leg1N} + ${r2N}×${leg2N}.`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <NumField label="Spread symbol id" value={spreadSym} onChange={setSpreadSym} />
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Leg 1 symbol id" value={leg1} onChange={setLeg1} />
        <NumField label="Leg 2 symbol id" value={leg2} onChange={setLeg2} />
        <SignedField label="Leg 1 ratio" value={r1} onChange={setR1} />
        <SignedField label="Leg 2 ratio" value={r2} onChange={setR2} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Applying…" : "Apply spread config"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 3. Trading params ─────────────────────────────────────────────
const TP_FIELDS: { key: string; label: string }[] = [
  { key: "max_qty", label: "Max qty" },
  { key: "max_notional", label: "Max notional" },
  { key: "price_band_pct", label: "Price band %" },
  { key: "circuit_breaker_pct", label: "Circuit breaker %" },
  { key: "min_block_size", label: "Min block size" },
];

function TradingParamsForm({ symbolId }: { symbolId: number }) {
  const m = useTradingParams();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [vals, setVals] = useState<Record<string, string>>({});
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  // All optional; only include the ones the operator filled. Any filled value must be >= 0.
  const filled = TP_FIELDS.filter((f) => (vals[f.key] ?? "").trim() !== "");
  const valid = symN > 0 && filled.every((f) => (parseInt(vals[f.key]!) || 0) >= 0) && filled.length > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Symbol id > 0 and set at least one non-negative param.", error: true });
      return;
    }
    setAck(null);
    const body: Record<string, number> = { symbolid: symN };
    for (const f of filled) body[f.key] = parseInt(vals[f.key]!) || 0;
    m.mutate(body as never, {
      onSuccess: (a) => setAck(ackFeedback(a, `Params applied to symbol ${a.symbolid ?? symN}.`)),
      onError: (e) => setAck({ text: errText(e), error: true }),
    });
  };

  return (
    <>
      <NumField label="Symbol id" value={symId} onChange={setSymId} />
      <div className="grid grid-cols-2 gap-2">
        {TP_FIELDS.map((f) => (
          <NumField
            key={f.key}
            label={f.label}
            value={vals[f.key] ?? ""}
            onChange={(v) => setVals((p) => ({ ...p, [f.key]: v }))}
          />
        ))}
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Applying…" : "Apply trading params"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 4. Risk config (per-MPID kill switch) ─────────────────────────
function RiskConfigForm() {
  const m = useRiskConfig();
  const [maxNotional, setMaxNotional] = useState("");
  const [windowSec, setWindowSec] = useState("");
  const [mpid, setMpid] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  const maxN = parseInt(maxNotional) || 0;
  const winN = parseInt(windowSec) || 0;
  const valid = maxN >= 0 && winN > 0 && maxNotional.trim() !== "";

  const submit = () => {
    if (!valid) {
      setAck({ text: "Max notional ≥ 0 and window seconds > 0 required.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { max_notional: maxN, window_seconds: winN, mpid: mpid.trim() || undefined },
      {
        onSuccess: (a) => setAck(ackFeedback(a, `Kill switch set: ${maxN} / ${winN}s${mpid.trim() ? ` for ${mpid.trim()}` : ""}.`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Max notional" value={maxNotional} onChange={setMaxNotional} />
        <NumField label="Window (seconds)" value={windowSec} onChange={setWindowSec} />
      </div>
      <TextField label="MPID (optional — blank = all)" value={mpid} onChange={setMpid} placeholder="MPID" />
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Applying…" : "Apply risk config"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 5. Spot index (perp funding) ──────────────────────────────────
function SpotIndexForm({ symbolId }: { symbolId: number }) {
  const m = useSpotIndex();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [idxPrice, setIdxPrice] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const idxN = parseInt(idxPrice) || 0;
  const valid = symN > 0 && idxN > 0 && idxPrice.trim() !== "";

  const submit = () => {
    if (!valid) {
      setAck({ text: "Symbol id and spot index price must be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { symbolid: symN, spot_index_price: idxN },
      {
        onSuccess: (a) => {
          const base = ackFeedback(a, `Index set on symbol ${a.symbolid ?? symN}.`);
          if (!base.error && a.funding_rate_bps != null) {
            base.text = `Index set on symbol ${a.symbolid ?? symN} → funding ${a.funding_rate_bps} bps.`;
          }
          setAck(base);
        },
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Symbol id" value={symId} onChange={setSymId} />
        <NumField label="Spot index price" value={idxPrice} onChange={setIdxPrice} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Applying…" : "Set spot index"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 6. Spot config (base/quote asset) ─────────────────────────────
function SpotConfigForm({ symbolId }: { symbolId: number }) {
  const m = useSpotConfig();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [base, setBase] = useState("");
  const [quote, setQuote] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const baseN = parseInt(base) || 0;
  const quoteN = parseInt(quote) || 0;
  const valid = symN > 0 && baseN >= 0 && quoteN >= 0 && base.trim() !== "" && quote.trim() !== "";

  const submit = () => {
    if (!valid) {
      setAck({ text: "Symbol id > 0 and base/quote asset ids required.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { symbolid: symN, base_asset: baseN, quote_asset: quoteN },
      {
        onSuccess: (a) => setAck(ackFeedback(a, `Symbol ${a.symbolid ?? symN} spot-enforced (${baseN}/${quoteN}).`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <NumField label="Symbol id" value={symId} onChange={setSymId} />
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Base asset id" value={base} onChange={setBase} />
        <NumField label="Quote asset id" value={quote} onChange={setQuote} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Applying…" : "Apply spot config"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── Panel: groups all six (admin-gated, collapsible) ──────────────
export function EngineConfigPanel({ symbolId }: { symbolId: number }) {
  const isAdmin = useAuthStore((st) => st.isAdmin);
  const [open, setOpen] = useState(false);

  if (!isAdmin) return null;

  return (
    <Card className="border-amber-500/40">
      <CardContent className="pt-4">
        <button
          type="button"
          className="flex w-full items-center justify-between text-sm font-semibold text-amber-600 dark:text-amber-400"
          onClick={() => setOpen((v) => !v)}
        >
          <span>Engine config (admin)</span>
          <span>{open ? "▲" : "▼"}</span>
        </button>
        {open && (
          <div className="mt-3 space-y-2">
            <p className="text-[10px] text-muted-foreground">
              Matching-engine tuning. Routes may be unavailable on this backend (404) — failures show inline.
            </p>
            <SubForm title="Matching algorithm">
              <MatchingAlgoForm symbolId={symbolId} />
            </SubForm>
            <SubForm title="Spread config">
              <SpreadConfigForm symbolId={symbolId} />
            </SubForm>
            <SubForm title="Trading params">
              <TradingParamsForm symbolId={symbolId} />
            </SubForm>
            <SubForm title="Risk config (kill switch)">
              <RiskConfigForm />
            </SubForm>
            <SubForm title="Spot index (perp funding)">
              <SpotIndexForm symbolId={symbolId} />
            </SubForm>
            <SubForm title="Spot config (base/quote)">
              <SpotConfigForm symbolId={symbolId} />
            </SubForm>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
