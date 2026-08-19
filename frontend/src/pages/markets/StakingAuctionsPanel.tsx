import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  useStakeRequest,
  useStakeOffer,
  useAuctionRequest,
  useAuctionBid,
  useStakeRequests,
  useOpenAuctions,
} from "@/hooks/useTrading";
import { formatPrice, formatQty } from "./format";

// ─── Trader: Staking & Auctions surfaces ───────────────────────────
// Two PEER trader mechanisms on the matching engine (NOT admin-gated): a
// collateral-staking market and distressed-position auctions. There is NO
// list/GET of open stake requests or open auctions — you can create + act-by-id
// but cannot browse open items, so each form surfaces the returned
// request_id / auction_id prominently (note/share it) and we show an honest
// "browsing open items isn't available yet" note. Mirrors PmAdminPanel styling
// (collapsible SubForms, inline ack). Routes MAY 404 (not deployed to prod) —
// failures surface inline, never crash the ticket.

type Ack = { text: string; error: boolean; id?: { label: string; value: number } } | null;

/** Turn a staking/auction ack into inline "created vs rejected" feedback. */
function ackFeedback(
  a: { status?: string; detail?: string; error?: string; note?: string; reason?: string | number; reasoncode?: number },
  okText: string,
  id?: { label: string; value?: number },
): { text: string; error: boolean; id?: { label: string; value: number } } {
  const okd = a.status === "ack" || a.status === "created" || a.status === "ok";
  if (okd) {
    return {
      text: okText,
      error: false,
      id: id && id.value != null ? { label: id.label, value: id.value } : undefined,
    };
  }
  const why = a.detail || a.error || a.note;
  const code = a.reason ?? a.reasoncode;
  const codeStr = code != null ? ` (code ${code})` : "";
  return { text: `Rejected${codeStr}${why ? `: ${why}` : ""}`, error: true };
}

/** Error → message; call out the 404 "not deployed" case clearly. */
function errText(e: unknown): string {
  const msg = (e as Error)?.message ?? "Request failed";
  if (/\b404\b/.test(msg) || /not found/i.test(msg)) {
    return "Unavailable on this backend (404) — the staking/auction surface is not deployed yet.";
  }
  return msg;
}

/** A single labeled numeric input (digits only). */
function NumField({
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
        inputMode="numeric"
        placeholder={placeholder ?? "0"}
        onChange={(e) => onChange(e.target.value.replace(/[^0-9]/g, ""))}
        className="mt-1 tabular-nums"
      />
    </div>
  );
}

/** Inline ack line (green created / red rejected). When an id is present it is
 *  shown prominently on its own so the trader can note/share it. */
function AckLine({ ack }: { ack: Ack }) {
  if (!ack) return null;
  return (
    <div className="space-y-1">
      <p
        className={cn(
          "text-xs font-mono",
          ack.error ? "text-rose-600 dark:text-rose-400" : "text-emerald-600 dark:text-emerald-400",
        )}
      >
        {ack.text}
      </p>
      {ack.id && (
        <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{ack.id.label}</div>
          <div className="select-all font-mono text-lg font-semibold tabular-nums text-emerald-700 dark:text-emerald-300">
            {ack.id.value}
          </div>
        </div>
      )}
    </div>
  );
}

/** A collapsible titled sub-section wrapping one form. */
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

// ─── 1. Create stake request (stake_request) ───────────────────────
function StakeRequestForm({ symbolId, scaler }: { symbolId: number; scaler: number }) {
  const m = useStakeRequest();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [minCollateral, setMinCollateral] = useState("");
  const [maxStakePct, setMaxStakePct] = useState("");
  const [lockup, setLockup] = useState("");
  const [duration, setDuration] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const minColN = parseInt(minCollateral) || 0;
  const maxPctN = parseInt(maxStakePct) || 0;
  const lockupN = parseInt(lockup) || 0;
  const durN = parseInt(duration) || 0;
  const valid = minColN > 0 && maxPctN > 0 && lockupN > 0 && durN > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Min collateral, max stake %, lockup and duration must all be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      {
        symbolid: symN > 0 ? symN : undefined,
        min_collateral: minColN,
        max_stake_pct: maxPctN,
        lockup_seconds: lockupN,
        duration_seconds: durN,
      },
      {
        onSuccess: (a) =>
          setAck(
            ackFeedback(
              a,
              `Stake request created (min collateral ${formatPrice(minColN, scaler)}, up to ${maxPctN}% stake).`,
              { label: "Request id", value: a.request_id },
            ),
          ),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Symbol id (optional)" value={symId} onChange={setSymId} />
        <NumField label="Min collateral (ticks)" value={minCollateral} onChange={setMinCollateral} />
      </div>
      <div className="grid grid-cols-3 gap-2">
        <NumField label="Max stake %" value={maxStakePct} onChange={setMaxStakePct} />
        <NumField label="Lockup (s)" value={lockup} onChange={setLockup} />
        <NumField label="Duration (s)" value={duration} onChange={setDuration} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Creating…" : "Create stake request"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 2. Offer on a stake request (stake_offer) ─────────────────────
function StakeOfferForm({ scaler }: { scaler: number }) {
  const m = useStakeOffer();
  const [requestId, setRequestId] = useState("");
  const [collateral, setCollateral] = useState("");
  const [stakePct, setStakePct] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  const reqN = parseInt(requestId) || 0;
  const colN = parseInt(collateral) || 0;
  const pctN = parseInt(stakePct) || 0;
  const valid = reqN > 0 && colN > 0 && pctN > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Request id, collateral amount and stake % must all be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { request_id: reqN, collateral_amount: colN, stake_pct: pctN },
      {
        onSuccess: (a) =>
          setAck(
            ackFeedback(
              a,
              `Offer submitted on request ${a.request_id ?? reqN} (collateral ${formatPrice(colN, scaler)}, ${pctN}% stake).`,
              a.offer_id != null ? { label: "Offer id", value: a.offer_id } : { label: "Request id", value: a.request_id ?? reqN },
            ),
          ),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <NumField label="Stake request id" value={requestId} onChange={setRequestId} />
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Collateral amount (ticks)" value={collateral} onChange={setCollateral} />
        <NumField label="Stake %" value={stakePct} onChange={setStakePct} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Offering…" : "Offer on request"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 3. Create auction (auction_request) ───────────────────────────
function AuctionRequestForm({ symbolId, scaler }: { symbolId: number; scaler: number }) {
  const m = useAuctionRequest();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [qty, setQty] = useState("");
  const [reserve, setReserve] = useState("");
  const [duration, setDuration] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const qtyN = parseInt(qty) || 0;
  const reserveN = parseInt(reserve) || 0;
  const durN = parseInt(duration) || 0;
  const valid = qtyN > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Auction qty must be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      {
        symbolid: symN > 0 ? symN : undefined,
        qty: qtyN,
        reserve_price: reserveN > 0 ? reserveN : undefined,
        duration_seconds: durN > 0 ? durN : undefined,
      },
      {
        onSuccess: (a) =>
          setAck(
            ackFeedback(
              a,
              `Auction created (qty ${formatQty(qtyN, scaler)}${reserveN > 0 ? `, reserve ${formatPrice(reserveN, scaler)}` : ""}).`,
              { label: "Auction id", value: a.auction_id },
            ),
          ),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Symbol id (optional)" value={symId} onChange={setSymId} />
        <NumField label="Qty" value={qty} onChange={setQty} />
      </div>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Reserve price (optional)" value={reserve} onChange={setReserve} />
        <NumField label="Duration (s, optional)" value={duration} onChange={setDuration} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Creating…" : "Create auction"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 4. Bid on an auction (auction_bid) ────────────────────────────
function AuctionBidForm({ scaler }: { scaler: number }) {
  const m = useAuctionBid();
  const [auctionId, setAuctionId] = useState("");
  const [price, setPrice] = useState("");
  const [qty, setQty] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  const aucN = parseInt(auctionId) || 0;
  const priceN = parseInt(price) || 0;
  const qtyN = parseInt(qty) || 0;
  const valid = aucN > 0 && priceN > 0 && qtyN > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Auction id, price and qty must all be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { auction_id: aucN, price: priceN, qty: qtyN },
      {
        onSuccess: (a) =>
          setAck(
            ackFeedback(
              a,
              `Bid submitted on auction ${a.auction_id ?? aucN} (${formatQty(qtyN, scaler)} @ ${formatPrice(priceN, scaler)}).`,
              a.bid_id != null ? { label: "Bid id", value: a.bid_id } : { label: "Auction id", value: a.auction_id ?? aucN },
            ),
          ),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <NumField label="Auction id" value={auctionId} onChange={setAuctionId} />
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Price (ticks)" value={price} onChange={setPrice} />
        <NumField label="Qty" value={qty} onChange={setQty} />
      </div>
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Bidding…" : "Bid on auction"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── Browse open items (read, STUB-backed) ─────────────────────────
// Two read-only "browse open" sections for the peer staking/auction market.
// The listing endpoints are STUB today (empty + stub:true + note) — render the
// list when present, otherwise show an honest empty state using the returned
// `note`. Routes MAY 404 (not deployed) — degrade gracefully (retry:false).

/** Honest empty / unavailable state for a browse section. */
function BrowseEmpty({ note, error }: { note?: string; error?: unknown }) {
  const msg =
    error != null
      ? errText(error)
      : note ||
        "Browsing open items isn't available yet — backend listing pending.";
  return (
    <p className="rounded-md border border-dashed bg-muted/20 px-3 py-3 text-[11px] text-muted-foreground">
      {msg}
    </p>
  );
}

/** Browse open stake requests (read). */
function OpenStakeRequests({ scaler }: { scaler: number }) {
  const q = useStakeRequests();
  const items = q.data?.stake_requests ?? [];
  return (
    <div className="space-y-2">
      {q.isLoading ? (
        <p className="text-[11px] text-muted-foreground">Loading…</p>
      ) : q.isError || items.length === 0 ? (
        <BrowseEmpty note={q.data?.note} error={q.isError ? q.error : undefined} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b text-left text-[10px] uppercase text-muted-foreground">
                <th className="py-1.5 pr-2 font-medium">Req id</th>
                <th className="py-1.5 pr-2 font-medium">Symbol</th>
                <th className="py-1.5 pr-2 text-right font-medium">Min collateral</th>
                <th className="py-1.5 pr-2 text-right font-medium">Max stake %</th>
                <th className="py-1.5 pr-2 text-right font-medium">Lockup (s)</th>
                <th className="py-1.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r, i) => (
                <tr key={r.request_id ?? i} className="border-b last:border-0">
                  <td className="py-1.5 pr-2 font-mono tabular-nums">{r.request_id ?? "—"}</td>
                  <td className="py-1.5 pr-2 tabular-nums">{r.symbolid ?? "—"}</td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">
                    {r.min_collateral != null ? formatPrice(r.min_collateral, scaler) : "—"}
                  </td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">{r.max_stake_pct ?? "—"}</td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">{r.lockup_seconds ?? "—"}</td>
                  <td className="py-1.5">{r.status ?? "open"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Browse open auctions (read). */
function OpenAuctions({ scaler }: { scaler: number }) {
  const q = useOpenAuctions();
  const items = q.data?.auctions ?? [];
  return (
    <div className="space-y-2">
      {q.isLoading ? (
        <p className="text-[11px] text-muted-foreground">Loading…</p>
      ) : q.isError || items.length === 0 ? (
        <BrowseEmpty note={q.data?.note} error={q.isError ? q.error : undefined} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b text-left text-[10px] uppercase text-muted-foreground">
                <th className="py-1.5 pr-2 font-medium">Auction id</th>
                <th className="py-1.5 pr-2 font-medium">Symbol</th>
                <th className="py-1.5 pr-2 text-right font-medium">Qty</th>
                <th className="py-1.5 pr-2 text-right font-medium">Reserve</th>
                <th className="py-1.5 pr-2 text-right font-medium">Duration (s)</th>
                <th className="py-1.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a, i) => (
                <tr key={a.auction_id ?? i} className="border-b last:border-0">
                  <td className="py-1.5 pr-2 font-mono tabular-nums">{a.auction_id ?? "—"}</td>
                  <td className="py-1.5 pr-2 tabular-nums">{a.symbolid ?? "—"}</td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">
                    {a.qty != null ? formatQty(a.qty, scaler) : "—"}
                  </td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">
                    {a.reserve_price != null ? formatPrice(a.reserve_price, scaler) : "—"}
                  </td>
                  <td className="py-1.5 pr-2 text-right tabular-nums">{a.duration_seconds ?? "—"}</td>
                  <td className="py-1.5">{a.status ?? "open"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Panel: groups the four trader forms (NOT admin-gated) ─────────
export function StakingAuctionsPanel({ symbolId, scaler }: { symbolId: number; scaler: number }) {
  const [open, setOpen] = useState(false);

  return (
    <Card className="border-sky-500/40">
      <CardContent className="pt-4">
        <button
          type="button"
          className="flex w-full items-center justify-between text-sm font-semibold text-sky-600 dark:text-sky-400"
          onClick={() => setOpen((v) => !v)}
        >
          <span>Staking &amp; Auctions</span>
          <span>{open ? "▲" : "▼"}</span>
        </button>
        {open && (
          <div className="mt-3 space-y-2">
            <p className="text-[10px] text-muted-foreground">
              Peer trader mechanisms: stake collateral against a request, or auction a position. Amounts / prices
              are int64 engine ticks. Note the returned request / auction id — you will need it to act.
              Routes may be unavailable (404) on backends without the surface deployed — failures show inline.
            </p>
            <p className="rounded-md border border-sky-500/30 bg-sky-500/5 px-3 py-2 text-[10px] text-muted-foreground">
              Note: browsing open stake requests / open auctions is backed by a stub listing today — items
              appear here when the engine exposes them. You can always create items and act on a specific id,
              then share the id shown below.
            </p>
            <SubForm title="Browse open stake requests">
              <OpenStakeRequests scaler={scaler} />
            </SubForm>
            <SubForm title="Browse open auctions">
              <OpenAuctions scaler={scaler} />
            </SubForm>
            <SubForm title="Create stake request">
              <StakeRequestForm symbolId={symbolId} scaler={scaler} />
            </SubForm>
            <SubForm title="Offer on a stake request (by id)">
              <StakeOfferForm scaler={scaler} />
            </SubForm>
            <SubForm title="Create auction (of a position qty)">
              <AuctionRequestForm symbolId={symbolId} scaler={scaler} />
            </SubForm>
            <SubForm title="Bid on an auction (by id)">
              <AuctionBidForm scaler={scaler} />
            </SubForm>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
