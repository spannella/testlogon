import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import {
  usePmConfig,
  usePmGroupConfig,
  usePmResolve,
  usePmGroupResolve,
  usePmResolutions,
} from "@/hooks/useTrading";
import type { PmAdminAck } from "@/api/endpoints/trading";
import { useAuthStore } from "@/stores/authStore";

// ─── Admin: prediction-market create/config + resolve surfaces ─────
// A single admin-gated panel grouping the four PM admin POST routes as compact
// collapsible forms, plus a resolution audit-log table. Mirrors EngineConfigPanel
// styling (amber accent, collapsible SubForms, inline ack). Returns null for
// non-admins. Every route MAY 404 (not deployed to all backends) and resolve
// routes MAY 403 (caller is not the designated resolver) — both surface inline,
// never crash the ticket.

type Ack = { text: string; error: boolean } | null;

/** Turn a PM admin ack into inline "applied vs rejected" feedback. */
function ackFeedback(a: PmAdminAck, appliedText: string): { text: string; error: boolean } {
  const okd = a.status === "ack" && (a.result ?? 0) === 0;
  if (okd) return { text: appliedText, error: false };
  const why = a.detail || a.error || a.note;
  const code = a.result != null ? ` (result ${a.result})` : "";
  return { text: `Rejected${code}${why ? `: ${why}` : ""}`, error: true };
}

/** Error → message; call out the 403 "not the designated resolver" case clearly. */
function errText(e: unknown): string {
  const msg = (e as Error)?.message ?? "Request failed";
  if (/\b403\b/.test(msg) || /forbidden/i.test(msg) || /resolver/i.test(msg)) {
    return "Rejected: you are not the designated resolver for this market (403).";
  }
  return msg;
}

/** A single labeled numeric input (digits only). */
function NumField({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
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

/** A single labeled free-text input (for resolver ids / source notes). */
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
      <Input value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className="mt-1" />
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

// ─── 1. Create binary market (pm_config) ───────────────────────────
function PmConfigForm({ symbolId }: { symbolId: number }) {
  const m = usePmConfig();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [face, setFace] = useState("");
  const [resolver, setResolver] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const faceN = parseInt(face) || 0;
  const valid = symN > 0 && faceN > 1;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Symbol id must be > 0 and face value > 1.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { symbolid: symN, face_value: faceN, resolver: resolver.trim() || undefined },
      {
        onSuccess: (a) => setAck(ackFeedback(a, `Binary PM set on symbol ${a.symbolid ?? symN} (face ${faceN}).`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Symbol id" value={symId} onChange={setSymId} />
        <NumField label="Face value (> 1)" value={face} onChange={setFace} />
      </div>
      <TextField label="Resolver (optional)" value={resolver} onChange={setResolver} placeholder="user id / MPID" />
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Creating…" : "Create binary market"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 2. Create categorical market (pm_group_config) ────────────────
function PmGroupConfigForm() {
  const m = usePmGroupConfig();
  const [groupId, setGroupId] = useState("");
  const [outcomes, setOutcomes] = useState("");
  const [face, setFace] = useState("");
  const [resolver, setResolver] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  const groupN = parseInt(groupId) || 0;
  const faceN = parseInt(face) || 0;
  // Comma/space separated symbol ids.
  const outArr = outcomes
    .split(/[\s,]+/)
    .map((s) => parseInt(s, 10))
    .filter((n) => Number.isFinite(n) && n > 0);
  const valid = groupN > 0 && faceN > 1 && outArr.length >= 2;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Group id > 0, face > 1, and ≥ 2 outcome symbol ids required.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { group_id: groupN, outcomes: outArr, face_value: faceN, resolver: resolver.trim() || undefined },
      {
        onSuccess: (a) =>
          setAck(ackFeedback(a, `Categorical group ${a.group_id ?? groupN} set (${outArr.length} outcomes, face ${faceN}).`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Group id" value={groupId} onChange={setGroupId} />
        <NumField label="Face value (> 1)" value={face} onChange={setFace} />
      </div>
      <TextField
        label="Outcome symbol ids (comma/space separated)"
        value={outcomes}
        onChange={setOutcomes}
        placeholder="101, 102, 103"
      />
      <TextField label="Resolver (optional)" value={resolver} onChange={setResolver} placeholder="user id / MPID" />
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Creating…" : "Create categorical market"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 3. Resolve binary (pm_resolve) ────────────────────────────────
function PmResolveForm({ symbolId }: { symbolId: number }) {
  const m = usePmResolve();
  const [symId, setSymId] = useState(String(symbolId || ""));
  const [outcome, setOutcome] = useState<"yes" | "no">("yes");
  const [source, setSource] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  useEffect(() => setSymId(String(symbolId || "")), [symbolId]);

  const symN = parseInt(symId) || 0;
  const valid = symN > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Symbol id must be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { symbolid: symN, outcome, source: source.trim() || undefined },
      {
        onSuccess: (a) =>
          setAck(
            ackFeedback(
              a,
              `Symbol ${a.symbolid ?? symN} resolved ${outcome.toUpperCase()} (${outcome === "yes" ? "YES pays face" : "YES pays 0"}).`,
            ),
          ),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <NumField label="Symbol id" value={symId} onChange={setSymId} />
      <div>
        <label className="text-xs text-muted-foreground">Outcome</label>
        <select
          value={outcome}
          onChange={(e) => setOutcome(e.target.value as "yes" | "no")}
          className="mt-1 h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
        >
          <option value="yes">YES — pays face value</option>
          <option value="no">NO — pays 0</option>
        </select>
      </div>
      <TextField label="Source (optional)" value={source} onChange={setSource} placeholder="e.g. official result" />
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Resolving…" : "Resolve binary market"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 4. Resolve categorical (pm_group_resolve) ─────────────────────
function PmGroupResolveForm() {
  const m = usePmGroupResolve();
  const [groupId, setGroupId] = useState("");
  const [winner, setWinner] = useState("");
  const [source, setSource] = useState("");
  const [ack, setAck] = useState<Ack>(null);

  const groupN = parseInt(groupId) || 0;
  const winN = parseInt(winner) || 0;
  const valid = groupN > 0 && winN > 0;

  const submit = () => {
    if (!valid) {
      setAck({ text: "Group id and winning symbol id must be > 0.", error: true });
      return;
    }
    setAck(null);
    m.mutate(
      { group_id: groupN, winning_symbolid: winN, source: source.trim() || undefined },
      {
        onSuccess: (a) =>
          setAck(ackFeedback(a, `Group ${a.group_id ?? groupN} resolved — winner ${winN} pays face, rest 0.`)),
        onError: (e) => setAck({ text: errText(e), error: true }),
      },
    );
  };

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <NumField label="Group id" value={groupId} onChange={setGroupId} />
        <NumField label="Winning symbol id" value={winner} onChange={setWinner} />
      </div>
      <TextField label="Source (optional)" value={source} onChange={setSource} placeholder="e.g. official result" />
      <Button type="button" variant="secondary" className="w-full" disabled={m.isPending || !valid} onClick={submit}>
        {m.isPending ? "Resolving…" : "Resolve categorical market"}
      </Button>
      <AckLine ack={ack} />
    </>
  );
}

// ─── 5. Resolution history (getPmResolutions) ──────────────────────
function fmtTs(ts?: number): string {
  if (!ts) return "—";
  // Engine may send seconds or ms — normalise to ms.
  const ms = ts > 1e12 ? ts : ts * 1000;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

function ResolutionHistory() {
  const q = usePmResolutions();
  const rows = q.data?.resolutions ?? [];

  return (
    <div className="space-y-2">
      {q.isError && (
        <p className="text-xs text-muted-foreground">Resolution log unavailable on this backend (404).</p>
      )}
      {!q.isError && rows.length === 0 && (
        <p className="text-xs text-muted-foreground">{q.isLoading ? "Loading…" : "No resolutions yet."}</p>
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="py-1 pr-2 font-medium">Market</th>
                <th className="py-1 pr-2 font-medium">Outcome</th>
                <th className="py-1 pr-2 font-medium">Resolver</th>
                <th className="py-1 pr-2 font-medium">Time</th>
                <th className="py-1 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="tabular-nums">
              {rows.map((r, i) => (
                <tr key={i} className="border-t">
                  <td className="py-1 pr-2">
                    {r.group_id != null
                      ? `group ${r.group_id}`
                      : r.symbolid != null
                        ? `sym ${r.symbolid}`
                        : "—"}
                  </td>
                  <td className="py-1 pr-2">
                    {r.winning_symbolid != null ? `win ${r.winning_symbolid}` : (r.outcome ?? "—")}
                  </td>
                  <td className="py-1 pr-2 font-mono">{r.resolver_id ?? "—"}</td>
                  <td className="py-1 pr-2">{fmtTs(r.ts)}</td>
                  <td className="py-1">{r.source ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Panel: groups the four PM admin forms + history (admin-gated) ─
export function PmAdminPanel({ symbolId }: { symbolId: number }) {
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
          <span>Prediction markets (admin)</span>
          <span>{open ? "▲" : "▼"}</span>
        </button>
        {open && (
          <div className="mt-3 space-y-2">
            <p className="text-[10px] text-muted-foreground">
              Create/config &amp; resolve prediction markets. Price = implied YES probability &times; face value.
              Routes may be unavailable (404) or resolve may be forbidden (403 if you are not the resolver) —
              failures show inline.
            </p>
            <SubForm title="Create binary market">
              <PmConfigForm symbolId={symbolId} />
            </SubForm>
            <SubForm title="Create categorical market">
              <PmGroupConfigForm />
            </SubForm>
            <SubForm title="Resolve binary market">
              <PmResolveForm symbolId={symbolId} />
            </SubForm>
            <SubForm title="Resolve categorical market">
              <PmGroupResolveForm />
            </SubForm>
            <SubForm title="Resolution history">
              <ResolutionHistory />
            </SubForm>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
