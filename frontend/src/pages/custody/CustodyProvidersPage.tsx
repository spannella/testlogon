// External custody-provider surface — a provider-aware companion to the
// internal /me/custody hub. Providers (Internal gateway / Fireblocks / BitGo)
// can be connected/disconnected here (creds stay SERVER-SIDE — the UI only
// initiates + shows status), each vault can be re-pointed at a provider, and
// provider-backed withdrawals surface a live approval stepper.
//
// Every read degrades on 404 (retry:false) to an honest "provider integration
// pending backend" state. The existing internal-custody behaviour is untouched.
import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  Building2,
  Server,
  KeyRound,
  Link2,
  Unlink,
  RefreshCw,
  Loader2,
  CheckCircle2,
  Clock,
  XCircle,
  AlertTriangle,
  Info,
  Layers,
  Wallet,
  Search,
} from "lucide-react";
import { toast } from "sonner";

import { ApiError } from "@/api/client";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  getProviders,
  connectProvider,
  disconnectProvider,
  getProviderStatus,
  getVaults,
  setVaultProvider,
  getWithdrawalApproval,
  type CustodyProvider,
  type ProviderKind,
  type ProviderVault,
} from "@/api/endpoints/custodyProviders";
import {
  providerStatusBadge,
  providerKindDisplay,
  providerAttestationLabel,
  approvalStepper,
  type BadgeSeverity,
} from "@/lib/custodyProviders";

// ─── shared helpers ─────────────────────────────────────────────

function isUnavailable(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 501);
}

function severityToVariant(
  sev: BadgeSeverity,
): "success" | "warning" | "destructive" | "secondary" {
  switch (sev) {
    case "success":
      return "success";
    case "warning":
      return "warning";
    case "danger":
      return "destructive";
    default:
      return "secondary";
  }
}

const KIND_ICON: Record<string, JSX.Element> = {
  internal: <Server className="h-5 w-5" />,
  fireblocks: <Building2 className="h-5 w-5" />,
  bitgo: <Building2 className="h-5 w-5" />,
  external: <Building2 className="h-5 w-5" />,
};

function kindIcon(kind: ProviderKind | string): JSX.Element {
  const key = providerKindDisplay(kind).iconKey;
  return KIND_ICON[key] ?? <Building2 className="h-5 w-5" />;
}

function fmtTs(ts: number | string | null | undefined): string {
  if (ts == null || ts === "") return "never";
  const n = typeof ts === "number" ? ts : Number(ts);
  const ms = Number.isFinite(n) ? (n > 1e12 ? n : n * 1000) : Date.parse(String(ts));
  if (!Number.isFinite(ms)) return String(ts);
  try {
    return new Date(ms).toLocaleString();
  } catch {
    return String(ts);
  }
}

function ProviderPendingCard({ line }: { line: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Building2 className="h-6 w-6" />
        </div>
        <div className="space-y-1">
          <p className="font-medium">Provider integration pending backend</p>
          <p className="mx-auto max-w-md text-sm text-muted-foreground">{line}</p>
        </div>
        <Badge variant="outline" className="gap-1.5">
          <Info className="h-3 w-3" /> Not available on this backend yet
        </Badge>
      </CardContent>
    </Card>
  );
}

// ─── Attestation badge ──────────────────────────────────────────

function AttestationBadge({ kind }: { kind: ProviderKind | string }) {
  const d = providerKindDisplay(kind);
  return (
    <Badge variant={d.external ? "default" : "secondary"} className="gap-1.5">
      <ShieldCheck className="h-3 w-3" />
      {providerAttestationLabel(kind)}
    </Badge>
  );
}

// ─── Provider status detail (per-card) ──────────────────────────

function ProviderStatusDetail({ id, connected }: { id: string; connected: boolean }) {
  const q = useQuery({
    queryKey: ["custody", "provider-status", id],
    queryFn: () => getProviderStatus(id),
    retry: false,
    enabled: connected,
    staleTime: 15_000,
  });

  if (!connected) {
    return (
      <p className="text-xs text-muted-foreground">
        Connect this provider to see attestation &amp; approvals.
      </p>
    );
  }
  if (q.isLoading) {
    return <Skeleton className="h-12 w-full rounded-md" />;
  }
  if (q.isError) {
    return (
      <p className="text-xs text-muted-foreground">
        Status unavailable on this backend yet.
      </p>
    );
  }
  const s = q.data;
  if (!s) return null;
  return (
    <div className="grid grid-cols-3 gap-2 text-center text-xs">
      <div className="rounded-md border bg-muted/30 p-2">
        <div className="flex items-center justify-center gap-1 text-muted-foreground">
          <ShieldCheck className="h-3 w-3" /> Attested
        </div>
        <div className="mt-0.5 font-medium">
          {s.balances_attested ? "Yes" : "No"}
        </div>
      </div>
      <div className="rounded-md border bg-muted/30 p-2">
        <div className="flex items-center justify-center gap-1 text-muted-foreground">
          <Clock className="h-3 w-3" /> Reconciled
        </div>
        <div className="mt-0.5 font-medium">{fmtTs(s.last_reconciled_ts)}</div>
      </div>
      <div className="rounded-md border bg-muted/30 p-2">
        <div className="flex items-center justify-center gap-1 text-muted-foreground">
          <KeyRound className="h-3 w-3" /> Approvals
        </div>
        <div className="mt-0.5 font-medium">{s.pending_approvals ?? 0}</div>
      </div>
    </div>
  );
}

// ─── Provider card ──────────────────────────────────────────────

function ProviderCard({ provider }: { provider: CustodyProvider }) {
  const qc = useQueryClient();
  const [label, setLabel] = useState("");
  const badge = providerStatusBadge(provider.status);
  const disp = providerKindDisplay(provider.kind);

  const connect = useMutation({
    mutationFn: () => connectProvider(provider.id, label.trim() || undefined),
    onSuccess: () => {
      toast.success(`Connection to ${disp.label} initiated`);
      setLabel("");
      qc.invalidateQueries({ queryKey: ["custody", "providers"] });
      qc.invalidateQueries({ queryKey: ["custody", "provider-status", provider.id] });
    },
    onError: (err) => {
      toast.error(
        err instanceof ApiError ? err.detail : `Could not connect ${disp.label}`,
      );
    },
  });

  const disconnect = useMutation({
    mutationFn: () => disconnectProvider(provider.id),
    onSuccess: () => {
      toast.success(`${disp.label} disconnected`);
      qc.invalidateQueries({ queryKey: ["custody", "providers"] });
      qc.invalidateQueries({ queryKey: ["custody", "provider-status", provider.id] });
    },
    onError: (err) => {
      toast.error(
        err instanceof ApiError ? err.detail : `Could not disconnect ${disp.label}`,
      );
    },
  });

  const busy = connect.isPending || disconnect.isPending;

  return (
    <Card className="flex flex-col">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
              {kindIcon(provider.kind)}
            </div>
            <div>
              <CardTitle className="text-base">{provider.name || disp.label}</CardTitle>
              <p className="text-xs text-muted-foreground">
                {disp.external ? "External qualified custodian" : "Internal gateway"}
              </p>
            </div>
          </div>
          <Badge variant={severityToVariant(badge.severity)}>{badge.label}</Badge>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        <AttestationBadge kind={provider.kind} />

        {provider.features?.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {provider.features.map((f) => (
              <Badge key={f} variant="outline" className="text-[10px]">
                {f}
              </Badge>
            ))}
          </div>
        )}

        <ProviderStatusDetail id={provider.id} connected={provider.connected} />

        <div className="mt-auto space-y-2 pt-1">
          {!provider.connected && disp.external && (
            <div className="space-y-1.5">
              <Label htmlFor={`label-${provider.id}`} className="text-xs">
                Connection label (optional)
              </Label>
              <Input
                id={`label-${provider.id}`}
                placeholder="e.g. treasury-desk"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                maxLength={48}
                disabled={busy}
              />
            </div>
          )}
          <div className="flex items-center gap-2">
            {provider.connected ? (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5"
                disabled={busy || provider.kind === "internal"}
                onClick={() => disconnect.mutate()}
                title={
                  provider.kind === "internal"
                    ? "The internal gateway can't be disconnected"
                    : undefined
                }
              >
                {disconnect.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Unlink className="h-4 w-4" />
                )}
                Disconnect
              </Button>
            ) : (
              <Button
                size="sm"
                className="gap-1.5"
                disabled={busy}
                onClick={() => connect.mutate()}
              >
                {connect.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Link2 className="h-4 w-4" />
                )}
                Connect
              </Button>
            )}
            <span className="text-[11px] text-muted-foreground">
              Provider API keys stay server-side.
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Providers grid ─────────────────────────────────────────────

function ProvidersSection() {
  const q = useQuery({
    queryKey: ["custody", "providers"],
    queryFn: getProviders,
    retry: false,
    staleTime: 15_000,
  });

  if (q.isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-64 w-full rounded-xl" />
        ))}
      </div>
    );
  }
  if (q.isError && isUnavailable(q.error)) {
    return (
      <ProviderPendingCard line="External custody providers (Fireblocks, BitGo, …) aren't served by this backend yet. Once the provider integration is deployed, you'll connect a qualified custodian and manage attestation here. Your internal-gateway custody keeps working in the meantime." />
    );
  }
  if (q.isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-2 py-10 text-sm text-muted-foreground">
          <AlertTriangle className="h-4 w-4" /> Could not load custody providers. Please try again.
        </CardContent>
      </Card>
    );
  }
  const providers = q.data?.providers ?? [];
  if (providers.length === 0) {
    return (
      <ProviderPendingCard line="No custody providers are configured for your account yet." />
    );
  }
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      {providers.map((p) => (
        <ProviderCard key={p.id} provider={p} />
      ))}
    </div>
  );
}

// ─── Per-vault provider selector ────────────────────────────────

const PROVIDER_OPTIONS: { value: ProviderKind; label: string }[] = [
  { value: "internal", label: "Internal gateway" },
  { value: "fireblocks", label: "Fireblocks" },
  { value: "bitgo", label: "BitGo" },
];

function VaultRow({ vault }: { vault: ProviderVault }) {
  const qc = useQueryClient();
  const current = (vault.provider as ProviderKind) || "internal";

  const mutate = useMutation({
    mutationFn: (provider: ProviderKind) => setVaultProvider(vault.vault, provider),
    onSuccess: (_data, provider) => {
      toast.success(
        `Vault re-pointed to ${providerKindDisplay(provider).label}`,
      );
      qc.invalidateQueries({ queryKey: ["custody", "vaults"] });
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.detail : "Could not change provider");
    },
  });

  return (
    <div className="flex flex-col gap-2 rounded-lg border p-3 md:flex-row md:items-center md:justify-between">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          {vault.label ? (
            <Layers className="h-4 w-4 text-muted-foreground" />
          ) : (
            <Wallet className="h-4 w-4 text-primary" />
          )}
          <span className="text-sm font-medium">
            {vault.label || "Base vault"}
          </span>
          <AttestationBadge kind={current} />
        </div>
        <span className="mt-0.5 block break-all font-mono text-xs text-muted-foreground">
          {vault.vault}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Select
          value={current}
          onValueChange={(v) => mutate.mutate(v as ProviderKind)}
          disabled={mutate.isPending}
        >
          <SelectTrigger className="w-[190px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PROVIDER_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {mutate.isPending && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
      </div>
    </div>
  );
}

function VaultProvidersSection() {
  const q = useQuery({
    queryKey: ["custody", "vaults"],
    queryFn: getVaults,
    retry: false,
    staleTime: 15_000,
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Layers className="h-5 w-5 text-primary" /> Vault custody provider
          </CardTitle>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => q.refetch()}
            disabled={q.isFetching}
          >
            <RefreshCw className={cn("h-4 w-4", q.isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {q.isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 2 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full rounded-lg" />
            ))}
          </div>
        )}
        {!q.isLoading && q.isError && isUnavailable(q.error) && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            Per-vault provider assignment isn't served by this backend yet — your
            vaults remain on the internal gateway.
          </p>
        )}
        {!q.isLoading && q.isError && !isUnavailable(q.error) && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <AlertTriangle className="h-4 w-4" /> Could not load vaults.
          </div>
        )}
        {!q.isLoading && !q.isError && (q.data?.vaults?.length ?? 0) === 0 && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No vaults yet.
          </p>
        )}
        {!q.isLoading &&
          !q.isError &&
          (q.data?.vaults ?? []).map((v) => <VaultRow key={v.vault} vault={v} />)}
      </CardContent>
    </Card>
  );
}

// ─── Provider-routed withdrawal approval stepper ────────────────

function ApprovalStepperView({ withdrawalId }: { withdrawalId: string }) {
  const q = useQuery({
    queryKey: ["custody", "withdrawal-approval", withdrawalId],
    queryFn: () => getWithdrawalApproval(withdrawalId),
    retry: false,
    enabled: withdrawalId.trim() !== "",
    // Poll while the approval is in flight (stops once broadcast/rejected).
    refetchInterval: (query) => {
      const st = query.state.data?.status;
      if (st === "broadcast" || st === "rejected") return false;
      return 5_000;
    },
  });

  if (withdrawalId.trim() === "") {
    return (
      <p className="py-6 text-center text-sm text-muted-foreground">
        Enter a provider-backed withdrawal id to track its approval.
      </p>
    );
  }
  if (q.isLoading) {
    return <Skeleton className="h-24 w-full rounded-md" />;
  }
  if (q.isError && isUnavailable(q.error)) {
    return (
      <p className="py-6 text-center text-sm text-muted-foreground">
        Withdrawal approval routing isn't served by this backend yet.
      </p>
    );
  }
  if (q.isError) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <AlertTriangle className="h-4 w-4" /> Could not load approval status.
      </div>
    );
  }
  const data = q.data;
  if (!data) return null;
  const model = approvalStepper(data.status);

  return (
    <div className="space-y-4">
      <ol className="flex flex-col gap-0 sm:flex-row sm:items-start sm:justify-between">
        {model.steps.map((step, i) => {
          const isRejected = step.state === "rejected";
          const done = step.state === "done";
          const current = step.state === "current";
          return (
            <li
              key={step.key}
              className="flex flex-1 items-center gap-2 sm:flex-col sm:text-center"
            >
              <div
                className={cn(
                  "flex h-8 w-8 shrink-0 items-center justify-center rounded-full border",
                  done && "border-success bg-success text-success-foreground",
                  current && "border-primary bg-primary/10 text-primary",
                  isRejected && "border-destructive bg-destructive text-destructive-foreground",
                  step.state === "upcoming" && "border-muted text-muted-foreground",
                )}
              >
                {done ? (
                  <CheckCircle2 className="h-4 w-4" />
                ) : isRejected ? (
                  <XCircle className="h-4 w-4" />
                ) : current ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <span className="text-xs">{i + 1}</span>
                )}
              </div>
              <span
                className={cn(
                  "text-xs",
                  (done || current) && "font-medium text-foreground",
                  isRejected && "font-medium text-destructive",
                  step.state === "upcoming" && "text-muted-foreground",
                )}
              >
                {step.label}
              </span>
            </li>
          );
        })}
      </ol>

      <Separator />

      <div className="flex flex-wrap items-center gap-3 text-sm">
        <span className="flex items-center gap-1.5">
          <KeyRound className="h-4 w-4 text-muted-foreground" /> Quorum:{" "}
          <span className="font-medium">
            {data.approvals?.length ?? 0} / {data.quorum ?? 0}
          </span>
        </span>
        {model.complete && (
          <Badge variant="success" className="gap-1">
            <CheckCircle2 className="h-3 w-3" /> Broadcast
          </Badge>
        )}
        {model.rejected && (
          <Badge variant="destructive" className="gap-1">
            <XCircle className="h-3 w-3" /> Rejected
          </Badge>
        )}
      </div>

      {(data.approvals?.length ?? 0) > 0 && (
        <div className="space-y-1.5">
          <p className="text-xs font-medium text-muted-foreground">Approvers</p>
          <ul className="space-y-1">
            {data.approvals.map((a, i) => (
              <li
                key={`${a.approver}-${i}`}
                className="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-1.5 text-xs"
              >
                <span className="font-medium">{a.approver}</span>
                <span className="text-muted-foreground">{fmtTs(a.at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function WithdrawalApprovalSection() {
  const [input, setInput] = useState("");
  const [tracked, setTracked] = useState("");
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-5 w-5 text-primary" /> Withdrawal approval
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          Track a provider-routed withdrawal through its approval quorum:
          pending → approved → signed → broadcast.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setTracked(input.trim());
          }}
        >
          <div className="flex-1 space-y-1.5">
            <Label htmlFor="withdrawal-id" className="text-xs">
              Withdrawal id
            </Label>
            <Input
              id="withdrawal-id"
              placeholder="e.g. wd_01H…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
          </div>
          <Button type="submit" className="gap-1.5" disabled={input.trim() === ""}>
            <Search className="h-4 w-4" /> Track
          </Button>
        </form>
        <ApprovalStepperView withdrawalId={tracked} />
      </CardContent>
    </Card>
  );
}

// ─── Page ───────────────────────────────────────────────────────

export default function CustodyProvidersPage() {
  const header = useMemo(
    () => (
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
          <Building2 className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight md:text-2xl">
            Custody providers
          </h1>
          <p className="text-sm text-muted-foreground">
            Back your vaults with an external qualified custodian (Fireblocks,
            BitGo) or the internal gateway. Keys stay server-side.
          </p>
        </div>
      </div>
    ),
    [],
  );

  return (
    <div className="mx-auto w-full max-w-6xl p-4 md:p-6">
      {header}
      <div className="space-y-6">
        <ProvidersSection />
        <VaultProvidersSection />
        <WithdrawalApprovalSection />
      </div>
    </div>
  );
}
