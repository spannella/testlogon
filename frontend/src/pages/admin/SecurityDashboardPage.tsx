import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ShieldAlert,
  ShieldCheck,
  Bug,
  KeyRound,
  Radar,
  RefreshCw,
  Trash2,
  Copy,
  Plus,
} from "lucide-react";
import {
  listHoneytokens,
  mintHoneytoken,
  retireHoneytoken,
  getHoneytokenHits,
  getSecurityOverview,
  listSecurityEvents,
} from "@/api/endpoints/security";
import type {
  HoneytokenKind,
  HoneytokenMintOut,
  HoneytokenOut,
  SecurityEventOut,
  SecurityOverviewOut,
  SecurityEventListOut,
} from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const SEV_COLORS: Record<string, string> = {
  info: "bg-gray-100 text-gray-700",
  low: "bg-blue-100 text-blue-800",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={SEV_COLORS[severity] || "bg-gray-100 text-gray-700"}>
      {severity}
    </Badge>
  );
}

function fmtTs(ts?: number) {
  if (!ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

/** True when the underlying request 404'd (dashboard API not mounted / flag off). */
function isNotFound(err: unknown): boolean {
  const status = (err as { status?: number } | null)?.status;
  return status === 404;
}

// ── Dashboard sections (HNY-013/014) ─────────────────────────────────────────

function StatCard({
  label,
  value,
  icon,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className="text-muted-foreground">{icon}</div>
        <div>
          <div className="text-2xl font-bold">{value}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function EventTable({
  events,
  emptyText,
  onSelect,
}: {
  events: SecurityEventOut[];
  emptyText: string;
  onSelect: (e: SecurityEventOut) => void;
}) {
  if (!events.length) {
    return <p className="py-6 text-center text-sm text-muted-foreground">{emptyText}</p>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Time</TableHead>
          <TableHead>Kind</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Source IP</TableHead>
          <TableHead>User</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((e) => (
          <TableRow
            key={e.event_id}
            className="cursor-pointer"
            onClick={() => onSelect(e)}
          >
            <TableCell className="whitespace-nowrap text-xs">{fmtTs(e.ts)}</TableCell>
            <TableCell className="font-mono text-xs">{e.kind}</TableCell>
            <TableCell>
              <SeverityBadge severity={e.severity} />
            </TableCell>
            <TableCell className="font-mono text-xs">{e.source_ip || "—"}</TableCell>
            <TableCell className="font-mono text-xs">{e.user_sub || "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function OverviewTab({
  overview,
  loading,
  unavailable,
  onSelect,
}: {
  overview?: SecurityOverviewOut;
  loading: boolean;
  unavailable: boolean;
  onSelect: (e: SecurityEventOut) => void;
}) {
  if (unavailable) {
    return (
      <Card>
        <CardContent className="space-y-2 p-6 text-center text-sm text-muted-foreground">
          <ShieldCheck className="mx-auto h-8 w-8" />
          <p className="font-medium text-foreground">Security dashboard aggregation is not enabled.</p>
          <p>
            Set <code>SECURITY_DASHBOARD_ENABLED=1</code> on the backend to populate the threat
            overview. Honeytoken management below is available regardless.
          </p>
        </CardContent>
      </Card>
    );
  }
  if (loading) {
    return <p className="py-6 text-center text-sm text-muted-foreground">Loading overview…</p>;
  }
  const o = overview || {};
  const counts = o.counts || {};
  const active = o.active_threats || [];
  const honeypot = o.honeypot_hits || [];
  const trips = o.honeytoken_trips || [];
  const ids = o.ids_signals || [];
  const offenders = o.rate_limit_offenders || [];
  const riskDist = o.risk_distribution || {};

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Active threats"
          value={active.length || counts.active_threats || 0}
          icon={<ShieldAlert className="h-5 w-5 text-red-600" />}
        />
        <StatCard
          label="Honeypot hits"
          value={honeypot.length || counts.honeypot_hits || 0}
          icon={<Bug className="h-5 w-5 text-orange-600" />}
        />
        <StatCard
          label="Honeytoken trips"
          value={trips.length || counts.honeytoken_trips || 0}
          icon={<KeyRound className="h-5 w-5 text-purple-600" />}
        />
        <StatCard
          label="IDS signals"
          value={ids.length || counts.ids_signals || 0}
          icon={<Radar className="h-5 w-5 text-blue-600" />}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldAlert className="h-4 w-4 text-red-600" /> Active Threats
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EventTable
            events={active}
            emptyText="No active threats in this window."
            onSelect={onSelect}
          />
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Honeypot Hits</CardTitle>
          </CardHeader>
          <CardContent>
            <EventTable events={honeypot} emptyText="No decoy hits." onSelect={onSelect} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Honeytoken Trips</CardTitle>
          </CardHeader>
          <CardContent>
            <EventTable events={trips} emptyText="No honeytoken trips." onSelect={onSelect} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">IDS Signals</CardTitle>
        </CardHeader>
        <CardContent>
          <EventTable events={ids} emptyText="No intrusion-detection signals." onSelect={onSelect} />
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Rate-Limit Offenders</CardTitle>
          </CardHeader>
          <CardContent>
            {offenders.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Identifier</TableHead>
                    <TableHead className="text-right">Count</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {offenders.map((off, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">
                        {off.ip || off.key || "—"}
                      </TableCell>
                      <TableCell className="text-right">{off.count ?? 0}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="py-6 text-center text-sm text-muted-foreground">No offenders.</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {Object.keys(riskDist).length ? (
              <div className="space-y-2">
                {Object.entries(riskDist).map(([tier, n]) => (
                  <div key={tier} className="flex items-center justify-between text-sm">
                    <span className="capitalize">{tier}</span>
                    <Badge variant="secondary">{n}</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="py-6 text-center text-sm text-muted-foreground">No risk data.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Events tab (HNY-014 GET /events) ─────────────────────────────────────────

function EventsTab({ onSelect }: { onSelect: (e: SecurityEventOut) => void }) {
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [ip, setIp] = useState("");
  const [ipInput, setIpInput] = useState("");

  const { data, isLoading, error, refetch, isFetching } = useQuery<SecurityEventListOut>({
    queryKey: ["security", "events", kind, severity, ip],
    queryFn: () =>
      listSecurityEvents({
        kind: kind || undefined,
        severity: severity || undefined,
        ip: ip || undefined,
        limit: 100,
      }),
    retry: false,
  });

  if (error && isNotFound(error)) {
    return (
      <Card>
        <CardContent className="space-y-2 p-6 text-center text-sm text-muted-foreground">
          <ShieldCheck className="mx-auto h-8 w-8" />
          <p className="font-medium text-foreground">The security-events API is not enabled.</p>
          <p>
            Set <code>SECURITY_DASHBOARD_ENABLED=1</code> on the backend to browse the raw event
            feed.
          </p>
        </CardContent>
      </Card>
    );
  }

  const events = data?.events || [];

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-end gap-3">
          <CardTitle className="text-base">Security Events</CardTitle>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Select value={kind || "all"} onValueChange={(v) => setKind(v === "all" ? "" : v)}>
              <SelectTrigger className="h-8 w-44">
                <SelectValue placeholder="Kind" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All kinds</SelectItem>
                <SelectItem value="honeypot_hit">Honeypot hit</SelectItem>
                <SelectItem value="honeytoken_api_key_used">Honeytoken trip</SelectItem>
                <SelectItem value="credential_stuffing">Credential stuffing</SelectItem>
                <SelectItem value="impossible_travel">Impossible travel</SelectItem>
                <SelectItem value="scanning">Scanning</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={severity || "all"}
              onValueChange={(v) => setSeverity(v === "all" ? "" : v)}
            >
              <SelectTrigger className="h-8 w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All severities</SelectItem>
                <SelectItem value="info">Info</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
              </SelectContent>
            </Select>
            <form
              className="flex items-center gap-1"
              onSubmit={(e) => {
                e.preventDefault();
                setIp(ipInput.trim());
              }}
            >
              <Input
                className="h-8 w-40"
                placeholder="Source IP"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
              />
              <Button type="submit" size="sm" variant="outline">
                Filter
              </Button>
            </form>
            <Button size="sm" variant="ghost" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="py-6 text-center text-sm text-muted-foreground">Loading events…</p>
        ) : (
          <EventTable events={events} emptyText="No events match these filters." onSelect={onSelect} />
        )}
      </CardContent>
    </Card>
  );
}

// ── Honeytokens tab (HNY-007, live) ──────────────────────────────────────────

function MintDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<HoneytokenKind>("api_key");
  const [label, setLabel] = useState("");
  const [placement, setPlacement] = useState("");
  const [minted, setMinted] = useState<HoneytokenMintOut | null>(null);

  const reset = () => {
    setKind("api_key");
    setLabel("");
    setPlacement("");
    setMinted(null);
  };

  const mintMut = useMutation({
    mutationFn: () =>
      mintHoneytoken({ kind, label, placement: placement.trim() || null }),
    onSuccess: (res) => {
      setMinted(res);
      queryClient.invalidateQueries({ queryKey: ["security", "honeytokens"] });
      toast.success("Honeytoken minted");
    },
    onError: (err: any) => {
      if (isNotFound(err)) {
        toast.error("Honeytoken API not available (HONEYTOKEN_ENABLED off?)");
      } else {
        toast.error(String(err?.message || "Mint failed"));
      }
    },
  });

  const copy = (v?: string | null) => {
    if (!v) return;
    navigator.clipboard?.writeText(v).then(
      () => toast.success("Copied"),
      () => toast.error("Copy failed"),
    );
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Mint honeytoken</DialogTitle>
          <DialogDescription>
            Create a decoy credential. The secret is shown ONCE and never stored in
            plaintext.
          </DialogDescription>
        </DialogHeader>

        {minted ? (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Place this decoy where an attacker might find it. Any use trips a critical
              security alert.
            </p>
            {minted.api_key && (
              <SecretRow label="API key" value={minted.api_key} onCopy={copy} />
            )}
            {minted.username && (
              <SecretRow label="Username" value={minted.username} onCopy={copy} />
            )}
            {minted.password && (
              <SecretRow label="Password" value={minted.password} onCopy={copy} />
            )}
            {minted.canary_id && (
              <SecretRow label="Canary ID" value={minted.canary_id} onCopy={copy} />
            )}
            <SecretRow label="Token ID" value={minted.token_id} onCopy={copy} />
            <DialogFooter>
              <Button
                onClick={() => {
                  reset();
                  onOpenChange(false);
                }}
              >
                Done
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="space-y-1">
              <label className="text-sm font-medium">Kind</label>
              <Select value={kind} onValueChange={(v) => setKind(v as HoneytokenKind)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="api_key">Decoy API key</SelectItem>
                  <SelectItem value="credential_record">Credential record</SelectItem>
                  <SelectItem value="canary_row">Canary data row</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Label</label>
              <Input
                placeholder="e.g. Fake AWS key in README"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Placement (optional)</label>
              <Input
                placeholder="Where it's planted"
                value={placement}
                onChange={(e) => setPlacement(e.target.value)}
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                disabled={!label.trim() || mintMut.isPending}
                onClick={() => mintMut.mutate()}
              >
                {mintMut.isPending ? "Minting…" : "Mint"}
              </Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function SecretRow({
  label,
  value,
  onCopy,
}: {
  label: string;
  value: string;
  onCopy: (v: string) => void;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">{label}</label>
      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded bg-muted px-2 py-1 text-xs">
          {value}
        </code>
        <Button size="icon" variant="ghost" onClick={() => onCopy(value)}>
          <Copy className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

function HoneytokensTab({ onSelect }: { onSelect: (e: SecurityEventOut) => void }) {
  const queryClient = useQueryClient();
  const [mintOpen, setMintOpen] = useState(false);
  const [hitsToken, setHitsToken] = useState<HoneytokenOut | null>(null);

  const { data, isLoading, error } = useQuery<HoneytokenOut[]>({
    queryKey: ["security", "honeytokens"],
    queryFn: listHoneytokens,
    retry: false,
  });

  const retireMut = useMutation({
    mutationFn: (tokenId: string) => retireHoneytoken(tokenId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["security", "honeytokens"] });
      toast.success("Honeytoken retired");
    },
    onError: (err: any) => toast.error(String(err?.message || "Retire failed")),
  });

  const tokens = data || [];

  if (error && isNotFound(error)) {
    return (
      <Card>
        <CardContent className="space-y-2 p-6 text-center text-sm text-muted-foreground">
          <KeyRound className="mx-auto h-8 w-8" />
          <p className="font-medium text-foreground">Honeytoken API is not available.</p>
          <p>This endpoint is root-gated; sign in as a root user to manage decoy credentials.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Honeytokens</CardTitle>
          <Button size="sm" onClick={() => setMintOpen(true)}>
            <Plus className="mr-1 h-4 w-4" /> Mint
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="py-6 text-center text-sm text-muted-foreground">Loading honeytokens…</p>
        ) : tokens.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No honeytokens yet. Mint a decoy to start trapping attackers.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Placement</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((t) => (
                <TableRow key={t.token_id}>
                  <TableCell className="font-medium">{t.label || "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{t.kind}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {t.placement || "—"}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-xs">
                    {fmtTs(t.created_at)}
                  </TableCell>
                  <TableCell>
                    {t.retired ? (
                      <Badge variant="secondary">Retired</Badge>
                    ) : (
                      <Badge className="bg-green-100 text-green-800">Active</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setHitsToken(t)}
                    >
                      Hits
                    </Button>
                    {!t.retired && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-red-600"
                        disabled={retireMut.isPending}
                        onClick={() => retireMut.mutate(t.token_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <MintDialog open={mintOpen} onOpenChange={setMintOpen} />
      <HitsDialog token={hitsToken} onClose={() => setHitsToken(null)} onSelect={onSelect} />
    </Card>
  );
}

function HitsDialog({
  token,
  onClose,
  onSelect,
}: {
  token: HoneytokenOut | null;
  onClose: () => void;
  onSelect: (e: SecurityEventOut) => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["security", "honeytoken-hits", token?.token_id],
    queryFn: () => getHoneytokenHits(token!.token_id),
    enabled: !!token,
    retry: false,
  });

  return (
    <Dialog open={!!token} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Hits — {token?.label}</DialogTitle>
          <DialogDescription>
            Security events recorded when this decoy was used.
          </DialogDescription>
        </DialogHeader>
        {isLoading ? (
          <p className="py-6 text-center text-sm text-muted-foreground">Loading hits…</p>
        ) : (
          <EventTable
            events={data?.events || []}
            emptyText="No hits yet — the decoy has not been touched."
            onSelect={onSelect}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── Event detail drill-down ──────────────────────────────────────────────────

function EventDetailDialog({
  event,
  onClose,
}: {
  event: SecurityEventOut | null;
  onClose: () => void;
}) {
  return (
    <Dialog open={!!event} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Security event</DialogTitle>
        </DialogHeader>
        {event && (
          <div className="space-y-2 text-sm">
            <DetailRow label="Event ID" value={event.event_id} mono />
            <DetailRow label="Kind" value={event.kind} mono />
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Severity</span>
              <SeverityBadge severity={event.severity} />
            </div>
            <DetailRow label="Source IP" value={event.source_ip || "—"} mono />
            <DetailRow label="User agent" value={event.user_agent || "—"} />
            <DetailRow label="User" value={event.user_sub || "—"} mono />
            <DetailRow label="Time" value={fmtTs(event.ts)} />
            {event.details && Object.keys(event.details).length > 0 && (
              <div>
                <span className="text-muted-foreground">Details</span>
                <pre className="mt-1 overflow-x-auto rounded bg-muted p-2 text-xs">
                  {JSON.stringify(event.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className={`text-right ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function SecurityDashboardPage() {
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventOut | null>(null);

  const { data: overview, isLoading: overviewLoading, error: overviewError } =
    useQuery<SecurityOverviewOut>({
      queryKey: ["security", "overview"],
      queryFn: () => getSecurityOverview(),
      retry: false,
    });

  const overviewUnavailable = useMemo(
    () => !!overviewError && isNotFound(overviewError),
    [overviewError],
  );

  return (
    <div className="space-y-6 p-4 md:p-6">
      <div className="flex items-center gap-3">
        <ShieldAlert className="h-7 w-7 text-red-600" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Defensive monitoring — honeypot hits, honeytoken trips, and IDS signals.
          </p>
        </div>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
          <TabsTrigger value="honeytokens">Honeytokens</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab
            overview={overview}
            loading={overviewLoading}
            unavailable={overviewUnavailable}
            onSelect={setSelectedEvent}
          />
        </TabsContent>

        <TabsContent value="events" className="mt-4">
          <EventsTab onSelect={setSelectedEvent} />
        </TabsContent>

        <TabsContent value="honeytokens" className="mt-4">
          <HoneytokensTab onSelect={setSelectedEvent} />
        </TabsContent>
      </Tabs>

      <EventDetailDialog event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
}
