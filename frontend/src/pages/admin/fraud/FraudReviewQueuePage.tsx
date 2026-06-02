import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, Snowflake, FolderOpen, SlidersHorizontal, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  getFraudQueue,
  reviewFlag,
  getUserRisk,
  freezeUser,
  unfreezeUser,
  listFraudCases,
  getFraudConfig,
  updateFraudConfig,
  getFraudStats,
} from "@/api/endpoints/fraudDetection";
import type { FraudFlagOut, UserRiskProfile, FraudConfigUpdate } from "@/api/types";

function formatCents(cents: number): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
}

function RiskScoreBadge({ score }: { score: number }) {
  const variant = score >= 70 ? "destructive" : score >= 40 ? "secondary" : "outline";
  return (
    <Badge variant={variant} data-testid="risk-score-badge">
      {score}
    </Badge>
  );
}

// --- Stats bar -------------------------------------------------------------

function FraudStatsBar() {
  const { data } = useQuery({ queryKey: ["fraud", "stats"], queryFn: getFraudStats });
  const cards = [
    { label: "Pending Flags", value: data?.pending_flags ?? 0 },
    { label: "Open Cases", value: data?.open_cases ?? 0 },
    { label: "Frozen Users", value: data?.frozen_users ?? 0 },
    { label: "Avg Resolution Time", value: `${(data?.avg_resolution_hours ?? 0).toFixed(1)}h` },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {cards.map((c) => (
        <Card key={c.label}>
          <CardContent className="p-4">
            <div className="text-xs text-muted-foreground">{c.label}</div>
            <div className="text-2xl font-semibold">{c.value}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// --- Queue tab -------------------------------------------------------------

function FlagQueue() {
  const qc = useQueryClient();
  const [status, setStatus] = useState("pending");
  const [reviewing, setReviewing] = useState<FraudFlagOut | null>(null);
  const [notes, setNotes] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["fraud", "queue", status],
    queryFn: () => getFraudQueue({ status }),
  });

  const reviewMut = useMutation({
    mutationFn: ({ flagId, action }: { flagId: string; action: "approve" | "block" | "investigate" }) =>
      reviewFlag(flagId, { action, notes }),
    onSuccess: () => {
      toast.success("Flag reviewed");
      setReviewing(null);
      setNotes("");
      qc.invalidateQueries({ queryKey: ["fraud", "queue"] });
      qc.invalidateQueries({ queryKey: ["fraud", "stats"] });
    },
    onError: (err: any) => toast.error(String(err?.message || "Review failed")),
  });

  const statuses = ["pending", "approved", "blocked", "investigating"];

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {statuses.map((s) => (
          <Button
            key={s}
            size="sm"
            variant={status === s ? "default" : "outline"}
            onClick={() => setStatus(s)}
          >
            {s}
          </Button>
        ))}
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Rule</TableHead>
            <TableHead>Score</TableHead>
            <TableHead>Amount</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(data?.flags ?? []).map((f) => (
            <TableRow key={f.flag_id} data-testid="flag-row">
              <TableCell className="font-mono text-xs">{f.user_id}</TableCell>
              <TableCell>
                <Badge variant="outline">{f.rule_triggered}</Badge>
              </TableCell>
              <TableCell>
                <RiskScoreBadge score={f.risk_score} />
              </TableCell>
              <TableCell>{formatCents(f.amount_cents)}</TableCell>
              <TableCell>{f.status}</TableCell>
              <TableCell className="space-x-1">
                <Button size="sm" variant="outline" onClick={() => setReviewing(f)}>
                  Review
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
      {!isLoading && (data?.flags?.length ?? 0) === 0 && (
        <div className="text-sm text-muted-foreground">No flags in this queue.</div>
      )}

      <Dialog open={!!reviewing} onOpenChange={(o) => !o && setReviewing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Review Flag</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Notes</Label>
            <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} />
          </div>
          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() =>
                reviewing && reviewMut.mutate({ flagId: reviewing.flag_id, action: "approve" })
              }
            >
              Approve
            </Button>
            <Button
              variant="secondary"
              onClick={() =>
                reviewing && reviewMut.mutate({ flagId: reviewing.flag_id, action: "investigate" })
              }
            >
              Investigate
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                reviewing && reviewMut.mutate({ flagId: reviewing.flag_id, action: "block" })
              }
            >
              Block
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// --- Cases tab -------------------------------------------------------------

function CaseList() {
  const [status, setStatus] = useState("open");
  const { data } = useQuery({
    queryKey: ["fraud", "cases", status],
    queryFn: () => listFraudCases(status),
  });
  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        {["open", "investigating", "resolved"].map((s) => (
          <Button
            key={s}
            size="sm"
            variant={status === s ? "default" : "outline"}
            onClick={() => setStatus(s)}
          >
            {s}
          </Button>
        ))}
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Case</TableHead>
            <TableHead>User</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Flags</TableHead>
            <TableHead>Assigned</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(data ?? []).map((c) => (
            <TableRow key={c.case_id} data-testid="case-row">
              <TableCell className="font-mono text-xs">{c.case_id}</TableCell>
              <TableCell className="font-mono text-xs">{c.user_id}</TableCell>
              <TableCell>{c.status}</TableCell>
              <TableCell>{c.flags.length}</TableCell>
              <TableCell>{c.assigned_to ?? "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {(data?.length ?? 0) === 0 && (
        <div className="text-sm text-muted-foreground">No cases.</div>
      )}
    </div>
  );
}

// --- Users tab -------------------------------------------------------------

function UserRiskSearch() {
  const qc = useQueryClient();
  const [query, setQuery] = useState("");
  const [userId, setUserId] = useState<string | null>(null);
  const [freezeReason, setFreezeReason] = useState("");

  const { data: profile } = useQuery<UserRiskProfile>({
    queryKey: ["fraud", "risk", userId],
    queryFn: () => getUserRisk(userId as string),
    enabled: !!userId,
  });

  const freezeMut = useMutation({
    mutationFn: () => freezeUser(userId as string, { reason: freezeReason }),
    onSuccess: () => {
      toast.success("User frozen");
      qc.invalidateQueries({ queryKey: ["fraud", "risk", userId] });
    },
    onError: (err: any) => toast.error(String(err?.message || "Freeze failed")),
  });

  const unfreezeMut = useMutation({
    mutationFn: () => unfreezeUser(userId as string),
    onSuccess: () => {
      toast.success("User unfrozen");
      qc.invalidateQueries({ queryKey: ["fraud", "risk", userId] });
    },
    onError: (err: any) => toast.error(String(err?.message || "Unfreeze failed")),
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Input
          placeholder="User ID"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          data-testid="user-risk-search-input"
        />
        <Button data-testid="user-risk-search-btn" onClick={() => setUserId(query.trim())}>
          Search
        </Button>
      </div>
      {profile && (
        <Card data-testid="risk-profile-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Risk Profile <RiskScoreBadge score={profile.score} />
              {profile.frozen && <Badge variant="destructive">Frozen</Badge>}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-sm md:grid-cols-3">
              {Object.entries(profile.components).map(([k, v]) => (
                <div key={k} className="rounded border p-2">
                  <div className="text-xs text-muted-foreground">{k}</div>
                  <div className="font-semibold">{v}</div>
                </div>
              ))}
            </div>
            <div className="text-sm text-muted-foreground">
              24h tx: {profile.tx_count_24h} · chargebacks: {profile.chargeback_count}
            </div>
            <div className="space-y-2">
              <Label>Freeze reason</Label>
              <Textarea
                value={freezeReason}
                onChange={(e) => setFreezeReason(e.target.value)}
              />
              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  disabled={profile.frozen || !freezeReason.trim()}
                  onClick={() => freezeMut.mutate()}
                >
                  Freeze
                </Button>
                <Button
                  variant="outline"
                  disabled={!profile.frozen}
                  onClick={() => unfreezeMut.mutate()}
                >
                  Unfreeze
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// --- Config tab ------------------------------------------------------------

function FraudConfigForm() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["fraud", "config"], queryFn: getFraudConfig });
  const [form, setForm] = useState<FraudConfigUpdate>({});

  const saveMut = useMutation({
    mutationFn: () => updateFraudConfig(form),
    onSuccess: () => {
      toast.success("Config saved");
      qc.invalidateQueries({ queryKey: ["fraud", "config"] });
      setForm({});
    },
    onError: (err: any) => toast.error(String(err?.message || "Save failed (root only)")),
  });

  const fields: { key: keyof FraudConfigUpdate; label: string }[] = [
    { key: "velocity_max_tx_per_hour", label: "Max TX per hour" },
    { key: "velocity_max_amount_per_hour", label: "Max amount per hour (cents)" },
    { key: "large_tx_threshold", label: "Large TX threshold (cents)" },
    { key: "new_account_age_days", label: "New account age (days)" },
    { key: "flag_score_threshold", label: "Flag score threshold" },
  ];

  return (
    <div className="max-w-md space-y-3" data-testid="fraud-config-form">
      {fields.map((f) => (
        <div key={f.key} className="space-y-1">
          <Label>{f.label}</Label>
          <Input
            type="number"
            defaultValue={data?.[f.key] as number | undefined}
            onChange={(e) =>
              setForm((prev) => ({ ...prev, [f.key]: Number(e.target.value) }))
            }
          />
        </div>
      ))}
      <Button onClick={() => saveMut.mutate()}>Save Config</Button>
      <p className="text-xs text-muted-foreground">
        Only root users can modify fraud configuration.
      </p>
    </div>
  );
}

// --- Page ------------------------------------------------------------------

export default function FraudReviewQueuePage() {
  return (
    <div className="space-y-6 p-4">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Fraud Detection</h1>
      </div>
      <FraudStatsBar />
      <Tabs defaultValue="queue">
        <TabsList>
          <TabsTrigger value="queue">
            <ShieldAlert className="mr-1 h-4 w-4" /> Queue
          </TabsTrigger>
          <TabsTrigger value="cases">
            <FolderOpen className="mr-1 h-4 w-4" /> Cases
          </TabsTrigger>
          <TabsTrigger value="users">
            <Snowflake className="mr-1 h-4 w-4" /> Users
          </TabsTrigger>
          <TabsTrigger value="config">
            <SlidersHorizontal className="mr-1 h-4 w-4" /> Config
          </TabsTrigger>
          <TabsTrigger value="stats">
            <Activity className="mr-1 h-4 w-4" /> Stats
          </TabsTrigger>
        </TabsList>
        <TabsContent value="queue">
          <FlagQueue />
        </TabsContent>
        <TabsContent value="cases">
          <CaseList />
        </TabsContent>
        <TabsContent value="users">
          <UserRiskSearch />
        </TabsContent>
        <TabsContent value="config">
          <FraudConfigForm />
        </TabsContent>
        <TabsContent value="stats">
          <FraudStatsBar />
        </TabsContent>
      </Tabs>
    </div>
  );
}
