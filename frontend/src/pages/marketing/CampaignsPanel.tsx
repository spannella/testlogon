import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Megaphone, Send, RefreshCw, Plus } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";

import {
  listCampaigns,
  getCampaign,
  createCampaign,
  transitionCampaign,
  sendCampaign,
  getCampaignAttribution,
  type CampaignObjective,
  type MarketingCampaign,
} from "@/api/endpoints/marketing";
import {
  CampaignStatusBadge,
  EmptyState,
  NotEnabledCard,
  errMsg,
  fmtCents,
  fmtTs,
  isNotEnabledError,
} from "./shared";

const OBJECTIVES: CampaignObjective[] = ["awareness", "traffic", "conversions", "retention"];

// transitions allowed per status (mirrors backend _CAMPAIGN_TRANSITIONS)
const TRANSITIONS: Record<string, string[]> = {
  draft: ["scheduled", "active", "archived"],
  scheduled: ["active", "archived"],
  active: ["paused", "completed", "archived"],
  paused: ["active", "archived"],
  completed: ["archived"],
  archived: [],
};

export function CampaignsPanel() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [objective, setObjective] = useState<CampaignObjective>("awareness");
  const [budget, setBudget] = useState("0");
  const [tracking, setTracking] = useState("");

  const listQ = useQuery({
    queryKey: ["mkt", "campaigns"],
    queryFn: () => listCampaigns({ limit: 100 }),
    retry: false,
  });

  const detailQ = useQuery({
    queryKey: ["mkt", "campaign", selectedId],
    queryFn: () => getCampaign(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const attributionQ = useQuery({
    queryKey: ["mkt", "campaign", selectedId, "attribution"],
    queryFn: () => getCampaignAttribution(selectedId!),
    enabled: !!selectedId,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createCampaign({
        name: name.trim(),
        objective,
        budget_cents: Math.round(Number(budget || "0") * 100),
        tracking_code: tracking.trim() || undefined,
      }),
    onSuccess: (c) => {
      toast.success("Campaign created");
      setCreateOpen(false);
      setName("");
      setBudget("0");
      setTracking("");
      setSelectedId(c.campaign_id);
      void qc.invalidateQueries({ queryKey: ["mkt", "campaigns"] });
    },
    onError: (e) => toast.error(errMsg(e, "Unable to create campaign")),
  });

  const transitionMut = useMutation({
    mutationFn: ({ id, target }: { id: string; target: string }) =>
      transitionCampaign(id, target),
    onSuccess: () => {
      toast.success("Campaign updated");
      void qc.invalidateQueries({ queryKey: ["mkt", "campaigns"] });
      void qc.invalidateQueries({ queryKey: ["mkt", "campaign", selectedId] });
    },
    onError: (e) => toast.error(errMsg(e, "Transition failed")),
  });

  const sendMut = useMutation({
    mutationFn: (id: string) => sendCampaign(id),
    onSuccess: (r) => {
      toast.success(`Sent to ${r.sent_count} parties (${r.skipped_count} skipped)`);
      void qc.invalidateQueries({ queryKey: ["mkt", "campaign", selectedId, "attribution"] });
    },
    onError: (e) => toast.error(errMsg(e, "Send failed")),
  });

  if (isNotEnabledError(listQ.error)) {
    return <NotEnabledCard what="Marketing campaigns" />;
  }

  const campaigns = listQ.data?.campaigns ?? [];
  const selected = detailQ.data;

  return (
    <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Megaphone className="h-4 w-4" /> Campaigns
            </CardTitle>
            <CardDescription>{campaigns.length} campaign(s)</CardDescription>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQ.refetch()}
              disabled={listQ.isFetching}
            >
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1 h-3.5 w-3.5" /> New
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {listQ.isLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : campaigns.length === 0 ? (
            <EmptyState title="No campaigns yet" hint="Create your first marketing campaign." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Objective</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Budget</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {campaigns.map((c: MarketingCampaign) => (
                  <TableRow
                    key={c.campaign_id}
                    data-testid="campaign-row"
                    className={
                      selectedId === c.campaign_id ? "cursor-pointer bg-muted" : "cursor-pointer"
                    }
                    onClick={() => setSelectedId(c.campaign_id)}
                  >
                    <TableCell className="font-medium">{c.name}</TableCell>
                    <TableCell className="capitalize">{c.objective}</TableCell>
                    <TableCell>
                      <CampaignStatusBadge status={c.status} />
                    </TableCell>
                    <TableCell className="text-right">{fmtCents(c.budget_cents)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Detail panel */}
      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
          <CardDescription>
            {selected ? selected.name : "Select a campaign to inspect"}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {!selectedId ? (
            <EmptyState title="No campaign selected" />
          ) : detailQ.isLoading ? (
            <Skeleton className="h-32 w-full" />
          ) : selected ? (
            <>
              <dl className="grid grid-cols-2 gap-y-2 text-sm">
                <dt className="text-muted-foreground">Status</dt>
                <dd>
                  <CampaignStatusBadge status={selected.status} />
                </dd>
                <dt className="text-muted-foreground">Objective</dt>
                <dd className="capitalize">{selected.objective}</dd>
                <dt className="text-muted-foreground">Budget</dt>
                <dd>{fmtCents(selected.budget_cents)}</dd>
                <dt className="text-muted-foreground">Tracking code</dt>
                <dd>{selected.tracking_code || "—"}</dd>
                <dt className="text-muted-foreground">Lists</dt>
                <dd>{selected.contact_list_ids.length}</dd>
                <dt className="text-muted-foreground">Segments</dt>
                <dd>{selected.segment_ids.length}</dd>
                <dt className="text-muted-foreground">Created</dt>
                <dd>{fmtTs(selected.created_at)}</dd>
              </dl>

              <Separator />

              <div className="space-y-2">
                <Label className="text-xs uppercase text-muted-foreground">State actions</Label>
                <div className="flex flex-wrap gap-2">
                  {(TRANSITIONS[selected.status] ?? []).length === 0 ? (
                    <span className="text-xs text-muted-foreground">No transitions available</span>
                  ) : (
                    (TRANSITIONS[selected.status] ?? []).map((t) => (
                      <Button
                        key={t}
                        size="sm"
                        variant="outline"
                        disabled={transitionMut.isPending}
                        onClick={() =>
                          transitionMut.mutate({ id: selected.campaign_id, target: t })
                        }
                      >
                        {t}
                      </Button>
                    ))
                  )}
                  <Button
                    size="sm"
                    disabled={sendMut.isPending}
                    onClick={() => sendMut.mutate(selected.campaign_id)}
                  >
                    <Send className="mr-1 h-3.5 w-3.5" /> Send
                  </Button>
                </div>
              </div>

              <Separator />

              <div className="space-y-2">
                <Label className="text-xs uppercase text-muted-foreground">Attribution</Label>
                {attributionQ.isLoading ? (
                  <Skeleton className="h-20 w-full" />
                ) : attributionQ.data ? (
                  <div className="grid grid-cols-2 gap-2">
                    <AttrStat label="Ad spend" value={fmtCents(attributionQ.data.ad_spend_cents)} />
                    <AttrStat
                      label="Promo discount"
                      value={fmtCents(attributionQ.data.promo_discount_cents)}
                    />
                    <AttrStat
                      label="Redemptions"
                      value={String(attributionQ.data.promo_redemptions)}
                    />
                    <AttrStat label="Visits" value={String(attributionQ.data.tracking_visits)} />
                    <AttrStat label="Orders" value={String(attributionQ.data.tracking_orders)} />
                  </div>
                ) : (
                  <span className="text-xs text-muted-foreground">No attribution data</span>
                )}
              </div>
            </>
          ) : (
            <EmptyState title="Campaign not found" />
          )}
        </CardContent>
      </Card>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New campaign</DialogTitle>
            <DialogDescription>Create a marketing campaign in draft state.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="mkt-name">Name</Label>
              <Input
                id="mkt-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Spring promo"
              />
            </div>
            <div className="space-y-1">
              <Label>Objective</Label>
              <Select value={objective} onValueChange={(v) => setObjective(v as CampaignObjective)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {OBJECTIVES.map((o) => (
                    <SelectItem key={o} value={o} className="capitalize">
                      {o}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="mkt-budget">Budget (USD)</Label>
              <Input
                id="mkt-budget"
                type="number"
                min="0"
                step="0.01"
                value={budget}
                onChange={(e) => setBudget(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="mkt-track">Tracking code (optional)</Label>
              <Input
                id="mkt-track"
                value={tracking}
                onChange={(e) => setTracking(e.target.value)}
                placeholder="spring2026"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!name.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AttrStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-semibold">{value}</p>
    </div>
  );
}
