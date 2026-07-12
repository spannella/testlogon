import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Link } from "react-router-dom";
import { Columns, List, Plus, Target } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  createOpportunity,
  formatCents,
  formatDate,
  getFeatureStatus,
  isLostStage,
  isWonStage,
  listOpportunities,
  listStages,
  stageLabel,
  type OpportunityCreateIn,
  type OpportunityOut,
  type StageConfigItemOut,
} from "@/api/endpoints/opportunities";
import { FeatureDisabledState } from "./FeatureDisabledState";
import { OpportunityFormDialog } from "./OpportunityFormDialog";

function stageBadgeVariant(
  stageKey: string,
): "default" | "secondary" | "success" | "destructive" {
  if (isWonStage(stageKey)) return "success";
  if (isLostStage(stageKey)) return "destructive";
  return "secondary";
}

function OppCard({ opp }: { opp: OpportunityOut }) {
  return (
    <Link
      to={`/crm/opportunities/${encodeURIComponent(opp.opp_id)}`}
      className="block rounded-md border bg-card p-3 transition hover:border-primary hover:shadow-sm"
      data-testid="opp-card"
    >
      <div className="flex items-start justify-between gap-2">
        <span className="line-clamp-2 text-sm font-medium">{opp.name}</span>
        <Badge variant="outline" className="shrink-0">
          {opp.probability}%
        </Badge>
      </div>
      <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
        <span className="font-semibold text-foreground">
          {formatCents(opp.amount_cents)}
        </span>
        <span>{formatDate(opp.close_date)}</span>
      </div>
      <div className="mt-1 text-xs text-muted-foreground">
        Weighted {formatCents(opp.weighted_amount_cents)}
      </div>
    </Link>
  );
}

export default function OpportunitiesPage() {
  const queryClient = useQueryClient();
  const [view, setView] = useState<"board" | "list">("board");
  const [stageFilter, setStageFilter] = useState<string>("all");
  const [dialogOpen, setDialogOpen] = useState(false);

  const featureQuery = useQuery({
    queryKey: ["opps", "feature-status"],
    queryFn: getFeatureStatus,
    retry: false,
  });

  const enabled = featureQuery.data?.enabled ?? false;

  const stagesQuery = useQuery({
    queryKey: ["opps", "stages"],
    queryFn: listStages,
    enabled,
    retry: false,
  });

  const oppsQuery = useQuery({
    queryKey: ["opps", "list", stageFilter],
    queryFn: () =>
      listOpportunities({
        stage: stageFilter === "all" ? undefined : stageFilter,
        limit: 200,
      }),
    enabled,
    retry: (count, err) => !(err instanceof ApiError && err.status === 503) && count < 2,
  });

  const stages: StageConfigItemOut[] = stagesQuery.data?.stages ?? [];
  const items = oppsQuery.data?.items ?? [];

  const createMut = useMutation({
    mutationFn: (body: OpportunityCreateIn) => createOpportunity(body),
    onSuccess: () => {
      toast.success("Opportunity created");
      setDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: ["opps", "list"] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to create"),
  });

  const grouped = useMemo(() => {
    const map = new Map<string, OpportunityOut[]>();
    for (const s of stages) map.set(s.stage_key, []);
    for (const opp of items) {
      if (!map.has(opp.stage)) map.set(opp.stage, []);
      map.get(opp.stage)!.push(opp);
    }
    return map;
  }, [stages, items]);

  const totals = useMemo(() => {
    let amount = 0;
    let weighted = 0;
    let open = 0;
    for (const opp of items) {
      amount += opp.amount_cents;
      weighted += opp.weighted_amount_cents;
      if (!isWonStage(opp.stage) && !isLostStage(opp.stage)) open += 1;
    }
    return { amount, weighted, open, count: items.length };
  }, [items]);

  // ── Feature gate ──
  if (featureQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const featureDisabled =
    !enabled ||
    (oppsQuery.error instanceof ApiError && oppsQuery.error.status === 503);

  const header = (
    <PageHeader
      title="Opportunities"
      description="Track deals through your sales pipeline."
      actions={
        enabled ? (
          <div className="flex items-center gap-2">
            <Link to="/crm/opportunities/pipeline">
              <Button variant="outline" size="sm">
                <Target className="mr-1.5 h-4 w-4" />
                Pipeline report
              </Button>
            </Link>
            <Button
              variant={view === "board" ? "default" : "outline"}
              size="sm"
              onClick={() => setView("board")}
            >
              <Columns className="mr-1.5 h-4 w-4" />
              Board
            </Button>
            <Button
              variant={view === "list" ? "default" : "outline"}
              size="sm"
              onClick={() => setView("list")}
            >
              <List className="mr-1.5 h-4 w-4" />
              List
            </Button>
            <Button size="sm" onClick={() => setDialogOpen(true)} data-testid="new-opp-btn">
              <Plus className="mr-1.5 h-4 w-4" />
              New
            </Button>
          </div>
        ) : undefined
      }
    />
  );

  if (featureDisabled) {
    return (
      <div className="space-y-6">
        {header}
        <FeatureDisabledState />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {header}

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Open deals
            </CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">{totals.open}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Total deals
            </CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">{totals.count}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Pipeline value
            </CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">
            {formatCents(totals.amount)}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Weighted value
            </CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold">
            {formatCents(totals.weighted)}
          </CardContent>
        </Card>
      </div>

      {/* Stage filter (list view) */}
      {view === "list" && (
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Stage</span>
          <Select value={stageFilter} onValueChange={setStageFilter}>
            <SelectTrigger className="w-56" data-testid="stage-filter">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All stages</SelectItem>
              {stages.map((s) => (
                <SelectItem key={s.stage_key} value={s.stage_key}>
                  {s.label || stageLabel(s.stage_key)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {oppsQuery.isLoading ? (
        <Skeleton className="h-64 w-full" />
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <Target className="h-10 w-10 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              No opportunities yet. Create your first deal to get started.
            </p>
            <Button onClick={() => setDialogOpen(true)}>
              <Plus className="mr-1.5 h-4 w-4" />
              New opportunity
            </Button>
          </CardContent>
        </Card>
      ) : view === "board" ? (
        <div className="flex gap-4 overflow-x-auto pb-4" data-testid="opp-board">
          {stages.map((s) => {
            const col = grouped.get(s.stage_key) ?? [];
            const colTotal = col.reduce((sum, o) => sum + o.amount_cents, 0);
            return (
              <div key={s.stage_key} className="w-72 shrink-0">
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant={stageBadgeVariant(s.stage_key)}>
                      {s.label || stageLabel(s.stage_key)}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{col.length}</span>
                  </div>
                  <span className="text-xs font-medium text-muted-foreground">
                    {formatCents(colTotal)}
                  </span>
                </div>
                <div className="flex flex-col gap-2 rounded-md bg-muted/40 p-2">
                  {col.length === 0 ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">
                      No deals
                    </p>
                  ) : (
                    col.map((opp) => <OppCard key={opp.opp_id} opp={opp} />)
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="divide-y">
              {items.map((opp) => (
                <Link
                  key={opp.opp_id}
                  to={`/crm/opportunities/${encodeURIComponent(opp.opp_id)}`}
                  className="flex items-center justify-between gap-4 px-4 py-3 transition hover:bg-muted/50"
                  data-testid="opp-row"
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{opp.name}</p>
                    <p className="text-xs text-muted-foreground">
                      Close {formatDate(opp.close_date)} · {opp.probability}%
                    </p>
                  </div>
                  <Badge variant={stageBadgeVariant(opp.stage)}>
                    {stageLabel(opp.stage)}
                  </Badge>
                  <div className="w-28 text-right text-sm font-semibold">
                    {formatCents(opp.amount_cents)}
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <OpportunityFormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        stages={stages}
        onSubmit={(body) => createMut.mutate(body)}
        saving={createMut.isPending}
      />
    </div>
  );
}
