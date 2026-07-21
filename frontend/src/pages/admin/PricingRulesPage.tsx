import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Tag, Ban, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { ApiError } from "@/api/client";
import { toast } from "sonner";
import {
  listPricingRules,
  deactivatePricingRule,
  type PricingRule,
} from "@/api/endpoints/erpFinance";

export default function PricingRulesPage() {
  const queryClient = useQueryClient();
  const [creatorId, setCreatorId] = useState("");
  const [applied, setApplied] = useState("");

  const query = useQuery({
    queryKey: ["pricing", "rules", { applied }],
    queryFn: () => listPricingRules(applied, 100),
    enabled: !!applied,
    staleTime: 30_000,
    retry: (count, err) => !(err instanceof ApiError && err.status === 403) && count < 2,
  });

  const deactivateMut = useMutation({
    mutationFn: (id: string) => deactivatePricingRule(id),
    onSuccess: () => {
      toast.success("Rule deactivated");
      queryClient.invalidateQueries({ queryKey: ["pricing", "rules"] });
    },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Deactivate failed"),
  });

  if (query.error instanceof ApiError && query.error.status === 403) {
    return (
      <ErrorPage
        status={403}
        title="Operator access required"
        description="Pricing-rule administration is available only to operators."
      />
    );
  }

  const rules = query.data?.rules ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Pricing Rules"
        description="Creator discount rules (tiered / bulk / conditional)"
      />

      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="creator">Creator ID</Label>
          <Input
            id="creator"
            placeholder="creator user id"
            value={creatorId}
            onChange={(e) => setCreatorId(e.target.value)}
            className="w-72"
          />
        </div>
        <Button size="sm" onClick={() => setApplied(creatorId.trim())} disabled={!creatorId.trim()}>
          <Search className="mr-1 h-3.5 w-3.5" /> Load rules
        </Button>
      </div>

      {!applied && (
        <EmptyState icon={<Tag className="h-6 w-6" />} title="Enter a creator ID" description="Pricing rules are creator-scoped; supply a creator ID to list their rules." />
      )}

      {applied && query.isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}
        </div>
      )}

      {applied && !query.isLoading && rules.length === 0 && (
        <EmptyState icon={<Tag className="h-6 w-6" />} title="No rules" description="This creator has no pricing rules." />
      )}

      {rules.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Stacking</TableHead>
                  <TableHead className="text-right">Priority</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((r: PricingRule) => (
                  <TableRow key={r.rule_id}>
                    <TableCell>
                      <div className="font-medium">{r.name}</div>
                      <div className="font-mono text-xs text-muted-foreground">{r.rule_id}</div>
                    </TableCell>
                    <TableCell className="capitalize">{r.rule_type}</TableCell>
                    <TableCell className="text-xs">{r.stacking_mode.replace(/_/g, " ")}</TableCell>
                    <TableCell className="text-right">{r.priority}</TableCell>
                    <TableCell>
                      <StatusBadge variant={r.active ? "success" : "neutral"}>
                        {r.active ? "active" : "inactive"}
                      </StatusBadge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!r.active || deactivateMut.isPending}
                        onClick={() => deactivateMut.mutate(r.rule_id)}
                      >
                        <Ban className="mr-1 h-3.5 w-3.5" /> Deactivate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
