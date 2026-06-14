import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Wrench } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import {
  listWorkOrderQueue,
  type AssetMaintenanceOrder,
} from "@/api/endpoints/fixedAssets";
import { fmtCents, fmtTs, prettyStatus, statusVariant } from "./lib";

const WO_STATUSES = ["", "open", "in_progress", "completed", "cancelled"] as const;

export default function MaintenanceQueuePage() {
  const [woStatus, setWoStatus] = useState<string>("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const queueQuery = useQuery({
    queryKey: ["fixed-assets", "wo-queue", { woStatus, cursor }],
    queryFn: () =>
      listWorkOrderQueue({
        wo_status: woStatus || undefined,
        cursor,
        limit: 50,
      }),
    retry: false,
  });

  const featureDisabled =
    queueQuery.error instanceof ApiError &&
    (queueQuery.error.status === 404 || queueQuery.error.status === 503);

  const orders = queueQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Maintenance Queue"
        description="All asset maintenance work orders across the fleet (admin)"
      />

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle>Work orders</CardTitle>
            <CardDescription>Open and in-progress maintenance across all assets</CardDescription>
          </div>
          <Select
            value={woStatus || "all"}
            onValueChange={(v) => {
              setWoStatus(v === "all" ? "" : v);
              setCursor(undefined);
            }}
          >
            <SelectTrigger className="w-44" aria-label="Work order status filter">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              {WO_STATUSES.map((s) => (
                <SelectItem key={s || "all"} value={s || "all"}>
                  {s ? prettyStatus(s) : "All statuses"}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          {queueQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Loading work orders…</p>
          ) : featureDisabled ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              The fixed-assets module is not enabled.
            </p>
          ) : orders.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <Wrench className="h-10 w-10 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No work orders in the queue.</p>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Title</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead className="text-right">Cost</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {orders.map((wo: AssetMaintenanceOrder) => (
                    <TableRow key={wo.work_order_id}>
                      <TableCell className="font-medium">{wo.title}</TableCell>
                      <TableCell className="font-mono text-xs">{wo.asset_id}</TableCell>
                      <TableCell>{wo.assignee_sub ?? "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmtCents(wo.cost_cents)}
                      </TableCell>
                      <TableCell>{fmtTs(wo.created_at)}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(wo.wo_status)}>
                          {prettyStatus(wo.wo_status)}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {queueQuery.data?.cursor && (
                <div className="mt-4 flex justify-center">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(queueQuery.data?.cursor ?? undefined)}
                  >
                    Load more
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
