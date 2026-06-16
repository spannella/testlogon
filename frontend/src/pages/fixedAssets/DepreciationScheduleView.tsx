import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CalendarClock, FileCheck2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  generateSchedule,
  getSchedule,
  postPeriod,
  type DepreciationPeriod,
  type FixedAsset,
} from "@/api/endpoints/fixedAssets";
import { fmtCents, fmtTs, prettyStatus, statusVariant } from "./lib";

interface Props {
  asset: FixedAsset;
  onChanged: () => void;
}

export function DepreciationScheduleView({ asset, onChanged }: Props) {
  const qc = useQueryClient();
  const assetId = asset.asset_id;

  const scheduleQuery = useQuery({
    queryKey: ["fixed-assets", "schedule", assetId],
    queryFn: () => getSchedule(assetId),
    retry: false,
  });

  const schedule = scheduleQuery.data;
  const periods = schedule?.periods ?? [];

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["fixed-assets", "schedule", assetId] });
    onChanged();
  };

  const genMut = useMutation({
    mutationFn: () => generateSchedule(assetId),
    onSuccess: () => {
      toast.success("Schedule generated");
      invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to generate schedule"),
  });

  const postMut = useMutation({
    mutationFn: (period: number) => postPeriod(assetId, period),
    onSuccess: () => {
      toast.success("Period posted");
      invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to post period"),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          {schedule && (
            <>
              <span>{schedule.total_periods} periods</span>
              <span>·</span>
              <span>{schedule.posted_periods} posted</span>
              <span>·</span>
              <span>{schedule.remaining_periods} remaining</span>
            </>
          )}
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => genMut.mutate()}
          disabled={genMut.isPending || asset.status === "disposed"}
        >
          <CalendarClock className="mr-2 h-4 w-4" />
          {periods.length === 0 ? "Generate schedule" : "Regenerate"}
        </Button>
      </div>

      {scheduleQuery.isLoading ? (
        <p className="py-6 text-center text-sm text-muted-foreground">Loading schedule…</p>
      ) : periods.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-8 text-center">
          <CalendarClock className="h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">
            No depreciation schedule yet. Generate one to begin posting periods.
          </p>
        </div>
      ) : (
        <div className="max-h-96 overflow-auto rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>#</TableHead>
                <TableHead>Period start</TableHead>
                <TableHead>Period end</TableHead>
                <TableHead className="text-right">Amount</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {periods.map((p: DepreciationPeriod) => (
                <TableRow key={p.period}>
                  <TableCell className="tabular-nums">{p.period}</TableCell>
                  <TableCell>{fmtTs(p.period_start_ts)}</TableCell>
                  <TableCell>{fmtTs(p.period_end_ts)}</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {fmtCents(p.amount_cents)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(p.schedule_status)}>
                      {prettyStatus(p.schedule_status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {p.schedule_status === "scheduled" ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => postMut.mutate(p.period)}
                        disabled={postMut.isPending}
                      >
                        <FileCheck2 className="mr-1 h-4 w-4" />
                        Post
                      </Button>
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        {p.schedule_status === "posted" ? "Posted" : "—"}
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
