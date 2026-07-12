/**
 * Run history / logs viewer for a single workflow rule.
 * SuiteCRM Workflow (WFL) cluster.
 */
import { useQuery } from "@tanstack/react-query";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { listRuleRuns, type WorkflowRuleOut } from "@/api/endpoints/crmWorkflow";
import {
  ActionResultBadge,
  fmtTs,
  isFlagOffError,
  NotEnabledCard,
  OutcomeBadge,
} from "./workflowShared";

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  rule: WorkflowRuleOut | null;
}

export function WorkflowRunsDialog({ open, onOpenChange, rule }: Props) {
  const runsQuery = useQuery({
    queryKey: ["crm-workflow", "runs", rule?.rule_id],
    queryFn: () => listRuleRuns(rule!.rule_id, { limit: 50 }),
    enabled: open && !!rule,
    retry: (count, err) => !isFlagOffError(err) && count < 1,
  });

  const runs = runsQuery.data?.runs ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-4xl overflow-hidden">
        <DialogHeader>
          <DialogTitle>Run history</DialogTitle>
          <DialogDescription>
            {rule ? `Recent executions of “${rule.name}” (newest first).` : ""}
          </DialogDescription>
        </DialogHeader>

        {runsQuery.isError ? (
          <NotEnabledCard error={runsQuery.error} title="Run history unavailable" />
        ) : runsQuery.isLoading ? (
          <div className="space-y-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : runs.length === 0 ? (
          <p className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
            No runs recorded yet for this rule.
          </p>
        ) : (
          <ScrollArea className="max-h-[60vh]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Started</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Record</TableHead>
                  <TableHead>Actions fired</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((run) => (
                  <TableRow key={run.run_id}>
                    <TableCell className="whitespace-nowrap text-sm">
                      {fmtTs(run.started_at)}
                    </TableCell>
                    <TableCell>
                      <OutcomeBadge outcome={run.outcome} />
                      {run.error_message && (
                        <p className="mt-1 text-xs text-destructive">
                          {run.error_message}
                        </p>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {run.record_id || "—"}
                    </TableCell>
                    <TableCell>
                      {run.actions_fired.length === 0 ? (
                        <span className="text-sm text-muted-foreground">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {run.actions_fired.map((af, i) => {
                            const type = String(af["action_type"] ?? "action");
                            const result = String(af["result"] ?? "");
                            return (
                              <span
                                key={i}
                                className="inline-flex items-center gap-1 text-xs"
                              >
                                <span className="font-medium">{type}</span>
                                {result && <ActionResultBadge result={result} />}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollArea>
        )}

        <div className="flex justify-end">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
