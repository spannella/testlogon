/**
 * SuiteCRM Workflow (WFL) — workflow rules list + management.
 * Admin-oriented. Route: /crm/workflow.
 */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { GitBranch, History, Pencil, Plus, Trash2 } from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  deleteWorkflowRule,
  disableWorkflowRule,
  enableWorkflowRule,
  listWorkflowRules,
  WORKFLOW_TARGET_MODULES,
  type WorkflowRuleOut,
} from "@/api/endpoints/crmWorkflow";
import {
  fmtTs,
  isFlagOffError,
  moduleLabel,
  NotEnabledCard,
  triggerLabel,
} from "./workflowShared";
import { WorkflowRuleEditorDialog } from "./WorkflowRuleEditorDialog";
import { WorkflowRunsDialog } from "./WorkflowRunsDialog";

export default function WorkflowRulesPage() {
  const qc = useQueryClient();

  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [enabledOnly, setEnabledOnly] = useState(false);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<WorkflowRuleOut | null>(null);

  const [runsOpen, setRunsOpen] = useState(false);
  const [runsRule, setRunsRule] = useState<WorkflowRuleOut | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<WorkflowRuleOut | null>(null);

  const rulesQuery = useQuery({
    queryKey: ["crm-workflow", "rules", { moduleFilter, enabledOnly }],
    queryFn: () =>
      listWorkflowRules({
        target_module: moduleFilter === "all" ? undefined : moduleFilter,
        enabled_only: enabledOnly,
        limit: 100,
      }),
    retry: (count, err) => !isFlagOffError(err) && count < 1,
  });

  const toggleMut = useMutation({
    mutationFn: ({ rule, enable }: { rule: WorkflowRuleOut; enable: boolean }) =>
      enable ? enableWorkflowRule(rule.rule_id) : disableWorkflowRule(rule.rule_id),
    onSuccess: (_data, vars) => {
      toast.success(vars.enable ? "Rule enabled" : "Rule disabled");
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "rules"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to update rule"),
  });

  const deleteMut = useMutation({
    mutationFn: (ruleId: string) => deleteWorkflowRule(ruleId),
    onSuccess: () => {
      toast.success("Rule deleted");
      setDeleteTarget(null);
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "rules"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to delete rule"),
  });

  const rules = rulesQuery.data?.rules ?? [];

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };
  const openEdit = (rule: WorkflowRuleOut) => {
    setEditing(rule);
    setEditorOpen(true);
  };
  const openRuns = (rule: WorkflowRuleOut) => {
    setRunsRule(rule);
    setRunsOpen(true);
  };

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Workflow automation"
        description="Define rules that automatically act on CRM records when conditions match."
        actions={
          <div className="flex items-center gap-2">
            <Button asChild variant="outline">
              <Link to="/crm/workflow/drip-sequences">
                <GitBranch className="mr-1 h-4 w-4" /> Drip sequences
              </Link>
            </Button>
            <Button onClick={openCreate}>
              <Plus className="mr-1 h-4 w-4" /> New rule
            </Button>
          </div>
        }
      />

      {rulesQuery.isError ? (
        <NotEnabledCard error={rulesQuery.error} />
      ) : (
        <Card>
          <CardContent className="space-y-4 pt-6">
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Module</span>
                <Select value={moduleFilter} onValueChange={setModuleFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All modules</SelectItem>
                    {WORKFLOW_TARGET_MODULES.map((m) => (
                      <SelectItem key={m} value={m}>
                        {moduleLabel(m)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <label className="flex cursor-pointer items-center gap-2 text-sm">
                <Switch checked={enabledOnly} onCheckedChange={setEnabledOnly} />
                Enabled only
              </label>
            </div>

            {rulesQuery.isLoading ? (
              <div className="space-y-2">
                {[0, 1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : rules.length === 0 ? (
              <div className="rounded-md border border-dashed p-10 text-center">
                <GitBranch className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
                <p className="text-sm font-medium">No workflow rules yet</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Create a rule to start automating your CRM.
                </p>
                <Button className="mt-4" onClick={openCreate}>
                  <Plus className="mr-1 h-4 w-4" /> New rule
                </Button>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Module</TableHead>
                    <TableHead>Trigger</TableHead>
                    <TableHead className="text-center">Conditions</TableHead>
                    <TableHead className="text-center">Actions</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="text-right">Manage</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule) => (
                    <TableRow key={rule.rule_id}>
                      <TableCell>
                        <div className="font-medium">{rule.name}</div>
                        {rule.description && (
                          <div className="max-w-xs truncate text-xs text-muted-foreground">
                            {rule.description}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{moduleLabel(rule.target_module)}</Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {triggerLabel(rule.trigger_type)}
                      </TableCell>
                      <TableCell className="text-center text-sm">
                        {rule.conditions.length}
                      </TableCell>
                      <TableCell className="text-center text-sm">
                        {rule.actions.length}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={rule.enabled}
                            disabled={toggleMut.isPending}
                            onCheckedChange={(v) =>
                              toggleMut.mutate({ rule, enable: v })
                            }
                            aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
                          />
                          <span className="text-xs text-muted-foreground">
                            {rule.enabled ? "On" : "Off"}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {fmtTs(rule.updated_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => openRuns(rule)}
                            aria-label="View run history"
                            title="Run history"
                          >
                            <History className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => openEdit(rule)}
                            aria-label="Edit rule"
                            title="Edit"
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => setDeleteTarget(rule)}
                            aria-label="Delete rule"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <WorkflowRuleEditorDialog
        open={editorOpen}
        onOpenChange={setEditorOpen}
        rule={editing}
      />
      <WorkflowRunsDialog open={runsOpen} onOpenChange={setRunsOpen} rule={runsRule} />

      <AlertDialog
        open={!!deleteTarget}
        onOpenChange={(v) => !v && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete workflow rule?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes “{deleteTarget?.name}”. Run history is
              retained but the rule will no longer fire.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMut.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleteMut.isPending}
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.rule_id)}
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
