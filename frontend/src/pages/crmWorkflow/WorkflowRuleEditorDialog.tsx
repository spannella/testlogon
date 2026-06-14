/**
 * Create / edit dialog for a workflow rule — the "builder/editor" with
 * conditions + actions. SuiteCRM Workflow (WFL) cluster.
 */
import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  createWorkflowRule,
  updateWorkflowRule,
  WORKFLOW_ACTION_TYPES,
  WORKFLOW_OPERATORS,
  WORKFLOW_TARGET_MODULES,
  WORKFLOW_TRIGGER_TYPES,
  type WorkflowActionIn,
  type WorkflowActionType,
  type WorkflowConditionIn,
  type WorkflowOperator,
  type WorkflowRuleOut,
} from "@/api/endpoints/crmWorkflow";
import {
  actionTypeLabel,
  moduleLabel,
  operatorLabel,
  operatorNeedsValue,
  triggerLabel,
} from "./workflowShared";

interface EditableCondition {
  field: string;
  operator: WorkflowOperator;
  value: string;
}

interface EditableAction {
  action_type: WorkflowActionType;
  configText: string; // raw JSON text edited by the user
}

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  /** When provided, the dialog edits this rule; otherwise it creates a new one. */
  rule?: WorkflowRuleOut | null;
}

function toEditableConditions(rule?: WorkflowRuleOut | null): EditableCondition[] {
  if (!rule) return [];
  return (rule.conditions ?? []).map((c) => ({
    field: String(c["field"] ?? ""),
    operator: (String(c["operator"] ?? "eq") as WorkflowOperator),
    value: c["value"] == null ? "" : String(c["value"]),
  }));
}

function toEditableActions(rule?: WorkflowRuleOut | null): EditableAction[] {
  if (!rule) return [];
  return (rule.actions ?? []).map((a) => ({
    action_type: (String(a["action_type"] ?? "modify_field") as WorkflowActionType),
    configText: JSON.stringify(a["config"] ?? {}, null, 2),
  }));
}

const ACTION_CONFIG_HINT: Record<WorkflowActionType, string> = {
  modify_field: '{ "field": "status", "value": "closed" }',
  create_record: '{ "module": "ticket", "fields": { "subject": "..." } }',
  send_email: '{ "to_field": "email", "template_id": "..." }',
  drip_sequence: '{ "sequence_id": "..." }',
};

export function WorkflowRuleEditorDialog({ open, onOpenChange, rule }: Props) {
  const qc = useQueryClient();
  const isEdit = !!rule;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetModule, setTargetModule] = useState<string>("ticket");
  const [triggerType, setTriggerType] = useState<string>("on_save");
  const [enabled, setEnabled] = useState(true);
  const [conditions, setConditions] = useState<EditableCondition[]>([]);
  const [actions, setActions] = useState<EditableAction[]>([]);

  useEffect(() => {
    if (!open) return;
    setName(rule?.name ?? "");
    setDescription(rule?.description ?? "");
    setTargetModule(rule?.target_module ?? "ticket");
    setTriggerType(rule?.trigger_type ?? "on_save");
    setEnabled(rule?.enabled ?? true);
    setConditions(toEditableConditions(rule));
    setActions(toEditableActions(rule));
  }, [open, rule]);

  const buildPayloadCommon = (): {
    conditions: WorkflowConditionIn[];
    actions: WorkflowActionIn[];
  } | null => {
    const builtConditions: WorkflowConditionIn[] = [];
    for (const c of conditions) {
      if (!c.field.trim()) {
        toast.error("Every condition needs a field name");
        return null;
      }
      builtConditions.push({
        field: c.field.trim(),
        operator: c.operator,
        value: operatorNeedsValue(c.operator) ? c.value : null,
      });
    }

    const builtActions: WorkflowActionIn[] = [];
    for (let i = 0; i < actions.length; i++) {
      const a = actions[i]!;
      let config: Record<string, unknown> = {};
      const text = a.configText.trim();
      if (text) {
        try {
          const parsed = JSON.parse(text);
          if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("not an object");
          }
          config = parsed as Record<string, unknown>;
        } catch {
          toast.error(`Action #${i + 1}: config must be a valid JSON object`);
          return null;
        }
      }
      builtActions.push({ action_type: a.action_type, config });
    }

    return { conditions: builtConditions, actions: builtActions };
  };

  const createMut = useMutation({
    mutationFn: () => {
      const common = buildPayloadCommon();
      if (!common) return Promise.reject(new Error("validation"));
      return createWorkflowRule({
        name: name.trim(),
        description: description.trim(),
        target_module: targetModule as never,
        trigger_type: triggerType as never,
        enabled,
        conditions: common.conditions,
        actions: common.actions,
      });
    },
    onSuccess: () => {
      toast.success("Workflow rule created");
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "rules"] });
      onOpenChange(false);
    },
    onError: (err: unknown) => {
      if (err instanceof Error && err.message === "validation") return;
      toast.error(err instanceof Error ? err.message : "Unable to create rule");
    },
  });

  const updateMut = useMutation({
    mutationFn: () => {
      const common = buildPayloadCommon();
      if (!common) return Promise.reject(new Error("validation"));
      return updateWorkflowRule(rule!.rule_id, {
        name: name.trim(),
        description: description.trim(),
        conditions: common.conditions,
        actions: common.actions,
      });
    },
    onSuccess: () => {
      toast.success("Workflow rule updated");
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "rules"] });
      void qc.invalidateQueries({ queryKey: ["crm-workflow", "rule", rule!.rule_id] });
      onOpenChange(false);
    },
    onError: (err: unknown) => {
      if (err instanceof Error && err.message === "validation") return;
      toast.error(err instanceof Error ? err.message : "Unable to update rule");
    },
  });

  const pending = createMut.isPending || updateMut.isPending;

  const addCondition = () =>
    setConditions((cs) => [...cs, { field: "", operator: "eq", value: "" }]);
  const removeCondition = (idx: number) =>
    setConditions((cs) => cs.filter((_, i) => i !== idx));
  const patchCondition = (idx: number, patch: Partial<EditableCondition>) =>
    setConditions((cs) => cs.map((c, i) => (i === idx ? { ...c, ...patch } : c)));

  const addAction = () =>
    setActions((as) => [
      ...as,
      { action_type: "modify_field", configText: ACTION_CONFIG_HINT.modify_field },
    ]);
  const removeAction = (idx: number) =>
    setActions((as) => as.filter((_, i) => i !== idx));
  const patchAction = (idx: number, patch: Partial<EditableAction>) =>
    setActions((as) => as.map((a, i) => (i === idx ? { ...a, ...patch } : a)));

  const submit = () => {
    if (!name.trim()) {
      toast.error("Rule name is required");
      return;
    }
    if (isEdit) updateMut.mutate();
    else createMut.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit workflow rule" : "New workflow rule"}</DialogTitle>
          <DialogDescription>
            Define when this rule runs (trigger), which records it applies to
            (conditions), and what it does (actions).
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Basics */}
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="wfl-name">Name</Label>
              <Input
                id="wfl-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Auto-close resolved tickets"
                maxLength={200}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="wfl-desc">Description</Label>
              <Textarea
                id="wfl-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Explain what this rule automates"
                rows={2}
                maxLength={2000}
              />
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Target module</Label>
                <Select
                  value={targetModule}
                  onValueChange={setTargetModule}
                  disabled={isEdit}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {WORKFLOW_TARGET_MODULES.map((m) => (
                      <SelectItem key={m} value={m}>
                        {moduleLabel(m)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {isEdit && (
                  <p className="text-xs text-muted-foreground">
                    Module cannot be changed after creation.
                  </p>
                )}
              </div>
              <div className="space-y-1.5">
                <Label>Trigger</Label>
                <Select
                  value={triggerType}
                  onValueChange={setTriggerType}
                  disabled={isEdit}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {WORKFLOW_TRIGGER_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>
                        {triggerLabel(t)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            {!isEdit && (
              <div className="flex items-center justify-between rounded-md border p-3">
                <div>
                  <Label htmlFor="wfl-enabled" className="cursor-pointer">
                    Enabled
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Disabled rules never fire until re-enabled.
                  </p>
                </div>
                <Switch id="wfl-enabled" checked={enabled} onCheckedChange={setEnabled} />
              </div>
            )}
          </div>

          {/* Conditions */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold">Conditions</h3>
                <p className="text-xs text-muted-foreground">
                  All conditions must match (AND). Leave empty to match every record.
                </p>
              </div>
              <Button type="button" size="sm" variant="outline" onClick={addCondition}>
                <Plus className="mr-1 h-4 w-4" /> Add condition
              </Button>
            </div>
            {conditions.length === 0 ? (
              <p className="rounded-md border border-dashed p-3 text-center text-sm text-muted-foreground">
                No conditions — rule applies to all {moduleLabel(targetModule)} records.
              </p>
            ) : (
              <div className="space-y-2">
                {conditions.map((c, idx) => (
                  <div
                    key={idx}
                    className="grid grid-cols-1 gap-2 rounded-md border p-2 sm:grid-cols-[1fr_1fr_1fr_auto]"
                  >
                    <Input
                      value={c.field}
                      onChange={(e) => patchCondition(idx, { field: e.target.value })}
                      placeholder="field (e.g. status)"
                      aria-label="Condition field"
                    />
                    <Select
                      value={c.operator}
                      onValueChange={(v) =>
                        patchCondition(idx, { operator: v as WorkflowOperator })
                      }
                    >
                      <SelectTrigger aria-label="Condition operator">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {WORKFLOW_OPERATORS.map((op) => (
                          <SelectItem key={op} value={op}>
                            {operatorLabel(op)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      value={c.value}
                      onChange={(e) => patchCondition(idx, { value: e.target.value })}
                      placeholder={operatorNeedsValue(c.operator) ? "value" : "(no value)"}
                      disabled={!operatorNeedsValue(c.operator)}
                      aria-label="Condition value"
                    />
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      onClick={() => removeCondition(idx)}
                      aria-label="Remove condition"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold">Actions</h3>
                <p className="text-xs text-muted-foreground">
                  Actions run in order when the conditions match.
                </p>
              </div>
              <Button type="button" size="sm" variant="outline" onClick={addAction}>
                <Plus className="mr-1 h-4 w-4" /> Add action
              </Button>
            </div>
            {actions.length === 0 ? (
              <p className="rounded-md border border-dashed p-3 text-center text-sm text-muted-foreground">
                No actions yet — add at least one for the rule to do something.
              </p>
            ) : (
              <div className="space-y-2">
                {actions.map((a, idx) => (
                  <div key={idx} className="space-y-2 rounded-md border p-3">
                    <div className="flex items-center gap-2">
                      <Select
                        value={a.action_type}
                        onValueChange={(v) =>
                          patchAction(idx, {
                            action_type: v as WorkflowActionType,
                            configText:
                              ACTION_CONFIG_HINT[v as WorkflowActionType] ?? "{}",
                          })
                        }
                      >
                        <SelectTrigger className="w-full" aria-label="Action type">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {WORKFLOW_ACTION_TYPES.map((t) => (
                            <SelectItem key={t} value={t}>
                              {actionTypeLabel(t)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        onClick={() => removeAction(idx)}
                        aria-label="Remove action"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">Config (JSON)</Label>
                      <Textarea
                        value={a.configText}
                        onChange={(e) => patchAction(idx, { configText: e.target.value })}
                        rows={4}
                        className="font-mono text-xs"
                        spellCheck={false}
                      />
                      <p className="text-xs text-muted-foreground">
                        Example: <code>{ACTION_CONFIG_HINT[a.action_type]}</code>
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={pending}>
            {pending ? "Saving…" : isEdit ? "Save changes" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
