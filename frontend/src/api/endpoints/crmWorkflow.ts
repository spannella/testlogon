/**
 * SuiteCRM Workflow (WFL) — admin CRUD endpoints.
 *
 * Mirrors the LIVE backend router app/routers/workflow_rules.py
 * (prefix /ui/admin/crm/workflow) and the Pydantic models in app/models.py.
 * Gated by CRM_WORKFLOW_ENABLED (default OFF -> 404).
 *
 * Types are defined INLINE here (not in shared api/types.ts) per cluster
 * isolation rules.
 */
import { api } from "@/api/client";

// ─── Enums / constants (mirror app/services/workflow_rules.py) ───────────────

export const WORKFLOW_TARGET_MODULES = [
  "ticket",
  "contact",
  "order",
  "subscription",
  "lead",
] as const;
export type WorkflowTargetModule = (typeof WORKFLOW_TARGET_MODULES)[number];

export const WORKFLOW_TRIGGER_TYPES = [
  "on_save",
  "on_schedule",
  "on_time_elapsed",
] as const;
export type WorkflowTriggerType = (typeof WORKFLOW_TRIGGER_TYPES)[number];

export const WORKFLOW_OPERATORS = [
  "eq",
  "neq",
  "contains",
  "gt",
  "lt",
  "is_empty",
  "is_not_empty",
] as const;
export type WorkflowOperator = (typeof WORKFLOW_OPERATORS)[number];

export const WORKFLOW_ACTION_TYPES = [
  "modify_field",
  "create_record",
  "send_email",
  "drip_sequence",
] as const;
export type WorkflowActionType = (typeof WORKFLOW_ACTION_TYPES)[number];

// ─── Wire types (mirror Pydantic models) ─────────────────────────────────────

export interface WorkflowConditionIn {
  field: string;
  operator: WorkflowOperator;
  value?: string | null;
}

export interface WorkflowActionIn {
  action_type: WorkflowActionType;
  config: Record<string, unknown>;
}

export interface WorkflowRuleCreateIn {
  name: string;
  description?: string;
  target_module: WorkflowTargetModule;
  trigger_type: WorkflowTriggerType;
  trigger_config?: Record<string, unknown>;
  conditions?: WorkflowConditionIn[];
  actions?: WorkflowActionIn[];
  enabled?: boolean;
}

export interface WorkflowRuleUpdateIn {
  name?: string;
  description?: string;
  trigger_config?: Record<string, unknown>;
  conditions?: WorkflowConditionIn[];
  actions?: WorkflowActionIn[];
}

export interface WorkflowRuleOut {
  rule_id: string;
  name: string;
  description: string;
  target_module: string;
  trigger_type: string;
  trigger_config: Record<string, unknown>;
  conditions: Array<Record<string, unknown>>;
  actions: Array<Record<string, unknown>>;
  enabled: boolean;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface WorkflowRuleListOut {
  rules: WorkflowRuleOut[];
  cursor?: string | null;
}

export interface WorkflowRunOut {
  run_id: string;
  rule_id: string;
  target_module: string;
  record_id: string;
  trigger_type: string;
  outcome: string; // "matched" | "error" | "skipped"
  actions_fired: Array<Record<string, unknown>>;
  started_at: number;
  finished_at?: number | null;
  error_message?: string | null;
}

export interface WorkflowRunListOut {
  runs: WorkflowRunOut[];
  cursor?: string | null;
}

export interface DripStageIn {
  stage_number: number;
  delay_hours: number;
  template_id: string;
  to_field: string;
}

export interface DripSequenceCreateIn {
  name: string;
  description?: string;
  stages: DripStageIn[];
}

export interface DripSequenceUpdateIn {
  name?: string;
  description?: string;
  stages?: DripStageIn[];
}

export interface DripSequenceOut {
  sequence_id: string;
  name: string;
  description: string;
  stages: Array<Record<string, unknown>>;
  created_by: string;
  created_at: number;
  updated_at: number;
}

export interface DripSequenceListOut {
  sequences: DripSequenceOut[];
  cursor?: string | null;
}

// ─── Base path ───────────────────────────────────────────────────────────────

const BASE = "/ui/admin/crm/workflow";

// ─── Rule CRUD ───────────────────────────────────────────────────────────────

export const listWorkflowRules = (opts?: {
  target_module?: string;
  enabled_only?: boolean;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.target_module) params["target_module"] = opts.target_module;
  if (opts?.enabled_only) params["enabled_only"] = "true";
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<WorkflowRuleListOut>(`${BASE}/rules`, params);
};

export const getWorkflowRule = (ruleId: string) =>
  api.get<WorkflowRuleOut>(`${BASE}/rules/${encodeURIComponent(ruleId)}`);

export const createWorkflowRule = (body: WorkflowRuleCreateIn) =>
  api.post<WorkflowRuleOut>(`${BASE}/rules`, body);

export const updateWorkflowRule = (ruleId: string, body: WorkflowRuleUpdateIn) =>
  api.patch<WorkflowRuleOut>(`${BASE}/rules/${encodeURIComponent(ruleId)}`, body);

export const deleteWorkflowRule = (ruleId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/rules/${encodeURIComponent(ruleId)}`);

export const enableWorkflowRule = (ruleId: string) =>
  api.post<WorkflowRuleOut>(`${BASE}/rules/${encodeURIComponent(ruleId)}/enable`, {});

export const disableWorkflowRule = (ruleId: string) =>
  api.post<WorkflowRuleOut>(`${BASE}/rules/${encodeURIComponent(ruleId)}/disable`, {});

// ─── Run history ─────────────────────────────────────────────────────────────

export const listRuleRuns = (
  ruleId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<WorkflowRunListOut>(
    `${BASE}/rules/${encodeURIComponent(ruleId)}/runs`,
    params,
  );
};

// ─── Drip sequences ──────────────────────────────────────────────────────────

export const listDripSequences = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<DripSequenceListOut>(`${BASE}/drip-sequences`, params);
};

export const getDripSequence = (sequenceId: string) =>
  api.get<DripSequenceOut>(`${BASE}/drip-sequences/${encodeURIComponent(sequenceId)}`);

export const createDripSequence = (body: DripSequenceCreateIn) =>
  api.post<DripSequenceOut>(`${BASE}/drip-sequences`, body);

export const updateDripSequence = (sequenceId: string, body: DripSequenceUpdateIn) =>
  api.patch<DripSequenceOut>(
    `${BASE}/drip-sequences/${encodeURIComponent(sequenceId)}`,
    body,
  );

export const deleteDripSequence = (sequenceId: string) =>
  api.del<{ ok: boolean }>(`${BASE}/drip-sequences/${encodeURIComponent(sequenceId)}`);
