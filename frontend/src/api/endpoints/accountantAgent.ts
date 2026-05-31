import { api } from "@/api/client";
import type {
  AccountantConfig,
  AccountantConfigIn,
  AgentCostEntry,
  AgentTypeCosts,
  CostAlert,
  CostAlertList,
  CostBudget,
  CostBudgetIn,
  CostBudgetUpdateIn,
  CostCollectResult,
  CostDailySummary,
  CostPeriodSummary,
  CostTrends,
  OptimizationRecommendation,
  TicketCost,
  TicketCostList,
} from "@/api/types";

const BASE = "/ui/agents/accountant";

export const recordCostEntry = (entry: Partial<AgentCostEntry> & { worker_id: string; agent_type: string; agent_id: string; date: string }) =>
  api.post<AgentCostEntry>(`${BASE}/costs/entries`, entry);

export const attributeTicketCost = (data: {
  ticket_id: string;
  agent_type: string;
  llm_tokens?: number;
  llm_cost_cents?: number;
  compute_hours?: number;
  compute_cost_cents?: number;
}) => api.post<TicketCost>(`${BASE}/costs/by-ticket`, data);

export const getDailyCostSummary = (date?: string) =>
  api.get<CostDailySummary>(`${BASE}/costs/summary/daily`, date ? { date } : undefined);

export const getPeriodCostSummary = (start: string, end: string, period = "custom") =>
  api.get<CostPeriodSummary>(`${BASE}/costs/summary/period`, { start, end, period });

export const getAgentTypeCosts = (agentType: string, days = 30) =>
  api.get<AgentTypeCosts>(`${BASE}/costs/by-agent-type`, { type: agentType, days: String(days) });

export const listTicketCosts = (limit = 25, cursor?: string) =>
  api.get<TicketCostList>(
    `${BASE}/costs/by-ticket`,
    cursor ? { limit: String(limit), cursor } : { limit: String(limit) },
  );

export const getTicketCost = (ticketId: string) =>
  api.get<TicketCost>(`${BASE}/costs/by-ticket/${encodeURIComponent(ticketId)}`);

export const getCostTrends = (days = 90) =>
  api.get<CostTrends>(`${BASE}/costs/trends`, { days: String(days) });

export const getOptimizations = () =>
  api.get<OptimizationRecommendation[]>(`${BASE}/costs/optimizations`);

export const listBudgets = () => api.get<CostBudget[]>(`${BASE}/costs/budgets`);

export const createBudget = (data: CostBudgetIn) =>
  api.post<CostBudget>(`${BASE}/costs/budgets`, data);

export const updateBudget = (budgetId: string, data: CostBudgetUpdateIn) =>
  api.put<CostBudget>(`${BASE}/costs/budgets/${budgetId}`, data);

export const deleteBudget = (budgetId: string) =>
  api.del<{ ok: boolean; budget_id: string }>(`${BASE}/costs/budgets/${budgetId}`);

export const listAlerts = (acknowledged?: boolean) =>
  api.get<CostAlertList>(
    `${BASE}/costs/alerts`,
    acknowledged === undefined ? undefined : { acknowledged: String(acknowledged) },
  );

export const acknowledgeAlert = (alertId: string) =>
  api.post<CostAlert>(`${BASE}/costs/alerts/${alertId}/acknowledge`, {});

export const getAccountantConfig = () =>
  api.get<AccountantConfig>(`${BASE}/costs/config`);

export const updateAccountantConfig = (config: AccountantConfigIn) =>
  api.put<AccountantConfig>(`${BASE}/costs/config`, config);

export const triggerCostCollection = () =>
  api.post<CostCollectResult>(`${BASE}/costs/collect`, {});
