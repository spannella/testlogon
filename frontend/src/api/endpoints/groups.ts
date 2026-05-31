import { api } from "@/api/client";
import type {
  TreasuryBalance,
  TreasuryLedgerResponse,
  ContributorListResponse,
  ContributeResponse,
  SpendResponse,
} from "@/api/types";

// ---------------------------------------------------------------------------
// Group Treasury (GROUP-004)
// ---------------------------------------------------------------------------

export const getTreasuryBalance = (groupId: string) =>
  api.get<TreasuryBalance>(`/ui/groups/${groupId}/treasury`);

export const contributeToTreasury = (groupId: string, amountCents: number) =>
  api.post<ContributeResponse>(`/ui/groups/${groupId}/treasury/contribute`, {
    amount_cents: amountCents,
  });

export const getTreasuryLedger = (
  groupId: string,
  params?: { cursor?: string; limit?: number },
) => api.get<TreasuryLedgerResponse>(`/ui/groups/${groupId}/treasury/ledger`, { params });

export const getTreasuryContributors = (groupId: string) =>
  api.get<ContributorListResponse>(`/ui/groups/${groupId}/treasury/contributors`);

export const setFundraisingGoal = (groupId: string, goalCents: number | null) =>
  api.patch<{ ok: boolean; fundraising_goal_cents: number | null }>(
    `/ui/groups/${groupId}/treasury/goal`,
    { goal_cents: goalCents },
  );

export const spendTreasury = (
  groupId: string,
  data: {
    amount_cents: number;
    reason: string;
    category?: string;
    reference_id?: string;
  },
) => api.post<SpendResponse>(`/ui/groups/${groupId}/treasury/spend`, data);
