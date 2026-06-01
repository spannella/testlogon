import { api } from "@/api/client";
import type {
  SyndicateTreasuryBalanceOut,
  SyndicateTreasuryContributorOut,
  SyndicateTreasuryDepositOut,
  SyndicateTreasuryDisburseOut,
  SyndicateTreasuryLedgerOut,
} from "@/api/types";

// -- Syndicate Treasury / Fund Management (SYND-004) --

export const getTreasuryBalance = (syndicateId: string) =>
  api.get<SyndicateTreasuryBalanceOut>(`/ui/syndicates/treasury/${syndicateId}`);

export const depositToTreasury = (syndicateId: string, amountCents: number) =>
  api.post<SyndicateTreasuryDepositOut>(
    `/ui/syndicates/treasury/${syndicateId}/deposit`,
    { amount_cents: amountCents },
  );

export const disburseFromTreasury = (
  syndicateId: string,
  body: { recipient_user_id: string; amount_cents: number; note?: string },
) =>
  api.post<SyndicateTreasuryDisburseOut>(
    `/ui/syndicates/treasury/${syndicateId}/disburse`,
    body,
  );

export const getTreasuryLedger = (syndicateId: string, limit = 50) =>
  api.get<SyndicateTreasuryLedgerOut>(
    `/ui/syndicates/treasury/${syndicateId}/ledger`,
    { limit: String(limit) },
  );

export const getTreasuryContributions = (syndicateId: string) =>
  api.get<SyndicateTreasuryContributorOut[]>(
    `/ui/syndicates/treasury/${syndicateId}/contributions`,
  );

export const getMyTreasuryContributions = (syndicateId: string) =>
  api.get<SyndicateTreasuryContributorOut>(
    `/ui/syndicates/treasury/${syndicateId}/my-contributions`,
  );
