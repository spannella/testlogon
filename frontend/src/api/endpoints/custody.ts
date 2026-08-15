import { api } from "@/api/client";

// ─── Types ──────────────────────────────────────────────────────

export interface CustodyAsset {
  asset: string;
  chain: string;
  name: string;
  symbol: string;
  decimals: number;
  network: string;
  balance: string | number;
  address_available: boolean;
}

export interface DepositAddress {
  asset: string;
  chain: string;
  network: string;
  address: string;
  memo?: string | null;
}

export interface CustodyDeposit {
  id: string;
  asset: string;
  chain: string;
  amount: string | number;
  status: string;
  confirmations: number;
}

export type WithdrawalStatus =
  | "screening"
  | "signed"
  | "pending_approval"
  | "blocked"
  | "rejected"
  | "broadcast"
  | "settled";

/** Shape returned by POST /ui/custody/withdrawals (create). */
export interface WithdrawalCreateResult {
  id: string;
  status: WithdrawalStatus;
  asset: string;
  chain: string;
  amount: string | number;
  destination: string;
  signature?: string | null;
  digest?: string | null;
  approvals_required?: number;
  approvals?: number | string[];
  error?: string | null;
  category?: string | null;
  source?: string | null;
  detail?: string | null;
}

/** Shape returned by list/detail endpoints. */
export interface Withdrawal {
  id: string;
  asset: string;
  chain_ref?: string;
  chain?: string;
  network?: string;
  recipient?: string;
  destination?: string;
  amount: string | number;
  status: WithdrawalStatus;
  approvals?: string[];
  approvals_count?: number;
  approvals_required?: number;
  signature?: string | null;
  digest?: string | null;
  error?: string | null;
  category?: string | null;
  source?: string | null;
  timelock_until_ms?: number | null;
  created_ms?: number;
}

export interface AuditEntry {
  seq: number;
  action: string;
  detail: string;
  ts_ms: number;
  prev: string;
  hash: string;
}

export interface AuditResp {
  entries: AuditEntry[];
}

export interface AuditVerifyResp {
  ok: boolean;
  entries: number;
}

export interface ApproveResp {
  withdrawal_id: string;
  status: WithdrawalStatus;
  approvals: number | string[];
  approvals_required: number;
}

export interface ReleaseResp {
  withdrawal_id: string;
  status: "signed";
  signature: string;
  digest: string;
}

// ─── Endpoints ──────────────────────────────────────────────────

export const listCustodyAssets = () =>
  api.get<CustodyAsset[]>("/ui/custody/assets");

export const getDepositAddress = (asset: string, chain: string) =>
  api.get<DepositAddress>("/ui/custody/deposit-address", { asset, chain });

export const listCustodyDeposits = () =>
  api.get<CustodyDeposit[]>("/ui/custody/deposits");

export const createWithdrawal = (body: {
  asset: string;
  chain: string;
  amount: string;
  destination: string;
  memo?: string;
}) => api.post<WithdrawalCreateResult>("/ui/custody/withdrawals", body);

export const listWithdrawals = () =>
  api.get<Withdrawal[]>("/ui/custody/withdrawals");

export const getWithdrawal = (id: string) =>
  api.get<Withdrawal>(`/ui/custody/withdrawals/${id}`);

// ─── Officer / admin ────────────────────────────────────────────

export const listApprovals = () =>
  api.get<Withdrawal[]>("/ui/custody/approvals");

export const approveWithdrawal = (id: string, approver?: string) =>
  api.post<ApproveResp>(`/ui/custody/withdrawals/${id}/approve`, approver ? { approver } : {});

export const releaseWithdrawal = (id: string) =>
  api.post<ReleaseResp>(`/ui/custody/withdrawals/${id}/release`, {});

export const getCustodyAudit = () =>
  api.get<AuditResp>("/ui/custody/audit");

export const verifyCustodyAudit = () =>
  api.get<AuditVerifyResp>("/ui/custody/audit/verify");
