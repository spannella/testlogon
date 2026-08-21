import { api } from "@/api/client";

// ─── External custody-provider surface ───────────────────────────
// Back a custody vault with an EXTERNAL qualified custodian (Fireblocks,
// BitGo, …) in addition to the internal gateway. Provider API creds live
// SERVER-SIDE only — the UI merely INITIATES a connection and SHOWS status;
// no provider secret ever touches the client.
//
// EVERY route below is NEW and MAY 404 on backends where the provider
// integration isn't deployed yet. All callers must degrade gracefully
// (react-query retry:false + an honest "provider integration pending backend"
// empty state). The existing internal-custody behaviour is unchanged.

export type ProviderKind = "internal" | "fireblocks" | "bitgo";

export type ProviderStatus =
  | "healthy"
  | "degraded"
  | "down"
  | "not_connected";

export interface CustodyProvider {
  id: string;
  name: string;
  kind: ProviderKind;
  connected: boolean;
  status: ProviderStatus;
  features: string[];
}

export interface ProvidersResult {
  providers: CustodyProvider[];
}

export interface ConnectResult {
  ok: boolean;
  status: ProviderStatus | string;
}

export interface ProviderStatusResult {
  status: ProviderStatus | string;
  balances_attested: boolean;
  last_reconciled_ts?: number | string | null;
  pending_approvals: number;
}

/** List the custody providers available to the caller (internal + external). */
export const getProviders = () =>
  api.get<ProvidersResult>("/me/custody/providers");

/** Initiate a server-side connection to a provider (creds stay server-side). */
export const connectProvider = (id: string, label?: string) =>
  api.post<ConnectResult>(`/me/custody/providers/${encodeURIComponent(id)}/connect`, {
    ...(label ? { label } : {}),
  });

/** Tear down a provider connection. */
export const disconnectProvider = (id: string) =>
  api.post<{ ok?: boolean; status?: string; [k: string]: unknown }>(
    `/me/custody/providers/${encodeURIComponent(id)}/disconnect`,
  );

/** Live provider status: attestation, last-reconciled, pending approvals. */
export const getProviderStatus = (id: string) =>
  api.get<ProviderStatusResult>(
    `/me/custody/providers/${encodeURIComponent(id)}/status`,
  );

// ─── Vaults (provider-aware) ─────────────────────────────────────
// A richer vault read than /me/custody/subaccounts: each vault carries the
// provider that custodies it. `provider` is OPTIONAL and defaults to
// "internal" when a backend omits it.

export interface ProviderVault {
  vault: string;
  label?: string;
  provider?: ProviderKind | string;
  balances?: Record<string, number | string>;
}

export interface VaultsResult {
  vaults: ProviderVault[];
}

/** List the caller's vaults with their custodying provider. */
export const getVaults = () => api.get<VaultsResult>("/me/custody/vaults");

/** Re-point a vault at a different custody provider. */
export const setVaultProvider = (vault: string, provider: ProviderKind | string) =>
  api.put<{ ok?: boolean; vault?: string; provider?: string; [k: string]: unknown }>(
    `/me/custody/vaults/${encodeURIComponent(vault)}/provider`,
    { provider },
  );

// ─── Provider-routed withdrawal approval ─────────────────────────

export type ApprovalStatus =
  | "pending_approval"
  | "approved"
  | "signed"
  | "broadcast"
  | "rejected";

export interface ApprovalRecord {
  approver: string;
  at: number | string;
}

export interface WithdrawalApprovalResult {
  status: ApprovalStatus | string;
  quorum: number;
  approvals: ApprovalRecord[];
}

/** Poll the approval state of a provider-backed withdrawal. */
export const getWithdrawalApproval = (id: string) =>
  api.get<WithdrawalApprovalResult>(
    `/me/custody/withdrawals/${encodeURIComponent(id)}/approval`,
  );
