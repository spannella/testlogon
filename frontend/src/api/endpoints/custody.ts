import { api } from "@/api/client";

// ─── Production /me/custody/* contract ──────────────────────────
// The exchange edge session-authenticates the caller and performs the
// HMAC-to-gateway itself. Only THREE endpoints exist:
//   GET  /me/custody/balance
//   GET  /me/custody/deposit-address?chain=<id>
//   POST /me/custody/withdraw
//   GET  /me/custody/deposits   (scanner-fed incoming-transfer feed)
// The deposit-scanner feed above lists incoming on-chain transfers the
// custody gateway has observed and credited. There is still NO withdrawal
// history / approvals / audit endpoint on the account-facing API.

// ─── Types ──────────────────────────────────────────────────────

export interface CustodyBalance {
  /** Auto-provisioned vault id for the session's account. */
  vault: string;
  /** Custody tier (e.g. "standard"). */
  tier: string;
  /** asset-symbol -> amount (string or number). */
  balances: Record<string, number | string>;
}

export interface DepositAddress {
  address: string;
  /** Chain id this address belongs to (as a string). */
  chain: string;
  /** Address family, e.g. "evm". */
  family: string;
  /** Derivation path / scheme metadata. */
  derivation: string;
  /** Signing / attestation domain. */
  domain: string;
}

export interface CustodyDeposit {
  /** Vault the deposit credited into. */
  vault?: string;
  /** Source chain id (as a string). Map to a name via CUSTODY_ASSETS. */
  chain: string;
  /** On-chain transaction hash of the incoming transfer. */
  txhash: string;
  /** Log index within the tx (as a string or number). */
  log_index: string | number;
  /** Credited asset symbol (e.g. "ETH", "USDC"). */
  asset: string;
  /** Amount as a string. */
  amount: string;
  /** Idempotency key for the credited transfer. */
  dedup_key?: string;
}

export interface CustodyDepositsResult {
  /** Vault id these deposits credited into. */
  vault: string;
  /** Incoming transfers. */
  deposits: CustodyDeposit[];
  /** Count of deposits. */
  count?: number;
}

export type WithdrawalStatus =
  | "signed"
  | "pending_approval"
  | "blocked"
  | "rejected"
  | "error";

export interface WithdrawRequest {
  /** Chain id, e.g. "1" for Ethereum mainnet. */
  chain: string;
  /** Destination address (a leading 0x is fine — backend strips it). */
  to: string;
  /** Amount as a string. */
  amount: string;
  /** "native" for the chain coin, or an ERC-20 contract address. */
  token?: string;
  nonce?: string | number;
  gas_price?: string | number;
  gas_limit?: string | number;
  expiry?: string | number;
  client_ref?: string;
}

/** Gateway withdrawal result. Extra fields may be present. */
export interface WithdrawResult {
  status: WithdrawalStatus | string;
  withdrawal_id?: string;
  signature?: string;
  digest?: string;
  client_ref: string;
  intent_id: string;
  /** Present on blocked/rejected/error. */
  detail?: string;
  error?: string;
  category?: string;
  reason?: string;
  /** Governed-withdrawal approvals metadata (shape not guaranteed). */
  approvals_required?: number;
  approvals?: number | string[];
  [k: string]: unknown;
}

// ─── Endpoints ──────────────────────────────────────────────────

export const getBalance = () => api.get<CustodyBalance>("/me/custody/balance");

export const getDepositAddress = (chainId: string | number) =>
  api.get<DepositAddress>("/me/custody/deposit-address", {
    chain: String(chainId),
  });

export const withdraw = (req: WithdrawRequest) =>
  api.post<WithdrawResult>("/me/custody/withdraw", req);

/**
 * The deposit-scanner feed of incoming on-chain transfers (newest first).
 * NEW endpoint — may 404 on backends where the scanner isn't deployed yet;
 * callers should render a graceful empty/unavailable state.
 */
export const getDeposits = () =>
  api.get<CustodyDepositsResult>("/me/custody/deposits");

// ─── Client-side asset registry ─────────────────────────────────
// The /me/custody API is keyed by CHAIN (deposit addresses) and by
// chain+token (withdrawals). This registry maps the human asset the UI
// shows to the chain id / token the API needs. EVM chains share a
// deposit address; the token disambiguates ERC-20s on withdrawal.

export interface CustodyAssetMeta {
  symbol: string;
  name: string;
  /** Chain id used by the deposit + withdraw endpoints. */
  chainId: number;
  /** Human chain name. */
  chainName: string;
  /** Display network label (e.g. "Ethereum (ERC-20)"). */
  network: string;
  /** "native" for the chain coin, or an ERC-20 contract address. */
  token: "native" | string;
  decimals: number;
}

export const CUSTODY_ASSETS: CustodyAssetMeta[] = [
  {
    symbol: "ETH",
    name: "Ether",
    chainId: 1,
    chainName: "Ethereum",
    network: "Ethereum",
    token: "native",
    decimals: 18,
  },
  {
    symbol: "USDC",
    name: "USD Coin",
    chainId: 1,
    chainName: "Ethereum",
    network: "Ethereum (ERC-20)",
    token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    decimals: 6,
  },
  {
    symbol: "USDT",
    name: "Tether USD",
    chainId: 1,
    chainName: "Ethereum",
    network: "Ethereum (ERC-20)",
    token: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    decimals: 6,
  },
  {
    symbol: "BNB",
    name: "BNB",
    chainId: 56,
    chainName: "BNB Smart Chain",
    network: "BNB Smart Chain",
    token: "native",
    decimals: 18,
  },
  {
    symbol: "POL",
    name: "Polygon",
    chainId: 137,
    chainName: "Polygon",
    network: "Polygon",
    token: "native",
    decimals: 18,
  },
];

export function findAsset(symbol: string): CustodyAssetMeta | undefined {
  const up = symbol.toUpperCase();
  return CUSTODY_ASSETS.find((a) => a.symbol.toUpperCase() === up);
}

/** A displayable asset row: registry metadata merged with a live balance. */
export interface DisplayAsset extends CustodyAssetMeta {
  balance: number | string;
  /** True if this row has no registry entry (balance-only fallback). */
  unknown: boolean;
}

/**
 * Merge the balance map (keyed by asset symbol) with the registry.
 * Every registry asset is shown (0 if absent), and every balance key not
 * in the registry is shown too with sensible fallbacks so nothing is hidden.
 */
export function mergeBalances(
  balances: Record<string, number | string> | undefined,
): DisplayAsset[] {
  const bal = balances ?? {};
  const rows: DisplayAsset[] = CUSTODY_ASSETS.map((a) => ({
    ...a,
    balance: bal[a.symbol] ?? bal[a.symbol.toUpperCase()] ?? 0,
    unknown: false,
  }));

  const known = new Set(CUSTODY_ASSETS.map((a) => a.symbol.toUpperCase()));
  for (const [key, value] of Object.entries(bal)) {
    if (known.has(key.toUpperCase())) continue;
    rows.push({
      symbol: key,
      name: key,
      chainId: 1,
      chainName: "Unknown",
      network: "Unknown network",
      token: "native",
      decimals: 18,
      balance: value,
      unknown: true,
    });
  }
  return rows;
}


// ─── Sub-accounts, custody<->trading bridge, and fee endpoints ───────────
// Gap-closing endpoints from the exchange-edge custody phase. Every one MAY
// 404 on backends where the edge isn't deployed yet — all callers must degrade
// gracefully (retry:false + an "unavailable" empty state). These routes are
// REAL (atomic, reversal-on-failure) — there is NO stub/simulated flag.

export interface Subaccount {
  /** Sub-account label (base vault has no label). */
  label: string;
  /** Full vault name. */
  vault: string;
}

export interface SubaccountsResult {
  subaccounts: Subaccount[];
}

/**
 * List the caller's sub-account vaults (label + vault only — no balances/tier).
 * 404s until the edge deploys — callers should render a graceful
 * "not available on this backend yet" state (retry:false).
 */
export const getSubaccounts = () =>
  api.get<SubaccountsResult>("/me/custody/subaccounts");

export interface CreateSubaccountResult {
  created: true;
  label: string;
  vault: string;
}

/** Create a named sub-account vault under the caller's base vault. */
export const createSubaccount = (label: string) =>
  api.post<CreateSubaccountResult>("/me/custody/subaccounts", { label });

/** Real atomic vault->vault transfer result. No stub flag. */
export interface SubaccountTransferResult {
  transferred: true;
  asset: string;
  amount: string | number;
  from: string;
  to: string;
  from_balance: string | number;
  to_balance: string | number;
}

export interface SubaccountTransferRequest {
  from_label?: string;
  to_label?: string;
  /** Defaults to "native" when omitted. */
  asset?: string;
  amount: number | string;
}

/**
 * Move an asset between two of the caller's OWN sub-account vaults (or the
 * base vault when a label is omitted). REAL atomic move — no stub.
 */
export const transferBetweenSubaccounts = (req: SubaccountTransferRequest) =>
  api.post<SubaccountTransferResult>("/me/custody/subaccounts/transfer", req);

// ─── Custody <-> trading bridge (FOUR real routes) ───────────────────────
// Move value between the custody vault and the exchange spot/margin ledgers.
// REAL (atomic, reversal-on-failure). Body is keyed by asset SYMBOL.

export interface BridgeRequest {
  /** Asset symbol from CUSTODY_ASSETS ("ETH","USDC","USDT","BNB","POL"). */
  token: string;
  /** Amount as a decimal string. */
  amount: string;
}

/** custody -> spot: 200. */
export interface FundSpotResult {
  funded: true;
  token: string;
  asset_id: number | string;
  amount: string | number;
  me_amount: string | number;
  spot: unknown;
}

/** spot -> custody: 200 | 422 {settled:false, reason, spot}. */
export interface SettleSpotResult {
  settled: boolean;
  token?: string;
  amount?: string | number;
  me_amount?: string | number;
  spot?: unknown;
  custody?: unknown;
  reason?: string;
}

/** custody -> margin: 200 | 422 {funded:false, reason, margin}. */
export interface FundMarginResult {
  funded: boolean;
  token?: string;
  asset_id?: number | string;
  amount?: string | number;
  me_amount?: string | number;
  margin?: unknown;
  reason?: string;
}

/** margin -> custody: 200 | 422. */
export interface SettleMarginResult {
  settled: boolean;
  token?: string;
  amount?: string | number;
  me_amount?: string | number;
  margin?: unknown;
  custody?: unknown;
  reason?: string;
}

/** custody -> spot */
export const fundSpot = (req: BridgeRequest) =>
  api.post<FundSpotResult>("/me/custody/fund-spot", req);

/** spot -> custody */
export const settleSpot = (req: BridgeRequest) =>
  api.post<SettleSpotResult>("/me/custody/settle-spot", req);

/** custody -> margin */
export const fundMargin = (req: BridgeRequest) =>
  api.post<FundMarginResult>("/me/custody/fund-margin", req);

/** margin -> custody */
export const settleMargin = (req: BridgeRequest) =>
  api.post<SettleMarginResult>("/me/custody/settle-margin", req);

// ─── Fees ────────────────────────────────────────────────────────────────

export interface FeeScheduleResult {
  status: "ok" | string;
  type?: string;
  symbolid: number;
  maker_fee_bps: number;
  taker_fee_bps: number;
  liquidation_fee_bps: number;
  source: "engine" | "venue_default" | string;
  configured: boolean;
}

/** The maker/taker/liquidation fee schedule for a symbol. */
export const getFeeSchedule = (symbolid: number) =>
  api.get<FeeScheduleResult>("/me/fees/schedule", { symbolid: String(symbolid) });
