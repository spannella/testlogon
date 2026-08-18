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
  /** Source chain id (as a string). Map to a name via CUSTODY_ASSETS. */
  chain: string;
  /** On-chain transaction hash of the incoming transfer. */
  txhash: string;
  /** Log index within the tx (as a string). */
  log_index: string;
  /** Credited asset symbol (e.g. "ETH", "USDC"). */
  asset: string;
  /** Amount as a string. */
  amount: string;
  /** "credited" once applied to the vault; "duplicate" if already seen. */
  status: "credited" | "duplicate" | string;
  /** Monotonic scanner sequence number. */
  seq: number;
  /** Unix timestamp — seconds if small, ms if large (detect on render). */
  ts: number;
}

export interface CustodyDepositsResult {
  /** Vault id these deposits credited into. */
  vault: string;
  /** Incoming transfers, newest first. */
  deposits: CustodyDeposit[];
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
