/**
 * OBP Banking Accounts API — ACC-001..ACC-004
 *
 * Backend prefix: /ui/banking
 * Gated by: OPEN_BANK_PROJECT_ENABLED AND BANKING_ACCOUNTS_ENABLED
 * When disabled, backend returns 404 (router not registered).
 *
 * All TS types defined inline (not added to shared api/types.ts).
 */

import { api } from "@/api/client";

// ─── Shared / primitive types ─────────────────────────────────────────────────

export interface BankAccount {
  /** Inline key-value attributes on the account */
  name: string;
  type: string; // "STRING" | "INTEGER" | "DOUBLE" | "BOOLEAN" | "DATE"
  value: string;
}

export interface AccountAttribute {
  name: string;
  type: string;
  value: string;
}

// ─── Banks (ACC-001) ──────────────────────────────────────────────────────────

export interface BankOut {
  bank_id: string;
  name: string;
  short_name: string;
  logo_url: string | null;
  website: string | null;
}

export interface BankListOut {
  banks: BankOut[];
}

// ─── Accounts (ACC-001) ───────────────────────────────────────────────────────

export interface AccountOut {
  account_id: string;
  bank_id: string;
  label: string;
  account_type: string;
  product_code: string;
  currency: string;
  owners: string[];
  is_default: boolean;
  wallet_backed: boolean;
  iban: string | null;
  routing_number: string | null;
  account_number_masked: string | null;
  attributes: AccountAttribute[];
  created_at: number;
  updated_at: number;
}

export interface AccountListOut {
  accounts: AccountOut[];
}

export interface AccountCreateIn {
  bank_id: string;
  label: string;
  account_type: string;
  product_code?: string;
  currency?: string;
  attributes?: AccountAttribute[];
  iban?: string | null;
  routing_number?: string | null;
  account_number_masked?: string | null;
}

export interface AccountUpdateIn {
  label?: string;
  attributes?: AccountAttribute[];
  iban?: string | null;
  routing_number?: string | null;
  account_number_masked?: string | null;
}

// ─── Balance (ACC-001) ────────────────────────────────────────────────────────

export interface AccountBalanceOut {
  currency: string;
  current: number; // dollars (not cents)
  available: number;
}

// ─── Transactions (ACC-002) ───────────────────────────────────────────────────

export interface TransactionAmountOut {
  currency: string;
  value: string; // decimal string e.g. "12.50"
}

export interface TransactionOut {
  transaction_id: string;
  account_id: string;
  type: string;
  amount: TransactionAmountOut;
  status: string;
  posted_at: number; // Unix timestamp
  description: string;
  provider: string | null;
  new_balance: TransactionAmountOut;
  has_metadata: boolean;
  metadata: TransactionMetadataOut | null;
}

export interface TransactionListOut {
  transactions: TransactionOut[];
  cursor: string | null;
}

// ─── Transaction metadata (ACC-003) ───────────────────────────────────────────

export interface NarrativeOut {
  text: string;
  author_sub: string;
  updated_at: number;
}

export interface GeotagOut {
  lat: number;
  lon: number;
  label: string | null;
  author_sub: string;
  updated_at: number;
}

export interface TransactionImageOut {
  image_id: string;
  url: string;
  author_sub: string;
  created_at: number;
}

export interface TransactionTagOut {
  tag_id: string;
  value: string;
  author_sub: string;
  created_at: number;
}

export interface TransactionCommentOut {
  comment_id: string;
  text: string;
  author_sub: string;
  created_at: number;
}

export interface TransactionMetadataOut {
  narrative: NarrativeOut | null;
  geotag: GeotagOut | null;
  image: TransactionImageOut | null;
  tags: TransactionTagOut[];
  comments: TransactionCommentOut[];
}

// ─── Account holders (ACC-004) ────────────────────────────────────────────────

export interface AccountHolderOut {
  user_sub: string;
  added_at: number;
  is_primary_owner: boolean;
}

export interface AccountHoldersOut {
  holders: AccountHolderOut[];
}

// ─── Banks ────────────────────────────────────────────────────────────────────

export const listBanks = () =>
  api.get<BankListOut>("/ui/banking/banks");

// ─── Accounts ─────────────────────────────────────────────────────────────────

export const listAccounts = () =>
  api.get<AccountListOut>("/ui/banking/accounts");

export const getAccount = (accountId: string) =>
  api.get<AccountOut>(`/ui/banking/accounts/${accountId}`);

export const createAccount = (body: AccountCreateIn) =>
  api.post<AccountOut>("/ui/banking/accounts", body);

export const updateAccount = (accountId: string, body: AccountUpdateIn) =>
  api.patch<AccountOut>(`/ui/banking/accounts/${accountId}`, body);

export const deleteAccount = (accountId: string) =>
  api.del<undefined>(`/ui/banking/accounts/${accountId}`);

export const getAccountBalance = (accountId: string) =>
  api.get<AccountBalanceOut>(`/ui/banking/accounts/${accountId}/balance`);

// ─── Transactions ─────────────────────────────────────────────────────────────

export const listTransactions = (
  accountId: string,
  opts?: {
    from?: string;
    to?: string;
    limit?: number;
    cursor?: string;
    order?: "asc" | "desc";
  }
) => {
  const params: Record<string, string> = {};
  if (opts?.from) params["from"] = opts.from;
  if (opts?.to) params["to"] = opts.to;
  if (opts?.limit != null) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  if (opts?.order) params["order"] = opts.order;
  return api.get<TransactionListOut>(
    `/ui/banking/accounts/${accountId}/transactions`,
    params
  );
};

export const getTransaction = (accountId: string, transactionId: string) =>
  api.get<TransactionOut>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}`
  );

// ─── Transaction metadata (ACC-003) ───────────────────────────────────────────

export const getTransactionMetadata = (
  accountId: string,
  transactionId: string
) =>
  api.get<TransactionMetadataOut>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/metadata`
  );

export const putNarrative = (
  accountId: string,
  transactionId: string,
  text: string
) =>
  api.put<NarrativeOut>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/narrative`,
    { text }
  );

export const putGeotag = (
  accountId: string,
  transactionId: string,
  body: { lat: number; lon: number; label?: string }
) =>
  api.put<GeotagOut>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/geotag`,
    body
  );

export const addTag = (
  accountId: string,
  transactionId: string,
  value: string
) =>
  api.post<TransactionTagOut>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/tags`,
    { value }
  );

export const removeTag = (
  accountId: string,
  transactionId: string,
  tagId: string
) =>
  api.del<{ ok: boolean }>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/tags/${tagId}`
  );

export const addComment = (
  accountId: string,
  transactionId: string,
  text: string
) =>
  api.post<TransactionCommentOut>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/comments`,
    { text }
  );

export const deleteComment = (
  accountId: string,
  transactionId: string,
  commentId: string
) =>
  api.del<{ ok: boolean }>(
    `/ui/banking/accounts/${accountId}/transactions/${transactionId}/comments/${commentId}`
  );

// ─── Account holders (ACC-004) ────────────────────────────────────────────────

export const listAccountHolders = (accountId: string) =>
  api.get<AccountHoldersOut>(`/ui/banking/accounts/${accountId}/holders`);

export const addAccountHolder = (accountId: string, userSub: string) =>
  api.post<{ account: AccountOut }>(`/ui/banking/accounts/${accountId}/holders`, {
    user_sub: userSub,
  });

export const removeAccountHolder = (accountId: string, userSub: string) =>
  api.del<{ account: AccountOut }>(
    `/ui/banking/accounts/${accountId}/holders/${userSub}`
  );
