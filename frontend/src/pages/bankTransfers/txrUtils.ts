/**
 * Shared helpers for the Transaction Request pages.
 */

import type { TxnRequestStatus, TxnRequestType } from "@/api/endpoints/txnRequests";

/** Format amount_cents (integer minor units) as a human-readable currency string. */
export function formatCurrency(cents: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: currency.toUpperCase(),
      minimumFractionDigits: 2,
    }).format(cents / 100);
  } catch {
    return `${(cents / 100).toFixed(2)} ${currency.toUpperCase()}`;
  }
}

/** Format a Unix timestamp (seconds) as a locale date-time string. */
export function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Badge colour classes per status. */
export const STATUS_BADGE: Record<TxnRequestStatus, string> = {
  INITIATED: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  PENDING: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  IN_FLIGHT: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
  COMPLETED: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  FAILED: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
};

/** Human-readable labels for transaction types. */
export const TYPE_LABEL: Record<TxnRequestType, string> = {
  WALLET_TRANSFER: "Wallet Transfer",
  COUNTERPARTY: "Counterparty Payment",
  PAYOUT: "Payout",
  REFUND: "Refund",
  FREE_FORM: "Free-Form Transfer",
};

/** Human-readable labels for statuses. */
export const STATUS_LABEL: Record<TxnRequestStatus, string> = {
  INITIATED: "Initiated",
  PENDING: "Pending SCA",
  IN_FLIGHT: "Processing",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

/** Supported transaction types with descriptions for the create form. */
export const TXN_TYPES: { value: TxnRequestType; label: string; description: string }[] = [
  {
    value: "WALLET_TRANSFER",
    label: "Wallet Transfer",
    description: "Send funds to another user's wallet.",
  },
  {
    value: "FREE_FORM",
    label: "Free-Form Transfer",
    description: "General-purpose fund movement or payment.",
  },
  {
    value: "PAYOUT",
    label: "Payout",
    description: "Withdraw to a registered payout method.",
  },
  {
    value: "REFUND",
    label: "Refund",
    description: "Refund a prior Stripe payment intent.",
  },
  {
    value: "COUNTERPARTY",
    label: "Counterparty Payment",
    description: "Send to an external counterparty reference.",
  },
];

/** Returns true when the request has an SCA challenge that still needs completing. */
export function needsSca(status: TxnRequestStatus): boolean {
  return status === "PENDING";
}

/** Returns true when the request can be executed. */
export function canExecute(status: TxnRequestStatus): boolean {
  return status === "INITIATED" || status === "PENDING";
}
