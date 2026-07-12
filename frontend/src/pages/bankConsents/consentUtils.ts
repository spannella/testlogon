/**
 * Shared helpers for the PSD2 Consent pages (CSN-001..CSN-006).
 */

import type { ConsentStatus, ConsentType } from "@/api/endpoints/psd2Consents";

/** Format a Unix timestamp (seconds) as a locale date-time string. */
export function fmtTs(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Format a Unix timestamp as a short date. */
export function fmtDate(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

/** Badge colour classes per consent status. */
export const STATUS_BADGE: Record<ConsentStatus, string> = {
  INITIATED: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  ACCEPTED: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  REVOKED: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  EXPIRED: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
};

/** Human-readable labels for consent statuses. */
export const STATUS_LABEL: Record<ConsentStatus, string> = {
  INITIATED: "Initiated",
  ACCEPTED: "Accepted",
  REVOKED: "Revoked",
  EXPIRED: "Expired",
};

/** Human-readable label for consent type. */
export function typeLabel(t: ConsentType): string {
  return t === "AIS" ? "Account Information" : "Payment Initiation";
}

/** Returns true if a consent can be revoked. */
export function canRevoke(status: ConsentStatus): boolean {
  return status === "INITIATED" || status === "ACCEPTED";
}

/** Returns true if a consent still needs SCA acceptance. */
export function needsAcceptance(status: ConsentStatus): boolean {
  return status === "INITIATED";
}
