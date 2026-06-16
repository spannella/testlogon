/**
 * Ticket Bounty Board API endpoints (TBT-001..TBT-009).
 *
 * All endpoints live under /tickets/* — the same proxy prefix already in
 * vite.config.ts for the tickets router (mounted at /tickets in main.py).
 *
 * Feature-flag: TICKET_BOUNTIES_ENABLED defaults OFF; all mutation endpoints
 * return 404 when off. Handle gracefully by catching ApiError.status === 404.
 */

import { api } from "@/api/client";

// ─── Inline types (mirroring app/routers/tickets.py) ─────────────────────────

export type BountyStatus =
  | "funded"
  | "claimed"
  | "submitted"
  | "paid_out"
  | "cancelled";

/** Mirrors BountyBoardItem in app/routers/tickets.py */
export interface BountyBoardItem {
  ticket_id: string;
  subject: string;
  owner_sub: string;
  status: string;
  labels: string[];
  created_at: number;
  updated_at: number;
  bounty_amount_cents: number;
  bounty_currency: string;
  bounty_status: BountyStatus | null;
  bounty_id: string | null;
  bounty_funded_at: number | null;
}

/** Mirrors BountyBoardEnvelope in app/routers/tickets.py */
export interface BountyBoardEnvelope {
  items: BountyBoardItem[];
  next_cursor: string | null;
}

/** Mirrors TicketOut in app/routers/tickets.py (bounty-relevant subset) */
export interface BountyTicket {
  ticket_id: string;
  subject: string;
  owner_sub: string;
  status: string;
  space_id: string | null;
  assigned_to_sub: string | null;
  claimed_by_sub: string | null;
  claimed_at: number | null;
  created_at: number;
  updated_at: number;
  version: number;
  bounty_amount_cents: number | null;
  bounty_currency: string | null;
  bounty_status: BountyStatus | null;
  bounty_id: string | null;
  bounty_funded_at: number | null;
  bounty_submitted_at: number | null;
  bounty_paid_at: number | null;
  bounty_cancelled_at: number | null;
  bounty_repost_count: number | null;
}

/** Mirrors TicketEnvelope in app/routers/tickets.py */
export interface BountyTicketEnvelope {
  ticket: BountyTicket;
}

/** Mirrors PostBountyReq in app/routers/tickets.py */
export interface PostBountyReq {
  amount_cents: number;
  currency?: string;
}

/** Mirrors RejectBountyReq in app/routers/tickets.py */
export interface RejectBountyReq {
  reason: string;
}

/** Mirrors CancelBountyReq in app/routers/tickets.py */
export interface CancelBountyReq {
  reason?: string;
}

// ─── Bounty Board endpoints ───────────────────────────────────────────────────

/** GET /tickets/bounties/open — list open (funded) bounties on the public board */
export const listOpenBounties = (opts?: { limit?: number; cursor?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params.limit = String(opts.limit);
  if (opts?.cursor) params.cursor = opts.cursor;
  return api.get<BountyBoardEnvelope>("/tickets/bounties/open", params);
};

/** GET /tickets/{ticket_id} — fetch a single ticket (for bounty detail view) */
export const getBountyTicket = (ticketId: string) =>
  api.get<BountyTicketEnvelope>(`/tickets/${ticketId}`);

// ─── Bounty mutation endpoints ────────────────────────────────────────────────

/**
 * POST /tickets/{ticket_id}/bounty — ticket owner funds a bounty (wallet → escrow).
 * Requires ticket ownership. Returns 404 when feature flag is off.
 */
export const postBounty = (ticketId: string, body: PostBountyReq) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty`, body);

/**
 * POST /tickets/{ticket_id}/bounty/claim — any authenticated user claims a funded bounty.
 * Atomically assigns the ticket and sets bounty_status → "claimed".
 */
export const claimBounty = (ticketId: string) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty/claim`);

/**
 * POST /tickets/{ticket_id}/bounty/unclaim — current claimant releases the bounty.
 * Reverts bounty_status → "funded" and removes assignment.
 */
export const unclaimBounty = (ticketId: string) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty/unclaim`);

/**
 * POST /tickets/{ticket_id}/bounty/submit — claimant submits work for review.
 * Sets bounty_status → "submitted" and ticket status → "done".
 */
export const submitBounty = (ticketId: string) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty/submit`);

/**
 * POST /tickets/{ticket_id}/bounty/approve — admin approves + releases escrow to claimant.
 * Sets bounty_status → "paid_out". Admin only.
 */
export const approveBounty = (ticketId: string) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty/approve`);

/**
 * POST /tickets/{ticket_id}/bounty/reject — admin rejects submitted work.
 * Reverts bounty_status → "claimed". Admin only.
 */
export const rejectBounty = (ticketId: string, body: RejectBountyReq) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty/reject`, body);

/**
 * POST /tickets/{ticket_id}/bounty/cancel — poster (pre-claim) or admin cancels bounty.
 * Refunds escrow to poster. Sets bounty_status → "cancelled".
 */
export const cancelBounty = (ticketId: string, body?: CancelBountyReq) =>
  api.post<BountyTicketEnvelope>(`/tickets/${ticketId}/bounty/cancel`, body ?? {});

// ─── Helper utilities ─────────────────────────────────────────────────────────

/**
 * Format an integer cent amount as a human-readable currency string.
 * e.g. 5000 → "$50.00"
 */
export function formatCents(cents: number, currency = "usd"): string {
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: currency.toUpperCase(),
      minimumFractionDigits: 2,
    }).format(cents / 100);
  } catch {
    return `$${(cents / 100).toFixed(2)}`;
  }
}

/** Human-readable label for a bounty status */
export function bountyStatusLabel(status: BountyStatus | null | undefined): string {
  switch (status) {
    case "funded":
      return "Open";
    case "claimed":
      return "Claimed";
    case "submitted":
      return "Pending Review";
    case "paid_out":
      return "Paid Out";
    case "cancelled":
      return "Cancelled";
    default:
      return "Unknown";
  }
}
