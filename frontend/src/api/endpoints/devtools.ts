import { api } from "@/api/client";
import type {
  DevtoolsBillingLedgerOut,
  DevtoolsBillingLedgerSummaryOut,
  DevtoolsEmailMessagesOut,
  DevtoolsSmsConversationsOut,
} from "@/api/types";

export interface DevtoolsEmailMessagesQuery {
  mailbox?: string;
  thread_id?: string;
  q?: string;
  state?: "all" | "unread" | "sent";
  limit?: number;
  cursor?: string;
}

export interface DevtoolsSmsConversationsQuery {
  participant?: string;
  q?: string;
  limit?: number;
  cursor?: string;
}

export interface DevtoolsBillingLedgerQuery {
  provider?: "stripe" | "ccbill" | "paypal";
  status?: "pending" | "completed" | "failed" | "refunded" | "canceled";
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

const cleanParams = (params: Record<string, string | undefined>) =>
  Object.fromEntries(Object.entries(params).filter(([, v]) => v != null && v !== "")) as Record<string, string>;

export const getDevtoolsEmailMessages = (query: DevtoolsEmailMessagesQuery = {}) =>
  api.get<DevtoolsEmailMessagesOut>(
    "/internal/dev-tools/email/messages",
    cleanParams({
      mailbox: query.mailbox,
      thread_id: query.thread_id,
      q: query.q,
      state: query.state,
      limit: query.limit != null ? String(query.limit) : undefined,
      cursor: query.cursor,
    }),
  );

export const getDevtoolsSmsConversations = (query: DevtoolsSmsConversationsQuery = {}) =>
  api.get<DevtoolsSmsConversationsOut>(
    "/internal/dev-tools/sms/conversations",
    cleanParams({
      participant: query.participant,
      q: query.q,
      limit: query.limit != null ? String(query.limit) : undefined,
      cursor: query.cursor,
    }),
  );

export const getDevtoolsBillingLedger = (query: DevtoolsBillingLedgerQuery = {}) =>
  api.get<DevtoolsBillingLedgerOut>(
    "/internal/dev-tools/billing/ledger",
    cleanParams({
      provider: query.provider,
      status: query.status,
      from: query.from,
      to: query.to,
      limit: query.limit != null ? String(query.limit) : undefined,
      cursor: query.cursor,
    }),
  );

export const getDevtoolsBillingSummary = (query: Omit<DevtoolsBillingLedgerQuery, "limit" | "cursor"> = {}) =>
  api.get<DevtoolsBillingLedgerSummaryOut>(
    "/internal/dev-tools/billing/summary",
    cleanParams({
      provider: query.provider,
      status: query.status,
      from: query.from,
      to: query.to,
    }),
  );
