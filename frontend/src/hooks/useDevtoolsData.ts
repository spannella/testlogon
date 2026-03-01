import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { ApiError, normalizeErrorDetail } from "@/api/client";
import {
  getDevtoolsBillingLedger,
  getDevtoolsBillingSummary,
  getDevtoolsEmailMessages,
  getDevtoolsSmsConversations,
  type DevtoolsBillingLedgerQuery,
  type DevtoolsEmailMessagesQuery,
  type DevtoolsSmsConversationsQuery,
} from "@/api/endpoints/devtools";

const asErrorMessage = (error: unknown): string | null => {
  if (!error) return null;
  if (error instanceof ApiError) {
    return normalizeErrorDetail((error.body as Record<string, unknown> | undefined)?.detail, error.detail);
  }
  if (error instanceof Error) return error.message;
  return "Unknown error";
};

export function useDevtoolsEmailMessages(query: Omit<DevtoolsEmailMessagesQuery, "cursor">, enabled = true) {
  const limit = query.limit ?? 50;
  const rq = useInfiniteQuery({
    queryKey: ["devtools", "email", query.mailbox ?? "", query.thread_id ?? "", query.q ?? "", query.state ?? "all", limit],
    queryFn: ({ pageParam }) => getDevtoolsEmailMessages({ ...query, limit, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled,
  });

  const firstPage = rq.data?.pages?.[0];
  const messages = rq.data?.pages.flatMap((p) => p.messages) ?? [];
  const warnings = rq.data?.pages.flatMap((p) => p.parse_warnings ?? []) ?? [];

  return {
    ...rq,
    mailboxes: firstPage?.mailboxes ?? [],
    threads: firstPage?.threads ?? [],
    messages,
    parseWarnings: warnings,
    isEmpty: !rq.isLoading && messages.length === 0,
    errorMessage: asErrorMessage(rq.error),
  };
}

export function useDevtoolsSmsConversations(query: Omit<DevtoolsSmsConversationsQuery, "cursor">, enabled = true) {
  const limit = query.limit ?? 50;
  const rq = useInfiniteQuery({
    queryKey: ["devtools", "sms", query.participant ?? "", query.q ?? "", limit],
    queryFn: ({ pageParam }) => getDevtoolsSmsConversations({ ...query, limit, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled,
  });

  const firstPage = rq.data?.pages?.[0];
  const messages = rq.data?.pages.flatMap((p) => p.messages) ?? [];
  const warnings = rq.data?.pages.flatMap((p) => p.parse_warnings ?? []) ?? [];

  return {
    ...rq,
    conversations: firstPage?.conversations ?? [],
    messages,
    parseWarnings: warnings,
    isEmpty: !rq.isLoading && messages.length === 0 && (firstPage?.conversations?.length ?? 0) === 0,
    errorMessage: asErrorMessage(rq.error),
  };
}

export function useDevtoolsBillingLedger(query: Omit<DevtoolsBillingLedgerQuery, "cursor">, enabled = true) {
  const limit = query.limit ?? 50;
  const rq = useInfiniteQuery({
    queryKey: [
      "devtools",
      "billing",
      "ledger",
      query.provider ?? "",
      query.status ?? "",
      query.from ?? "",
      query.to ?? "",
      limit,
    ],
    queryFn: ({ pageParam }) => getDevtoolsBillingLedger({ ...query, limit, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled,
  });

  const firstPage = rq.data?.pages?.[0];
  const entries = rq.data?.pages.flatMap((p) => p.entries) ?? [];
  const warnings = rq.data?.pages.flatMap((p) => p.parse_warnings ?? []) ?? [];

  return {
    ...rq,
    summary: firstPage?.summary,
    entries,
    parseWarnings: warnings,
    isEmpty: !rq.isLoading && entries.length === 0,
    errorMessage: asErrorMessage(rq.error),
  };
}

export function useDevtoolsBillingSummary(query: Omit<DevtoolsBillingLedgerQuery, "limit" | "cursor">, enabled = true) {
  const rq = useQuery({
    queryKey: ["devtools", "billing", "summary", query.provider ?? "", query.status ?? "", query.from ?? "", query.to ?? ""],
    queryFn: () => getDevtoolsBillingSummary(query),
    enabled,
  });

  return {
    ...rq,
    parseWarnings: rq.data?.parse_warnings ?? [],
    isEmpty: !rq.isLoading && (rq.data?.transaction_count ?? 0) === 0,
    errorMessage: asErrorMessage(rq.error),
  };
}
