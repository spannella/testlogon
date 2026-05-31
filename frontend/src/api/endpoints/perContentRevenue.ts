import { api } from "@/api/client";
import type {
  ContentRevenueListResponse,
  ContentRevenueDetailResponse,
  ContentRevenueListParams,
} from "@/api/types";

const BASE = "/ui/analytics/content-revenue";

function toQuery(params: ContentRevenueListParams): Record<string, string> {
  const out: Record<string, string> = {};
  if (params.from_date) out.from_date = params.from_date;
  if (params.to_date) out.to_date = params.to_date;
  if (params.sort_by) out.sort_by = params.sort_by;
  if (params.sort_order) out.sort_order = params.sort_order;
  if (params.content_type) out.content_type = params.content_type;
  if (params.limit != null) out.limit = String(params.limit);
  if (params.cursor) out.cursor = params.cursor;
  return out;
}

export const getContentRevenueList = (params: ContentRevenueListParams = {}) =>
  api.get<ContentRevenueListResponse>(BASE, toQuery(params));

export const getContentRevenueDetail = (
  contentId: string,
  params: Pick<ContentRevenueListParams, "from_date" | "to_date"> = {},
) => api.get<ContentRevenueDetailResponse>(`${BASE}/${encodeURIComponent(contentId)}`, toQuery(params));

export function contentRevenueExportUrl(
  params: Pick<ContentRevenueListParams, "from_date" | "to_date"> = {},
): string {
  const q = new URLSearchParams(toQuery(params)).toString();
  return q ? `${BASE}/export?${q}` : `${BASE}/export`;
}
