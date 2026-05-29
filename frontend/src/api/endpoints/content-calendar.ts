import { api } from "@/api/client";
import type {
  ContentCalendarResponse,
  TodayAgendaResponse,
  ConflictsResponse,
  ContentCalendarItem,
  ContentItemType,
} from "@/api/types";

export async function getContentCalendar(
  fromTs: number,
  toTs: number,
  types?: ContentItemType[],
): Promise<ContentCalendarResponse> {
  const params: Record<string, string> = {
    from_ts: String(fromTs),
    to_ts: String(toTs),
  };
  if (types && types.length > 0) {
    params.types = types.join(",");
  }
  return api.get<ContentCalendarResponse>("/ui/content-calendar", params);
}

export async function getTodayAgenda(): Promise<TodayAgendaResponse> {
  return api.get<TodayAgendaResponse>("/ui/content-calendar/today");
}

export async function getConflicts(
  fromTs: number,
  toTs: number,
): Promise<ConflictsResponse> {
  return api.get<ConflictsResponse>("/ui/content-calendar/conflicts", {
    from_ts: String(fromTs),
    to_ts: String(toTs),
  });
}

export async function rescheduleCalendarItem(
  itemId: string,
  itemType: ContentItemType,
  newScheduledAt: number,
): Promise<ContentCalendarItem> {
  return api.post<ContentCalendarItem>(
    "/ui/content-calendar/reschedule",
    null,
    {
      item_id: itemId,
      item_type: itemType,
      new_scheduled_at: String(newScheduledAt),
    },
  );
}

export async function cancelCalendarItem(
  itemId: string,
  itemType: ContentItemType,
): Promise<{ ok: string; id: string; type: ContentItemType }> {
  return api.post<{ ok: string; id: string; type: ContentItemType }>(
    "/ui/content-calendar/cancel",
    null,
    {
      item_id: itemId,
      item_type: itemType,
    },
  );
}
