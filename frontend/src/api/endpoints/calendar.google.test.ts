import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import {
  createGoogleCalendarMapping,
  getGoogleCalendarProviderCalendars,
  runGoogleCalendarSync,
} from "@/api/endpoints/calendar";

describe("google calendar endpoint bindings", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("loads provider calendars", async () => {
    const spy = vi.spyOn(api, "get").mockResolvedValue({ calendars: [] } as never);
    await getGoogleCalendarProviderCalendars();
    expect(spy).toHaveBeenCalledWith("/ui/calendar/integrations/google/calendars");
  });

  it("creates mappings", async () => {
    const spy = vi.spyOn(api, "post").mockResolvedValue({} as never);
    await createGoogleCalendarMapping({ internal_calendar_id: "int-1", google_calendar_id: "g-1" });
    expect(spy).toHaveBeenCalledWith("/ui/calendar/integrations/google/mappings", {
      internal_calendar_id: "int-1",
      google_calendar_id: "g-1",
    });
  });

  it("runs manual sync", async () => {
    const spy = vi.spyOn(api, "post").mockResolvedValue({} as never);
    await runGoogleCalendarSync("full");
    expect(spy).toHaveBeenCalledWith("/ui/calendar/integrations/google/sync/run", {}, { mode: "full" });
  });
});
