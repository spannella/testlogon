import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Save } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import DaypartingGrid from "@/components/ads/DaypartingGrid";
import FlightScheduler from "@/components/ads/FlightScheduler";
import {
  getCampaignSchedule,
  getScheduleEligibility,
  updateCampaignSchedule,
} from "@/api/endpoints/adDayparting";
import type { CampaignFlight } from "@/api/types";

export default function AdSchedulePage() {
  const [params] = useSearchParams();
  const campaignId = params.get("campaign") ?? "";
  const queryClient = useQueryClient();

  const [timezone, setTimezone] = useState("UTC");
  const [schedule, setSchedule] = useState<Record<string, number[]>>({});
  const [flights, setFlights] = useState<CampaignFlight[]>([]);
  const [error, setError] = useState<string | null>(null);

  const { data: current } = useQuery({
    queryKey: ["ad-schedule", campaignId],
    queryFn: () => getCampaignSchedule(campaignId),
    enabled: !!campaignId,
  });

  const { data: eligibility } = useQuery({
    queryKey: ["ad-schedule-eligibility", campaignId],
    queryFn: () => getScheduleEligibility(campaignId),
    enabled: !!campaignId,
  });

  useEffect(() => {
    if (!current) return;
    setTimezone(current.dayparting?.timezone ?? current.campaign_timezone ?? "UTC");
    setSchedule(current.dayparting?.schedule ?? {});
    setFlights(current.flights ?? []);
  }, [current]);

  const saveMut = useMutation({
    mutationFn: () =>
      updateCampaignSchedule(campaignId, {
        campaign_timezone: timezone,
        dayparting: { timezone, schedule },
        flights,
      }),
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: ["ad-schedule", campaignId] });
      queryClient.invalidateQueries({
        queryKey: ["ad-schedule-eligibility", campaignId],
      });
    },
    onError: (e: unknown) => {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "Failed to save schedule";
      setError(msg);
    },
  });

  if (!campaignId) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground">
          Select a campaign to configure its schedule.
        </p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-4 p-4">
      <div className="flex items-center gap-2">
        <CalendarClock className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">Ad Schedule &amp; Dayparting</h1>
      </div>

      {eligibility && (
        <div
          data-testid="eligibility-banner"
          className="rounded-md border px-3 py-2 text-sm"
        >
          Currently{" "}
          <span className={eligibility.eligible ? "text-green-600" : "text-amber-600"}>
            {eligibility.eligible ? "eligible to serve" : "paused (out of daypart)"}
          </span>
          {eligibility.day != null && (
            <> · {eligibility.day} {eligibility.hour}:00 {eligibility.timezone}</>
          )}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Timezone</CardTitle>
        </CardHeader>
        <CardContent>
          <Label htmlFor="tz" className="text-xs">
            IANA timezone
          </Label>
          <Input
            id="tz"
            data-testid="timezone-input"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            placeholder="UTC"
            className="max-w-xs"
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Dayparting (weekly grid)</CardTitle>
        </CardHeader>
        <CardContent>
          <DaypartingGrid schedule={schedule} onChange={setSchedule} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Flights</CardTitle>
        </CardHeader>
        <CardContent>
          <FlightScheduler flights={flights} onChange={setFlights} />
        </CardContent>
      </Card>

      {error && (
        <p data-testid="schedule-error" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <Button
        data-testid="save-schedule"
        onClick={() => saveMut.mutate()}
        disabled={saveMut.isPending}
      >
        <Save className="mr-1 h-4 w-4" />
        {saveMut.isPending ? "Saving…" : "Save schedule"}
      </Button>
    </div>
  );
}
