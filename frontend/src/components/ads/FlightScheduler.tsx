import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Trash2 } from "lucide-react";
import type { CampaignFlight } from "@/api/types";

export interface FlightSchedulerProps {
  flights: CampaignFlight[];
  onChange: (flights: CampaignFlight[]) => void;
}

function blankFlight(idx: number): CampaignFlight {
  return {
    name: `Flight ${idx + 1}`,
    start_date: "",
    end_date: "",
    daily_budget_cents: 5000,
    creative_ids: [],
  };
}

export default function FlightScheduler({
  flights,
  onChange,
}: FlightSchedulerProps) {
  const update = (idx: number, patch: Partial<CampaignFlight>) =>
    onChange(flights.map((f, i) => (i === idx ? { ...f, ...patch } : f)));

  const remove = (idx: number) =>
    onChange(flights.filter((_, i) => i !== idx));

  const add = () => onChange([...flights, blankFlight(flights.length)]);

  // Overlap detection (sorted by start date).
  const overlapIdx = new Set<number>();
  const sorted = flights
    .map((f, i) => ({ f, i }))
    .filter(({ f }) => f.start_date && f.end_date)
    .sort((a, b) => a.f.start_date.localeCompare(b.f.start_date));
  for (let k = 0; k < sorted.length - 1; k++) {
    if (sorted[k].f.end_date >= sorted[k + 1].f.start_date) {
      overlapIdx.add(sorted[k].i);
      overlapIdx.add(sorted[k + 1].i);
    }
  }

  return (
    <div className="space-y-3" data-testid="flight-scheduler">
      {flights.length === 0 && (
        <p className="text-sm text-muted-foreground">No flights configured.</p>
      )}
      {flights.map((flight, idx) => (
        <div
          key={idx}
          data-testid={`flight-row-${idx}`}
          className={`space-y-2 rounded-md border p-3 ${
            overlapIdx.has(idx) ? "border-destructive" : ""
          }`}
        >
          <div className="flex items-center gap-2">
            <Input
              data-testid={`flight-name-${idx}`}
              value={flight.name}
              onChange={(e) => update(idx, { name: e.target.value })}
              placeholder="Flight name"
              className="flex-1"
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              data-testid={`flight-remove-${idx}`}
              onClick={() => remove(idx)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label className="text-xs">Start</Label>
              <Input
                type="date"
                data-testid={`flight-start-${idx}`}
                value={flight.start_date}
                onChange={(e) => update(idx, { start_date: e.target.value })}
              />
            </div>
            <div>
              <Label className="text-xs">End</Label>
              <Input
                type="date"
                data-testid={`flight-end-${idx}`}
                value={flight.end_date}
                onChange={(e) => update(idx, { end_date: e.target.value })}
              />
            </div>
            <div>
              <Label className="text-xs">Daily budget (cents)</Label>
              <Input
                type="number"
                data-testid={`flight-budget-${idx}`}
                value={flight.daily_budget_cents}
                onChange={(e) =>
                  update(idx, {
                    daily_budget_cents: Number(e.target.value) || 0,
                  })
                }
              />
            </div>
            <div>
              <Label className="text-xs">Creative IDs (comma-separated)</Label>
              <Input
                data-testid={`flight-creatives-${idx}`}
                value={flight.creative_ids.join(",")}
                onChange={(e) =>
                  update(idx, {
                    creative_ids: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  })
                }
              />
            </div>
          </div>
          {overlapIdx.has(idx) && (
            <p className="text-xs text-destructive">
              This flight overlaps another flight.
            </p>
          )}
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        data-testid="flight-add"
        onClick={add}
      >
        <Plus className="mr-1 h-4 w-4" /> Add flight
      </Button>
    </div>
  );
}
