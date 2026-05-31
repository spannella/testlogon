import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getPmConfig, updatePmConfig } from "@/api/endpoints/productAgent";

export default function PmConfigPanel() {
  const queryClient = useQueryClient();
  const { data: config } = useQuery({
    queryKey: ["pm-config"],
    queryFn: () => getPmConfig().catch(() => undefined),
    staleTime: 60_000,
  });

  const [frequency, setFrequency] = useState<"daily" | "weekly" | "biweekly">("weekly");
  const [hour, setHour] = useState(9);
  const [maxIdeas, setMaxIdeas] = useState(5);
  const [focusAreas, setFocusAreas] = useState("messaging, billing, ux, feed");
  const [analyzeSupport, setAnalyzeSupport] = useState(true);
  const [lookback, setLookback] = useState(30);

  useEffect(() => {
    if (!config) return;
    setFrequency(config.review_frequency);
    setHour(config.review_hour_utc);
    setMaxIdeas(config.max_ideas_per_review);
    setFocusAreas((config.focus_areas || []).join(", "));
    setAnalyzeSupport(config.analyze_support_tickets);
    setLookback(config.support_ticket_lookback_days);
  }, [config]);

  const saveMut = useMutation({
    mutationFn: () =>
      updatePmConfig({
        review_frequency: frequency,
        review_hour_utc: hour,
        max_ideas_per_review: maxIdeas,
        focus_areas: focusAreas
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        analyze_support_tickets: analyzeSupport,
        support_ticket_lookback_days: lookback,
      }),
    onSuccess: () => {
      toast.success("PM configuration saved");
      queryClient.invalidateQueries({ queryKey: ["pm-config"] });
    },
    onError: (e: Error) => toast.error(e.message || "Save failed"),
  });

  return (
    <Card data-testid="pm-config-panel">
      <CardHeader>
        <CardTitle>PM Agent Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <Label>Review Frequency</Label>
            <Select value={frequency} onValueChange={(v) => setFrequency(v as typeof frequency)}>
              <SelectTrigger data-testid="pm-frequency">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="biweekly">Biweekly</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="pm-hour">Review Hour (UTC)</Label>
            <Input
              id="pm-hour"
              type="number"
              data-testid="pm-hour"
              value={hour}
              onChange={(e) => setHour(Number(e.target.value))}
            />
          </div>
          <div>
            <Label htmlFor="pm-max-ideas">Max Ideas / Review</Label>
            <Input
              id="pm-max-ideas"
              type="number"
              data-testid="pm-max-ideas"
              value={maxIdeas}
              onChange={(e) => setMaxIdeas(Number(e.target.value))}
            />
          </div>
          <div>
            <Label htmlFor="pm-lookback">Support Lookback (days)</Label>
            <Input
              id="pm-lookback"
              type="number"
              data-testid="pm-lookback"
              value={lookback}
              onChange={(e) => setLookback(Number(e.target.value))}
            />
          </div>
        </div>
        <div>
          <Label htmlFor="pm-focus">Focus Areas (comma-separated)</Label>
          <Input
            id="pm-focus"
            data-testid="pm-focus-areas"
            value={focusAreas}
            onChange={(e) => setFocusAreas(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={analyzeSupport}
            onCheckedChange={setAnalyzeSupport}
            data-testid="pm-analyze-support"
          />
          <Label>Analyze support tickets</Label>
        </div>
        <Button onClick={() => saveMut.mutate()} disabled={saveMut.isPending} data-testid="pm-config-save">
          Save Configuration
        </Button>
      </CardContent>
    </Card>
  );
}
