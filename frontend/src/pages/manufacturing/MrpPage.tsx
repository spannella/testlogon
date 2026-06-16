import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Play, AlertTriangle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { runMrp, type MrpRunOut } from "@/api/endpoints/manufacturing";
import { fmtTs, isFeatureDisabled } from "./lib";

const ACTION_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  purchase: "destructive",
  manufacture: "default",
  none: "outline",
};

export default function MrpPage() {
  const [horizonDays, setHorizonDays] = useState(30);
  const [locationId, setLocationId] = useState("warehouse");
  const [result, setResult] = useState<MrpRunOut | null>(null);
  const [featureOff, setFeatureOff] = useState(false);

  const runMut = useMutation({
    mutationFn: () => runMrp({ horizon_days: horizonDays, location_id: locationId.trim() || "warehouse" }),
    onSuccess: (run) => {
      setResult(run);
      toast.success(`MRP run complete — ${run.requirement_count} requirement(s)`);
    },
    onError: (e: unknown) => {
      if (isFeatureDisabled(e)) {
        setFeatureOff(true);
        return;
      }
      toast.error(e instanceof Error ? e.message : "MRP run failed");
    },
  });

  const requirements = result?.requirements ?? [];
  const actionable = requirements.filter((r) => r.suggested_action !== "none");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Material Requirements Planning"
        description="Run MRP to compute net requirements and replenishment suggestions."
      />

      {featureOff ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Manufacturing is not enabled on this environment.
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Run parameters</CardTitle>
              <CardDescription>Plan over a forward horizon for a stock location.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-end gap-4">
                <div className="space-y-1">
                  <Label htmlFor="mrp-horizon">Horizon (days)</Label>
                  <Input
                    id="mrp-horizon"
                    type="number"
                    min={1}
                    max={365}
                    value={horizonDays}
                    onChange={(e) => setHorizonDays(Math.max(1, Math.min(365, Number(e.target.value))))}
                    className="w-32"
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="mrp-location">Location</Label>
                  <Input
                    id="mrp-location"
                    value={locationId}
                    onChange={(e) => setLocationId(e.target.value)}
                    className="w-48"
                  />
                </div>
                <Button onClick={() => runMut.mutate()} disabled={runMut.isPending}>
                  <Play className="mr-2 h-4 w-4" /> {runMut.isPending ? "Running…" : "Run MRP"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {result && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <CardTitle>Suggestions</CardTitle>
                    <CardDescription>
                      Run {result.mrp_run_id} · {result.status} · completed {fmtTs(result.completed_at)} ·{" "}
                      {actionable.length} actionable of {requirements.length}
                    </CardDescription>
                  </div>
                  {actionable.length > 0 && (
                    <Badge variant="destructive" className="flex items-center gap-1">
                      <AlertTriangle className="h-3.5 w-3.5" /> {actionable.length} shortfall(s)
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>SKU</TableHead>
                      <TableHead>Gross req.</TableHead>
                      <TableHead>On hand</TableHead>
                      <TableHead>Scheduled</TableHead>
                      <TableHead>Net req.</TableHead>
                      <TableHead>Suggested action</TableHead>
                      <TableHead>Suggested qty</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {requirements.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">
                          No requirements — supply meets demand.
                        </TableCell>
                      </TableRow>
                    )}
                    {requirements.map((r) => (
                      <TableRow key={`${r.sku}-${r.depth}`}>
                        <TableCell className="font-medium">{r.sku}</TableCell>
                        <TableCell>{r.gross_requirement}</TableCell>
                        <TableCell>{r.on_hand_available}</TableCell>
                        <TableCell>{r.scheduled_receipts}</TableCell>
                        <TableCell>{r.net_requirement}</TableCell>
                        <TableCell>
                          <Badge variant={ACTION_VARIANT[r.suggested_action] ?? "secondary"}>
                            {r.suggested_action}
                          </Badge>
                        </TableCell>
                        <TableCell>{r.suggested_quantity}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
