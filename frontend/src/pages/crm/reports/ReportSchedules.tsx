import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CalendarClock, Plus, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  createSchedule,
  deleteSchedule,
  listSchedules,
  updateSchedule,
  type ScheduleCadence,
  type ScheduleFormat,
} from "@/api/endpoints/crmReports";
import { fmtTs } from "./reportUtils";

export function ReportSchedules({ reportId }: { reportId: string }) {
  const qc = useQueryClient();

  const [cadence, setCadence] = useState<ScheduleCadence>("daily");
  const [recipients, setRecipients] = useState("");
  const [format, setFormat] = useState<ScheduleFormat>("csv");

  const schedulesQuery = useQuery({
    queryKey: ["crm-reports", "schedules", reportId],
    queryFn: () => listSchedules(reportId),
    enabled: !!reportId,
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () => {
      const recips = recipients
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean);
      return createSchedule(reportId, { cadence, recipients: recips, format });
    },
    onSuccess: () => {
      toast.success("Schedule created");
      setRecipients("");
      void qc.invalidateQueries({ queryKey: ["crm-reports", "schedules", reportId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to create schedule"),
  });

  const toggleMut = useMutation({
    mutationFn: ({ sid, enabled }: { sid: string; enabled: boolean }) =>
      updateSchedule(reportId, sid, { enabled }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["crm-reports", "schedules", reportId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to update schedule"),
  });

  const deleteMut = useMutation({
    mutationFn: (sid: string) => deleteSchedule(reportId, sid),
    onSuccess: () => {
      toast.success("Schedule deleted");
      void qc.invalidateQueries({ queryKey: ["crm-reports", "schedules", reportId] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to delete schedule"),
  });

  const schedules = schedulesQuery.data?.schedules ?? [];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Schedule this report</CardTitle>
          <CardDescription>
            Email a generated copy of this report to recipients on a recurring cadence.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-4 sm:items-end">
            <div className="space-y-1.5">
              <Label>Cadence</Label>
              <Select value={cadence} onValueChange={(v) => setCadence(v as ScheduleCadence)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                  <SelectItem value="monthly">Monthly</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="sched-recips">Recipients (comma-separated)</Label>
              <Input
                id="sched-recips"
                value={recipients}
                onChange={(e) => setRecipients(e.target.value)}
                placeholder="ops@example.com, lead@example.com"
              />
            </div>
            <div className="space-y-1.5">
              <Label>Format</Label>
              <Select value={format} onValueChange={(v) => setFormat(v as ScheduleFormat)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="mt-3 flex justify-end">
            <Button
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending || !recipients.trim()}
            >
              <Plus className="mr-2 h-4 w-4" />
              Add schedule
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Active schedules</CardTitle>
        </CardHeader>
        <CardContent>
          {schedulesQuery.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : schedules.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-muted-foreground">
              <CalendarClock className="h-8 w-8" />
              No schedules configured.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Cadence</TableHead>
                  <TableHead>Recipients</TableHead>
                  <TableHead>Format</TableHead>
                  <TableHead>Next run</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((s) => (
                  <TableRow key={s.schedule_id}>
                    <TableCell className="capitalize">{s.cadence}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {s.recipients.join(", ")}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{s.format.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtTs(s.next_run_at)}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={s.enabled}
                        onCheckedChange={(enabled) =>
                          toggleMut.mutate({ sid: s.schedule_id, enabled })
                        }
                      />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          if (window.confirm("Delete this schedule?")) {
                            deleteMut.mutate(s.schedule_id);
                          }
                        }}
                        disabled={deleteMut.isPending}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
