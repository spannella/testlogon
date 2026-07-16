import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Phone, PhoneIncoming, PhoneOutgoing, Video, Trash2, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

import { listCallHistory, deleteCallRecord, getCallStats } from "@/api/endpoints/callHistory";
import type { CallRecordOut, CallStatsOut } from "@/api/types";

// ─── Helpers ────────────────────────────────────────────────────────

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

function formatTimestamp(ts: number): string {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  completed: "default",
  missed: "destructive",
  declined: "secondary",
  failed: "destructive",
};

// ─── Stats Card ─────────────────────────────────────────────────────

function StatsCards({ stats }: { stats: CallStatsOut | undefined }) {
  if (!stats) return null;
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Total Calls</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-2xl font-bold">{stats.total_calls}</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Total Duration</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-2xl font-bold">{formatDuration(stats.total_duration_seconds)}</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Audio Calls</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-2xl font-bold">{stats.calls_by_type?.audio ?? 0}</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">Video Calls</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-2xl font-bold">{stats.calls_by_type?.video ?? 0}</p>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Page Component ─────────────────────────────────────────────────

export default function CallHistoryPage() {
  const queryClient = useQueryClient();
  const [cursor, setCursor] = useState<string | undefined>(undefined);

  const historyQuery = useQuery({
    queryKey: ["call-history", cursor],
    queryFn: () => listCallHistory({ cursor, limit: 20 }),
  });

  const statsQuery = useQuery({
    queryKey: ["call-stats"],
    queryFn: () => getCallStats(),
  });

  const deleteMut = useMutation({
    mutationFn: (callId: string) => deleteCallRecord(callId),
    onSuccess: () => {
      toast.success("Call record deleted");
      queryClient.invalidateQueries({ queryKey: ["call-history"] });
      queryClient.invalidateQueries({ queryKey: ["call-stats"] });
    },
    onError: () => {
      toast.error("Failed to delete call record");
    },
  });

  const items: CallRecordOut[] = historyQuery.data?.items ?? [];
  const nextCursor = historyQuery.data?.next_cursor;

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Call History"
        description="View and manage your call logs"
      />

      <StatsCards stats={statsQuery.data} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Phone className="h-5 w-5" />
            Recent Calls
          </CardTitle>
        </CardHeader>
        <CardContent>
          {historyQuery.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : items.length === 0 ? (
            <p className="py-8 text-center text-muted-foreground">No call history yet.</p>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Direction</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Caller</TableHead>
                    <TableHead>Callee</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((call) => (
                    <TableRow key={call.call_id} data-testid={`call-row-${call.call_id}`}>
                      <TableCell>
                        {call.direction === "incoming" ? (
                          <span className="flex items-center gap-1 text-sm">
                            <PhoneIncoming className="h-4 w-4 text-blue-500" />
                            Incoming
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-sm">
                            <PhoneOutgoing className="h-4 w-4 text-green-500" />
                            Outgoing
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="flex items-center gap-1 text-sm">
                          {call.call_type === "video" ? (
                            <Video className="h-4 w-4" />
                          ) : (
                            <Phone className="h-4 w-4" />
                          )}
                          {call.call_type}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm">{call.caller_id}</TableCell>
                      <TableCell className="text-sm">{call.callee_id}</TableCell>
                      <TableCell className="font-mono text-sm tabular-nums">
                        {formatDuration(call.duration_seconds)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={STATUS_VARIANT[call.status] ?? "outline"}>
                          {call.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatTimestamp(call.created_at)}
                      </TableCell>
                      <TableCell>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8"
                              aria-label="Delete call record"
                            >
                              <Trash2 className="h-4 w-4 text-muted-foreground" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Delete call record?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This will permanently remove this call from your history.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => deleteMut.mutate(call.call_id)}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                              >
                                Delete
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {/* Pagination */}
              <div className="mt-4 flex items-center justify-between">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!cursor}
                  onClick={() => setCursor(undefined)}
                >
                  First page
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!nextCursor}
                  onClick={() => setCursor(nextCursor ?? undefined)}
                >
                  Next page
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
