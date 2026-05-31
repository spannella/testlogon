import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CalendarClock, RefreshCw, Loader2, Bell, CalendarPlus, X, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import type { BroadcastSession } from "@/api/endpoints/broadcast";
import {
  listScheduledSessions,
  listUpcomingSessions,
  rescheduleSession,
  cancelSchedule,
  registerReminder,
  downloadIcal,
} from "@/api/endpoints/broadcastSchedule";
import { BroadcastScheduleCountdown } from "./BroadcastScheduleCountdown";
import { BroadcastScheduleDialog } from "./BroadcastScheduleDialog";

function formatWhen(ts?: number | null): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function ScheduledCard({
  session,
  showActions,
  onReschedule,
  onCancel,
}: {
  session: BroadcastSession;
  showActions: boolean;
  onReschedule: (s: BroadcastSession) => void;
  onCancel: (s: BroadcastSession) => void;
}) {
  const remindMut = useMutation({
    mutationFn: () => registerReminder(session.id),
    onSuccess: () => toast.success("Reminder set"),
    onError: () => toast.error("Could not set reminder"),
  });

  return (
    <Card data-testid="scheduled-card">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-base">{session.name || "Untitled Broadcast"}</CardTitle>
          <Badge variant="secondary">Scheduled</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {session.description && (
          <p className="text-sm text-muted-foreground line-clamp-2">{session.description}</p>
        )}
        <div className="flex items-center gap-2 text-sm">
          <Clock className="h-4 w-4 text-muted-foreground" />
          <span>{formatWhen(session.scheduled_at)}</span>
        </div>
        {session.scheduled_at && (
          <div className="text-sm">
            <BroadcastScheduleCountdown scheduledAt={session.scheduled_at} variant="full" />
          </div>
        )}
        <div className="flex flex-wrap gap-2 pt-1">
          <Button size="sm" variant="outline" onClick={() => remindMut.mutate()} disabled={remindMut.isPending}>
            <Bell className="h-3.5 w-3.5 mr-1" /> Set Reminder
          </Button>
          <Button size="sm" variant="outline" onClick={() => downloadIcal(session.id)}>
            <CalendarPlus className="h-3.5 w-3.5 mr-1" /> Add to Calendar
          </Button>
          {showActions && (
            <>
              <Button size="sm" variant="outline" onClick={() => onReschedule(session)}>
                Reschedule
              </Button>
              <Button size="sm" variant="destructive" onClick={() => onCancel(session)}>
                <X className="h-3.5 w-3.5 mr-1" /> Cancel
              </Button>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default function BroadcastSchedulePage() {
  const queryClient = useQueryClient();
  const [rescheduleTarget, setRescheduleTarget] = useState<BroadcastSession | null>(null);
  const [cancelTarget, setCancelTarget] = useState<BroadcastSession | null>(null);

  const mineQuery = useQuery({
    queryKey: ["broadcast", "scheduled", "mine"],
    queryFn: () => listScheduledSessions({ limit: 100 }),
  });

  const upcomingQuery = useQuery({
    queryKey: ["broadcast", "upcoming"],
    queryFn: () => listUpcomingSessions({ limit: 100 }),
    refetchInterval: 60_000,
  });

  const rescheduleMut = useMutation({
    mutationFn: ({ id, scheduledAt }: { id: string; scheduledAt: number }) =>
      rescheduleSession(id, { scheduled_at: scheduledAt }),
    onSuccess: () => {
      toast.success("Broadcast rescheduled");
      setRescheduleTarget(null);
      queryClient.invalidateQueries({ queryKey: ["broadcast"] });
    },
    onError: () => toast.error("Reschedule failed"),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelSchedule(id),
    onSuccess: () => {
      toast.success("Schedule cancelled");
      setCancelTarget(null);
      queryClient.invalidateQueries({ queryKey: ["broadcast"] });
    },
    onError: () => toast.error("Cancel failed"),
  });

  const mine = mineQuery.data?.items ?? [];
  const upcoming = upcomingQuery.data?.items ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CalendarClock className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Scheduled Broadcasts</h1>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            mineQuery.refetch();
            upcomingQuery.refetch();
          }}
        >
          <RefreshCw className="h-4 w-4 mr-1" /> Refresh
        </Button>
      </div>

      <Tabs defaultValue="mine" className="space-y-4">
        <TabsList>
          <TabsTrigger value="mine">My Schedule</TabsTrigger>
          <TabsTrigger value="upcoming">Upcoming</TabsTrigger>
        </TabsList>

        <TabsContent value="mine" className="space-y-4">
          {mineQuery.isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : mine.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center" data-testid="schedule-empty">
              No upcoming broadcasts scheduled.
            </p>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {mine.map((s) => (
                <ScheduledCard
                  key={s.id}
                  session={s}
                  showActions
                  onReschedule={setRescheduleTarget}
                  onCancel={setCancelTarget}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="upcoming" className="space-y-4">
          {upcomingQuery.isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : upcoming.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center" data-testid="upcoming-empty">
              No upcoming broadcasts scheduled.
            </p>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {upcoming.map((s) => (
                <ScheduledCard
                  key={s.id}
                  session={s}
                  showActions={false}
                  onReschedule={setRescheduleTarget}
                  onCancel={setCancelTarget}
                />
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      <BroadcastScheduleDialog
        open={!!rescheduleTarget}
        onOpenChange={(o) => !o && setRescheduleTarget(null)}
        rescheduleOnly
        initialScheduledAt={rescheduleTarget?.scheduled_at}
        sessionName={rescheduleTarget?.name ?? undefined}
        isSubmitting={rescheduleMut.isPending}
        onConfirm={({ scheduledAt }) =>
          rescheduleTarget && rescheduleMut.mutate({ id: rescheduleTarget.id, scheduledAt })
        }
      />

      <AlertDialog open={!!cancelTarget} onOpenChange={(o) => !o && setCancelTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cancel scheduled broadcast?</AlertDialogTitle>
            <AlertDialogDescription>
              This will cancel "{cancelTarget?.name || "this broadcast"}" and notify any subscribers.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep</AlertDialogCancel>
            <AlertDialogAction onClick={() => cancelTarget && cancelMut.mutate(cancelTarget.id)}>
              Cancel Broadcast
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
