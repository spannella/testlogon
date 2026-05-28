import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CalendarClock, Bell, Calendar, Play, XCircle, RefreshCw, Radio } from "lucide-react";
import { BroadcastCountdown } from "./BroadcastCountdown";
import type { BroadcastSession } from "@/api/endpoints/broadcast";

interface ScheduledBroadcastCardProps {
  session: BroadcastSession;
  showActions?: boolean;
  onCancel?: (sessionId: string) => void;
  onReschedule?: (sessionId: string) => void;
  onStartEarly?: (sessionId: string) => void;
  onReminder?: (sessionId: string) => void;
  onDownloadIcal?: (sessionId: string) => void;
}

export function ScheduledBroadcastCard({
  session,
  showActions,
  onCancel,
  onReschedule,
  onStartEarly,
  onReminder,
  onDownloadIcal,
}: ScheduledBroadcastCardProps) {
  const scheduledDate = session.scheduled_at
    ? new Date(session.scheduled_at * 1000).toLocaleString()
    : "Not set";

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            {session.thumbnail_url ? (
              <img
                src={session.thumbnail_url}
                alt=""
                className="h-8 w-8 rounded object-cover"
              />
            ) : (
              <Radio className="h-5 w-5 text-muted-foreground" />
            )}
            {session.name || session.id.slice(0, 12) + "..."}
          </CardTitle>
          <Badge variant="secondary" className="bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200 gap-1">
            <CalendarClock className="h-3 w-3" />
            scheduled
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex justify-between">
          <span className="text-muted-foreground">Scheduled:</span>
          <span>{scheduledDate}</span>
        </div>

        {session.scheduled_at && (
          <div className="flex justify-between items-center">
            <span className="text-muted-foreground">Countdown:</span>
            <BroadcastCountdown scheduledAt={session.scheduled_at} variant="compact" />
          </div>
        )}

        {session.description && (
          <p className="text-xs text-muted-foreground line-clamp-2">
            {session.description}
          </p>
        )}

        {/* Viewer actions */}
        <div className="flex gap-2 pt-1">
          {onReminder && (
            <Button variant="outline" size="sm" onClick={() => onReminder(session.id)}>
              <Bell className="h-3 w-3 mr-1" /> Remind Me
            </Button>
          )}
          {onDownloadIcal && (
            <Button variant="outline" size="sm" onClick={() => onDownloadIcal(session.id)}>
              <Calendar className="h-3 w-3 mr-1" /> Add to Calendar
            </Button>
          )}
        </div>

        {/* Creator actions */}
        {showActions && (
          <div className="flex gap-2 pt-1 border-t">
            {onStartEarly && (
              <Button variant="default" size="sm" onClick={() => onStartEarly(session.id)}>
                <Play className="h-3 w-3 mr-1" /> Start Early
              </Button>
            )}
            {onReschedule && (
              <Button variant="outline" size="sm" onClick={() => onReschedule(session.id)}>
                <RefreshCw className="h-3 w-3 mr-1" /> Reschedule
              </Button>
            )}
            {onCancel && (
              <Button variant="ghost" size="sm" className="text-destructive" onClick={() => onCancel(session.id)}>
                <XCircle className="h-3 w-3 mr-1" /> Cancel
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
