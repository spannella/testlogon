import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus, Trash2, Users, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { getCalendars, getCalendarShares, shareCalendar, removeCalendarShare } from "@/api/endpoints/calendar";
import type { Calendar, CalendarShare } from "@/api/types";

export function CalendarSharing() {
  const queryClient = useQueryClient();
  const [selectedCalendarId, setSelectedCalendarId] = useState<string | null>(null);
  const [userSub, setUserSub] = useState("");
  const [permission, setPermission] = useState<"read" | "write">("read");
  const [removeTarget, setRemoveTarget] = useState<CalendarShare | null>(null);

  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
  });

  const calendars: Calendar[] = Array.isArray(calendarsQuery.data) ? calendarsQuery.data : [];
  const calId = selectedCalendarId ?? (calendars.length > 0 ? calendars[0]!.calendar_id : null);

  const sharesQuery = useQuery({
    queryKey: ["calendar-shares", calId],
    queryFn: () => getCalendarShares(calId!),
    enabled: !!calId,
  });

  const shares: CalendarShare[] = Array.isArray(sharesQuery.data) ? sharesQuery.data : [];

  const addMutation = useMutation({
    mutationFn: () => shareCalendar(calId!, { user_sub: userSub.trim(), permission }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendar-shares", calId] });
      setUserSub("");
      toast.success("Collaborator added");
    },
    onError: () => {
      toast.error("Failed to add collaborator");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (share: CalendarShare) => removeCalendarShare(share.calendar_id, share.user_sub),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendar-shares", calId] });
      setRemoveTarget(null);
      toast.success("Collaborator removed");
    },
    onError: () => {
      toast.error("Failed to remove collaborator");
    },
  });

  if (calendarsQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (calendars.length === 0) {
    return (
      <EmptyState
        icon={<Users className="h-6 w-6" />}
        title="No calendars"
        description="Create a calendar first to manage sharing"
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Calendar selector */}
      {calendars.length > 1 && (
        <div className="space-y-1.5">
          <Label>Calendar</Label>
          <Select value={calId ?? ""} onValueChange={setSelectedCalendarId}>
            <SelectTrigger className="w-60">
              <SelectValue placeholder="Select calendar" />
            </SelectTrigger>
            <SelectContent>
              {calendars.map((c) => (
                <SelectItem key={c.calendar_id} value={c.calendar_id}>
                  {c.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Add collaborator */}
      <div className="rounded-lg border p-4 space-y-3">
        <h3 className="text-sm font-medium">Add collaborator</h3>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="flex-1 space-y-1">
            <Label htmlFor="share-user" className="text-xs">
              User ID
            </Label>
            <Input
              id="share-user"
              placeholder="user sub or email"
              value={userSub}
              onChange={(e) => setUserSub(e.target.value)}
            />
          </div>
          <div className="w-28 space-y-1">
            <Label className="text-xs">Permission</Label>
            <Select value={permission} onValueChange={(v) => setPermission(v as "read" | "write")}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="read">Read</SelectItem>
                <SelectItem value="write">Write</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button
            size="sm"
            disabled={!userSub.trim() || addMutation.isPending}
            onClick={() => addMutation.mutate()}
          >
            {addMutation.isPending ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <UserPlus className="mr-1 h-3.5 w-3.5" />
            )}
            Add
          </Button>
        </div>
      </div>

      {/* Existing shares */}
      <div className="space-y-2">
        <h3 className="text-sm font-medium">
          Current collaborators
          {sharesQuery.isLoading && <Loader2 className="ml-2 inline h-3 w-3 animate-spin" />}
        </h3>

        {shares.length === 0 && !sharesQuery.isLoading && (
          <p className="text-sm text-muted-foreground">
            No one else has access to this calendar yet.
          </p>
        )}

        <div className="divide-y rounded-lg border">
          {shares.map((share) => (
            <div
              key={share.user_sub}
              className="flex items-center justify-between px-4 py-2.5"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-xs font-medium uppercase">
                  {share.user_sub.slice(0, 2)}
                </div>
                <div>
                  <p className="text-sm font-medium">{share.user_sub}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {new Date(share.created_at_utc).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={share.permission === "write" ? "default" : "secondary"}>
                  {share.permission}
                </Badge>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-destructive hover:text-destructive"
                  onClick={() => setRemoveTarget(share)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <ConfirmDialog
        open={!!removeTarget}
        onOpenChange={(v) => { if (!v) setRemoveTarget(null); }}
        title="Remove collaborator?"
        description={`This will revoke ${removeTarget?.user_sub ?? "this user"}'s access to the calendar.`}
        confirmLabel="Remove"
        variant="danger"
        onConfirm={() => { if (removeTarget) removeMutation.mutate(removeTarget); }}
        loading={removeMutation.isPending}
      />
    </div>
  );
}
