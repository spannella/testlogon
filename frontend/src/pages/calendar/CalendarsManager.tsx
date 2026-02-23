import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CalendarDays, Pencil, Plus, Trash2, Loader2, Check, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getCalendars,
  createCalendar,
  updateCalendar,
  deleteCalendar,
} from "@/api/endpoints/calendar";
import type { Calendar } from "@/api/types";

const DEFAULT_TIMEZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

// ─── Create Calendar Dialog ───────────────────────────────────────

interface CreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}

function CreateCalendarDialog({ open, onOpenChange, onCreated }: CreateDialogProps) {
  const [name, setName] = useState("");
  const [timezone, setTimezone] = useState(DEFAULT_TIMEZONE);

  const createMutation = useMutation({
    mutationFn: () =>
      createCalendar({
        name: name.trim(),
        timezone: timezone.trim() || DEFAULT_TIMEZONE,
      }),
    onSuccess: () => {
      toast.success(`Calendar "${name.trim()}" created`);
      setName("");
      setTimezone(DEFAULT_TIMEZONE);
      onOpenChange(false);
      onCreated();
    },
    onError: () => {
      toast.error("Failed to create calendar");
    },
  });

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    createMutation.mutate();
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Calendar</DialogTitle>
          <DialogDescription>
            Create a new calendar to organise events separately.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="new-cal-name">Name</Label>
            <Input
              id="new-cal-name"
              placeholder="e.g. Work, Personal"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-cal-tz">Timezone</Label>
            <Input
              id="new-cal-tz"
              placeholder="e.g. America/New_York"
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!name.trim() || createMutation.isPending}>
              {createMutation.isPending && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
              Create Calendar
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ─── Inline Rename Row ────────────────────────────────────────────

interface RenameRowProps {
  calendar: Calendar;
  onDone: () => void;
}

function RenameRow({ calendar, onDone }: RenameRowProps) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(calendar.name);
  const [timezone, setTimezone] = useState(calendar.timezone);

  const saveMutation = useMutation({
    mutationFn: () =>
      updateCalendar(calendar.calendar_id, {
        name: name.trim(),
        timezone: timezone.trim() || calendar.timezone,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendars"] });
      toast.success("Calendar updated");
      onDone();
    },
    onError: () => {
      toast.error("Failed to update calendar");
    },
  });

  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <Input
        className="h-8 text-sm"
        value={name}
        onChange={(e) => setName(e.target.value)}
        autoFocus
        onKeyDown={(e) => {
          if (e.key === "Enter") saveMutation.mutate();
          if (e.key === "Escape") onDone();
        }}
      />
      <Input
        className="h-8 text-sm w-52"
        placeholder="Timezone"
        value={timezone}
        onChange={(e) => setTimezone(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") saveMutation.mutate();
          if (e.key === "Escape") onDone();
        }}
      />
      <div className="flex gap-1">
        <Button
          size="icon"
          className="h-8 w-8"
          disabled={!name.trim() || saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          {saveMutation.isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Check className="h-3.5 w-3.5" />
          )}
        </Button>
        <Button size="icon" variant="ghost" className="h-8 w-8" onClick={onDone}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────

export function CalendarsManager() {
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deletingCalendar, setDeletingCalendar] = useState<Calendar | null>(null);

  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
  });

  const calendars: Calendar[] = Array.isArray(calendarsQuery.data) ? calendarsQuery.data : [];

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteCalendar(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["calendars"] });
      setDeletingCalendar(null);
      toast.success("Calendar deleted");
    },
    onError: () => {
      toast.error("Failed to delete calendar");
    },
  });

  if (calendarsQuery.isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-9 w-36" />
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {calendars.length} calendar{calendars.length !== 1 ? "s" : ""}
        </p>
        <Button size="sm" onClick={() => setCreateOpen(true)}>
          <Plus className="mr-1 h-3.5 w-3.5" />
          New Calendar
        </Button>
      </div>

      <div className="space-y-3">
        {calendars.map((cal, index) => {
          const isEditing = editingId === cal.calendar_id;
          const isDefault = index === 0;
          const isOnly = calendars.length === 1;

          return (
            <Card key={cal.calendar_id}>
              <CardContent className="p-4">
                {isEditing ? (
                  <RenameRow
                    calendar={cal}
                    onDone={() => setEditingId(null)}
                  />
                ) : (
                  <div className="flex items-center gap-3">
                    <CalendarDays className="h-5 w-5 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium">{cal.name}</span>
                        {isDefault && (
                          <Badge variant="secondary" className="text-[10px]">
                            Default
                          </Badge>
                        )}
                      </div>
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">
                        {cal.timezone}
                        {cal.conflict_detection && " · Conflict detection on"}
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        title="Rename"
                        onClick={() => setEditingId(cal.calendar_id)}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive"
                        title={isOnly ? "Cannot delete the only calendar" : "Delete"}
                        disabled={isOnly}
                        onClick={() => setDeletingCalendar(cal)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      <CreateCalendarDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => queryClient.invalidateQueries({ queryKey: ["calendars"] })}
      />

      <ConfirmDialog
        open={!!deletingCalendar}
        onOpenChange={(open) => { if (!open) setDeletingCalendar(null); }}
        title="Delete calendar?"
        description={`This will permanently delete "${deletingCalendar?.name ?? ""}" and all its events. This cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => {
          if (deletingCalendar) deleteMutation.mutate(deletingCalendar.calendar_id);
        }}
        loading={deleteMutation.isPending}
      />
    </div>
  );
}
