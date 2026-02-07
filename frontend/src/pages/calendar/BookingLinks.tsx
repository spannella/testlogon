import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Copy, Link2, Plus, Eye, ChevronUp, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { EmptyState } from "@/components/shared/EmptyState";
import { getCalendars, createBookingLink, listBookingLinks, getPublicOpenings } from "@/api/endpoints/calendar";
import type { BookingLink, Calendar, Opening } from "@/api/types";

const linkSchema = z.object({
  name: z.string().min(1, "Name is required"),
  duration_minutes: z.coerce.number().min(5, "Minimum 5 minutes"),
});

type LinkFormValues = z.infer<typeof linkSchema>;

function formatSlot(slot: Opening): string {
  const start = new Date(slot.start_utc);
  const end = new Date(slot.end_utc);
  const dateStr = start.toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  });
  const startTime = start.toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });
  const endTime = end.toLocaleTimeString(undefined, {
    hour: "numeric",
    minute: "2-digit",
  });
  return `${dateStr}, ${startTime} \u2013 ${endTime}`;
}

function OpeningsPanel({ linkId }: { linkId: string }) {
  const now = new Date();
  const end = new Date(now);
  end.setDate(end.getDate() + 7);

  const query = useQuery({
    queryKey: ["booking-openings", linkId],
    queryFn: () => getPublicOpenings(linkId, now.toISOString(), end.toISOString(), 10),
  });

  const openings: Opening[] = Array.isArray(query.data) ? query.data : [];

  if (query.isLoading) {
    return (
      <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        Loading openings...
      </div>
    );
  }

  if (openings.length === 0) {
    return (
      <p className="py-2 text-xs text-muted-foreground">
        No available slots in the next 7 days.
      </p>
    );
  }

  return (
    <div className="mt-2 grid gap-1 sm:grid-cols-2">
      {openings.map((slot, i) => (
        <div
          key={i}
          className="rounded border px-2 py-1.5 text-xs text-muted-foreground"
        >
          {formatSlot(slot)}
        </div>
      ))}
    </div>
  );
}

export function BookingLinks() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedCalId, setSelectedCalId] = useState<string>("");
  const [expandedLink, setExpandedLink] = useState<string | null>(null);

  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
  });

  const calendars: Calendar[] = Array.isArray(calendarsQuery.data) ? calendarsQuery.data : [];

  // Auto-select first calendar
  if (!selectedCalId && calendars.length > 0) {
    setSelectedCalId(calendars[0]!.calendar_id);
  }

  const calId = selectedCalId || (calendars.length > 0 ? calendars[0]!.calendar_id : "");

  const linksQuery = useQuery({
    queryKey: ["booking-links", calId],
    queryFn: () => listBookingLinks(calId),
    enabled: !!calId,
  });

  const links: BookingLink[] = Array.isArray(linksQuery.data) ? linksQuery.data : [];

  const form = useForm<LinkFormValues>({
    resolver: zodResolver(linkSchema),
    defaultValues: { name: "", duration_minutes: 30 },
  });

  const createMutation = useMutation({
    mutationFn: (values: LinkFormValues) =>
      createBookingLink(calId, {
        name: values.name,
        duration_minutes: values.duration_minutes,
      }),
    onSuccess: () => {
      setDialogOpen(false);
      form.reset({ name: "", duration_minutes: 30 });
      queryClient.invalidateQueries({ queryKey: ["booking-links", calId] });
      toast.success("Booking link created");
    },
    onError: () => {
      toast.error("Failed to create booking link");
    },
  });

  const copyToClipboard = (url: string) => {
    navigator.clipboard.writeText(url).then(
      () => toast.success("Link copied to clipboard"),
      () => toast.error("Failed to copy"),
    );
  };

  const toggleOpenings = (linkId: string) => {
    setExpandedLink((prev) => (prev === linkId ? null : linkId));
  };

  if (calendarsQuery.isLoading || linksQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <p className="text-sm text-muted-foreground">
            {links.length} booking link{links.length !== 1 ? "s" : ""}
          </p>
          {calendars.length > 1 && (
            <Select value={calId} onValueChange={setSelectedCalId}>
              <SelectTrigger className="h-8 w-40 text-xs">
                <SelectValue placeholder="Calendar" />
              </SelectTrigger>
              <SelectContent>
                {calendars.map((c) => (
                  <SelectItem key={c.calendar_id} value={c.calendar_id}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setDialogOpen(true)}
          disabled={calendars.length === 0}
        >
          <Plus className="mr-1 h-3.5 w-3.5" />
          Create Link
        </Button>
      </div>

      {links.length === 0 ? (
        <EmptyState
          icon={<Link2 className="h-6 w-6" />}
          title="No booking links"
          description="Create a booking link so others can schedule time with you"
          className="py-12"
        />
      ) : (
        <div className="space-y-3">
          {links.map((link) => (
            <Card key={link.link_id}>
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold">{link.name}</span>
                      <Badge variant="outline" className="text-[10px]">
                        {link.duration_minutes} min
                      </Badge>
                    </div>
                    <p className="mt-0.5 truncate text-xs font-mono text-muted-foreground">
                      {link.public_url}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 shrink-0"
                    onClick={() => toggleOpenings(link.link_id)}
                    title="View openings"
                  >
                    {expandedLink === link.link_id ? (
                      <ChevronUp className="h-3.5 w-3.5" />
                    ) : (
                      <Eye className="h-3.5 w-3.5" />
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 shrink-0"
                    onClick={() => copyToClipboard(link.public_url)}
                    title="Copy link"
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
                {expandedLink === link.link_id && (
                  <OpeningsPanel linkId={link.link_id} />
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Booking Link</DialogTitle>
          </DialogHeader>
          <form
            onSubmit={form.handleSubmit((v) => createMutation.mutate(v))}
            className="space-y-4 py-2"
          >
            <div className="space-y-1.5">
              <Label htmlFor="link-name">Name *</Label>
              <Input id="link-name" placeholder="e.g. 30 min meeting" {...form.register("name")} />
              {form.formState.errors.name && (
                <p className="text-xs text-destructive">{form.formState.errors.name.message}</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="link-duration">Duration (minutes)</Label>
              <Input id="link-duration" type="number" min={5} {...form.register("duration_minutes")} />
            </div>
            {calendars.length > 1 && (
              <div className="space-y-1.5">
                <Label>Calendar</Label>
                <Select value={calId} onValueChange={setSelectedCalId}>
                  <SelectTrigger>
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
            <DialogFooter>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
