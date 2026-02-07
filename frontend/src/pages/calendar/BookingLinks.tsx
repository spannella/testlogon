import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Copy, Link2, Plus } from "lucide-react";
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
import { getCalendars, createBookingLink } from "@/api/endpoints/calendar";
import type { BookingLink, Calendar } from "@/api/types";

const linkSchema = z.object({
  name: z.string().min(1, "Name is required"),
  duration_minutes: z.coerce.number().min(5, "Minimum 5 minutes"),
});

type LinkFormValues = z.infer<typeof linkSchema>;

export function BookingLinks() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedCalId, setSelectedCalId] = useState<string>("");

  // We store created links locally since there's no list endpoint
  const [links, setLinks] = useState<BookingLink[]>([]);

  const calendarsQuery = useQuery({
    queryKey: ["calendars"],
    queryFn: () => getCalendars(),
  });

  const calendars: Calendar[] = Array.isArray(calendarsQuery.data) ? calendarsQuery.data : [];

  // Auto-select first calendar
  if (!selectedCalId && calendars.length > 0) {
    setSelectedCalId(calendars[0]!.calendar_id);
  }

  const form = useForm<LinkFormValues>({
    resolver: zodResolver(linkSchema),
    defaultValues: { name: "", duration_minutes: 30 },
  });

  const createMutation = useMutation({
    mutationFn: (values: LinkFormValues) =>
      createBookingLink(selectedCalId, {
        name: values.name,
        duration_minutes: values.duration_minutes,
      }),
    onSuccess: (data) => {
      setLinks((prev) => [...prev, data]);
      setDialogOpen(false);
      form.reset({ name: "", duration_minutes: 30 });
      queryClient.invalidateQueries({ queryKey: ["booking-links"] });
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

  if (calendarsQuery.isLoading) {
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
        <p className="text-sm text-muted-foreground">
          {links.length} booking link{links.length !== 1 ? "s" : ""}
        </p>
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
              <CardContent className="flex items-center gap-4 p-4">
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
                  onClick={() => copyToClipboard(link.public_url)}
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
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
                <Select value={selectedCalId} onValueChange={setSelectedCalId}>
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
