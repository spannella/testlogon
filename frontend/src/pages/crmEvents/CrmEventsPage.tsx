import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQueries } from "@tanstack/react-query";
import { CalendarDays, Plus, Users, Search } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  getEventCapacity,
  readLocalEvents,
  type LocalEventEntry,
} from "@/api/endpoints/crmEvents";

function fmtDate(ts?: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export default function CrmEventsPage() {
  const [filter, setFilter] = useState("");
  const events: LocalEventEntry[] = useMemo(() => readLocalEvents(), []);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return events;
    return events.filter(
      (e) =>
        e.name.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q),
    );
  }, [events, filter]);

  // Best-effort live capacity per event. Disabled-feature (404/503) errors are
  // swallowed silently — the card just shows the local snapshot.
  const capacityQueries = useQueries({
    queries: filtered.map((e) => ({
      queryKey: ["crm-events", "capacity", e.event_id],
      queryFn: () => getEventCapacity(e.event_id),
      retry: false,
      staleTime: 15_000,
    })),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Events"
        description="SuiteCRM events — registrations, capacity, and invitee management."
        actions={
          <Button asChild size="sm">
            <Link to="/crm/events/new">
              <Plus className="mr-1 h-4 w-4" />
              New event
            </Link>
          </Button>
        }
      />

      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          className="pl-8"
          placeholder="Search events…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={<CalendarDays className="h-7 w-7" />}
          title={events.length === 0 ? "No events yet" : "No matching events"}
          description={
            events.length === 0
              ? "Create your first event to start managing invitees and registrations."
              : "Try a different search term."
          }
          action={
            events.length === 0
              ? { label: "Create event", onClick: () => undefined }
              : undefined
          }
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filtered.map((e, idx) => {
            const cap = capacityQueries[idx]?.data;
            return (
              <Link key={e.event_id} to={`/crm/events/${e.event_id}`}>
                <Card className="h-full transition-colors hover:border-primary/40">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-start justify-between gap-2 text-base">
                      <span className="line-clamp-1">{e.name}</span>
                      {e.max_attendance != null && (
                        <Badge variant="secondary" className="shrink-0">
                          cap {e.max_attendance}
                        </Badge>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <p className="line-clamp-2 min-h-[2.5rem] text-sm text-muted-foreground">
                      {e.description || "No description."}
                    </p>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>Created {fmtDate(e.created_at)}</span>
                      {cap && (
                        <span className="flex items-center gap-1 tabular-nums">
                          <Users className="h-3.5 w-3.5" />
                          {cap.accepted_count}
                          {cap.max_attendance != null ? `/${cap.max_attendance}` : ""}
                          {cap.waitlisted_count > 0 ? ` (+${cap.waitlisted_count} wl)` : ""}
                        </span>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
