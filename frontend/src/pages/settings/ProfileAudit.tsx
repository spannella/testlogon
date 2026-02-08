import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Clock, Filter, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { getProfileAudit } from "@/api/endpoints/profile";
import type { ProfileAuditEntry } from "@/api/types";

function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function eventLabel(event: string): string {
  return event
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ProfileAudit() {
  const [filterEvent, setFilterEvent] = useState<string | null>(null);

  const auditQuery = useQuery({
    queryKey: ["profile", "audit"],
    queryFn: () => getProfileAudit(),
  });

  const entries: ProfileAuditEntry[] = useMemo(() => {
    const raw = auditQuery.data?.audit ?? [];
    return raw
      .map((r) => ({
        event: String(r["event"] ?? "unknown"),
        ts: Number(r["ts"] ?? 0),
        outcome: r["outcome"] != null ? String(r["outcome"]) : undefined,
        ...r,
      }))
      .sort((a, b) => b.ts - a.ts);
  }, [auditQuery.data]);

  const eventTypes = useMemo(() => {
    const set = new Set<string>();
    for (const e of entries) set.add(e.event);
    return Array.from(set).sort();
  }, [entries]);

  const filtered = filterEvent
    ? entries.filter((e) => e.event === filterEvent)
    : entries;

  if (auditQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <EmptyState
        icon={<Clock className="h-6 w-6" />}
        title="No activity"
        description="Profile changes will appear here"
        className="py-12"
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Filter toolbar */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {filtered.length} event{filtered.length !== 1 ? "s" : ""}
        </p>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm">
              <Filter className="mr-1 h-3.5 w-3.5" />
              {filterEvent ? eventLabel(filterEvent) : "All events"}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => setFilterEvent(null)}>
              All events
            </DropdownMenuItem>
            {eventTypes.map((evt) => (
              <DropdownMenuItem key={evt} onClick={() => setFilterEvent(evt)}>
                {eventLabel(evt)}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Timeline */}
      <div className="relative space-y-0 pl-6">
        {/* Vertical line */}
        <div className="absolute left-2.5 top-1 bottom-1 w-px bg-border" />

        {filtered.map((entry, idx) => (
          <div key={idx} className="relative pb-6 last:pb-0">
            {/* Circle connector */}
            <div className="absolute -left-6 top-1 flex h-5 w-5 items-center justify-center rounded-full border-2 border-background bg-muted">
              <div className="h-2 w-2 rounded-full bg-foreground/40" />
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary" className="text-xs">
                  {eventLabel(entry.event)}
                </Badge>
                {entry.outcome && (
                  <Badge
                    variant={entry.outcome === "success" ? "default" : "destructive"}
                    className="text-xs"
                  >
                    {entry.outcome}
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                {formatTimestamp(entry.ts)}
              </p>
              {/* Show extra details if present */}
              {Object.entries(entry)
                .filter(
                  ([k]) =>
                    !["event", "ts", "outcome", "user_sub", "ttl_epoch"].includes(k),
                )
                .map(([k, v]) => (
                  <p key={k} className="text-xs text-muted-foreground">
                    <span className="font-medium">{k}:</span>{" "}
                    {typeof v === "object" ? JSON.stringify(v) : String(v)}
                  </p>
                ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
