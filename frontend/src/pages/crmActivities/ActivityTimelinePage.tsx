import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  Phone,
  CheckSquare,
  StickyNote,
  Calendar,
  Mail,
  Activity,
  Trash2,
  Search,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { ApiError } from "@/api/client";
import {
  getEntityTimeline,
  deleteTimelineEntry,
  type CrmActivityOut,
  type CrmEntityType,
} from "@/api/endpoints/crmActivities";
import { CreateActivityDialog } from "./CreateActivityDialog";
import { ActivitiesNotEnabled } from "./ActivitiesNotEnabled";
import { fmtTs, ACTIVITY_TYPE_LABELS } from "./activityHelpers";

const ENTITY_TYPES: CrmEntityType[] = ["contact", "lead", "account", "opportunity"];

const TYPE_ICON: Record<string, React.ReactNode> = {
  call: <Phone className="h-4 w-4" />,
  task: <CheckSquare className="h-4 w-4" />,
  note: <StickyNote className="h-4 w-4" />,
  calendar_event: <Calendar className="h-4 w-4" />,
  email: <Mail className="h-4 w-4" />,
};

function notEnabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export default function ActivityTimelinePage() {
  const params = useParams<{ entityType?: string; entityId?: string }>();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const qc = useQueryClient();

  // Resolve current entity from route params or query string.
  const routeType = params.entityType ?? search.get("entity_type") ?? "";
  const routeId = params.entityId ?? search.get("entity_id") ?? "";

  const [entityType, setEntityType] = useState<string>(routeType || "contact");
  const [entityId, setEntityId] = useState<string>(routeId);
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [createOpen, setCreateOpen] = useState(false);

  // Keep the form in sync if the route changes (deep link).
  useEffect(() => {
    if (routeType) setEntityType(routeType);
    setEntityId(routeId);
  }, [routeType, routeId]);

  const active = !!routeType && !!routeId;

  const timelineQuery = useQuery({
    queryKey: ["crm-activities", "timeline", routeType, routeId, typeFilter],
    queryFn: () =>
      getEntityTimeline(routeType, routeId, {
        limit: 50,
        activity_type: typeFilter || undefined,
      }),
    enabled: active,
    retry: false,
  });

  const delMut = useMutation({
    mutationFn: (item: CrmActivityOut & { sk?: string }) =>
      deleteTimelineEntry(routeType, routeId, item.sk ?? buildSk(item)),
    onSuccess: () => {
      toast.success("Timeline entry removed");
      void qc.invalidateQueries({ queryKey: ["crm-activities", "timeline"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Delete failed"),
  });

  const goToEntity = () => {
    if (!entityType || !entityId.trim()) {
      toast.error("Enter an entity type and id");
      return;
    }
    navigate(`/crm/timeline/${entityType}/${encodeURIComponent(entityId.trim())}`);
  };

  const disabled = notEnabled(timelineQuery.error);

  const items = timelineQuery.data?.items ?? [];

  const prefillLink = useMemo(
    () =>
      active
        ? { entity_type: routeType as CrmEntityType, entity_id: routeId }
        : undefined,
    [active, routeType, routeId],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Activity Timeline"
        description="Chronological history of calls, tasks, and notes logged against a CRM record."
        actions={
          active && !disabled ? (
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1.5 h-4 w-4" />
              Log activity
            </Button>
          ) : undefined
        }
      />

      {/* Record selector */}
      <Card>
        <CardContent className="flex flex-wrap items-end gap-3 py-4">
          <div className="space-y-1.5">
            <Label>Record type</Label>
            <Select value={entityType} onValueChange={setEntityType}>
              <SelectTrigger className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ENTITY_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="entity-id">Record ID</Label>
            <Input
              id="entity-id"
              value={entityId}
              onChange={(e) => setEntityId(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") goToEntity();
              }}
              placeholder="e.g. contact_123"
              className="w-72"
            />
          </div>
          <Button variant="outline" onClick={goToEntity}>
            <Search className="mr-1.5 h-4 w-4" />
            View timeline
          </Button>
        </CardContent>
      </Card>

      {!active ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center gap-2 py-16 text-center">
            <Activity className="h-8 w-8 text-muted-foreground" />
            <p className="text-lg font-medium">Select a record</p>
            <p className="text-sm text-muted-foreground">
              Pick a record type and enter its ID to view its activity history.
            </p>
          </CardContent>
        </Card>
      ) : disabled ? (
        <ActivitiesNotEnabled feature="CRM Activity Timeline" />
      ) : (
        <>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Filter type</span>
            <Select
              value={typeFilter || "all"}
              onValueChange={(v) => setTypeFilter(v === "all" ? "" : v)}
            >
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                <SelectItem value="call">Call</SelectItem>
                <SelectItem value="task">Task</SelectItem>
                <SelectItem value="note">Note</SelectItem>
                <SelectItem value="calendar_event">Calendar event</SelectItem>
                <SelectItem value="email">Email</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {timelineQuery.isLoading ? (
            <div className="space-y-2">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          ) : items.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center gap-2 py-16 text-center">
                <Activity className="h-8 w-8 text-muted-foreground" />
                <p className="text-lg font-medium">No activity yet</p>
                <p className="text-sm text-muted-foreground">
                  Logged calls, tasks, and notes for{" "}
                  <span className="font-medium">
                    {routeType} {routeId}
                  </span>{" "}
                  will appear here.
                </p>
                <Button variant="outline" onClick={() => setCreateOpen(true)}>
                  Log the first activity
                </Button>
              </CardContent>
            </Card>
          ) : (
            <ol className="relative space-y-3 border-l pl-6">
              {items.map((it) => (
                <li key={`${it.activity_type}-${it.activity_id}-${it.created_at}`} className="relative">
                  <span className="absolute -left-[31px] flex h-6 w-6 items-center justify-center rounded-full border bg-background text-muted-foreground">
                    {TYPE_ICON[it.activity_type] ?? <Activity className="h-3.5 w-3.5" />}
                  </span>
                  <Card>
                    <CardContent className="flex items-start justify-between gap-3 py-3">
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="secondary">
                            {ACTIVITY_TYPE_LABELS[it.activity_type] ?? it.activity_type}
                          </Badge>
                          <span className="font-medium">
                            {it.summary || "(no summary)"}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground">{fmtTs(it.created_at)}</p>
                      </div>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label="Remove timeline entry"
                        onClick={() => delMut.mutate(it as CrmActivityOut)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </CardContent>
                  </Card>
                </li>
              ))}
            </ol>
          )}
        </>
      )}

      <CreateActivityDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        prefillLink={prefillLink}
        defaultKind="call"
        onCreated={() => {
          void qc.invalidateQueries({ queryKey: ["crm-activities", "timeline"] });
        }}
      />
    </div>
  );
}

// The timeline SK isn't returned by the API; reconstruct the canonical form
// (inverted_ts:013d#activity_type#activity_id) used by the backend so deletes
// target the right row.
const INVERTED_MAX = 9_999_999_999_999;
function buildSk(item: CrmActivityOut): string {
  const inverted = INVERTED_MAX - (item.created_at || 0);
  return `${String(inverted).padStart(13, "0")}#${item.activity_type}#${item.activity_id}`;
}
