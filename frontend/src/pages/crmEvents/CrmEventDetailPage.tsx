import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  CalendarDays,
  CheckCircle2,
  Mail,
  RefreshCw,
  Send,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  addInvitee,
  cancelRegistration,
  checkInAttendee,
  getEventCapacity,
  getLocalEvent,
  listInvitees,
  listRegistrations,
  registerForEvent,
  removeInvitee,
  sendInvitations,
  type CrmInvitee,
  type CrmRegistration,
} from "@/api/endpoints/crmEvents";
import { EventsFeatureDisabled } from "./EventsFeatureDisabled";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const REG_VARIANT: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  accepted: "default",
  attended: "default",
  registered: "secondary",
  waitlisted: "outline",
  declined: "destructive",
};

function isDisabled(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export default function CrmEventDetailPage() {
  const { eventId = "" } = useParams();
  const qc = useQueryClient();
  const local = getLocalEvent(eventId);

  const [inviteeSub, setInviteeSub] = useState("");

  const capacityQuery = useQuery({
    queryKey: ["crm-events", "capacity", eventId],
    queryFn: () => getEventCapacity(eventId),
    enabled: !!eventId,
    retry: (count, err) => !isDisabled(err) && count < 2,
  });

  const regsQuery = useQuery({
    queryKey: ["crm-events", "registrations", eventId],
    queryFn: () => listRegistrations(eventId, { limit: 200 }),
    enabled: !!eventId,
    retry: (count, err) => !isDisabled(err) && count < 2,
  });

  const inviteesQuery = useQuery({
    queryKey: ["crm-events", "invitees", eventId],
    queryFn: () => listInvitees(eventId, { limit: 200 }),
    enabled: !!eventId,
    retry: (count, err) => !isDisabled(err) && count < 2,
  });

  const invalidateAll = () => {
    qc.invalidateQueries({ queryKey: ["crm-events", "capacity", eventId] });
    qc.invalidateQueries({ queryKey: ["crm-events", "registrations", eventId] });
    qc.invalidateQueries({ queryKey: ["crm-events", "invitees", eventId] });
  };

  const onError = (action: string) => (err: unknown) =>
    toast.error(err instanceof ApiError ? err.detail : `Failed to ${action}`);

  const addInviteeMut = useMutation({
    mutationFn: () => addInvitee(eventId, inviteeSub.trim()),
    onSuccess: () => {
      toast.success("Invitee added");
      setInviteeSub("");
      invalidateAll();
    },
    onError: onError("add invitee"),
  });

  const removeInviteeMut = useMutation({
    mutationFn: (sub: string) => removeInvitee(eventId, sub),
    onSuccess: () => {
      toast.success("Invitee removed");
      invalidateAll();
    },
    onError: onError("remove invitee"),
  });

  const sendInvitesMut = useMutation({
    mutationFn: () => sendInvitations(eventId),
    onSuccess: (res) => {
      toast.success(`Invitations: ${res.sent} sent, ${res.skipped} skipped, ${res.failed} failed`);
      invalidateAll();
    },
    onError: onError("send invitations"),
  });

  const registerMut = useMutation({
    mutationFn: () => registerForEvent(eventId),
    onSuccess: (reg) => {
      toast.success(
        reg.status === "waitlisted"
          ? `Waitlisted (position ${reg.waitlist_position ?? "?"})`
          : "Registered for event",
      );
      invalidateAll();
    },
    onError: onError("register"),
  });

  const checkInMut = useMutation({
    mutationFn: (sub: string) => checkInAttendee(eventId, sub),
    onSuccess: () => {
      toast.success("Checked in");
      invalidateAll();
    },
    onError: onError("check in"),
  });

  const cancelRegMut = useMutation({
    mutationFn: (sub: string) => cancelRegistration(eventId, sub),
    onSuccess: () => {
      toast.success("Registration cancelled");
      invalidateAll();
    },
    onError: onError("cancel registration"),
  });

  // Feature-disabled short-circuit
  if (isDisabled(capacityQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Event" description="SuiteCRM Events" />
        <EventsFeatureDisabled />
      </div>
    );
  }

  const cap = capacityQuery.data;
  const regs: CrmRegistration[] = regsQuery.data?.registrations ?? [];
  const invitees: CrmInvitee[] = inviteesQuery.data?.invitees ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={local?.name ?? "Event"}
        description={local?.description || `Event ${eventId.slice(0, 12)}…`}
        actions={
          <div className="flex items-center gap-2">
            <Button asChild variant="outline" size="sm">
              <Link to="/crm/events">
                <ArrowLeft className="mr-1 h-4 w-4" />
                Back
              </Link>
            </Button>
            <Button variant="outline" size="sm" onClick={invalidateAll}>
              <RefreshCw className="mr-1 h-4 w-4" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => registerMut.mutate()} disabled={registerMut.isPending}>
              <CalendarDays className="mr-1 h-4 w-4" />
              Register me
            </Button>
          </div>
        }
      />

      {/* Capacity summary */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <CapacityStat label="Capacity" value={cap?.max_attendance ?? "∞"} loading={capacityQuery.isLoading} />
        <CapacityStat label="Accepted" value={cap?.accepted_count ?? 0} loading={capacityQuery.isLoading} />
        <CapacityStat label="Waitlisted" value={cap?.waitlisted_count ?? 0} loading={capacityQuery.isLoading} />
        <CapacityStat
          label="Available"
          value={cap?.available_spots ?? "∞"}
          loading={capacityQuery.isLoading}
        />
      </div>

      <Tabs defaultValue="registrations">
        <TabsList>
          <TabsTrigger value="registrations">
            Registrations ({regs.length})
          </TabsTrigger>
          <TabsTrigger value="invitees">Invitees ({invitees.length})</TabsTrigger>
        </TabsList>

        {/* Registrations management */}
        <TabsContent value="registrations" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Users className="h-4 w-4" />
                Registrations
              </CardTitle>
            </CardHeader>
            <CardContent>
              {regsQuery.isLoading ? (
                <Skeleton className="h-40 w-full" />
              ) : regs.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  No registrations yet.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Registrant</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Registered</TableHead>
                      <TableHead>Checked in</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {regs.map((r) => (
                      <TableRow key={r.registrant_sub}>
                        <TableCell className="font-mono text-xs">
                          {r.registrant_sub}
                          {r.invited ? (
                            <Badge variant="outline" className="ml-2">
                              invited
                            </Badge>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          <Badge variant={REG_VARIANT[r.status] ?? "secondary"}>
                            {r.status}
                            {r.status === "waitlisted" && r.waitlist_position != null
                              ? ` #${r.waitlist_position}`
                              : ""}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">{fmt(r.registered_at)}</TableCell>
                        <TableCell className="text-xs">{fmt(r.checked_in_at)}</TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={r.status === "attended" || checkInMut.isPending}
                              onClick={() => checkInMut.mutate(r.registrant_sub)}
                            >
                              <CheckCircle2 className="mr-1 h-3.5 w-3.5" />
                              Check in
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-destructive"
                              disabled={cancelRegMut.isPending}
                              onClick={() => cancelRegMut.mutate(r.registrant_sub)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Invitee management */}
        <TabsContent value="invitees" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-end justify-between gap-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Mail className="h-4 w-4" />
                Invitees
              </CardTitle>
              <Button
                size="sm"
                variant="outline"
                disabled={sendInvitesMut.isPending}
                onClick={() => sendInvitesMut.mutate()}
              >
                <Send className="mr-1 h-4 w-4" />
                Send invitations
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-end gap-2">
                <div className="flex-1 space-y-1">
                  <Label htmlFor="invitee-sub" className="text-xs">
                    Add invitee (user sub)
                  </Label>
                  <Input
                    id="invitee-sub"
                    placeholder="user_sub…"
                    value={inviteeSub}
                    onChange={(e) => setInviteeSub(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && inviteeSub.trim()) addInviteeMut.mutate();
                    }}
                  />
                </div>
                <Button
                  disabled={!inviteeSub.trim() || addInviteeMut.isPending}
                  onClick={() => addInviteeMut.mutate()}
                >
                  <UserPlus className="mr-1 h-4 w-4" />
                  Add
                </Button>
              </div>

              {inviteesQuery.isLoading ? (
                <Skeleton className="h-32 w-full" />
              ) : invitees.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  No invitees. Add invitees above, then send invitations.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Invitee</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Invited</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {invitees.map((inv) => (
                      <TableRow key={inv.invitee_sub}>
                        <TableCell>
                          <span className="font-medium">
                            {inv.display_name || inv.invitee_sub}
                          </span>
                          {inv.display_name && (
                            <span className="ml-2 font-mono text-xs text-muted-foreground">
                              {inv.invitee_sub}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant={inv.invite_status === "sent" ? "default" : "secondary"}>
                            {inv.invite_status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">{fmt(inv.invited_at)}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-destructive"
                            disabled={removeInviteeMut.isPending}
                            onClick={() => removeInviteeMut.mutate(inv.invitee_sub)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function CapacityStat({
  label,
  value,
  loading,
}: {
  label: string;
  value: number | string;
  loading: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs text-muted-foreground">{label}</p>
        {loading ? (
          <Skeleton className="mt-1 h-7 w-12" />
        ) : (
          <p className="text-2xl font-semibold tabular-nums">{value}</p>
        )}
      </CardContent>
    </Card>
  );
}
