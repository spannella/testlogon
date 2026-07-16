import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Building2, Users, FolderOpen, CalendarDays, CreditCard } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import {
  getOrg,
  listMembers,
  inviteMember,
  listOrgEvents,
  listOrgFiles,
  type OrgMemberOut,
  type OrgEventOut,
} from "@/api/endpoints/orgs";

export default function OrgDashboard() {
  const { orgId } = useParams<{ orgId: string }>();
  const qc = useQueryClient();

  const { data: org } = useQuery({
    queryKey: ["org", orgId],
    queryFn: () => getOrg(orgId!),
    enabled: !!orgId,
  });

  const { data: members = [] } = useQuery({
    queryKey: ["org-members", orgId],
    queryFn: () => listMembers(orgId!),
    enabled: !!orgId,
  });

  const { data: events = [] } = useQuery({
    queryKey: ["org-events", orgId],
    queryFn: () => listOrgEvents(orgId!),
    enabled: !!orgId,
  });

  const { data: files = [] } = useQuery({
    queryKey: ["org-files", orgId],
    queryFn: () => listOrgFiles(orgId!),
    enabled: !!orgId,
  });

  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);

  const inviteMut = useMutation({
    mutationFn: () => inviteMember(orgId!, { email: inviteEmail }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["org-members", orgId] });
      setInviteOpen(false);
      setInviteEmail("");
    },
  });

  if (!org) return <p className="p-6 text-muted-foreground">Loading...</p>;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <Building2 className="h-6 w-6" />
        <h1 className="text-2xl font-bold">{org.name}</h1>
        <Badge>{org.status}</Badge>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="files">Files</TabsTrigger>
          <TabsTrigger value="calendar">Calendar</TabsTrigger>
          <TabsTrigger value="billing">Billing</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Members</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold">{org.member_count}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Plan</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold capitalize">{org.plan}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Billing Mode</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold capitalize">{org.billing_mode}</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="members" className="mt-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Members
              </CardTitle>
              <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
                <DialogTrigger asChild>
                  <Button size="sm">Invite Member</Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Invite Member</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4 pt-4">
                    <Input
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      placeholder="email@example.com"
                    />
                    <Button onClick={() => inviteMut.mutate()} disabled={!inviteEmail || inviteMut.isPending}>
                      {inviteMut.isPending ? "Sending..." : "Send Invite"}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {members.map((m: OrgMemberOut) => (
                  <div key={m.user_sub} className="flex items-center justify-between rounded-md border p-3">
                    <span className="text-sm font-medium">{m.user_sub}</span>
                    <Badge variant={m.org_role === "owner" ? "default" : "secondary"}>{m.org_role}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="files" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FolderOpen className="h-5 w-5" />
                Shared Files
              </CardTitle>
            </CardHeader>
            <CardContent>
              {files.length === 0 ? (
                <p className="text-muted-foreground">No files uploaded yet.</p>
              ) : (
                <div className="space-y-2">
                  {files.map((f) => (
                    <div key={f.node_id} className="flex items-center justify-between rounded-md border p-3">
                      <span className="text-sm">{f.name}</span>
                      <span className="text-xs text-muted-foreground">{f.uploaded_by}</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="calendar" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CalendarDays className="h-5 w-5" />
                Team Calendar
              </CardTitle>
            </CardHeader>
            <CardContent>
              {events.length === 0 ? (
                <p className="text-muted-foreground">No events scheduled.</p>
              ) : (
                <div className="space-y-2">
                  {events.map((e: OrgEventOut) => (
                    <div key={e.event_id} className="rounded-md border p-3">
                      <p className="font-medium">{e.title}</p>
                      <p className="text-xs text-muted-foreground">
                        {e.start_time} - {e.end_time}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="billing" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CreditCard className="h-5 w-5" />
                Billing
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Billing management is available for organization owners.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
