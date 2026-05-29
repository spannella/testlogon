import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, UserPlus, Shield, Clock, LogOut, Trash2, ArrowLeftRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  getSyndicate,
  listMembers,
  listRequests,
  getAuditLog,
  inviteMember,
  approveRequest,
  rejectRequest,
  transferAdmin,
  leaveSyndicate,
  removeMember,
} from "@/api/endpoints/syndicates";
import { useAuthStore } from "@/stores/authStore";

export default function SyndicateDetailPage() {
  const { syndicateId } = useParams<{ syndicateId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);

  const { data: syndicate } = useQuery({
    queryKey: ["syndicates", syndicateId],
    queryFn: async () => (await getSyndicate(syndicateId!)).data,
    enabled: !!syndicateId,
  });

  const { data: members = [] } = useQuery({
    queryKey: ["syndicates", syndicateId, "members"],
    queryFn: async () => (await listMembers(syndicateId!)).data,
    enabled: !!syndicateId,
  });

  const { data: requests = [] } = useQuery({
    queryKey: ["syndicates", syndicateId, "requests"],
    queryFn: async () => (await listRequests(syndicateId!)).data,
    enabled: !!syndicateId,
  });

  const { data: auditLog = [] } = useQuery({
    queryKey: ["syndicates", syndicateId, "audit"],
    queryFn: async () => (await getAuditLog(syndicateId!)).data,
    enabled: !!syndicateId,
  });

  const isAdmin = syndicate?.admin_user_id === userId;

  const leaveMut = useMutation({
    mutationFn: () => leaveSyndicate(syndicateId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
      navigate("/syndicates");
    },
  });

  if (!syndicate) {
    return <div className="p-6">Loading...</div>;
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Users className="h-6 w-6" />
            {syndicate.name}
          </h1>
          {syndicate.description && (
            <p className="mt-1 text-muted-foreground">{syndicate.description}</p>
          )}
          <div className="flex items-center gap-3 mt-2">
            <Badge>{syndicate.status}</Badge>
            <span className="text-sm text-muted-foreground">
              {syndicate.member_count} member(s)
            </span>
          </div>
        </div>
        <Button
          variant="destructive"
          size="sm"
          onClick={() => leaveMut.mutate()}
          disabled={leaveMut.isPending}
        >
          <LogOut className="h-4 w-4 mr-1" />
          Leave Syndicate
        </Button>
      </div>

      {syndicate.member_count === 1 && (
        <div className="rounded-lg border border-yellow-300 bg-yellow-50 dark:bg-yellow-900/20 p-3 text-sm text-yellow-800 dark:text-yellow-200">
          Warning: You are the only member. Leaving will dissolve this syndicate.
        </div>
      )}

      <Tabs defaultValue="members">
        <TabsList>
          <TabsTrigger value="members">Members</TabsTrigger>
          {isAdmin && <TabsTrigger value="requests">Requests ({requests.length})</TabsTrigger>}
          {isAdmin && <TabsTrigger value="audit">Audit Log</TabsTrigger>}
        </TabsList>

        {/* Members Tab */}
        <TabsContent value="members">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Members</CardTitle>
              {isAdmin && <InviteMemberDialog syndicateId={syndicateId!} />}
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {members.map((m) => (
                  <div key={m.user_id} className="flex items-center justify-between rounded-lg border p-3">
                    <div>
                      <p className="font-medium">{m.display_name || m.user_id}</p>
                      <p className="text-sm text-muted-foreground">
                        Joined {new Date(m.joined_at * 1000).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={m.role === "admin" ? "default" : "secondary"}>
                        {m.role}
                      </Badge>
                      {isAdmin && m.user_id !== userId && (
                        <>
                          <TransferAdminButton syndicateId={syndicateId!} targetUserId={m.user_id} />
                          <RemoveMemberButton syndicateId={syndicateId!} targetUserId={m.user_id} />
                        </>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Requests Tab */}
        {isAdmin && (
          <TabsContent value="requests">
            <Card>
              <CardHeader>
                <CardTitle>Pending Requests</CardTitle>
              </CardHeader>
              <CardContent>
                {requests.length === 0 ? (
                  <p className="text-muted-foreground">No pending requests.</p>
                ) : (
                  <div className="space-y-3">
                    {requests.map((r) => (
                      <RequestRow key={r.user_id} syndicateId={syndicateId!} request={r} />
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {/* Audit Tab */}
        {isAdmin && (
          <TabsContent value="audit">
            <Card>
              <CardHeader>
                <CardTitle>Audit Log</CardTitle>
              </CardHeader>
              <CardContent>
                {auditLog.length === 0 ? (
                  <p className="text-muted-foreground">No audit entries yet.</p>
                ) : (
                  <div className="space-y-2">
                    {auditLog.map((a) => (
                      <div key={a.event_id} className="flex items-start gap-3 rounded border p-2 text-sm">
                        <Clock className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                        <div>
                          <p>
                            <span className="font-medium">{a.actor_id}</span>{" "}
                            <span className="text-muted-foreground">{a.action}</span>{" "}
                            {a.target_id && <span className="font-medium">{a.target_id}</span>}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {new Date(a.ts * 1000).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

function InviteMemberDialog({ syndicateId }: { syndicateId: string }) {
  const [open, setOpen] = useState(false);
  const [userId, setUserId] = useState("");
  const queryClient = useQueryClient();

  const mut = useMutation({
    mutationFn: () => inviteMember(syndicateId, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
      setOpen(false);
      setUserId("");
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <UserPlus className="h-4 w-4 mr-1" /> Invite
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite Member</DialogTitle>
        </DialogHeader>
        <div>
          <label className="text-sm font-medium">User ID</label>
          <Input
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="user@example.com"
          />
        </div>
        <DialogFooter>
          <Button onClick={() => mut.mutate()} disabled={!userId || mut.isPending}>
            {mut.isPending ? "Inviting..." : "Send Invite"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TransferAdminButton({ syndicateId, targetUserId }: { syndicateId: string; targetUserId: string }) {
  const queryClient = useQueryClient();
  const mut = useMutation({
    mutationFn: () => transferAdmin(syndicateId, targetUserId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
    },
  });

  return (
    <Button
      size="sm"
      variant="ghost"
      onClick={() => mut.mutate()}
      disabled={mut.isPending}
      title="Transfer Admin"
    >
      <ArrowLeftRight className="h-4 w-4" />
    </Button>
  );
}

function RemoveMemberButton({ syndicateId, targetUserId }: { syndicateId: string; targetUserId: string }) {
  const queryClient = useQueryClient();
  const mut = useMutation({
    mutationFn: () => removeMember(syndicateId, targetUserId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
    },
  });

  return (
    <Button
      size="sm"
      variant="ghost"
      className="text-destructive"
      onClick={() => mut.mutate()}
      disabled={mut.isPending}
      title="Remove Member"
    >
      <Trash2 className="h-4 w-4" />
    </Button>
  );
}

function RequestRow({ syndicateId, request }: { syndicateId: string; request: { user_id: string; message: string; requested_at: number } }) {
  const queryClient = useQueryClient();

  const approveMut = useMutation({
    mutationFn: () => approveRequest(syndicateId, request.user_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
    },
  });

  const rejectMut = useMutation({
    mutationFn: () => rejectRequest(syndicateId, request.user_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicates"] });
    },
  });

  return (
    <div className="flex items-center justify-between rounded-lg border p-3">
      <div>
        <p className="font-medium">{request.user_id}</p>
        {request.message && <p className="text-sm text-muted-foreground">{request.message}</p>}
        <p className="text-xs text-muted-foreground">
          {new Date(request.requested_at * 1000).toLocaleDateString()}
        </p>
      </div>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => approveMut.mutate()} disabled={approveMut.isPending}>
          Approve
        </Button>
        <Button size="sm" variant="outline" onClick={() => rejectMut.mutate()} disabled={rejectMut.isPending}>
          Reject
        </Button>
      </div>
    </div>
  );
}
