import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, UserPlus, Shield, Clock, LogOut, Trash2, ArrowLeftRight, Package, Plus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
  listBundlePlans,
  createBundlePlan,
  updateBundlePlan,
  archiveBundlePlan,
  subscribeToBundlePlan,
} from "@/api/endpoints/syndicates";
import type { BundlePlanOut } from "@/api/types";
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
          <TabsTrigger value="plans">Plans</TabsTrigger>
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

        {/* Plans Tab (SYND-002) */}
        <TabsContent value="plans">
          <BundlePlansTab syndicateId={syndicateId!} isAdmin={isAdmin} />
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

function BundlePlansTab({ syndicateId, isAdmin }: { syndicateId: string; isAdmin: boolean }) {
  const queryClient = useQueryClient();

  const { data: plans = [] } = useQuery({
    queryKey: ["syndicate-plans", syndicateId],
    queryFn: async () => (await listBundlePlans(syndicateId)).data,
    enabled: !!syndicateId,
  });

  const archiveMut = useMutation({
    mutationFn: (planId: string) => archiveBundlePlan(syndicateId, planId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-plans", syndicateId] });
    },
  });

  const subscribeMut = useMutation({
    mutationFn: (planId: string) => subscribeToBundlePlan(syndicateId, planId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["my-bundles"] });
      queryClient.invalidateQueries({ queryKey: ["syndicate-plans", syndicateId] });
    },
  });

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <Package className="h-5 w-5" />
          Bundle Plans
        </CardTitle>
        {isAdmin && <CreateBundlePlanDialog syndicateId={syndicateId} />}
      </CardHeader>
      <CardContent>
        {plans.length === 0 ? (
          <div className="text-center py-6">
            <p className="text-muted-foreground">No bundle plans yet</p>
            {isAdmin && (
              <p className="text-sm text-muted-foreground mt-1">Create your first plan to attract subscribers</p>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {plans.map((p: BundlePlanOut) => (
              <div key={p.plan_id} className="rounded-lg border p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-semibold">{p.name}</h3>
                  <Badge variant={p.status === "active" ? "default" : "secondary"}>
                    {p.status}
                  </Badge>
                </div>
                {p.description && (
                  <p className="text-sm text-muted-foreground mb-2">{p.description}</p>
                )}
                <p className="text-lg font-medium mb-3">
                  ${(p.price_cents / 100).toFixed(2)}/{p.interval}
                </p>
                <div className="flex gap-2">
                  {isAdmin && p.status === "active" && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-destructive"
                      onClick={() => archiveMut.mutate(p.plan_id)}
                      disabled={archiveMut.isPending}
                    >
                      Archive
                    </Button>
                  )}
                  {!isAdmin && p.status === "active" && (
                    <Button
                      size="sm"
                      onClick={() => subscribeMut.mutate(p.plan_id)}
                      disabled={subscribeMut.isPending}
                    >
                      Subscribe
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CreateBundlePlanDialog({ syndicateId }: { syndicateId: string }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [priceDollars, setPriceDollars] = useState("");
  const [interval, setInterval] = useState("month");
  const queryClient = useQueryClient();

  const mut = useMutation({
    mutationFn: () =>
      createBundlePlan(syndicateId, {
        name,
        description,
        price_cents: Math.round(parseFloat(priceDollars) * 100),
        interval,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["syndicate-plans", syndicateId] });
      setOpen(false);
      setName("");
      setDescription("");
      setPriceDollars("");
      setInterval("month");
    },
  });

  const priceValid = priceDollars && parseFloat(priceDollars) >= 1 && parseFloat(priceDollars) <= 1000;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="h-4 w-4 mr-1" /> Create Plan
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Bundle Plan</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium">Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="All-Access Bundle"
              maxLength={100}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Description</label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Access content from all syndicate creators"
              maxLength={1000}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Price (USD)</label>
            <Input
              type="number"
              value={priceDollars}
              onChange={(e) => setPriceDollars(e.target.value)}
              placeholder="20.00"
              min={1}
              max={1000}
              step={0.01}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Billing Interval</label>
            <Select value={interval} onValueChange={setInterval}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="month">Monthly</SelectItem>
                <SelectItem value="year">Yearly</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => mut.mutate()}
            disabled={name.length < 2 || !priceValid || mut.isPending}
          >
            {mut.isPending ? "Creating..." : "Create Plan"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
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
