import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Users,
  Shield,
  ShieldCheck,
  Crown,
  Trash2,
  ArrowUpCircle,
  ArrowDownCircle,
  UserPlus,
  Check,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/components/ui/use-toast";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  getGroup,
  updateGroup,
  deleteGroup,
  listGroupMembers,
  listPendingMembers,
  updateMemberRole,
  removeMember,
  inviteToGroup,
  reviewJoinRequest,
} from "@/api/endpoints/groups";
import type { UserGroup, GroupMember } from "@/api/types";

const settingsSchema = z.object({
  name: z.string().min(3).max(100),
  description: z.string().max(2000),
  topic: z.string().max(50).optional(),
});

type SettingsValues = z.infer<typeof settingsSchema>;

function RoleIcon({ role }: { role: string }) {
  switch (role) {
    case "admin":
      return <Crown className="h-4 w-4 text-yellow-500" />;
    case "moderator":
      return <ShieldCheck className="h-4 w-4 text-blue-500" />;
    default:
      return <Users className="h-4 w-4 text-muted-foreground" />;
  }
}

export default function GroupSettingsPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [inviteUserId, setInviteUserId] = useState("");

  const groupQuery = useQuery({
    queryKey: ["groups", groupId],
    queryFn: () => getGroup(groupId!).then((r) => r.data),
    enabled: !!groupId,
    staleTime: 30_000,
  });

  const membersQuery = useQuery({
    queryKey: ["groups", groupId, "members"],
    queryFn: () => listGroupMembers(groupId!).then((r) => r.data),
    enabled: !!groupId,
    staleTime: 15_000,
  });

  const pendingQuery = useQuery({
    queryKey: ["groups", groupId, "pending"],
    queryFn: () => listPendingMembers(groupId!).then((r) => r.data),
    enabled: !!groupId && (groupQuery.data?.my_role === "admin" || groupQuery.data?.my_role === "moderator"),
    staleTime: 15_000,
  });

  const group = groupQuery.data;
  const isAdmin = group?.my_role === "admin";
  const isModOrAdmin = group?.my_role === "admin" || group?.my_role === "moderator";

  const form = useForm<SettingsValues>({
    resolver: zodResolver(settingsSchema),
    values: group
      ? {
          name: group.name,
          description: group.description || "",
          topic: group.topic || "",
        }
      : undefined,
  });

  const updateMut = useMutation({
    mutationFn: (values: SettingsValues) =>
      updateGroup(groupId!, {
        name: values.name,
        description: values.description,
        topic: values.topic || undefined,
      }),
    onSuccess: () => {
      toast({ title: "Group settings saved" });
      queryClient.invalidateQueries({ queryKey: ["groups"] });
    },
  });

  const dissolveMut = useMutation({
    mutationFn: () => deleteGroup(groupId!),
    onSuccess: () => {
      toast({ title: "Group dissolved" });
      queryClient.invalidateQueries({ queryKey: ["groups"] });
      navigate("/groups");
    },
  });

  const promoteMut = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: "moderator" | "member" }) =>
      updateMemberRole(groupId!, userId, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["groups", groupId, "members"] });
      toast({ title: "Role updated" });
    },
  });

  const removeMut = useMutation({
    mutationFn: (userId: string) => removeMember(groupId!, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["groups", groupId, "members"] });
      queryClient.invalidateQueries({ queryKey: ["groups"] });
      toast({ title: "Member removed" });
    },
  });

  const inviteMut = useMutation({
    mutationFn: (userId: string) => inviteToGroup(groupId!, userId),
    onSuccess: () => {
      setInviteUserId("");
      queryClient.invalidateQueries({ queryKey: ["groups", groupId] });
      toast({ title: "Invitation sent" });
    },
    onError: (err: any) => {
      toast({
        title: "Invite failed",
        description: err?.response?.data?.detail || "Unknown error",
        variant: "destructive",
      });
    },
  });

  const reviewMut = useMutation({
    mutationFn: ({ userId, approved }: { userId: string; approved: boolean }) =>
      reviewJoinRequest(groupId!, userId, approved),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["groups", groupId] });
      toast({ title: "Request reviewed" });
    },
  });

  if (groupQuery.isLoading) {
    return (
      <div className="container max-w-3xl py-6">
        <p className="text-muted-foreground text-center py-8">Loading...</p>
      </div>
    );
  }

  if (!group) {
    return (
      <div className="container max-w-3xl py-6">
        <p className="text-muted-foreground text-center py-8">Group not found.</p>
      </div>
    );
  }

  return (
    <div className="container max-w-3xl py-6 space-y-6" data-testid="group-settings-page">
      <div>
        <h1 className="text-2xl font-bold">{group.name}</h1>
        <p className="text-muted-foreground">
          {group.member_count} member{group.member_count !== 1 ? "s" : ""} ·{" "}
          {group.visibility} group
        </p>
      </div>

      {/* Settings form (admin only) */}
      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle>Group Settings</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={form.handleSubmit((v) => updateMut.mutate(v))}
              className="space-y-4"
            >
              <div className="space-y-2">
                <Label htmlFor="settings-name">Name</Label>
                <Input id="settings-name" {...form.register("name")} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="settings-description">Description</Label>
                <Textarea
                  id="settings-description"
                  rows={3}
                  {...form.register("description")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="settings-topic">Topic</Label>
                <Input id="settings-topic" {...form.register("topic")} />
              </div>
              <Button type="submit" disabled={updateMut.isPending}>
                {updateMut.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Members list */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Members ({membersQuery.data?.count ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {isModOrAdmin && (
            <div className="flex gap-2">
              <Input
                placeholder="User ID to invite..."
                value={inviteUserId}
                onChange={(e) => setInviteUserId(e.target.value)}
              />
              <Button
                size="sm"
                onClick={() => inviteUserId && inviteMut.mutate(inviteUserId)}
                disabled={!inviteUserId || inviteMut.isPending}
              >
                <UserPlus className="h-4 w-4 mr-1" />
                Invite
              </Button>
            </div>
          )}
          <Separator />
          {membersQuery.data?.members?.map((member) => (
            <div
              key={member.user_id}
              className="flex items-center justify-between py-2"
            >
              <div className="flex items-center gap-2">
                <RoleIcon role={member.role} />
                <span className="font-medium">
                  {member.display_name || member.user_id}
                </span>
                <Badge variant="outline" className="text-xs">
                  {member.role}
                </Badge>
              </div>
              <div className="flex items-center gap-1">
                {isAdmin && member.role !== "admin" && (
                  <>
                    {member.role === "member" ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          promoteMut.mutate({
                            userId: member.user_id,
                            role: "moderator",
                          })
                        }
                        title="Promote to moderator"
                      >
                        <ArrowUpCircle className="h-4 w-4" />
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          promoteMut.mutate({
                            userId: member.user_id,
                            role: "member",
                          })
                        }
                        title="Demote to member"
                      >
                        <ArrowDownCircle className="h-4 w-4" />
                      </Button>
                    )}
                  </>
                )}
                {isModOrAdmin && member.role !== "admin" && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-destructive"
                    onClick={() => removeMut.mutate(member.user_id)}
                    title="Remove member"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Pending requests (admin/mod) */}
      {isModOrAdmin && pendingQuery.data && pendingQuery.data.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Pending Requests</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {pendingQuery.data.map((pending) => (
              <div
                key={pending.user_id}
                className="flex items-center justify-between py-2"
              >
                <div className="flex items-center gap-2">
                  <span className="font-medium">
                    {pending.display_name || pending.user_id}
                  </span>
                  <Badge variant="outline" className="text-xs">
                    {pending.status === "invited" ? "Invited" : "Requesting"}
                  </Badge>
                </div>
                {pending.status === "pending_approval" && (
                  <div className="flex gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        reviewMut.mutate({
                          userId: pending.user_id,
                          approved: true,
                        })
                      }
                    >
                      <Check className="h-4 w-4 text-green-600" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        reviewMut.mutate({
                          userId: pending.user_id,
                          approved: false,
                        })
                      }
                    >
                      <X className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Danger zone */}
      {isAdmin && (
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
          </CardHeader>
          <CardContent>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive">Dissolve Group</Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Dissolve Group?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will permanently dissolve "{group.name}" and remove all
                    members. This action cannot be undone.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => dissolveMut.mutate()}
                    className="bg-destructive text-destructive-foreground"
                  >
                    Dissolve
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
