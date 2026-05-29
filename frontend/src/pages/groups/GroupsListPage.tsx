import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Users, Plus, Search, Globe, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/components/ui/use-toast";
import { listMyGroups, discoverGroups, joinGroup } from "@/api/endpoints/groups";
import type { UserGroup } from "@/api/types";
import CreateGroupDialog from "./CreateGroupDialog";

function roleBadgeVariant(role?: string) {
  switch (role) {
    case "admin":
      return "default" as const;
    case "moderator":
      return "secondary" as const;
    default:
      return "outline" as const;
  }
}

function GroupCard({ group }: { group: UserGroup }) {
  return (
    <Link to={`/groups/${group.group_id}/settings`}>
      <Card className="hover:bg-accent/50 transition-colors">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                <Users className="h-5 w-5 text-primary" />
              </div>
              <div className="min-w-0">
                <p className="font-semibold truncate">{group.name}</p>
                <p className="text-sm text-muted-foreground truncate">
                  {group.member_count} member{group.member_count !== 1 ? "s" : ""}
                  {group.topic ? ` · ${group.topic}` : ""}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {group.visibility === "private" ? (
                <Lock className="h-4 w-4 text-muted-foreground" />
              ) : (
                <Globe className="h-4 w-4 text-muted-foreground" />
              )}
              {group.my_role && (
                <Badge variant={roleBadgeVariant(group.my_role)}>
                  {group.my_role}
                </Badge>
              )}
            </div>
          </div>
          {group.description && (
            <p className="mt-2 text-sm text-muted-foreground line-clamp-2">
              {group.description}
            </p>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}

function DiscoverCard({
  group,
  onJoin,
  isJoining,
}: {
  group: UserGroup;
  onJoin: (id: string) => void;
  isJoining: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
              <Users className="h-5 w-5 text-primary" />
            </div>
            <div className="min-w-0">
              <p className="font-semibold truncate">{group.name}</p>
              <p className="text-sm text-muted-foreground truncate">
                {group.member_count} member{group.member_count !== 1 ? "s" : ""}
                {group.topic && (
                  <Badge variant="outline" className="ml-2 text-xs">
                    {group.topic}
                  </Badge>
                )}
              </p>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => onJoin(group.group_id)}
            disabled={isJoining}
          >
            {group.visibility === "private" ? "Request" : "Join"}
          </Button>
        </div>
        {group.description && (
          <p className="mt-2 text-sm text-muted-foreground line-clamp-2">
            {group.description}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export default function GroupsListPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const myGroupsQuery = useQuery({
    queryKey: ["groups", "my"],
    queryFn: () => listMyGroups().then((r) => r.data),
    staleTime: 30_000,
  });

  const discoverQuery = useQuery({
    queryKey: ["groups", "discover", searchQuery],
    queryFn: () =>
      discoverGroups({
        query: searchQuery || undefined,
        limit: 50,
      }).then((r) => r.data),
    staleTime: 60_000,
  });

  const joinMut = useMutation({
    mutationFn: (groupId: string) => joinGroup(groupId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["groups"] });
      toast({ title: "Joined group successfully" });
    },
    onError: (err: any) => {
      toast({
        title: "Could not join group",
        description: err?.response?.data?.detail || "Unknown error",
        variant: "destructive",
      });
    },
  });

  return (
    <div className="container max-w-3xl py-6 space-y-6" data-testid="groups-list-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Groups</h1>
          <p className="text-muted-foreground">
            Create and join communities
          </p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Create Group
        </Button>
      </div>

      <Tabs defaultValue="my-groups">
        <TabsList>
          <TabsTrigger value="my-groups">My Groups</TabsTrigger>
          <TabsTrigger value="discover">Discover</TabsTrigger>
        </TabsList>

        <TabsContent value="my-groups" className="space-y-3 mt-4">
          {myGroupsQuery.isLoading && (
            <p className="text-muted-foreground text-center py-8">Loading...</p>
          )}
          {myGroupsQuery.data && myGroupsQuery.data.length === 0 && (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                You haven't joined any groups yet.
              </CardContent>
            </Card>
          )}
          {myGroupsQuery.data?.map((group) => (
            <GroupCard key={group.group_id} group={group} />
          ))}
        </TabsContent>

        <TabsContent value="discover" className="space-y-3 mt-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-10"
              placeholder="Search groups by name or topic..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          {discoverQuery.isLoading && (
            <p className="text-muted-foreground text-center py-8">Loading...</p>
          )}
          {discoverQuery.data?.groups?.length === 0 && (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                No public groups found.
              </CardContent>
            </Card>
          )}
          {discoverQuery.data?.groups?.map((group) => (
            <DiscoverCard
              key={group.group_id}
              group={group}
              onJoin={(id) => joinMut.mutate(id)}
              isJoining={joinMut.isPending}
            />
          ))}
        </TabsContent>
      </Tabs>

      <CreateGroupDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => {
          queryClient.invalidateQueries({ queryKey: ["groups"] });
        }}
      />
    </div>
  );
}
