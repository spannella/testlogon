import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Users, Plus, Search, Globe, Lock } from "lucide-react";
import { listMyGroups, discoverGroups, createGroup, joinGroup } from "@/api/endpoints/groups";
import type { UserGroup } from "@/api/types";

export default function GroupsListPage() {
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [createOpen, setCreateOpen] = useState(false);

  const { data: myGroups } = useQuery({
    queryKey: ["my-groups"],
    queryFn: () => listMyGroups(),
    staleTime: 30_000,
  });

  const { data: publicGroups } = useQuery({
    queryKey: ["discover-groups", searchQuery],
    queryFn: () => discoverGroups({ query: searchQuery }),
    staleTime: 60_000,
  });

  return (
    <div className="max-w-3xl mx-auto p-4 space-y-4" data-testid="groups-list-page">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Groups</h1>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-1" /> Create Group
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Group</DialogTitle>
            </DialogHeader>
            <CreateGroupForm
              onCreated={() => {
                setCreateOpen(false);
                queryClient.invalidateQueries({ queryKey: ["my-groups"] });
              }}
            />
          </DialogContent>
        </Dialog>
      </div>

      <Tabs defaultValue="my-groups">
        <TabsList>
          <TabsTrigger value="my-groups">My Groups</TabsTrigger>
          <TabsTrigger value="discover">Discover</TabsTrigger>
        </TabsList>

        <TabsContent value="my-groups" className="space-y-3 mt-4">
          {(myGroups as any)?.groups?.length === 0 && (
            <p className="text-muted-foreground text-center py-8">
              You haven't joined any groups yet.
            </p>
          )}
          {(myGroups as any)?.groups?.map((group: UserGroup) => (
            <GroupCard key={group.group_id} group={group} />
          ))}
        </TabsContent>

        <TabsContent value="discover" className="space-y-3 mt-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search groups..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          {(publicGroups as any)?.groups?.map((group: UserGroup) => (
            <DiscoverGroupCard
              key={group.group_id}
              group={group}
              onJoined={() => {
                queryClient.invalidateQueries({ queryKey: ["my-groups"] });
                queryClient.invalidateQueries({ queryKey: ["discover-groups"] });
              }}
            />
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function GroupCard({ group }: { group: UserGroup }) {
  return (
    <Link to={`/groups/${group.group_id}`}>
      <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
        <CardContent className="py-3 flex items-center justify-between">
          <div>
            <p className="font-medium">{group.name}</p>
            <p className="text-sm text-muted-foreground line-clamp-1">
              {group.description}
            </p>
            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
              <Users className="h-3 w-3" />
              <span>{group.member_count} members</span>
              {group.my_role && <Badge variant="outline" className="text-xs">{group.my_role}</Badge>}
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

function DiscoverGroupCard({
  group,
  onJoined,
}: {
  group: UserGroup;
  onJoined: () => void;
}) {
  const joinMut = useMutation({
    mutationFn: () => joinGroup(group.group_id),
    onSuccess: onJoined,
  });

  return (
    <Card>
      <CardContent className="py-3 flex items-center justify-between">
        <div>
          <p className="font-medium">{group.name}</p>
          <p className="text-sm text-muted-foreground line-clamp-1">
            {group.description}
          </p>
          <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
            <Users className="h-3 w-3" />
            <span>{group.member_count} members</span>
            {group.topic && <Badge variant="secondary" className="text-xs">{group.topic}</Badge>}
          </div>
        </div>
        <Button
          size="sm"
          onClick={() => joinMut.mutate()}
          disabled={joinMut.isPending}
        >
          {group.visibility === "public" ? "Join" : "Request"}
        </Button>
      </CardContent>
    </Card>
  );
}

function CreateGroupForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [visibility, setVisibility] = useState<"public" | "private">("public");
  const [topic, setTopic] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createGroup({ name, description, visibility, topic: topic || undefined }),
    onSuccess: onCreated,
  });

  return (
    <div className="space-y-3">
      <Input
        placeholder="Group name"
        value={name}
        onChange={(e) => setName(e.target.value)}
      />
      <Textarea
        placeholder="Description"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        rows={3}
      />
      <Input
        placeholder="Topic (optional)"
        value={topic}
        onChange={(e) => setTopic(e.target.value)}
      />
      <div className="flex gap-2">
        <Button
          variant={visibility === "public" ? "default" : "outline"}
          size="sm"
          onClick={() => setVisibility("public")}
        >
          <Globe className="h-3 w-3 mr-1" /> Public
        </Button>
        <Button
          variant={visibility === "private" ? "default" : "outline"}
          size="sm"
          onClick={() => setVisibility("private")}
        >
          <Lock className="h-3 w-3 mr-1" /> Private
        </Button>
      </div>
      <Button
        className="w-full"
        onClick={() => createMut.mutate()}
        disabled={!name.trim() || name.length < 3 || createMut.isPending}
      >
        Create Group
      </Button>
    </div>
  );
}
