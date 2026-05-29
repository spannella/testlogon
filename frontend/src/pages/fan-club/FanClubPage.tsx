import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Trash2, Hash, Send } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
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
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageHeader } from "@/components/shared/PageHeader";
import { MemberBadge } from "@/components/shared/MemberBadge";
import {
  listTiers,
  createTier,
  deleteTier,
  listChannels,
  createChannel,
  sendChannelMessage,
  getChannelMessages,
} from "@/api/endpoints/fan-club";
import type { TierOut, ChannelOut, ChannelMessageOut } from "@/api/types";

// ─── Tier Card ──────────────────────────────────────────────────

function TierCard({
  tier,
  onDelete,
}: {
  tier: TierOut;
  onDelete: (id: string) => void;
}) {
  return (
    <Card data-testid={`tier-card-${tier.tier_id}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MemberBadge
              badge={{
                tier_name: tier.name,
                tier_level: tier.level,
                badge_emoji: tier.badge_emoji,
                badge_color: tier.color,
              }}
              size="md"
            />
            <CardTitle className="text-lg">{tier.name}</CardTitle>
          </div>
          <div className="flex items-center gap-1">
            <Badge variant="outline">Level {tier.level}</Badge>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8">
                  <Trash2 className="h-4 w-4" />
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Archive tier</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will archive the &quot;{tier.name}&quot; tier. Existing
                    members will retain access until their subscription expires.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={() => onDelete(tier.tier_id)}>
                    Archive
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {tier.description && (
          <p className="text-sm text-muted-foreground">{tier.description}</p>
        )}
        {tier.benefits && tier.benefits.length > 0 && (
          <ul className="mt-2 space-y-1">
            {tier.benefits.map((b, i) => (
              <li key={i} className="text-xs text-muted-foreground">
                {b.type}
                {b.label ? `: ${b.label}` : ""}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
      <CardFooter className="text-xs text-muted-foreground">
        {tier.member_count} member{tier.member_count !== 1 ? "s" : ""}
      </CardFooter>
    </Card>
  );
}

// ─── Channel Card ──────────────────────────────────────────────

function ChannelCard({
  channel,
  onSelect,
}: {
  channel: ChannelOut;
  onSelect: (ch: ChannelOut) => void;
}) {
  return (
    <Card
      className="cursor-pointer hover:bg-accent/50 transition-colors"
      onClick={() => onSelect(channel)}
      data-testid={`channel-card-${channel.channel_id}`}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Hash className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-base">{channel.name}</CardTitle>
          <Badge variant="secondary" className="ml-auto">
            Tier {channel.min_tier_level}+
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {channel.description && (
          <p className="text-sm text-muted-foreground">
            {channel.description}
          </p>
        )}
        <p className="mt-1 text-xs text-muted-foreground">
          {channel.message_count} message
          {channel.message_count !== 1 ? "s" : ""}
        </p>
      </CardContent>
    </Card>
  );
}

// ─── Channel Chat View ─────────────────────────────────────────

function ChannelChatView({
  channel,
  onBack,
}: {
  channel: ChannelOut;
  onBack: () => void;
}) {
  const [text, setText] = useState("");
  const queryClient = useQueryClient();

  const { data: messages = [], isLoading } = useQuery<ChannelMessageOut[]>({
    queryKey: ["fan-club", "channel-messages", channel.channel_id],
    queryFn: () => getChannelMessages(channel.channel_id),
    refetchInterval: 5000,
  });

  const sendMut = useMutation({
    mutationFn: (msg: string) =>
      sendChannelMessage(channel.channel_id, msg),
    onSuccess: () => {
      setText("");
      queryClient.invalidateQueries({
        queryKey: ["fan-club", "channel-messages", channel.channel_id],
      });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const sorted = [...messages].sort(
    (a, b) => a.created_at - b.created_at,
  );

  return (
    <div className="flex flex-col h-[500px]">
      <div className="flex items-center gap-2 border-b px-4 py-2">
        <Button variant="ghost" size="sm" onClick={onBack}>
          Back
        </Button>
        <Hash className="h-4 w-4" />
        <span className="font-semibold">{channel.name}</span>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-10 w-3/4" />
            <Skeleton className="h-10 w-1/2" />
          </div>
        ) : sorted.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No messages yet. Start the conversation!
          </p>
        ) : (
          sorted.map((m) => (
            <div key={m.message_id} className="flex flex-col gap-0.5">
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-medium">
                  {m.sender_display_name}
                </span>
                {m.sender_badge && (
                  <MemberBadge badge={m.sender_badge} size="xs" />
                )}
                <span className="text-xs text-muted-foreground">
                  {new Date(m.created_at * 1000).toLocaleTimeString()}
                </span>
              </div>
              <p className="text-sm">{m.text}</p>
            </div>
          ))
        )}
      </div>
      <form
        className="border-t p-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (text.trim()) sendMut.mutate(text.trim());
        }}
      >
        <Input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Type a message..."
          className="flex-1"
        />
        <Button type="submit" size="icon" disabled={!text.trim()}>
          <Send className="h-4 w-4" />
        </Button>
      </form>
    </div>
  );
}

// ─── Create Tier Dialog ────────────────────────────────────────

function CreateTierDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [level, setLevel] = useState("1");
  const [color, setColor] = useState("#3B82F6");
  const [emoji, setEmoji] = useState("");
  const [description, setDescription] = useState("");
  const [planId, setPlanId] = useState("");

  const createMut = useMutation({
    mutationFn: () =>
      createTier({
        plan_id: planId,
        name,
        level: parseInt(level, 10),
        color,
        badge_emoji: emoji || undefined,
        description: description || undefined,
        benefits: [{ type: "badge", display: true }],
      }),
    onSuccess: () => {
      toast.success("Tier created");
      setOpen(false);
      setName("");
      setLevel("1");
      setColor("#3B82F6");
      setEmoji("");
      setDescription("");
      setPlanId("");
      onCreated();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Create Tier
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Tier</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="tier-plan-id">Plan ID</Label>
            <Input
              id="tier-plan-id"
              value={planId}
              onChange={(e) => setPlanId(e.target.value)}
              placeholder="plan_..."
            />
          </div>
          <div>
            <Label htmlFor="tier-name">Name</Label>
            <Input
              id="tier-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. VIP"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="tier-level">Level</Label>
              <Input
                id="tier-level"
                type="number"
                value={level}
                onChange={(e) => setLevel(e.target.value)}
                min={1}
              />
            </div>
            <div>
              <Label htmlFor="tier-color">Color</Label>
              <Input
                id="tier-color"
                type="color"
                value={color}
                onChange={(e) => setColor(e.target.value)}
              />
            </div>
          </div>
          <div>
            <Label htmlFor="tier-emoji">Badge Emoji</Label>
            <Input
              id="tier-emoji"
              value={emoji}
              onChange={(e) => setEmoji(e.target.value)}
              placeholder="e.g. star"
            />
          </div>
          <div>
            <Label htmlFor="tier-desc">Description</Label>
            <Textarea
              id="tier-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe this tier..."
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!name || !planId || createMut.isPending}
          >
            {createMut.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Create Channel Dialog ─────────────────────────────────────

function CreateChannelDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [minLevel, setMinLevel] = useState("1");

  const createMut = useMutation({
    mutationFn: () =>
      createChannel({
        name,
        description: desc || undefined,
        min_tier_level: parseInt(minLevel, 10),
      }),
    onSuccess: () => {
      toast.success("Channel created");
      setOpen(false);
      setName("");
      setDesc("");
      setMinLevel("1");
      onCreated();
    },
    onError: (err: Error) => toast.error(err.message),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Plus className="mr-2 h-4 w-4" /> Create Channel
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Channel</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="ch-name">Name</Label>
            <Input
              id="ch-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. VIP Lounge"
            />
          </div>
          <div>
            <Label htmlFor="ch-desc">Description</Label>
            <Textarea
              id="ch-desc"
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder="Channel description..."
            />
          </div>
          <div>
            <Label htmlFor="ch-level">Minimum Tier Level</Label>
            <Input
              id="ch-level"
              type="number"
              value={minLevel}
              onChange={(e) => setMinLevel(e.target.value)}
              min={1}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!name || createMut.isPending}
          >
            {createMut.isPending ? "Creating..." : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page ────────────────────────────────────────────────

export default function FanClubPage() {
  const queryClient = useQueryClient();
  const [selectedChannel, setSelectedChannel] = useState<ChannelOut | null>(
    null,
  );

  const {
    data: tiers = [],
    isLoading: tiersLoading,
  } = useQuery<TierOut[]>({
    queryKey: ["fan-club", "tiers"],
    queryFn: listTiers,
  });

  const {
    data: channels = [],
    isLoading: channelsLoading,
  } = useQuery<ChannelOut[]>({
    queryKey: ["fan-club", "channels"],
    queryFn: () => listChannels(),
  });

  const deleteMut = useMutation({
    mutationFn: deleteTier,
    onSuccess: () => {
      toast.success("Tier archived");
      queryClient.invalidateQueries({ queryKey: ["fan-club", "tiers"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["fan-club"] });
  };

  return (
    <div className="space-y-6 p-4 md:p-6">
      <PageHeader
        title="Fan Club"
        description="Manage membership tiers and exclusive channels"
      />

      <Tabs defaultValue="tiers">
        <TabsList>
          <TabsTrigger value="tiers">Tiers</TabsTrigger>
          <TabsTrigger value="channels">Channels</TabsTrigger>
        </TabsList>

        {/* ─── Tiers Tab ─── */}
        <TabsContent value="tiers" className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Membership Tiers</h2>
            <CreateTierDialog onCreated={handleRefresh} />
          </div>

          {tiersLoading ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-48 w-full" />
              ))}
            </div>
          ) : tiers.length === 0 ? (
            <EmptyState
              title="No tiers yet"
              description="Create your first membership tier to start building your fan club."
            />
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {tiers.map((t) => (
                <TierCard
                  key={t.tier_id}
                  tier={t}
                  onDelete={(id) => deleteMut.mutate(id)}
                />
              ))}
            </div>
          )}
        </TabsContent>

        {/* ─── Channels Tab ─── */}
        <TabsContent value="channels" className="space-y-4">
          {selectedChannel ? (
            <ChannelChatView
              channel={selectedChannel}
              onBack={() => setSelectedChannel(null)}
            />
          ) : (
            <>
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Exclusive Channels</h2>
                <CreateChannelDialog onCreated={handleRefresh} />
              </div>

              {channelsLoading ? (
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  {[1, 2].map((i) => (
                    <Skeleton key={i} className="h-32 w-full" />
                  ))}
                </div>
              ) : channels.length === 0 ? (
                <EmptyState
                  title="No channels yet"
                  description="Create an exclusive channel for your fan club members."
                />
              ) : (
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  {channels.map((ch) => (
                    <ChannelCard
                      key={ch.channel_id}
                      channel={ch}
                      onSelect={setSelectedChannel}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
