import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Bot, Plus, Pause, Play, Trash2, Settings2, Power } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  listBots,
  createBot,
  updateBot,
  updateBotStatus,
  deleteBot,
} from "@/api/endpoints/bots";
import type { ChatBot } from "@/api/types";

function statusBadge(status: string) {
  switch (status) {
    case "active":
      return <Badge variant="default" className="bg-green-600">Active</Badge>;
    case "paused":
      return <Badge variant="secondary" className="bg-yellow-500 text-black">Paused</Badge>;
    case "disabled":
      return <Badge variant="outline">Disabled</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

export default function BotManagerPage() {
  const queryClient = useQueryClient();
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingBot, setEditingBot] = useState<ChatBot | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ChatBot | null>(null);

  // Form state
  const [formName, setFormName] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formPersonality, setFormPersonality] = useState("friendly");
  const [formCustomPersonality, setFormCustomPersonality] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["bots"],
    queryFn: listBots,
  });

  const createMut = useMutation({
    mutationFn: (d: { name: string; description?: string; personality?: string; custom_personality?: string }) =>
      createBot(d),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bots"] });
      toast.success("Bot created");
      setEditorOpen(false);
      resetForm();
    },
    onError: () => toast.error("Failed to create bot"),
  });

  const updateMut = useMutation({
    mutationFn: ({ botId, data: d }: { botId: string; data: Partial<ChatBot> }) =>
      updateBot(botId, d),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bots"] });
      toast.success("Bot updated");
      setEditorOpen(false);
      resetForm();
    },
    onError: () => toast.error("Failed to update bot"),
  });

  const statusMut = useMutation({
    mutationFn: ({ botId, status }: { botId: string; status: string }) =>
      updateBotStatus(botId, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bots"] });
      toast.success("Bot status updated");
    },
    onError: () => toast.error("Failed to update status"),
  });

  const deleteMut = useMutation({
    mutationFn: (botId: string) => deleteBot(botId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bots"] });
      toast.success("Bot deleted");
      setDeleteTarget(null);
    },
    onError: () => toast.error("Failed to delete bot"),
  });

  function resetForm() {
    setFormName("");
    setFormDescription("");
    setFormPersonality("friendly");
    setFormCustomPersonality("");
    setEditingBot(null);
  }

  function openCreate() {
    resetForm();
    setEditorOpen(true);
  }

  function openEdit(bot: ChatBot) {
    setEditingBot(bot);
    setFormName(bot.name);
    setFormDescription(bot.description || "");
    setFormPersonality(bot.personality || "friendly");
    setFormCustomPersonality(bot.custom_personality || "");
    setEditorOpen(true);
  }

  function handleSave() {
    const payload = {
      name: formName,
      description: formDescription || undefined,
      personality: formPersonality,
      custom_personality: formPersonality === "custom" ? formCustomPersonality : undefined,
    };
    if (editingBot) {
      updateMut.mutate({
        botId: editingBot.bot_id,
        data: payload as Partial<ChatBot>,
      });
    } else {
      createMut.mutate(payload);
    }
  }

  const bots = data?.bots ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6" data-testid="bot-manager-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bot className="h-7 w-7" />
          <h1 className="text-2xl font-bold">Chat Bots</h1>
          {bots.length > 0 && (
            <Badge variant="secondary">{bots.length} bot{bots.length !== 1 ? "s" : ""}</Badge>
          )}
        </div>
        <Button onClick={openCreate} data-testid="create-bot-btn">
          <Plus className="mr-2 h-4 w-4" />
          New Bot
        </Button>
      </div>

      {isLoading && <p className="text-muted-foreground">Loading...</p>}

      {!isLoading && bots.length === 0 && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Bot className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-lg font-medium">No bots yet</p>
            <p className="text-muted-foreground mb-4">Create your first bot to automate conversations.</p>
            <Button onClick={openCreate}>Create your first bot</Button>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {bots.map((bot) => (
          <Card key={bot.bot_id} data-testid={`bot-card-${bot.bot_id}`}>
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                    <Bot className="h-5 w-5" />
                  </div>
                  <div>
                    <CardTitle className="text-base">{bot.name}</CardTitle>
                    <div className="flex items-center gap-2 mt-1">
                      {statusBadge(bot.status)}
                      <Badge variant="outline" className="text-xs">{bot.personality}</Badge>
                    </div>
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {bot.description && (
                <p className="text-sm text-muted-foreground line-clamp-2">{bot.description}</p>
              )}
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>{bot.message_count} messages</span>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => openEdit(bot)}>
                  <Settings2 className="mr-1 h-3 w-3" /> Edit
                </Button>
                {bot.status === "active" && (
                  <Button
                    size="sm"
                    variant="outline"
                    data-testid={`pause-bot-${bot.bot_id}`}
                    onClick={() => statusMut.mutate({ botId: bot.bot_id, status: "paused" })}
                  >
                    <Pause className="mr-1 h-3 w-3" /> Pause
                  </Button>
                )}
                {bot.status === "paused" && (
                  <Button
                    size="sm"
                    variant="outline"
                    data-testid={`resume-bot-${bot.bot_id}`}
                    onClick={() => statusMut.mutate({ botId: bot.bot_id, status: "active" })}
                  >
                    <Play className="mr-1 h-3 w-3" /> Resume
                  </Button>
                )}
                {bot.status === "disabled" && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => statusMut.mutate({ botId: bot.bot_id, status: "active" })}
                  >
                    <Power className="mr-1 h-3 w-3" /> Enable
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => setDeleteTarget(bot)}
                >
                  <Trash2 className="mr-1 h-3 w-3" /> Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Editor Dialog */}
      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent data-testid="bot-editor-dialog">
          <DialogHeader>
            <DialogTitle>{editingBot ? "Edit Bot" : "New Bot"}</DialogTitle>
            <DialogDescription>
              {editingBot ? "Update your bot's configuration." : "Create a new chat bot."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="bot-name">Name</Label>
              <Input
                id="bot-name"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="e.g. Welcome Bot"
                maxLength={50}
                data-testid="bot-name-input"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="bot-description">Description</Label>
              <Textarea
                id="bot-description"
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="What does this bot do?"
                maxLength={500}
                data-testid="bot-description-input"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="bot-personality">Personality</Label>
              <Select value={formPersonality} onValueChange={setFormPersonality}>
                <SelectTrigger id="bot-personality" data-testid="bot-personality-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="friendly">Friendly</SelectItem>
                  <SelectItem value="professional">Professional</SelectItem>
                  <SelectItem value="casual">Casual</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {formPersonality === "custom" && (
              <div className="space-y-2">
                <Label htmlFor="bot-custom-personality">Custom Personality Instructions</Label>
                <Textarea
                  id="bot-custom-personality"
                  value={formCustomPersonality}
                  onChange={(e) => setFormCustomPersonality(e.target.value)}
                  placeholder="Describe how the bot should behave..."
                  maxLength={2000}
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditorOpen(false)}>Cancel</Button>
            <Button
              onClick={handleSave}
              disabled={!formName.trim()}
              data-testid="bot-save-btn"
            >
              {editingBot ? "Save Changes" : "Create Bot"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      {deleteTarget && (
        <ConfirmDialog
          open={!!deleteTarget}
          onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
          title="Delete Bot"
          description={`Are you sure you want to delete "${deleteTarget.name}"? This action cannot be undone.`}
          confirmLabel="Delete"
          variant="danger"
          onConfirm={() => deleteMut.mutate(deleteTarget.bot_id)}
        />
      )}
    </div>
  );
}
