import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Handshake, Plus } from "lucide-react";
import {
  listCollaborations,
  acceptCollaboration,
  rejectCollaboration,
  cancelCollaboration,
  terminateCollaboration,
  getCollabSettings,
  updateCollabSettings,
  createCollaboration,
  getCollabRevisions,
} from "@/api/endpoints/collaborations";
import type {
  CollaborationOut,
  CollaborationSettingsIn,
  CollaborationCreateIn,
  CollaborationRevisionOut,
} from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

function statusBadgeVariant(status: string) {
  switch (status) {
    case "accepted": return "default";
    case "pending": return "secondary";
    case "counter": return "outline";
    case "rejected":
    case "cancelled":
    case "terminated":
    case "expired": return "destructive";
    default: return "secondary";
  }
}

export default function CollaborationsPage() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"active" | "pending" | "history">("active");
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedCollab, setSelectedCollab] = useState<CollaborationOut | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const activeQuery = useQuery({
    queryKey: ["collaborations", "active"],
    queryFn: () => listCollaborations({ status: "accepted" }),
  });

  const pendingQuery = useQuery({
    queryKey: ["collaborations", "pending"],
    queryFn: () => listCollaborations({ status: "pending,counter" }),
  });

  const historyQuery = useQuery({
    queryKey: ["collaborations", "history"],
    queryFn: () => listCollaborations({ status: "rejected,cancelled,terminated,expired" }),
  });

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ["collaborations"] });
  };

  const acceptMut = useMutation({
    mutationFn: (id: string) => acceptCollaboration(id),
    onSuccess: () => { toast.success("Collaboration accepted"); invalidateAll(); },
  });

  const rejectMut = useMutation({
    mutationFn: (id: string) => rejectCollaboration(id),
    onSuccess: () => { toast.success("Collaboration rejected"); invalidateAll(); },
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelCollaboration(id),
    onSuccess: () => { toast.success("Collaboration cancelled"); invalidateAll(); },
  });

  const terminateMut = useMutation({
    mutationFn: (id: string) => terminateCollaboration(id),
    onSuccess: () => { toast.success("Collaboration terminated"); invalidateAll(); },
  });

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Handshake className="h-7 w-7 text-primary" />
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Collaborations</h1>
            <p className="text-sm text-muted-foreground">Manage creator partnerships and revenue splits</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setSettingsOpen(true)}>Settings</Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New Collaboration
          </Button>
        </div>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)}>
        <TabsList>
          <TabsTrigger value="active">
            Active {activeQuery.data?.items?.length ? `(${activeQuery.data.items.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="pending">
            Pending {pendingQuery.data?.items?.length ? `(${pendingQuery.data.items.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="active" className="mt-4 space-y-4">
          {activeQuery.data?.items?.length === 0 && (
            <p className="text-center text-sm text-muted-foreground py-8">No active collaborations yet.</p>
          )}
          {activeQuery.data?.items?.map((c) => (
            <CollabCard key={c.collaboration_id} collab={c} onSelect={setSelectedCollab} onTerminate={(id) => terminateMut.mutate(id)} />
          ))}
        </TabsContent>

        <TabsContent value="pending" className="mt-4 space-y-4">
          {pendingQuery.data?.items?.length === 0 && (
            <p className="text-center text-sm text-muted-foreground py-8">No pending requests.</p>
          )}
          {pendingQuery.data?.items?.map((c) => (
            <CollabCard
              key={c.collaboration_id}
              collab={c}
              onSelect={setSelectedCollab}
              onAccept={(id) => acceptMut.mutate(id)}
              onReject={(id) => rejectMut.mutate(id)}
              onCancel={(id) => cancelMut.mutate(id)}
            />
          ))}
        </TabsContent>

        <TabsContent value="history" className="mt-4 space-y-4">
          {historyQuery.data?.items?.length === 0 && (
            <p className="text-center text-sm text-muted-foreground py-8">No past collaborations.</p>
          )}
          {historyQuery.data?.items?.map((c) => (
            <CollabCard key={c.collaboration_id} collab={c} onSelect={setSelectedCollab} />
          ))}
        </TabsContent>
      </Tabs>

      <CreateCollaborationDialog open={createOpen} onOpenChange={setCreateOpen} onCreated={invalidateAll} />
      {selectedCollab && (
        <CollaborationDetailDialog
          collab={selectedCollab}
          open={!!selectedCollab}
          onOpenChange={() => setSelectedCollab(null)}
        />
      )}
      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
    </div>
  );
}

// ─── Collab Card ──────────────────────────────────────────────────

interface CollabCardProps {
  collab: CollaborationOut;
  onSelect: (c: CollaborationOut) => void;
  onAccept?: (id: string) => void;
  onReject?: (id: string) => void;
  onCancel?: (id: string) => void;
  onTerminate?: (id: string) => void;
}

function CollabCard({ collab, onSelect, onAccept, onReject, onCancel, onTerminate }: CollabCardProps) {
  const splitEntries = Object.entries(collab.split);
  return (
    <Card className="cursor-pointer hover:border-primary/40 transition-colors" onClick={() => onSelect(collab)}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">{collab.title}</CardTitle>
          <Badge variant={statusBadgeVariant(collab.status)}>{collab.status}</Badge>
        </div>
        <CardDescription className="text-xs">
          {collab.content_types.join(", ")} &middot; Rev {collab.revision}
          {collab.total_revenue_cents > 0 && ` · $${(collab.total_revenue_cents / 100).toFixed(2)} earned`}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Split: {splitEntries.map(([uid, pct]) => `${uid.slice(0, 8)}...=${pct}%`).join(", ")}
        </div>
        <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
          {onAccept && (collab.status === "pending" || collab.status === "counter") && (
            <Button size="sm" variant="default" onClick={() => onAccept(collab.collaboration_id)}>Accept</Button>
          )}
          {onReject && (collab.status === "pending" || collab.status === "counter") && (
            <Button size="sm" variant="outline" onClick={() => onReject(collab.collaboration_id)}>Reject</Button>
          )}
          {onCancel && (collab.status === "pending" || collab.status === "counter") && (
            <Button size="sm" variant="ghost" onClick={() => onCancel(collab.collaboration_id)}>Cancel</Button>
          )}
          {onTerminate && collab.status === "accepted" && (
            <Button size="sm" variant="destructive" onClick={() => onTerminate(collab.collaboration_id)}>Terminate</Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Create Dialog ────────────────────────────────────────────────

function CreateCollaborationDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCreated: () => void;
}) {
  const [recipientId, setRecipientId] = useState("");
  const [title, setTitle] = useState("");
  const [splitPct, setSplitPct] = useState(60);
  const [contentTypes] = useState<string[]>(["broadcast", "post"]);

  const createMut = useMutation({
    mutationFn: (data: CollaborationCreateIn) => createCollaboration(data),
    onSuccess: () => {
      toast.success("Collaboration request sent");
      onOpenChange(false);
      onCreated();
    },
    onError: (err: any) => {
      toast.error(err?.message || "Failed to create collaboration");
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Collaboration</DialogTitle>
          <DialogDescription>Propose a collaboration with another creator.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="recipient">Recipient User ID</Label>
            <Input id="recipient" value={recipientId} onChange={(e) => setRecipientId(e.target.value)} placeholder="user_id" />
          </div>
          <div>
            <Label htmlFor="title">Title</Label>
            <Input id="title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Summer Collab" />
          </div>
          <div>
            <Label htmlFor="split">Your Split %</Label>
            <Input id="split" type="number" value={splitPct} onChange={(e) => setSplitPct(Number(e.target.value))} min={1} max={99} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={() => createMut.mutate({ recipient_id: recipientId, title, split_pct: splitPct, content_types: contentTypes })}
            disabled={!recipientId || !title || createMut.isPending}
          >
            Send Proposal
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Detail Dialog ────────────────────────────────────────────────

function CollaborationDetailDialog({
  collab,
  open,
  onOpenChange,
}: {
  collab: CollaborationOut;
  open: boolean;
  onOpenChange: () => void;
}) {
  const revisionsQuery = useQuery({
    queryKey: ["collab-revisions", collab.collaboration_id],
    queryFn: () => getCollabRevisions(collab.collaboration_id),
    enabled: open,
  });

  return (
    <Dialog open={open} onOpenChange={() => onOpenChange()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{collab.title}</DialogTitle>
          <DialogDescription>Collaboration details and revision history</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 text-sm">
          <p><strong>Status:</strong> {collab.status}</p>
          <p><strong>Initiator:</strong> {collab.initiator_id}</p>
          <p><strong>Recipient:</strong> {collab.recipient_id}</p>
          <p><strong>Content types:</strong> {collab.content_types.join(", ")}</p>
          <p><strong>Split:</strong> {Object.entries(collab.split).map(([k, v]) => `${k}: ${v}%`).join(", ")}</p>
          <p><strong>Revenue:</strong> ${(collab.total_revenue_cents / 100).toFixed(2)}</p>
          {collab.description && <p><strong>Description:</strong> {collab.description}</p>}
          {collab.terms_text && <p><strong>Terms:</strong> {collab.terms_text}</p>}
          <p><strong>Revision:</strong> {collab.revision}</p>

          {revisionsQuery.data && revisionsQuery.data.length > 0 && (
            <div>
              <h4 className="font-semibold mt-4 mb-2">Revision History</h4>
              {revisionsQuery.data.map((rev: CollaborationRevisionOut) => (
                <div key={rev.revision} className="border rounded p-2 mb-2 text-xs">
                  <p>Rev {rev.revision} by {rev.proposed_by}</p>
                  <p>Split: {Object.entries(rev.split).map(([k, v]) => `${k}: ${v}%`).join(", ")}</p>
                  <p>Status: {rev.status}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Settings Dialog ──────────────────────────────────────────────

function SettingsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const queryClient = useQueryClient();
  const settingsQuery = useQuery({
    queryKey: ["collab-settings"],
    queryFn: () => getCollabSettings(),
    enabled: open,
  });

  const updateMut = useMutation({
    mutationFn: (data: CollaborationSettingsIn) => updateCollabSettings(data),
    onSuccess: () => {
      toast.success("Settings updated");
      queryClient.invalidateQueries({ queryKey: ["collab-settings"] });
    },
  });

  const settings = settingsQuery.data;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Collaboration Settings</DialogTitle>
          <DialogDescription>Configure your collaboration preferences.</DialogDescription>
        </DialogHeader>
        {settings && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <Label>Accepting Requests</Label>
              <Button
                size="sm"
                variant={settings.accepting_requests ? "default" : "outline"}
                onClick={() => updateMut.mutate({ accepting_requests: !settings.accepting_requests })}
              >
                {settings.accepting_requests ? "Yes" : "No"}
              </Button>
            </div>
            <div>
              <Label>Minimum Split %</Label>
              <p className="text-sm text-muted-foreground">{settings.min_split_pct}%</p>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
