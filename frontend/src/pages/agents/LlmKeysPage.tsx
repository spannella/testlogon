import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { KeyRound, Plus, MoreHorizontal, FlaskConical, RotateCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { listKeys, testKey, rotateKey, deleteKey } from "@/api/endpoints/llmKeys";
import type { LlmKeyOut } from "@/api/types";
import AddLlmKeyDialog from "./AddLlmKeyDialog";

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  active: "default",
  inactive: "secondary",
  budget_exceeded: "destructive",
  invalid: "outline",
};

function statusLabel(s: string) {
  if (s === "budget_exceeded") return "Budget Exceeded";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function providerLabel(p: string) {
  const map: Record<string, string> = {
    openai: "OpenAI",
    anthropic: "Anthropic",
    deepseek: "DeepSeek",
    gemini: "Gemini",
    custom: "Custom",
  };
  return map[p] || p;
}

export default function LlmKeysPage() {
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<LlmKeyOut | null>(null);
  const [rotateTarget, setRotateTarget] = useState<LlmKeyOut | null>(null);
  const [newApiKey, setNewApiKey] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["llm-keys"],
    queryFn: listKeys,
  });

  const testMut = useMutation({
    mutationFn: testKey,
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["llm-keys"] });
      if (res.ok) {
        toast.success(`Key test passed (${res.models?.length ?? 0} models, ${res.latency_ms}ms)`);
      } else {
        toast.error(`Key test failed: ${res.error}`);
      }
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const rotateMut = useMutation({
    mutationFn: ({ keyId, body }: { keyId: string; body: { new_api_key: string } }) =>
      rotateKey(keyId, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["llm-keys"] });
      toast.success("Key rotated successfully");
      setRotateTarget(null);
      setNewApiKey("");
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteMut = useMutation({
    mutationFn: deleteKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["llm-keys"] });
      toast.success("Key deleted");
      setDeleteTarget(null);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const keys = data?.keys ?? [];

  return (
    <div className="container mx-auto max-w-5xl py-6 space-y-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            <h1 className="font-semibold leading-none tracking-tight">LLM API Keys</h1>
          </div>
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Add Key
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground text-sm py-8 text-center">Loading...</p>
          ) : keys.length === 0 ? (
            <p className="text-muted-foreground text-sm py-8 text-center">
              No LLM keys configured. Add your first API key to start using AI agents.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Usage</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.key_id}>
                    <TableCell>
                      <div>
                        <p className="font-medium text-sm">{k.label}</p>
                        <p className="text-xs text-muted-foreground">...{k.key_suffix}</p>
                      </div>
                    </TableCell>
                    <TableCell>{providerLabel(k.provider)}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {k.model_preference || "-"}
                    </TableCell>
                    <TableCell>
                      <Badge variant={STATUS_VARIANT[k.status ?? ""] ?? "secondary"}>
                        {statusLabel(k.status ?? "")}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {(k.monthly_budget_cents ?? 0) > 0 ? (
                        <div className="w-24">
                          <Progress
                            value={Math.min(
                              100,
                              ((k.current_month_usage_cents ?? 0) / (k.monthly_budget_cents ?? 1)) * 100,
                            )}
                            className="h-2"
                          />
                          <p className="text-xs text-muted-foreground mt-0.5">
                            ${((k.current_month_usage_cents ?? 0) / 100).toFixed(2)} / $
                            {((k.monthly_budget_cents ?? 0) / 100).toFixed(2)}
                          </p>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          {k.total_requests} reqs
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => testMut.mutate(k.key_id)}
                            disabled={testMut.isPending}
                          >
                            <FlaskConical className="h-4 w-4 mr-2" />
                            Test
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setRotateTarget(k)}>
                            <RotateCw className="h-4 w-4 mr-2" />
                            Rotate
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            className="text-destructive"
                            onClick={() => setDeleteTarget(k)}
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Add Key Dialog */}
      <AddLlmKeyDialog open={addOpen} onOpenChange={setAddOpen} />

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete LLM Key</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{deleteTarget?.label}&quot;? This action cannot
              be undone. Any agents using this key will lose access.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.key_id)}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Rotate Key Dialog */}
      <Dialog open={!!rotateTarget} onOpenChange={(o) => { if (!o) { setRotateTarget(null); setNewApiKey(""); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate API Key</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <p className="text-sm text-muted-foreground">
              Enter a new API key for &quot;{rotateTarget?.label}&quot;. The key_id stays the same
              so assigned workers continue working.
            </p>
            <div className="space-y-2">
              <Label htmlFor="rotate-key">New API Key</Label>
              <Input
                id="rotate-key"
                type="password"
                placeholder="sk-..."
                value={newApiKey}
                onChange={(e) => setNewApiKey(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setRotateTarget(null); setNewApiKey(""); }}>
              Cancel
            </Button>
            <Button
              onClick={() =>
                rotateTarget &&
                rotateMut.mutate({
                  keyId: rotateTarget.key_id,
                  body: { new_api_key: newApiKey },
                })
              }
              disabled={!newApiKey || newApiKey.length < 8 || rotateMut.isPending}
            >
              {rotateMut.isPending ? "Rotating..." : "Rotate Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
