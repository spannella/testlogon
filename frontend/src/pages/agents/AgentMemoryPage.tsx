import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  getIdentity,
  updateIdentity,
  getProjectContext,
  updateProjectContext,
  listEntries,
  addEntry,
  deleteEntry,
  getFullContext,
  exportMemory,
  importMemory,
  listTemplates,
} from "@/api/endpoints/agentMemory";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Brain, Plus, Download, Upload, Eye, Trash2, Star } from "lucide-react";
import type {
  AgentIdentity,
  ProjectContext,
  MemoryEntry,
  MemoryEntryCreate,
  FullContextOut,
  MemoryTemplate,
} from "@/api/types";

export default function AgentMemoryPage() {
  const { workerId } = useParams<{ workerId: string }>();
  const qc = useQueryClient();
  const [identityText, setIdentityText] = useState("");
  const [customInstructions, setCustomInstructions] = useState("");
  const [identityDirty, setIdentityDirty] = useState(false);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [showContextPreview, setShowContextPreview] = useState(false);
  const [newEntry, setNewEntry] = useState<MemoryEntryCreate>({
    category: "learning",
    title: "",
    content: "",
    importance: 3,
  });

  // Project context form state
  const [projectForm, setProjectForm] = useState({
    repo_url: "",
    branch_convention: "",
    coding_standards: "",
    pr_template: "",
    test_framework: "",
    ci_commands: "",
    file_structure_notes: "",
  });
  const [projectDirty, setProjectDirty] = useState(false);

  // ─── Queries ─────────────────────────────────────────────────

  const identityQ = useQuery({
    queryKey: ["agent-memory", workerId, "identity"],
    queryFn: async () => {
      const data: AgentIdentity = await getIdentity(workerId!);
      setIdentityText(data.identity_text);
      setCustomInstructions(data.custom_instructions);
      return data;
    },
    enabled: !!workerId,
  });

  useQuery({
    queryKey: ["agent-memory", workerId, "project"],
    queryFn: async () => {
      const data: ProjectContext = await getProjectContext(workerId!);
      setProjectForm({
        repo_url: data.repo_url,
        branch_convention: data.branch_convention,
        coding_standards: data.coding_standards,
        pr_template: data.pr_template,
        test_framework: data.test_framework,
        ci_commands: data.ci_commands,
        file_structure_notes: data.file_structure_notes,
      });
      return data;
    },
    enabled: !!workerId,
  });

  const entriesQ = useQuery({
    queryKey: ["agent-memory", workerId, "entries"],
    queryFn: () => listEntries(workerId!),
    enabled: !!workerId,
  });

  const contextQ = useQuery({
    queryKey: ["agent-memory", workerId, "full-context"],
    queryFn: () => getFullContext(workerId!) as Promise<FullContextOut>,
    enabled: !!workerId && showContextPreview,
  });

  const templatesQ = useQuery({
    queryKey: ["agent-memory", "templates"],
    queryFn: () => listTemplates() as Promise<MemoryTemplate[]>,
  });

  // ─── Mutations ───────────────────────────────────────────────

  const identityMut = useMutation({
    mutationFn: () =>
      updateIdentity(workerId!, {
        identity_text: identityText,
        custom_instructions: customInstructions,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-memory", workerId, "identity"] });
      setIdentityDirty(false);
    },
  });

  const projectMut = useMutation({
    mutationFn: () => updateProjectContext(workerId!, projectForm),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-memory", workerId, "project"] });
      setProjectDirty(false);
    },
  });

  const addMut = useMutation({
    mutationFn: (entry: MemoryEntryCreate) => addEntry(workerId!, entry),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-memory", workerId, "entries"] });
      setShowAddDialog(false);
      setNewEntry({ category: "learning", title: "", content: "", importance: 3 });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (memoryId: string) => deleteEntry(workerId!, memoryId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-memory", workerId, "entries"] });
    },
  });

  const exportMut = useMutation({
    mutationFn: () => exportMemory(workerId!),
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `agent-memory-${workerId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    },
  });

  const importMut = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      importMemory(workerId!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-memory", workerId] });
    },
  });

  const handleImport = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const text = await file.text();
      try {
        const data = JSON.parse(text);
        importMut.mutate(data);
      } catch {
        // ignore parse errors
      }
    };
    input.click();
  };

  const categoryColors: Record<string, string> = {
    learning: "bg-blue-100 text-blue-800",
    decision: "bg-green-100 text-green-800",
    pattern: "bg-purple-100 text-purple-800",
    error: "bg-red-100 text-red-800",
    custom: "bg-gray-100 text-gray-800",
  };

  const entriesData = entriesQ.data as { entries?: MemoryEntry[]; total_tokens?: number } | undefined;
  const totalTokens = entriesData?.total_tokens ?? 0;
  const tokenBudget = 100000;
  const tokenPct = Math.min(100, (totalTokens / tokenBudget) * 100);
  const tokenColor =
    tokenPct > 80 ? "bg-red-500" : tokenPct > 60 ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Brain className="h-8 w-8" />
        <div>
          <h1 className="text-2xl font-bold">Agent Memory</h1>
          <p className="text-muted-foreground">Worker: {workerId}</p>
        </div>
        <div className="ml-auto flex gap-2">
          <Button variant="outline" size="sm" onClick={() => exportMut.mutate()}>
            <Download className="h-4 w-4 mr-1" /> Export
          </Button>
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Upload className="h-4 w-4 mr-1" /> Import
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowContextPreview(!showContextPreview)}
          >
            <Eye className="h-4 w-4 mr-1" /> Preview Context
          </Button>
        </div>
      </div>

      {/* Token budget bar */}
      <div className="space-y-1">
        <div className="flex justify-between text-sm text-muted-foreground">
          <span>Token budget</span>
          <span>
            {totalTokens.toLocaleString()} / {tokenBudget.toLocaleString()} tokens
          </span>
        </div>
        <div className="h-2 bg-muted rounded-full overflow-hidden">
          <div
            className={`h-full ${tokenColor} transition-all`}
            style={{ width: `${tokenPct}%` }}
          />
        </div>
      </div>

      {/* Context Preview */}
      {showContextPreview && (
        <Card>
          <CardHeader>
            <CardTitle asChild>
              <h2>Context Preview</h2>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {contextQ.isLoading && <p>Loading context...</p>}
            {contextQ.data && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-muted-foreground">
                  <span>Total tokens: {(contextQ.data as FullContextOut).total_tokens}</span>
                  <span>Sections: {(contextQ.data as FullContextOut).sections.length}</span>
                </div>
                <pre className="bg-muted p-4 rounded-md text-sm whitespace-pre-wrap max-h-96 overflow-y-auto">
                  {(contextQ.data as FullContextOut).context_text}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Identity Section */}
      <Card>
        <CardHeader>
          <CardTitle>Agent Identity</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {identityQ.data && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Badge variant="secondary">{(identityQ.data as AgentIdentity).agent_type}</Badge>
              {templatesQ.data && (
                <Select
                  onValueChange={(v: string) => {
                    const templates = templatesQ.data as MemoryTemplate[];
                    const t = templates.find((tpl) => tpl.agent_type === v);
                    if (t) {
                      setIdentityText(t.identity_text);
                      setIdentityDirty(true);
                    }
                  }}
                >
                  <SelectTrigger className="w-48">
                    <SelectValue placeholder="Reset to template" />
                  </SelectTrigger>
                  <SelectContent>
                    {(templatesQ.data as MemoryTemplate[]).map((t) => (
                      <SelectItem key={t.agent_type} value={t.agent_type}>
                        {t.agent_type}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          )}
          <div>
            <label className="text-sm font-medium">Identity prompt</label>
            <Textarea
              className="mt-1 min-h-[200px] font-mono text-sm"
              value={identityText}
              onChange={(e) => {
                setIdentityText(e.target.value);
                setIdentityDirty(true);
              }}
            />
          </div>
          <div>
            <label className="text-sm font-medium">Custom instructions</label>
            <Textarea
              className="mt-1 min-h-[80px]"
              value={customInstructions}
              onChange={(e) => {
                setCustomInstructions(e.target.value);
                setIdentityDirty(true);
              }}
              placeholder="Additional instructions for this agent..."
            />
          </div>
          {identityDirty && (
            <Button
              onClick={() => identityMut.mutate()}
              disabled={identityMut.isPending}
            >
              Save Identity
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Project Context Section */}
      <Card>
        <CardHeader>
          <CardTitle>Project Context</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-sm font-medium">Repository URL</label>
              <Input
                value={projectForm.repo_url}
                onChange={(e) => {
                  setProjectForm((p) => ({ ...p, repo_url: e.target.value }));
                  setProjectDirty(true);
                }}
                placeholder="https://github.com/..."
              />
            </div>
            <div>
              <label className="text-sm font-medium">Branch convention</label>
              <Input
                value={projectForm.branch_convention}
                onChange={(e) => {
                  setProjectForm((p) => ({
                    ...p,
                    branch_convention: e.target.value,
                  }));
                  setProjectDirty(true);
                }}
                placeholder="agent/{worker_id}/{ticket_id}"
              />
            </div>
            <div>
              <label className="text-sm font-medium">Test framework</label>
              <Input
                value={projectForm.test_framework}
                onChange={(e) => {
                  setProjectForm((p) => ({
                    ...p,
                    test_framework: e.target.value,
                  }));
                  setProjectDirty(true);
                }}
                placeholder="pytest"
              />
            </div>
            <div>
              <label className="text-sm font-medium">CI commands</label>
              <Input
                value={projectForm.ci_commands}
                onChange={(e) => {
                  setProjectForm((p) => ({ ...p, ci_commands: e.target.value }));
                  setProjectDirty(true);
                }}
                placeholder="just test && just e2e"
              />
            </div>
          </div>
          <div>
            <label className="text-sm font-medium">Coding standards</label>
            <Textarea
              className="mt-1 min-h-[80px]"
              value={projectForm.coding_standards}
              onChange={(e) => {
                setProjectForm((p) => ({
                  ...p,
                  coding_standards: e.target.value,
                }));
                setProjectDirty(true);
              }}
              placeholder="Project coding standards..."
            />
          </div>
          {projectDirty && (
            <Button
              onClick={() => projectMut.mutate()}
              disabled={projectMut.isPending}
            >
              Save Project Context
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Memory Entries Section */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle asChild>
            <h2>Memory Entries</h2>
          </CardTitle>
          <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-1" /> Add Memory
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Memory Entry</DialogTitle>
              </DialogHeader>
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium">Category</label>
                  <Select
                    value={newEntry.category}
                    onValueChange={(v: string) =>
                      setNewEntry((e) => ({
                        ...e,
                        category: v as MemoryEntryCreate["category"],
                      }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="learning">Learning</SelectItem>
                      <SelectItem value="decision">Decision</SelectItem>
                      <SelectItem value="pattern">Pattern</SelectItem>
                      <SelectItem value="error">Error</SelectItem>
                      <SelectItem value="custom">Custom</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="text-sm font-medium">Title</label>
                  <Input
                    value={newEntry.title}
                    onChange={(e) =>
                      setNewEntry((n) => ({ ...n, title: e.target.value }))
                    }
                    placeholder="Memory title"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">Content</label>
                  <Textarea
                    className="min-h-[100px]"
                    value={newEntry.content}
                    onChange={(e) =>
                      setNewEntry((n) => ({ ...n, content: e.target.value }))
                    }
                    placeholder="What the agent learned..."
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">
                    Importance (1-5)
                  </label>
                  <div className="flex gap-1 mt-1">
                    {[1, 2, 3, 4, 5].map((i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() =>
                          setNewEntry((n) => ({ ...n, importance: i }))
                        }
                        className="p-1"
                      >
                        <Star
                          className={`h-5 w-5 ${
                            i <= (newEntry.importance ?? 3)
                              ? "fill-yellow-400 text-yellow-400"
                              : "text-gray-300"
                          }`}
                        />
                      </button>
                    ))}
                  </div>
                </div>
                <Button
                  onClick={() => addMut.mutate(newEntry)}
                  disabled={!newEntry.title || !newEntry.content || addMut.isPending}
                  className="w-full"
                >
                  Add Entry
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </CardHeader>
        <CardContent>
          {(!entriesData?.entries || entriesData.entries.length === 0) && (
            <p className="text-muted-foreground text-center py-8">
              No memory entries yet. Add one to help the agent learn.
            </p>
          )}
          <div className="space-y-2">
            {entriesData?.entries?.map((entry: MemoryEntry) => (
              <div
                key={entry.memory_id}
                className="border rounded-lg p-3 space-y-1"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge
                      className={
                        categoryColors[entry.category] ?? categoryColors.custom
                      }
                    >
                      {entry.category}
                    </Badge>
                    <span className="font-medium">{entry.title}</span>
                    <span className="text-xs text-muted-foreground">
                      {entry.token_count} tokens
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    {Array.from({ length: entry.importance }, (_, i) => (
                      <Star
                        key={i}
                        className="h-3 w-3 fill-yellow-400 text-yellow-400"
                      />
                    ))}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => deleteMut.mutate(entry.memory_id)}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground line-clamp-2">
                  {entry.summarized ? entry.summary : entry.content}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
