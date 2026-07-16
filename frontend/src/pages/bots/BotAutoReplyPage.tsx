import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Plus,
  Trash2,
  Pencil,
  TestTube,
  GripVertical,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
  listAutoReplyRules,
  createAutoReplyRule,
  updateAutoReplyRule,
  deleteAutoReplyRule,
  testAutoReply,
} from "@/api/endpoints/botAutoReply";
import type { AutoReplyRule } from "@/api/types";

function matchTypeBadge(matchType: string) {
  switch (matchType) {
    case "exact":
      return <Badge variant="default">Exact</Badge>;
    case "contains":
      return <Badge variant="secondary">Contains</Badge>;
    case "keyword":
      return <Badge className="bg-blue-600 text-white">Keyword</Badge>;
    case "regex":
      return <Badge className="bg-purple-600 text-white">Regex</Badge>;
    default:
      return <Badge variant="outline">{matchType}</Badge>;
  }
}

export default function BotAutoReplyPage() {
  const { botId } = useParams<{ botId: string }>();
  const queryClient = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [editRule, setEditRule] = useState<AutoReplyRule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AutoReplyRule | null>(null);
  const [testOpen, setTestOpen] = useState(false);
  const [testInput, setTestInput] = useState("");
  const [testResult, setTestResult] = useState<any>(null);

  // Form state
  const [formPattern, setFormPattern] = useState("");
  const [formResponse, setFormResponse] = useState("");
  const [formMatchType, setFormMatchType] = useState<string>("contains");
  const [formPriority, setFormPriority] = useState("100");
  const [formEnabled, setFormEnabled] = useState(true);

  const rulesQuery = useQuery({
    queryKey: ["bot-auto-replies", botId],
    queryFn: () => listAutoReplyRules(botId!),
    enabled: !!botId,
  });

  const createMut = useMutation({
    mutationFn: (data: {
      trigger_pattern: string;
      response_template: string;
      match_type: "keyword" | "regex" | "contains" | "exact";
      priority: number;
      enabled: boolean;
    }) => createAutoReplyRule(botId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-auto-replies", botId] });
      toast.success("Auto-reply rule created");
      setShowCreate(false);
      resetForm();
    },
    onError: () => toast.error("Failed to create rule"),
  });

  const updateMut = useMutation({
    mutationFn: ({
      ruleId,
      data,
    }: {
      ruleId: string;
      data: Partial<AutoReplyRule>;
    }) => updateAutoReplyRule(botId!, ruleId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-auto-replies", botId] });
      toast.success("Rule updated");
      setEditRule(null);
      resetForm();
    },
    onError: () => toast.error("Failed to update rule"),
  });

  const deleteMut = useMutation({
    mutationFn: (ruleId: string) => deleteAutoReplyRule(botId!, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-auto-replies", botId] });
      toast.success("Rule deleted");
      setDeleteTarget(null);
    },
    onError: () => toast.error("Failed to delete rule"),
  });

  const testMut = useMutation({
    mutationFn: (msg: string) => testAutoReply(botId!, msg),
    onSuccess: (data) => {
      setTestResult(data);
    },
    onError: () => toast.error("Test failed"),
  });

  function resetForm() {
    setFormPattern("");
    setFormResponse("");
    setFormMatchType("contains");
    setFormPriority("100");
    setFormEnabled(true);
  }

  function openEdit(rule: AutoReplyRule) {
    setFormPattern(rule.trigger_pattern);
    setFormResponse(rule.response_template);
    setFormMatchType(rule.match_type);
    setFormPriority(String(rule.priority));
    setFormEnabled(rule.enabled);
    setEditRule(rule);
  }

  function handleSubmit() {
    const data = {
      trigger_pattern: formPattern,
      response_template: formResponse,
      match_type: formMatchType as "keyword" | "regex" | "contains" | "exact",
      priority: parseInt(formPriority, 10) || 100,
      enabled: formEnabled,
    };

    if (editRule) {
      updateMut.mutate({ ruleId: editRule.rule_id, data });
    } else {
      createMut.mutate(data);
    }
  }

  const rules = (rulesQuery.data as any)?.rules ?? [];

  return (
    <div className="container max-w-4xl py-8 space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/bots">
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <h1 className="text-2xl font-bold">Auto-Reply Rules</h1>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-muted-foreground">
          Configure automatic responses based on incoming message patterns.
          Rules are evaluated in priority order (lower = higher priority).
        </p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => {
              setTestOpen(true);
              setTestResult(null);
              setTestInput("");
            }}
          >
            <TestTube className="mr-2 h-4 w-4" />
            Test Message
          </Button>
          <Button
            onClick={() => {
              resetForm();
              setShowCreate(true);
            }}
          >
            <Plus className="mr-2 h-4 w-4" />
            Add Rule
          </Button>
        </div>
      </div>

      {rules.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            No auto-reply rules yet. Create one to get started.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {rules.map((rule: AutoReplyRule) => (
            <Card key={rule.rule_id} data-testid={`rule-${rule.rule_id}`}>
              <CardContent className="flex items-center justify-between py-4">
                <div className="flex items-center gap-4 flex-1 min-w-0">
                  <GripVertical className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      {matchTypeBadge(rule.match_type)}
                      <Badge variant="outline">Priority: {rule.priority}</Badge>
                      {!rule.enabled && (
                        <Badge variant="secondary" className="bg-gray-400 text-white">
                          Disabled
                        </Badge>
                      )}
                      <span className="text-xs text-muted-foreground">
                        {rule.match_count} matches
                      </span>
                    </div>
                    <p className="text-sm font-mono truncate" title={rule.trigger_pattern}>
                      Pattern: {rule.trigger_pattern}
                    </p>
                    <p className="text-sm text-muted-foreground truncate" title={rule.response_template}>
                      Response: {rule.response_template}
                    </p>
                  </div>
                </div>
                <div className="flex gap-1">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() =>
                      updateMut.mutate({
                        ruleId: rule.rule_id,
                        data: { enabled: !rule.enabled },
                      })
                    }
                    title={rule.enabled ? "Disable" : "Enable"}
                  >
                    {rule.enabled ? (
                      <ToggleRight className="h-4 w-4 text-green-600" />
                    ) : (
                      <ToggleLeft className="h-4 w-4 text-gray-400" />
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => openEdit(rule)}
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setDeleteTarget(rule)}
                  >
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog
        open={showCreate || !!editRule}
        onOpenChange={(open) => {
          if (!open) {
            setShowCreate(false);
            setEditRule(null);
            resetForm();
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editRule ? "Edit Auto-Reply Rule" : "Create Auto-Reply Rule"}
            </DialogTitle>
            <DialogDescription>
              Define a trigger pattern and the automatic response.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="matchType">Match Type</Label>
              <Select value={formMatchType} onValueChange={setFormMatchType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="contains">Contains</SelectItem>
                  <SelectItem value="exact">Exact Match</SelectItem>
                  <SelectItem value="keyword">Keyword</SelectItem>
                  <SelectItem value="regex">Regex</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="pattern">Trigger Pattern</Label>
              <Input
                id="pattern"
                value={formPattern}
                onChange={(e) => setFormPattern(e.target.value)}
                placeholder={
                  formMatchType === "keyword"
                    ? "hello, hi, hey"
                    : formMatchType === "regex"
                    ? "^(hello|hi).*"
                    : "hello"
                }
              />
            </div>
            <div>
              <Label htmlFor="response">Response Template</Label>
              <Textarea
                id="response"
                value={formResponse}
                onChange={(e) => setFormResponse(e.target.value)}
                placeholder="Hi there! How can I help you?"
                rows={3}
              />
            </div>
            <div>
              <Label htmlFor="priority">Priority (lower = higher priority)</Label>
              <Input
                id="priority"
                type="number"
                min={1}
                max={10000}
                value={formPriority}
                onChange={(e) => setFormPriority(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                checked={formEnabled}
                onChange={(e) => setFormEnabled(e.target.checked)}
                className="h-4 w-4"
              />
              <Label htmlFor="enabled">Enabled</Label>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowCreate(false);
                setEditRule(null);
                resetForm();
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={!formPattern.trim() || !formResponse.trim()}
            >
              {editRule ? "Save Changes" : "Create Rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      {deleteTarget && (
        <ConfirmDialog
          open={!!deleteTarget}
          onOpenChange={(open) => !open && setDeleteTarget(null)}
          title="Delete Auto-Reply Rule"
          description={`Delete the rule matching "${deleteTarget.trigger_pattern}"? This cannot be undone.`}
          onConfirm={() => deleteMut.mutate(deleteTarget.rule_id)}
          confirmLabel="Delete"
          variant="danger"
        />
      )}

      {/* Test Message Dialog */}
      <Dialog open={testOpen} onOpenChange={setTestOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Message Against Rules</DialogTitle>
            <DialogDescription>
              Enter a message to see which auto-reply rules would match.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="testMessage">Test Message</Label>
              <Input
                id="testMessage"
                value={testInput}
                onChange={(e) => setTestInput(e.target.value)}
                placeholder="Type a test message..."
                onKeyDown={(e) => {
                  if (e.key === "Enter" && testInput.trim()) {
                    testMut.mutate(testInput);
                  }
                }}
              />
            </div>
            <Button
              onClick={() => testMut.mutate(testInput)}
              disabled={!testInput.trim() || testMut.isPending}
            >
              {testMut.isPending ? "Testing..." : "Test"}
            </Button>
            {testResult && (
              <div className="mt-4 p-4 rounded-lg bg-muted">
                {testResult.matched ? (
                  <div>
                    <p className="font-semibold text-green-600 mb-2">
                      Matched {testResult.match_count} rule(s)
                    </p>
                    <p className="text-sm mb-1">
                      <strong>First match response:</strong>
                    </p>
                    <p className="text-sm bg-background p-2 rounded">
                      {testResult.first_match?.response_text}
                    </p>
                    {testResult.all_matches.length > 1 && (
                      <p className="text-xs text-muted-foreground mt-2">
                        +{testResult.all_matches.length - 1} more matching
                        rule(s)
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="text-muted-foreground">
                    No rules matched this message.
                  </p>
                )}
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
