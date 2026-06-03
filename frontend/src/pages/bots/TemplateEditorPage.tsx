import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Plus,
  Trash2,
  Pencil,
  Clock,
  BarChart3,
  MessageSquare,
} from "lucide-react";
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
import { Switch } from "@/components/ui/switch";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getBot,
  listTemplates,
  createTemplate,
  updateTemplate,
  deleteTemplate,
  previewTemplate,
  listScheduledSends,
  createScheduledSend,
  updateScheduledSend,
  deleteScheduledSend,
} from "@/api/endpoints/bots";
import type { BotTemplate, BotScheduledSend, TemplatePreviewOut } from "@/api/types";

const CATEGORIES = [
  { value: "all", label: "All" },
  { value: "greeting", label: "Greeting" },
  { value: "support", label: "Support" },
  { value: "promotion", label: "Promotion" },
  { value: "farewell", label: "Farewell" },
  { value: "away", label: "Away" },
  { value: "custom", label: "Custom" },
] as const;

const VARIABLES = [
  "{user_name}",
  "{creator_name}",
  "{bot_name}",
  "{current_time}",
  "{current_date}",
  "{subscriber_status}",
  "{conversation_name}",
];

function categoryBadge(category: string) {
  const colors: Record<string, string> = {
    greeting: "bg-green-100 text-green-800",
    support: "bg-blue-100 text-blue-800",
    promotion: "bg-purple-100 text-purple-800",
    farewell: "bg-orange-100 text-orange-800",
    away: "bg-yellow-100 text-yellow-800",
    custom: "bg-gray-100 text-gray-800",
  };
  return (
    <Badge variant="outline" className={colors[category] || ""}>
      {category}
    </Badge>
  );
}

export default function TemplateEditorPage() {
  const { botId } = useParams<{ botId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [formOpen, setFormOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<BotTemplate | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<BotTemplate | null>(null);
  const [previewResult, setPreviewResult] = useState<TemplatePreviewOut | null>(null);

  // Form state
  const [formName, setFormName] = useState("");
  const [formText, setFormText] = useState("");
  const [formCategory, setFormCategory] = useState("custom");
  const [formBodyFormat, setFormBodyFormat] = useState("plain");
  const [formQuickReplies, setFormQuickReplies] = useState<Array<{ label: string; value: string }>>([]);
  const [formAbGroup, setFormAbGroup] = useState("");
  const [formAbWeight, setFormAbWeight] = useState(1);

  // Schedule form
  const [scheduleFormOpen, setScheduleFormOpen] = useState(false);
  const [schedFormTemplateId, setSchedFormTemplateId] = useState("");
  const [schedFormTargetType, setSchedFormTargetType] = useState("all_dms");
  const [schedFormCron, setSchedFormCron] = useState("0 14 * * *");
  const [schedFormTimezone, setSchedFormTimezone] = useState("UTC");

  const botQuery = useQuery({
    queryKey: ["bots", botId],
    queryFn: () => getBot(botId!),
    enabled: !!botId,
  });

  const templatesQuery = useQuery({
    queryKey: ["bot-templates", botId, categoryFilter],
    queryFn: () =>
      listTemplates(botId!, categoryFilter === "all" ? undefined : categoryFilter),
    enabled: !!botId,
  });

  const schedulesQuery = useQuery({
    queryKey: ["bot-schedules", botId],
    queryFn: () => listScheduledSends(botId!),
    enabled: !!botId,
  });

  const createMut = useMutation({
    mutationFn: (data: Parameters<typeof createTemplate>[1]) =>
      createTemplate(botId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-templates", botId] });
      toast.success("Template created");
      setFormOpen(false);
      resetForm();
    },
    onError: () => toast.error("Failed to create template"),
  });

  const updateMut = useMutation({
    mutationFn: ({
      templateId,
      data,
    }: {
      templateId: string;
      data: Partial<BotTemplate>;
    }) => updateTemplate(botId!, templateId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-templates", botId] });
      toast.success("Template updated");
      setFormOpen(false);
      resetForm();
    },
    onError: () => toast.error("Failed to update template"),
  });

  const deleteMut = useMutation({
    mutationFn: (templateId: string) => deleteTemplate(botId!, templateId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-templates", botId] });
      toast.success("Template deleted");
      setDeleteTarget(null);
    },
    onError: () => toast.error("Failed to delete template"),
  });

  const previewMut = useMutation({
    mutationFn: (templateId: string) =>
      previewTemplate(botId!, templateId, { sample_user_name: "TestUser" }),
    onSuccess: (data) => setPreviewResult(data),
    onError: () => toast.error("Failed to preview template"),
  });

  const createScheduleMut = useMutation({
    mutationFn: (data: Parameters<typeof createScheduledSend>[1]) =>
      createScheduledSend(botId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-schedules", botId] });
      toast.success("Schedule created");
      setScheduleFormOpen(false);
    },
    onError: () => toast.error("Failed to create schedule"),
  });

  const toggleScheduleMut = useMutation({
    mutationFn: ({ scheduleId, enabled }: { scheduleId: string; enabled: boolean }) =>
      updateScheduledSend(botId!, scheduleId, { enabled } as Partial<BotScheduledSend>),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-schedules", botId] });
      toast.success("Schedule updated");
    },
    onError: () => toast.error("Failed to update schedule"),
  });

  const deleteScheduleMut = useMutation({
    mutationFn: (scheduleId: string) => deleteScheduledSend(botId!, scheduleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bot-schedules", botId] });
      toast.success("Schedule deleted");
    },
    onError: () => toast.error("Failed to delete schedule"),
  });

  function resetForm() {
    setFormName("");
    setFormText("");
    setFormCategory("custom");
    setFormBodyFormat("plain");
    setFormQuickReplies([]);
    setFormAbGroup("");
    setFormAbWeight(1);
    setEditingTemplate(null);
    setPreviewResult(null);
  }

  function openCreate() {
    resetForm();
    setFormOpen(true);
  }

  function openEdit(t: BotTemplate) {
    setEditingTemplate(t);
    setFormName(t.name);
    setFormText(t.text);
    setFormCategory(t.category);
    setFormBodyFormat(t.body_format);
    setFormQuickReplies(t.quick_replies || []);
    setFormAbGroup(t.ab_group || "");
    setFormAbWeight(t.ab_weight);
    setFormOpen(true);
  }

  function handleSave() {
    const payload = {
      name: formName,
      text: formText,
      category: formCategory,
      body_format: formBodyFormat,
      quick_replies: formQuickReplies.length > 0 ? formQuickReplies : undefined,
      ab_group: formAbGroup || undefined,
      ab_weight: formAbWeight,
    };
    if (editingTemplate) {
      updateMut.mutate({
        templateId: editingTemplate.template_id,
        data: payload as Partial<BotTemplate>,
      });
    } else {
      createMut.mutate(payload);
    }
  }

  function addQuickReply() {
    if (formQuickReplies.length < 5) {
      setFormQuickReplies([...formQuickReplies, { label: "", value: "" }]);
    }
  }

  function removeQuickReply(index: number) {
    setFormQuickReplies(formQuickReplies.filter((_, i) => i !== index));
  }

  function updateQuickReply(index: number, field: "label" | "value", val: string) {
    setFormQuickReplies((prev) =>
      prev.map((qr, i) => (i === index ? { ...qr, [field]: val } : qr)),
    );
  }

  function insertVariable(variable: string) {
    setFormText((prev) => prev + variable);
  }

  const templates = templatesQuery.data || [];
  const schedules = schedulesQuery.data || [];
  const bot = botQuery.data;

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6" data-testid="template-editor-page">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={() => navigate("/bots")}>
          <ArrowLeft className="mr-1 h-4 w-4" /> Back
        </Button>
        <MessageSquare className="h-6 w-6" />
        <h1 className="text-2xl font-bold">
          Templates{bot ? ` - ${bot.name}` : ""}
        </h1>
        <Button onClick={openCreate} data-testid="create-template-btn">
          <Plus className="mr-2 h-4 w-4" /> New Template
        </Button>
      </div>

      {/* Category tabs */}
      <div className="flex gap-2 flex-wrap">
        {CATEGORIES.map((cat) => (
          <Button
            key={cat.value}
            variant={categoryFilter === cat.value ? "default" : "outline"}
            size="sm"
            onClick={() => setCategoryFilter(cat.value)}
            data-testid={`category-tab-${cat.value}`}
          >
            {cat.label}
          </Button>
        ))}
      </div>

      {/* Templates list */}
      {templatesQuery.isLoading && <p className="text-muted-foreground">Loading...</p>}
      {!templatesQuery.isLoading && templates.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-muted-foreground">No templates yet. Create one to get started.</p>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {templates.map((t) => (
          <Card key={t.template_id} data-testid={`template-card-${t.template_id}`}>
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-base">{t.name}</CardTitle>
                  <div className="flex items-center gap-2 mt-1">
                    {categoryBadge(t.category)}
                    {t.ab_group && (
                      <Badge variant="secondary" className="text-xs">
                        A/B: {t.ab_group} (w:{t.ab_weight})
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-sm text-muted-foreground line-clamp-2">{t.text}</p>
              {t.variables_used && t.variables_used.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {t.variables_used.map((v) => (
                    <Badge key={v} variant="outline" className="text-xs">
                      {"{" + v + "}"}
                    </Badge>
                  ))}
                </div>
              )}
              {t.quick_replies && t.quick_replies.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {t.quick_replies.map((qr, i) => (
                    <Badge key={i} variant="secondary" className="text-xs">
                      {qr.label}
                    </Badge>
                  ))}
                </div>
              )}
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <BarChart3 className="h-3 w-3" />
                  {t.impression_count} sent
                </span>
                <span>
                  {t.impression_count > 0
                    ? `${Math.round((t.response_count / t.impression_count) * 100)}% response`
                    : "0% response"}
                </span>
              </div>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={() => openEdit(t)}>
                  <Pencil className="mr-1 h-3 w-3" /> Edit
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => previewMut.mutate(t.template_id)}
                >
                  Preview
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => setDeleteTarget(t)}
                >
                  <Trash2 className="mr-1 h-3 w-3" /> Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Preview panel */}
      {previewResult && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Preview</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm" data-testid="preview-rendered-text">
              {previewResult.rendered_text}
            </p>
            {previewResult.quick_replies && (
              <div className="flex gap-2 mt-2" data-testid="preview-quick-replies">
                {previewResult.quick_replies.map((qr, i) => (
                  <Button key={i} variant="outline" size="sm">
                    {qr.label}
                  </Button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Scheduled Sends section */}
      <div className="space-y-4" data-testid="schedule-manager-panel">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Clock className="h-5 w-5" /> Scheduled Sends
          </h2>
          <Button
            size="sm"
            onClick={() => setScheduleFormOpen(true)}
            disabled={templates.length === 0}
          >
            <Plus className="mr-1 h-3 w-3" /> Add Schedule
          </Button>
        </div>

        {schedules.length === 0 && (
          <p className="text-sm text-muted-foreground">No scheduled sends configured.</p>
        )}

        <div className="grid gap-3">
          {schedules.map((s) => (
            <Card key={s.schedule_id} data-testid={`schedule-card-${s.schedule_id}`}>
              <CardContent className="flex items-center justify-between py-4">
                <div className="space-y-1">
                  <p className="text-sm font-medium">
                    Template: {templates.find((t) => t.template_id === s.template_id)?.name || s.template_id}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Cron: {s.cron_expression} ({s.timezone})
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Target: {s.target_type}
                    {s.next_run_at
                      ? ` | Next: ${new Date(s.next_run_at * 1000).toLocaleString()}`
                      : ""}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2">
                    <Label htmlFor={`sched-toggle-${s.schedule_id}`} className="text-xs">
                      {s.enabled ? "Enabled" : "Disabled"}
                    </Label>
                    <Switch
                      id={`sched-toggle-${s.schedule_id}`}
                      checked={s.enabled}
                      onCheckedChange={(checked) =>
                        toggleScheduleMut.mutate({
                          scheduleId: s.schedule_id,
                          enabled: checked,
                        })
                      }
                    />
                  </div>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => deleteScheduleMut.mutate(s.schedule_id)}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Template form dialog */}
      <Dialog open={formOpen} onOpenChange={setFormOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto" data-testid="template-form-dialog">
          <DialogHeader>
            <DialogTitle>
              {editingTemplate ? "Edit Template" : "New Template"}
            </DialogTitle>
            <DialogDescription>
              {editingTemplate
                ? "Update your message template."
                : "Create a reusable message template for your bot."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="tpl-name">Name</Label>
              <Input
                id="tpl-name"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="e.g. Welcome Greeting"
                maxLength={100}
                data-testid="template-name-input"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="tpl-category">Category</Label>
              <Select value={formCategory} onValueChange={setFormCategory}>
                <SelectTrigger id="tpl-category" data-testid="template-category-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="greeting">Greeting</SelectItem>
                  <SelectItem value="support">Support</SelectItem>
                  <SelectItem value="promotion">Promotion</SelectItem>
                  <SelectItem value="farewell">Farewell</SelectItem>
                  <SelectItem value="away">Away</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Variables</Label>
              <div className="flex gap-1 flex-wrap">
                {VARIABLES.map((v) => (
                  <Button
                    key={v}
                    type="button"
                    variant="outline"
                    size="sm"
                    className="text-xs"
                    onClick={() => insertVariable(v)}
                  >
                    {v}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="tpl-text">Template Text</Label>
              <Textarea
                id="tpl-text"
                value={formText}
                onChange={(e) => setFormText(e.target.value)}
                placeholder="Hello {user_name}! Welcome..."
                maxLength={4000}
                rows={5}
                data-testid="template-text-input"
              />
            </div>

            {/* Quick Replies */}
            <div className="space-y-2">
              <Label>Quick Replies ({formQuickReplies.length}/5)</Label>
              {formQuickReplies.map((qr, i) => (
                <div key={i} className="flex gap-2 items-center">
                  <Input
                    placeholder="Label"
                    value={qr.label}
                    onChange={(e) => updateQuickReply(i, "label", e.target.value)}
                    maxLength={40}
                    className="flex-1"
                    data-testid={`qr-label-${i}`}
                  />
                  <Input
                    placeholder="Value"
                    value={qr.value}
                    onChange={(e) => updateQuickReply(i, "value", e.target.value)}
                    maxLength={200}
                    className="flex-1"
                    data-testid={`qr-value-${i}`}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => removeQuickReply(i)}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))}
              {formQuickReplies.length < 5 && (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={addQuickReply}
                  data-testid="add-quick-reply-btn"
                >
                  <Plus className="mr-1 h-3 w-3" /> Add Quick Reply
                </Button>
              )}
            </div>

            {/* A/B group */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="tpl-ab-group">A/B Group (optional)</Label>
                <Input
                  id="tpl-ab-group"
                  value={formAbGroup}
                  onChange={(e) => setFormAbGroup(e.target.value)}
                  placeholder="e.g. greeting_test"
                  maxLength={50}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tpl-ab-weight">A/B Weight</Label>
                <Input
                  id="tpl-ab-weight"
                  type="number"
                  min={1}
                  max={100}
                  value={formAbWeight}
                  onChange={(e) => setFormAbWeight(Number(e.target.value))}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setFormOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={!formName.trim() || !formText.trim()}
              data-testid="template-save-btn"
            >
              {editingTemplate ? "Save Changes" : "Create Template"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Schedule form dialog */}
      <Dialog open={scheduleFormOpen} onOpenChange={setScheduleFormOpen}>
        <DialogContent data-testid="schedule-form-dialog">
          <DialogHeader>
            <DialogTitle>New Scheduled Send</DialogTitle>
            <DialogDescription>
              Schedule a template to be sent automatically.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>Template</Label>
              <Select value={schedFormTemplateId} onValueChange={setSchedFormTemplateId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a template" />
                </SelectTrigger>
                <SelectContent>
                  {templates.map((t) => (
                    <SelectItem key={t.template_id} value={t.template_id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Target</Label>
              <Select value={schedFormTargetType} onValueChange={setSchedFormTargetType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all_dms">All DMs</SelectItem>
                  <SelectItem value="all_groups">All Groups</SelectItem>
                  <SelectItem value="all_broadcasts">All Broadcasts</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sched-cron">Cron Expression</Label>
              <Input
                id="sched-cron"
                value={schedFormCron}
                onChange={(e) => setSchedFormCron(e.target.value)}
                placeholder="0 14 * * *"
              />
              <p className="text-xs text-muted-foreground">
                Format: minute hour day-of-month month day-of-week
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sched-tz">Timezone</Label>
              <Input
                id="sched-tz"
                value={schedFormTimezone}
                onChange={(e) => setSchedFormTimezone(e.target.value)}
                placeholder="UTC"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setScheduleFormOpen(false)}
            >
              Cancel
            </Button>
            <Button
              onClick={() =>
                createScheduleMut.mutate({
                  template_id: schedFormTemplateId,
                  target_type: schedFormTargetType,
                  cron_expression: schedFormCron,
                  timezone: schedFormTimezone,
                })
              }
              disabled={!schedFormTemplateId || !schedFormCron.trim()}
              data-testid="schedule-save-btn"
            >
              Create Schedule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      {deleteTarget && (
        <ConfirmDialog
          open={!!deleteTarget}
          onOpenChange={(open) => {
            if (!open) setDeleteTarget(null);
          }}
          title="Delete Template"
          description={`Are you sure you want to delete "${deleteTarget.name}"? This action cannot be undone.`}
          confirmLabel="Delete"
          variant="danger"
          onConfirm={() => deleteMut.mutate(deleteTarget.template_id)}
        />
      )}
    </div>
  );
}
