import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Send, Mail, Eye, FlaskConical } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import {
  createCampaign,
  listCampaigns,
  listEmailTemplates,
  previewCampaignEmail,
  sendCampaign,
  type CrmCampaign,
  type MarketingCampaignSendOut,
  type MarketingEmailPreviewOut,
} from "@/api/endpoints/crmEmail";
import { NotEnabledState, isNotEnabledError } from "./NotEnabledState";

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function dollars(cents?: number): string {
  return `$${((cents ?? 0) / 100).toFixed(2)}`;
}

export default function EmailComposePage() {
  const qc = useQueryClient();

  const [selectedId, setSelectedId] = useState<string | null>(null);

  // New-campaign form
  const [name, setName] = useState("");
  const [objective, setObjective] = useState("");
  const [budget, setBudget] = useState("");
  const [templateId, setTemplateId] = useState<string>("");
  const [contactLists, setContactLists] = useState("");

  const [preview, setPreview] = useState<MarketingEmailPreviewOut | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [sendResult, setSendResult] = useState<MarketingCampaignSendOut | null>(null);
  const [sendResultOpen, setSendResultOpen] = useState(false);

  const campaignsQuery = useQuery({
    queryKey: ["crm-email", "campaigns", "email"],
    queryFn: () => listCampaigns({ campaign_type: "email", limit: 100 }),
    retry: false,
  });

  const templatesQuery = useQuery({
    queryKey: ["crm-email", "templates"],
    queryFn: () => listEmailTemplates({ limit: 100 }),
    retry: false,
    enabled: !(campaignsQuery.isError && isNotEnabledError(campaignsQuery.error)),
  });

  const campaigns = campaignsQuery.data?.campaigns ?? [];
  const templates = templatesQuery.data?.templates ?? [];
  const selected = campaigns.find((c) => c.campaign_id === selectedId) ?? null;

  const createMut = useMutation({
    mutationFn: () =>
      createCampaign({
        name: name.trim(),
        campaign_type: "email",
        objective: objective.trim() || undefined,
        budget_cents: budget.trim() ? Math.round(parseFloat(budget) * 100) : undefined,
        email_template_id: templateId || undefined,
        contact_list_ids: contactLists
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    onSuccess: (res) => {
      toast.success("Campaign created");
      setName("");
      setObjective("");
      setBudget("");
      setTemplateId("");
      setContactLists("");
      setSelectedId(res.campaign_id);
      void qc.invalidateQueries({ queryKey: ["crm-email", "campaigns", "email"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to create campaign"),
  });

  const previewMut = useMutation({
    mutationFn: (id: string) => previewCampaignEmail(id, {}),
    onSuccess: (res) => {
      setPreview(res);
      setPreviewOpen(true);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to render preview"),
  });

  const dryRunMut = useMutation({
    mutationFn: (id: string) => sendCampaign(id, { dry_run: true }),
    onSuccess: (res) => {
      setSendResult(res);
      setSendResultOpen(true);
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Dry run failed"),
  });

  const sendMut = useMutation({
    mutationFn: (id: string) => sendCampaign(id, { dry_run: false }),
    onSuccess: (res) => {
      setSendResult(res);
      setSendResultOpen(true);
      toast.success(`Sent to ${res.total_sent} recipient(s)`);
      void qc.invalidateQueries({ queryKey: ["crm-email", "campaigns", "email"] });
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Send failed"),
  });

  const canCreate = useMemo(() => name.trim().length > 0, [name]);

  if (campaignsQuery.isError && isNotEnabledError(campaignsQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Compose & Send" description="SuiteCRM email campaigns" />
        <NotEnabledState feature="Email campaigns" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compose & Send"
        description="Create an email campaign, attach a template, preview merge tags, and send."
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        {/* New campaign + selected detail */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Plus className="h-4 w-4" /> New email campaign
              </CardTitle>
              <CardDescription>Draft a campaign — it is created in draft status.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="c-name">Campaign name</Label>
                <Input
                  id="c-name"
                  value={name}
                  maxLength={200}
                  placeholder="Spring newsletter"
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="c-budget">Budget (USD)</Label>
                  <Input
                    id="c-budget"
                    type="number"
                    min="0"
                    step="0.01"
                    value={budget}
                    placeholder="0.00"
                    onChange={(e) => setBudget(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="c-template">Email template</Label>
                  <Select value={templateId} onValueChange={setTemplateId}>
                    <SelectTrigger id="c-template">
                      <SelectValue placeholder="None" />
                    </SelectTrigger>
                    <SelectContent>
                      {templates.length === 0 && (
                        <SelectItem value="__none" disabled>
                          No templates available
                        </SelectItem>
                      )}
                      {templates.map((t) => (
                        <SelectItem key={t.template_id} value={t.template_id}>
                          {t.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="c-lists">Contact list IDs (comma-separated)</Label>
                <Input
                  id="c-lists"
                  value={contactLists}
                  placeholder="list_abc, list_xyz"
                  onChange={(e) => setContactLists(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="c-objective">Objective</Label>
                <Textarea
                  id="c-objective"
                  value={objective}
                  maxLength={500}
                  rows={2}
                  placeholder="Drive Q2 re-engagement"
                  onChange={(e) => setObjective(e.target.value)}
                />
              </div>
              <Button onClick={() => createMut.mutate()} disabled={!canCreate || createMut.isPending}>
                <Plus className="mr-2 h-4 w-4" />
                {createMut.isPending ? "Creating…" : "Create campaign"}
              </Button>
            </CardContent>
          </Card>

          {selected && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between gap-2 text-base">
                  <span className="flex items-center gap-2">
                    <Mail className="h-4 w-4" /> {selected.name}
                  </span>
                  <Badge variant={selected.status === "draft" ? "secondary" : "default"}>
                    {selected.status}
                  </Badge>
                </CardTitle>
                <CardDescription>{selected.objective || "No objective set"}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                  <dt className="text-muted-foreground">Budget</dt>
                  <dd>{dollars(selected.budget_cents)}</dd>
                  <dt className="text-muted-foreground">Template</dt>
                  <dd>{selected.email_template_id || "—"}</dd>
                  <dt className="text-muted-foreground">Contact lists</dt>
                  <dd>{selected.contact_list_ids.length || 0}</dd>
                  <dt className="text-muted-foreground">Tracking code</dt>
                  <dd className="truncate">{selected.tracking_code || "—"}</dd>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd>{fmt(selected.created_at)}</dd>
                </dl>

                <div className="flex flex-wrap gap-2 pt-2">
                  <Button
                    variant="outline"
                    onClick={() => previewMut.mutate(selected.campaign_id)}
                    disabled={previewMut.isPending}
                  >
                    <Eye className="mr-2 h-4 w-4" /> Preview email
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => dryRunMut.mutate(selected.campaign_id)}
                    disabled={dryRunMut.isPending}
                  >
                    <FlaskConical className="mr-2 h-4 w-4" />
                    {dryRunMut.isPending ? "Resolving…" : "Dry run"}
                  </Button>
                  <Button
                    onClick={() => sendMut.mutate(selected.campaign_id)}
                    disabled={sendMut.isPending}
                  >
                    <Send className="mr-2 h-4 w-4" />
                    {sendMut.isPending ? "Sending…" : "Send campaign"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Campaign picker */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Email campaigns</CardTitle>
            <CardDescription>
              {campaignsQuery.data ? `${campaignsQuery.data.count} campaign(s)` : "Loading…"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {campaignsQuery.isLoading && (
              <>
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </>
            )}
            {campaignsQuery.isError && !isNotEnabledError(campaignsQuery.error) && (
              <p className="text-sm text-destructive">
                {(campaignsQuery.error as ApiError)?.detail ?? "Failed to load campaigns"}
              </p>
            )}
            {!campaignsQuery.isLoading && campaigns.length === 0 && (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No email campaigns yet.
              </p>
            )}
            {campaigns.map((c: CrmCampaign) => (
              <button
                key={c.campaign_id}
                onClick={() => setSelectedId(c.campaign_id)}
                className={`flex w-full flex-col gap-1 rounded-md border p-3 text-left transition hover:bg-accent ${
                  selectedId === c.campaign_id ? "border-primary bg-accent" : "border-border"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">{c.name}</span>
                  <Badge variant={c.status === "draft" ? "secondary" : "default"}>
                    {c.status}
                  </Badge>
                </div>
                <span className="text-xs text-muted-foreground">
                  {dollars(c.budget_cents)} · {fmt(c.created_at)}
                </span>
              </button>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Preview dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Email preview</DialogTitle>
            <DialogDescription>Rendered with sample merge values.</DialogDescription>
          </DialogHeader>
          {preview && (
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-muted-foreground">Subject</Label>
                <p className="font-medium">{preview.subject}</p>
              </div>
              {preview.body_html ? (
                <div>
                  <Label className="text-xs text-muted-foreground">HTML body</Label>
                  <div
                    className="mt-1 max-h-80 overflow-auto rounded-md border bg-white p-4 text-sm text-black"
                    dangerouslySetInnerHTML={{ __html: preview.body_html }}
                  />
                </div>
              ) : (
                <div>
                  <Label className="text-xs text-muted-foreground">Text body</Label>
                  <pre className="mt-1 max-h-80 overflow-auto whitespace-pre-wrap rounded-md border p-4 text-sm">
                    {preview.body_text}
                  </pre>
                </div>
              )}
              {preview.merge_vars_missing.length > 0 && (
                <p className="text-xs text-amber-600">
                  Missing merge values: {preview.merge_vars_missing.join(", ")}
                </p>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Send result dialog */}
      <Dialog open={sendResultOpen} onOpenChange={setSendResultOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{sendResult?.dry_run ? "Dry run result" : "Send complete"}</DialogTitle>
            <DialogDescription>
              {sendResult?.dry_run
                ? "No emails were sent. This is a preview of resolved recipients."
                : "The campaign has been dispatched."}
            </DialogDescription>
          </DialogHeader>
          {sendResult && (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
              <dt className="text-muted-foreground">Resolved</dt>
              <dd>{sendResult.total_resolved}</dd>
              <dt className="text-muted-foreground">Sent</dt>
              <dd>{sendResult.total_sent}</dd>
              <dt className="text-muted-foreground">Skipped</dt>
              <dd>{sendResult.total_skipped}</dd>
            </dl>
          )}
          <DialogFooter>
            <Button onClick={() => setSendResultOpen(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
